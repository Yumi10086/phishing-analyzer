"""附件内容分析编排：解析后立即执行，先于 IOC 提取。

两件事：
1. **OCR 图内文字回收**：正文文字极少且存在图片（附件图或内嵌 CID 图）时跑 OCR，
   文本**直接并入 ``parsed["body_text"]``**——本函数在 pipeline 中先于
   ``extract_iocs`` 调用，图内的钓鱼 URL/域名因此能走完整的
   「IOC 提取 -> VT/URLScan -> 情报 55 分」链路，而不只是启发式关键词匹配；
2. **附件内容分析**：归档递归（archive）/Office 宏与远程模板（office）/
   PDF 关键字（pdf），结论写回 ``parsed["attachments"][i]`` 的子字典，
   features 侧转成附件作用域字段供规则计分。

非对应类型的附件不产生任何字段，规则按 False 兜底，互不干扰。
"""
from __future__ import annotations

from typing import Any

from app.attachment.archive import analyze_attachment_bytes
from app.attachment.ocr import decode_qr, ocr_available, ocr_images
from app.attachment.office import analyze_office
from app.attachment.pdf import analyze_pdf
from app.rules import loader as yara_loader

# 密码候选来源文本的截断长度（正文+HTML 合计）
_PASSWORD_TEXT_LIMIT = 200_000
# OCR 触发门控：正文文字极少（<200 字符）且存在图片——"文字藏在图内"的规避形态；
# 正常长文本邮件零 OCR 成本。报告里记录的 OCR 文本截断长度
_OCR_BODY_TEXT_LIMIT = 200
_OCR_TEXT_REPORT_LIMIT = 1000


def _password_source_text(parsed: dict[str, Any]) -> str:
    headers = parsed.get("headers", {}) or {}
    subject = headers.get("subject") or ""
    if isinstance(subject, list):
        subject = " ".join(str(s) for s in subject)
    return "\n".join([
        str(subject),
        (parsed.get("body_text") or "")[:_PASSWORD_TEXT_LIMIT],
        (parsed.get("body_html") or "")[:_PASSWORD_TEXT_LIMIT],
    ])


def annotate_attachments(parsed: dict[str, Any]) -> None:
    """OCR 图内文字回收 + 附件内容分析（在 IOC 提取之前由 pipeline 调用）。"""
    blobs = parsed.get("_attachment_blobs") or {}
    attachments = parsed.get("attachments") or []
    inline_images = parsed.get("_inline_images") or []
    text_for_password = _password_source_text(parsed)

    # 1) 图内信息回收：二维码解码（ms 级，先跑）+ OCR。必须在 archive/office/pdf
    #    与 IOC 提取之前——解码出的 URL/文本并入 body_text 后，extract_iocs 能把
    #    图内钓鱼链接送进「VT/URLScan -> 情报 55 分」链路；图内也可能写有压缩包
    #    解压密码，密码候选来源需在此之后刷新。
    body_text = parsed.get("body_text") or ""
    ocr_pool = [data for idx, data in blobs.items()
                if 0 <= idx < len(attachments)
                and (attachments[idx].get("real_type") in ("jpeg", "png", "gif", "bmp")
                     or attachments[idx].get("content_type", "").startswith("image/"))]
    ocr_pool += inline_images
    if ocr_pool and len(body_text.strip()) < _OCR_BODY_TEXT_LIMIT:
        recovered: list[str] = []
        qr_codes: list[str] = []
        for img_data in ocr_pool:
            for q in decode_qr(img_data):
                if q not in qr_codes:
                    qr_codes.append(q)
        if qr_codes:
            recovered += qr_codes
        if ocr_available():
            ocr_text = ocr_images(ocr_pool)
            if ocr_text:
                recovered.append(ocr_text)
        if recovered:
            addition = "\n".join(recovered)
            parsed["qr_codes"] = qr_codes
            parsed["ocr_text"] = addition
            parsed["body_text"] = body_text + "\n" + addition
            # 图内可能写有压缩包密码，刷新候选来源供下方归档分析使用
            text_for_password = _password_source_text(parsed)

    # 2) 附件内容分析（只针对附件字节；纯内嵌图邮件无附件，到此为止）
    if not blobs or not attachments:
        return
    for idx, data in blobs.items():
        if not (0 <= idx < len(attachments)):
            continue
        att = attachments[idx]
        extension = att.get("extension", "")

        archive = analyze_attachment_bytes(data, text_for_password)
        if archive:
            att["archive"] = archive

        office = analyze_office(data, extension)
        if office:
            att["office"] = office

        pdf = analyze_pdf(data)
        if pdf:
            att["pdf"] = pdf

        # YARA 家族规则扫描（app/rules/phishing.yar；yara-python 未安装时空结果）
        yara_hits = yara_loader.scan_bytes(data)
        if yara_hits:
            severities = [str(h.get("meta", {}).get("severity", "medium")) for h in yara_hits]
            att["yara"] = {"rules": [h["rule"] for h in yara_hits],
                           "severity": "high" if "high" in severities else
                                       ("medium" if "medium" in severities else severities[0])}


def report_ocr_text(parsed: dict[str, Any]) -> str:
    """报告用 OCR 文本摘录（分析师可见"图内识别出了什么"）。"""
    return (parsed.get("ocr_text") or "")[:_OCR_TEXT_REPORT_LIMIT]
