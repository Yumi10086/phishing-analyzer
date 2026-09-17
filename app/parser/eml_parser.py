""".eml 解析器：基于标准库 email，解析头部、认证结果、正文与附件哈希。"""
from __future__ import annotations

import hashlib
from email import policy
from email.header import decode_header, make_header
from email.parser import BytesParser
from email.message import EmailMessage

from app.attachment.detector import sniff
from app.parser.schemas import ParsedMail, _empty_result, safe_filename

# 内容分析用的附件字节上限：单附件 5MB、单封累计 20MB（防超大附件把内存打爆）。
# 超限附件只保留哈希与 real_type（嗅探仅需头部 4KB），P1 的宏/压缩包分析跳过它们。
_MAX_CONTENT_BYTES = 5 * 1024 * 1024
_MAX_TOTAL_CONTENT_BYTES = 20 * 1024 * 1024
from app.utils.logger import get_logger

log = get_logger(__name__)

# 需要保留的关键头部（小写）
_HEADER_KEYS = [
    "from", "to", "cc", "subject", "date", "message-id",
    "reply-to", "return-path", "x-mailer", "user-agent",
    "content-type", "list-unsubscribe", "list-id", "list-post", "precedence",
    "received-spf", "x-originating-ip",
]


# 声明字符集的常见别名：trec06c/国内邮件大量声明 gb2312，实际是 GBK/GB18030
# 超集内容，用窄字符集严格解码会大面积失败
_CHARSET_ALIASES = {
    "gb2312": "gb18030",
    "gbk": "gb18030",
    "gb_2312-80": "gb18030",
    "ks_c_5601-1987": "cp949",
    "hz-gb-2312": "hz",
}


def _text_quality(text: str) -> float:
    """解码质量评分：可打印（含 CJK/全角）占比高、替换符与控制字符占比低者优。"""
    if not text:
        return -1.0
    n = len(text)
    good = bad = 0
    for c in text:
        if c == "\ufffd" or (ord(c) < 32 and c not in "\t\n\r\f"):
            bad += 1
        elif ("\u4e00" <= c <= "\u9fff" or "\u3000" <= c <= "\u303f"
              or "\uff00" <= c <= "\uffef" or c.isascii()):
            good += 1
    return (good - bad * 4) / n


def _decode_text_payload(payload: bytes, declared_charset: str | None) -> str:
    """按候选编码链解码文本字节，质量评分选优。

    背景（trec06c 实测 ham 正文 84% 不可用）：老式中文邮件常声明 gb2312 却装着
    UTF-8/GBK 字节，email 库内部 errors=replace 产出乱码而不报错；仅 utf-8 回退
    会把 GBK 中文打成 U+FFFD。链条顺序有讲究：
      1. 声明字符集（归一化后**严格**解码——真声明 gb2312 的邮件在此直接成功）；
      2. utf-8 严格——utf-8 字节流严格解码成功几乎必然正确，必须排在 gb18030
         之前（gb18030 几乎接受任何字节流，会把 UTF-8 中文"成功"解码成乱码 CJK）；
      3. gb18030 严格（兼容 GBK/GB2312 的超集）；
      4. big5 严格；
      5. utf-8 replace 兜底（保证有输出）。
    """
    candidates: list[str] = []
    if declared_charset:
        d = declared_charset.strip().strip('"').lower()
        candidates.append(_CHARSET_ALIASES.get(d, d))
    candidates += ["utf-8", "gb18030", "big5", "utf-8"]

    best_text, best_score = "", -1.0
    seen: set[str] = set()
    last_index = len(candidates) - 1
    for i, enc in enumerate(candidates):
        if enc in seen:
            continue
        seen.add(enc)
        # 末位的 utf-8 用 replace 兜底保证有输出；其余一律严格解码——严格失败
        # 本身就是"字节不是这个编码"的证据，混 replace 会重蹈 email 库乱码覆辙
        errors = "replace" if i == last_index else "strict"
        try:
            text = payload.decode(enc, errors=errors)
        except (UnicodeDecodeError, LookupError):
            continue
        score = _text_quality(text)
        if score > best_score:
            best_text, best_score = text, score
    return best_text


def _decode_filename(name: str | None) -> str:
    """还原 RFC2047 编码的附件名。

    compat32 视角的 get_filename() 不做解码，返回形如
    ``=?gb2312?B?ufrX1Mi7u/m98MnqsajXq9C0o6gz1MK33aOp0afPsM2o1qouZG9jeA==?=``
    的原始串——不还原会被 is_random_filename 当成"混合大小写+数字的随机名"
    （datacon 实测 att_random_name 从 560 虚增到 2069）。policy.default 会自动
    解码，双解析改造后需在此手工补上。
    """
    if not name:
        return ""
    try:
        return str(make_header(decode_header(name))).strip()
    except Exception:  # noqa: BLE001 - 解码失败保留原串
        return str(name).strip()


def parse_eml(raw: bytes) -> ParsedMail:
    result = _empty_result("eml", len(raw))
    # 头部与正文双解析：policy.default 的 RFC2047 主题/头部解码质量好，但对残缺
    # MIME（损坏的 boundary、截断的 Content-Type）会**静默丢弃部件**——trec06c
    # 实测大批中文邮件正文因此消失；compat32 极度宽容、结构一个不丢但头部保持
    # 原始编码。两者各取所长：头部取 default，正文遍历取 compat32。
    try:
        msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:  # noqa: BLE001 - 解析失败时返回空结果而不是抛出
        log.error("eml 解析失败: %s", exc)
        return result
    try:
        msg_compat = BytesParser(policy=policy.compat32).parsebytes(raw)
    except Exception:  # noqa: BLE001 - 双解析都失败才放弃
        msg_compat = msg

    headers: dict[str, object] = {}
    for key in _HEADER_KEYS:
        values = msg.get_all(key)
        if not values:
            continue
        headers[key] = [str(v) for v in values] if len(values) > 1 else str(values[0])

    # Received 链路完整保留（分析回溯时可能用到，但默认不参与评分）
    received = msg.get_all("received") or []
    if received:
        headers["received"] = [str(r) for r in received]

    result["headers"] = headers
    result["authentication_results"] = [str(v) for v in (msg.get_all("authentication-results") or [])]

    # 遍历 MIME 结构：抽取正文与附件（compat32 视角）
    text_parts: list[str] = []
    html_parts: list[str] = []
    blobs: dict[int, bytes] = {}      # 附件字节：供 P1 内容分析（宏/压缩包/PDF）
    blobs_total = 0
    for part in msg_compat.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        filename = safe_filename(_decode_filename(part.get_filename()))

        is_attachment = disposition == "attachment" or bool(filename)
        if is_attachment:
            payload = part.get_payload(decode=True) or b""
            size = len(payload)
            oversized = size > _MAX_CONTENT_BYTES
            # 内容分析用字节保留（见 _MAX_CONTENT_BYTES 说明）；超限只记哈希
            if not oversized and blobs_total + size <= _MAX_TOTAL_CONTENT_BYTES:
                blobs[len(result["attachments"])] = payload
                blobs_total += size
            result["attachments"].append({
                "filename": filename or "(unnamed)",
                "content_type": content_type,
                "size": size,
                "sha256": hashlib.sha256(payload).hexdigest(),
                "md5": hashlib.md5(payload).hexdigest(),  # noqa: S324 - 仅用于 IOC 比对
                "extension": filename.rsplit(".", 1)[-1].lower() if "." in filename else "",
                # 真实类型嗅探（纯签名表，只看头部 4KB）与内容分析上限标记
                "real_type": sniff(payload[:4096]),
                "oversized": oversized,
            })
            continue

        payload = part.get_payload(decode=True)
        if payload is None:
            # 非 text/* 的嵌套结构（如 message/rfc822）没有可解码字节，跳过
            continue
        # 内嵌图片（CID 引用、无 Content-Disposition）：文字藏图内的钓鱼常用形态，
        # 收集给 OCR（app/attachment/ocr.py）；此前直接丢弃导致该形态完全不可见
        if content_type.startswith("image/") and payload:
            result.setdefault("_inline_images", []).append(payload)
            continue
        content = _decode_text_payload(payload, part.get_content_charset())
        if content_type == "text/plain":
            text_parts.append(content)
        elif content_type == "text/html":
            html_parts.append(content)

    # 兜底：MIME 结构残缺（边界损坏/全部部件被当附件/编码失败）导致正文全空时，
    # 把首个空行之后的原始字节按解码链解出。老式 8bit 中文邮件（trec06c 实测
    # ham 43% 空正文）靠这条路恢复可匹配文本，宁滥勿缺——后续规则匹配自己会
    # 处理噪声。
    if not text_parts and not html_parts:
        sep = max(raw.find(b"\n\n"), raw.find(b"\r\n\r\n"))
        if sep > 0:
            body_bytes = raw[sep:].lstrip(b"\r\n")
            if body_bytes:
                text_parts.append(_decode_text_payload(body_bytes, None))

    result["body_text"] = "\n".join(text_parts)
    result["body_html"] = "\n".join(html_parts)
    result["_attachment_blobs"] = blobs
    return result
