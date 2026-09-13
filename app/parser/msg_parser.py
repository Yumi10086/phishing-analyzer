""".msg（Outlook）解析器：基于 extract-msg，输出与 .eml 一致的结构化结果。"""
from __future__ import annotations

import hashlib

from app.parser.schemas import ParsedMail, _empty_result, safe_filename
from app.utils.logger import get_logger

log = get_logger(__name__)


def parse_msg(raw: bytes) -> ParsedMail:
    result = _empty_result("msg", len(raw))
    try:
        import extract_msg  # 延迟导入，核心链路不强制依赖
    except ImportError:
        log.warning("extract-msg 未安装，无法解析 .msg 文件（pip install extract-msg）")
        return result

    try:
        msg = extract_msg.Msg(bytes(raw))
    except Exception as exc:  # noqa: BLE001
        log.error("msg 解析失败: %s", exc)
        return result

    headers: dict[str, object] = {}
    header_map = {
        "from": "from", "to": "to", "cc": "cc", "subject": "subject",
        "date": "date", "message-id": "messageId", "reply-to": "replyTo",
    }
    for key, attr in header_map.items():
        value = getattr(msg, attr, None)
        if value:
            headers[key] = str(value)
    header = msg.header  # 原始头文本
    if header:
        for line in header.splitlines():
            if line.lower().startswith("authentication-results:"):
                result["authentication_results"].append(line.split(":", 1)[1].strip())

    result["headers"] = headers
    result["body_text"] = msg.body or ""
    try:
        result["body_html"] = msg.htmlBody.decode("utf-8", errors="replace") if msg.htmlBody else ""
    except Exception:  # noqa: BLE001
        result["body_html"] = ""

    for att in msg.attachments:
        data = att.data or b""
        name = safe_filename(att.longFilename or att.shortFilename or "(unnamed)")
        result["attachments"].append({
            "filename": name,
            "content_type": "application/octet-stream",
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "md5": hashlib.md5(data).hexdigest(),  # noqa: S324
            "extension": name.rsplit(".", 1)[-1].lower() if "." in name else "",
        })
    return result


def parse_any(raw: bytes, filename: str = "") -> ParsedMail:
    """根据扩展名/内容自动选择解析器。"""
    name = filename.lower()
    if name.endswith(".msg"):
        return parse_msg(raw)
    return parse_eml(raw)
