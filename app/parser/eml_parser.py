""".eml 解析器：基于标准库 email，解析头部、认证结果、正文与附件哈希。"""
from __future__ import annotations

import hashlib
from email import policy
from email.parser import BytesParser
from email.message import EmailMessage

from app.parser.schemas import ParsedMail, _empty_result, safe_filename
from app.utils.logger import get_logger

log = get_logger(__name__)

# 需要保留的关键头部（小写）
_HEADER_KEYS = [
    "from", "to", "cc", "subject", "date", "message-id",
    "reply-to", "return-path", "x-mailer", "user-agent",
    "content-type", "list-unsubscribe", "received-spf", "x-originating-ip",
]


def parse_eml(raw: bytes) -> ParsedMail:
    result = _empty_result("eml", len(raw))
    try:
        msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    except Exception as exc:  # noqa: BLE001 - 解析失败时返回空结果而不是抛出
        log.error("eml 解析失败: %s", exc)
        return result

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

    # 遍历 MIME 结构：抽取正文与附件
    text_parts: list[str] = []
    html_parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        content_type = part.get_content_type()
        disposition = (part.get_content_disposition() or "").lower()
        filename = safe_filename(part.get_filename())

        is_attachment = disposition == "attachment" or bool(filename)
        if is_attachment:
            payload = part.get_payload(decode=True) or b""
            result["attachments"].append({
                "filename": filename or "(unnamed)",
                "content_type": content_type,
                "size": len(payload),
                "sha256": hashlib.sha256(payload).hexdigest(),
                "md5": hashlib.md5(payload).hexdigest(),  # noqa: S324 - 仅用于 IOC 比对
                "extension": filename.rsplit(".", 1)[-1].lower() if "." in filename else "",
            })
            continue

        try:
            content = part.get_content()
        except Exception:  # noqa: BLE001 - 编码异常时降级为原始字节
            payload = part.get_payload(decode=True) or b""
            content = payload.decode("utf-8", errors="replace")
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")
        if content_type == "text/plain":
            text_parts.append(content)
        elif content_type == "text/html":
            html_parts.append(content)

    result["body_text"] = "\n".join(text_parts)
    result["body_html"] = "\n".join(html_parts)
    return result
