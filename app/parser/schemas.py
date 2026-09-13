"""邮件解析公共模型：.eml 与 .msg 解析器输出统一的结构化 dict。"""
from __future__ import annotations

from typing import Any, TypedDict


class AttachmentInfo(TypedDict):
    filename: str
    content_type: str
    size: int
    sha256: str
    md5: str
    extension: str


class ParsedMail(TypedDict):
    source_format: str                 # "eml" | "msg"
    headers: dict[str, Any]            # 关键头部字段
    authentication_results: list[str]  # 原始 Authentication-Results 头
    body_text: str
    body_html: str
    attachments: list[AttachmentInfo]
    raw_size: int


def _empty_result(source_format: str, raw_size: int) -> ParsedMail:
    return {
        "source_format": source_format,
        "headers": {},
        "authentication_results": [],
        "body_text": "",
        "body_html": "",
        "attachments": [],
        "raw_size": raw_size,
    }


def safe_filename(name: str | None) -> str:
    """清理附件文件名，防止路径穿越。"""
    if not name:
        return ""
    return name.replace("\\", "_").replace("/", "_").replace("\x00", "").strip()
