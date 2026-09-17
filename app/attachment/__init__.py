"""附件深度分析包。

P0（已实现）：真实类型嗅探与三重核对（detector.py）——签名表判真实类型、
扩展名跨族伪装、声明 MIME 与内容冲突、通用 MIME 夹带具体类型、文件名欺骗字符。
P1（规划）：压缩包递归（archive.py）、Office 宏分析（office.py）。
P2（规划）：PDF 关键字扫描（pdf.py）。
"""
from app.attachment.detector import (
    BIDI_CONTROLS,
    extension_type_mismatch,
    generic_mime_known_ext,
    max_space_run,
    mime_type_conflict,
    sniff,
)

__all__ = [
    "BIDI_CONTROLS",
    "extension_type_mismatch",
    "generic_mime_known_ext",
    "max_space_run",
    "mime_type_conflict",
    "sniff",
]
