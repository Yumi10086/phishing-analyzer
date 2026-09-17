"""PDF 附件关键字扫描（P2）：零依赖字节正则，不引重型 PDF 库。

设计取舍
--------
- **只扫 magic 确认是 PDF 的文件**（由解析器的 real_type 把关，调用方负责）：这样
  合成语料里"内容其实是文本的 .pdf 占位附件"不会进入扫描，避免上一轮踩过的坑；
- **不单独对 /OpenAction 计分**：合法的"打开跳到第 N 页"就是 /OpenAction + /GoTo，
  在正常 PDF 里极常见；只有与 /JavaScript、/Launch 同现时才有风险，而那两种标记
  本身已被独立计分，重复计分只会制造噪声；
- 扫描上限 2MB：超大 PDF 只扫头部——恶意标记几乎总在文档前部与对象字典处，
  且避免用正则吃掉大文件全量内存。
"""
from __future__ import annotations

import re
from typing import Any

_PDF_MAGIC = b"%PDF"
_SCAN_LIMIT = 2 * 1024 * 1024

_MARKERS: dict[str, re.Pattern[bytes]] = {
    # /JS 是 /JavaScript 的缩写形式，对象字典里两种写法都常见
    "javascript": re.compile(rb"/JavaScript\b|/JS\b"),
    "launch": re.compile(rb"/Launch\b"),
    "embedded": re.compile(rb"/EmbeddedFile\b"),
}


def analyze_pdf(data: bytes) -> dict[str, Any] | None:
    """PDF 关键字扫描；非 PDF 返回 None。"""
    if not data or not data.startswith(_PDF_MAGIC):
        return None
    head = data[:_SCAN_LIMIT]
    return {name: bool(pat.search(head)) for name, pat in _MARKERS.items()}
