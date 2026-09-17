"""附件真实类型嗅探：纯 Python 签名表 + 三重核对（声明 MIME / 扩展名 / magic bytes）。

设计取舍
--------
- **不引 python-magic**：Windows 上 python-magic-bin 已停更、libmagic 依赖部署麻烦；
  本模块只需识别十余种钓鱼场景有意义的类型，签名表几行即可且完全可单测。
- **只嗅头部（≤4KB）**：不解析容器结构——压缩包递归、OLE 宏分析是 P1 的职责。
- **扩展名"跨族"才算伪装**：只有扩展名明确属于另一个已知族才判不符（fake .pdf 是 PE
  → 命中）；未知扩展名（.dat/.bin/无扩展名）一律不判，避免正常未知附件误报。
"""
from __future__ import annotations

# ---- 签名表：(类型, 魔数, 偏移) ----
_SIGNATURES: list[tuple[str, bytes, int]] = [
    ("pe", b"MZ", 0),                                  # DOS/PE 可执行头
    ("zip", b"PK\x03\x04", 0),                         # zip 及其派生（docx/xlsx/jar/apk…）
    ("zip", b"PK\x05\x06", 0),                         # 空 zip（PK 尾部结构）
    ("ole2", b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", 0),  # OLE2 复合文档（doc/xls/msi…）
    ("pdf", b"%PDF", 0),
    ("rar", b"Rar!\x1a\x07", 0),
    ("sevenzip", b"7z\xbc\xaf\x27\x1c", 0),
    ("lnk", b"\x4c\x00\x00\x00\x01\x14\x02\x00", 0),   # Windows 快捷方式
    ("gzip", b"\x1f\x8b", 0),
    ("rtf", b"{\\rtf", 0),
    ("jpeg", b"\xff\xd8\xff", 0),
    ("png", b"\x89PNG\r\n\x1a\n", 0),
    ("gif", b"GIF8", 0),
]

# ISO 的卷描述符在偏移 32769（0x8001）处
_ISO_SIG, _ISO_OFF = b"CD001", 0x8001

# ---- 类型 → 允许的扩展名族 ----
TYPE_EXTENSIONS: dict[str, set[str]] = {
    "pe": {"exe", "dll", "scr", "com", "pif", "sys", "ocx", "cpl"},
    "zip": {"zip", "docx", "xlsx", "pptx", "odt", "ods", "odp", "odg",
            "jar", "apk", "epub", "xpi", "kmz", "vsdx", "xlsb", "docm", "xlsm", "pptm"},
    "ole2": {"doc", "xls", "ppt", "msg", "vsd", "msi", "mdb", "pub", "dot", "xlt", "pot",
             "docm", "xlsm", "pptm"},   # 宏文档既可是 OLE2 也可是 zip 派生的 OOXML
    "pdf": {"pdf"},
    "rar": {"rar"},
    "sevenzip": {"7z"},
    "lnk": {"lnk"},
    "iso": {"iso", "img", "udf"},
    "gzip": {"gz", "tgz"},
    "rtf": {"rtf", "doc"},             # .doc 装 RTF 内容是历史常见现象，不算伪装
    "jpeg": {"jpg", "jpeg", "jpe"},
    "png": {"png"},
    "gif": {"gif"},
    "text": {"txt", "csv", "log", "md", "json", "xml", "ini", "conf", "bat", "ps1",
             "vbs", "js", "html", "htm", "eml", "yaml", "yml", "srt", "vcf"},
    "html": {"html", "htm", "xhtml"},
}

# ---- 声明 MIME → 类型族（用于"声明 MIME 与真实内容冲突"核对）----
MIME_FAMILIES: dict[str, str] = {
    "application/pdf": "pdf",
    "application/x-dosexec": "pe",
    "application/x-msdownload": "pe",
    "application/x-msdos-program": "pe",
    "application/vnd.microsoft.portable-executable": "pe",
    "application/zip": "zip",
    "application/x-zip-compressed": "zip",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "zip",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "zip",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "zip",
    "application/vnd.oasis.opendocument.text": "zip",
    "application/java-archive": "zip",
    "application/vnd.android.package-archive": "zip",
    "application/msword": "ole2",
    "application/vnd.ms-excel": "ole2",
    "application/vnd.ms-powerpoint": "ole2",
    "application/vnd.ms-outlook": "ole2",
    "application/vnd.ms-installer": "ole2",
    "application/x-ole-storage": "ole2",
    "application/x-msi": "ole2",
    "application/x-rar-compressed": "rar",
    "application/vnd.rar": "rar",
    "application/x-7z-compressed": "sevenzip",
    "application/x-iso9660-image": "iso",
    "application/gzip": "gzip",
    "application/x-gzip": "gzip",
    "application/rtf": "rtf",
    "text/rtf": "rtf",
    "image/jpeg": "jpeg",
    "image/png": "png",
    "image/gif": "gif",
    "text/html": "html",
}

# 通用/无断言 MIME：不构成"声明与内容冲突"，仅在与具体扩展名共存时作弱信号
GENERIC_MIMES = {
    "", "application/octet-stream", "application/binary", "binary/octet-stream",
    "application/force-download", "application/download", "application/unknown",
}

# 全族扩展名并集：扩展名跨族才判"伪装"；不在并集里的未知扩展名一律不判
ALL_KNOWN_EXTENSIONS: set[str] = set().union(*TYPE_EXTENSIONS.values())


# 弱启发式类型：文本/HTML 靠"可打印占比"猜出，良性改名（用户把 CSV 存成 .xls、
# WordPad 把 .doc 存成纯文本）在真实收件箱里常见，且这两类内容本身危害低
# （真正的恶意形态是 HTML 附件，由 att_html 单独计分）。不参与伪装/冲突判定。
_WEAK_TYPES = frozenset({"text", "html", "unknown"})

# 通用 MIME 夹带信号只对这些"二进制/结构化"扩展名计分。文本类扩展名
# （txt/csv/log/md/json…）用 octet-stream 声明在正常邮件里极常见，不构成掩盖。
_STRUCTURED_EXTENSIONS: set[str] = set().union(*(
    TYPE_EXTENSIONS[t] for t in
    ("pe", "zip", "ole2", "pdf", "rar", "sevenzip", "lnk", "iso", "gzip", "rtf", "jpeg", "png", "gif")
))


def sniff(data: bytes) -> str:
    """返回真实类型标识；无法识别时返回 "unknown"（文本判定为 "text"/"html"）。"""
    if not data:
        return "unknown"
    for name, sig, off in _SIGNATURES:
        if data[off:off + len(sig)] == sig:
            return name
    if data[_ISO_OFF:_ISO_OFF + len(_ISO_SIG)] == _ISO_SIG:
        return "iso"
    head = data[:4096]
    low = head.lstrip()[:256].lower()
    if low.startswith(b"<!doctype html") or low.startswith(b"<html") or b"<html" in low:
        return "html"
    # 文本启发式：可打印占比 >95%（含常见多字节文本）且无 NUL 控制字节
    if b"\x00" not in head:
        printable = sum(1 for b in head if 9 <= b <= 13 or 32 <= b <= 126 or b >= 0x80)
        if len(head) >= 16 and printable / len(head) > 0.95:
            return "text"
    return "unknown"


def extension_type_mismatch(real_type: str, extension: str) -> bool:
    """扩展名与真实类型是否跨族不符（fake .pdf 实为 PE → True）。

    两条保守边界：
    - 文本/HTML 等弱启发式类型不判（良性改名常见，见 _WEAK_TYPES）；
    - 未知扩展名（不在任何已知族里，如 .dat/.bin）不判。
    """
    allowed = TYPE_EXTENSIONS.get(real_type)
    ext = (extension or "").lower().strip()
    if not allowed or not ext or ext in allowed or real_type in _WEAK_TYPES:
        return False
    return ext in ALL_KNOWN_EXTENSIONS


def mime_type_conflict(declared_mime: str, real_type: str) -> bool:
    """声明 MIME 与真实内容是否冲突（声明 application/pdf 实为 PE → True）。

    通用 MIME（octet-stream 等）不参与本判定，走 generic_mime_known_ext；
    弱启发式真实类型（text/html）不判——合成语料与真实收件箱都有"内容其实是
    纯文本却挂着 docx/pptx 声明"的良性形态（用户改名、占位文档）。
    """
    mime = (declared_mime or "").lower().strip().split(";")[0]
    if mime in GENERIC_MIMES or real_type in _WEAK_TYPES:
        return False
    family = MIME_FAMILIES.get(mime)
    if not family:
        return False
    return family != real_type


def generic_mime_known_ext(declared_mime: str, extension: str) -> bool:
    """通用 MIME + 具体"二进制/结构化"扩展名（octet-stream 夹带 docx 的伪装形态）。

    正常发件方会给出准确 MIME；钓鱼投递链常统一标 octet-stream 以掩盖真实类型。
    只对二进制/结构化扩展名计分（txt/csv 等文本类型用 octet-stream 是正常现象），
    且单条仅 3 分弱信号，不能单独定性。
    """
    mime = (declared_mime or "").lower().strip().split(";")[0]
    ext = (extension or "").lower().strip()
    return mime in GENERIC_MIMES and ext in _STRUCTURED_EXTENSIONS


# 双向文本控制字符：RTL Override 等，用于伪装扩展名（"gpj.exe" 显示成 "exe.jpg"）
BIDI_CONTROLS = frozenset("\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069")


def max_space_run(name: str) -> int:
    """文件名中最长连续空格数（空格填充伪装）。"""
    run = best = 0
    for ch in name:
        run = run + 1 if ch == " " else 0
        best = max(best, run)
    return best
