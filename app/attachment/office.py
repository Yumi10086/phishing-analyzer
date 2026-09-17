"""Office 文档分析（P1）：VBA 宏、远程模板注入与 DDE。

三块能力，依赖策略不同：
- **OOXML 结构检查（零依赖，stdlib zipfile）**：远程模板注入（.rels 里 Target 指向
  外部 http(s)）与 DDEAUTO 字段——这两类不依赖 oletools，任何环境都能跑；
- **VBA 宏提取（oletools 可选依赖）**：未安装时静默降级（宏文档仍由扩展名档位
  计分），沿用 yara-python 的可选依赖模式；
- **宏语义分级（纯函数）**：对提取出的 VBA 源码分级（自动执行/Shell/下载执行/
  混淆），与 oletools 解耦，可独立单测。

诚实边界：宏的**正向**路径需要真实带宏样本才能端到端验证，本仓库不含恶意样本
（合规），该路径目前只有分类器的合成样例单测覆盖。
"""
from __future__ import annotations

import io
import re
import zipfile
from typing import Any

# 参与 Office 分析的扩展名（OLE2 老格式 + OOXML 新格式）
OOXML_EXTS = frozenset({"docx", "docm", "xlsx", "xlsm", "pptx", "pptm", "dotm", "xlam", "xlsb", "odt", "ods"})
OLE2_EXTS = frozenset({"doc", "xls", "ppt", "msi", "msg", "vsd", "pub"})
OFFICE_EXTS = OOXML_EXTS | OLE2_EXTS

_ZIP_MAGIC = b"PK\x03\x04"
_OLE2_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
_EXTERNAL_TARGET_RE = re.compile(rb'Target="(https?://[^"\s]+)"', re.IGNORECASE)
_DDE_RE = re.compile(rb"DDEAUTO|DDEAUTO\s|{\s*DDE", re.IGNORECASE)

# 宏语义分级：模式 → 发现项 id（与规则一一对应）
_MACRO_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("autoexec", re.compile(
        r"\b(?:AutoOpen|Auto_Open|AutoExec|AutoClose|Auto_Close|Document_Open|"
        r"Document_Close|DocumentBeforeClose|Workbook_Open|Workbook_BeforeClose|"
        r"Workbook_Activate|AutoNew)\b", re.IGNORECASE)),
    ("shell", re.compile(
        r"\b(?:Shell|ShellExecute|WScript\.Shell|CreateObject|cmd\.exe|powershell|"
        r"WinExec|CallByName)\b", re.IGNORECASE)),
    ("download", re.compile(
        r"\b(?:URLDownloadToFile|XMLHTTP|MSXML2|ServerXMLHTTP|ADODB\.Stream|"
        r"WinHttp|InternetOpenUrl|FollowHyperlink|DownloadFile|GetObject)\b", re.IGNORECASE)),
)

# 混淆启发式：大量 Chr()/StrReverse/Base64 是宏免杀常见手法
_OBFUSCATION_CHR_MIN = 3
_OBFUSCATION_RES = (
    re.compile(r"\bStrReverse\b", re.IGNORECASE),
    re.compile(r"\bChrW?\s*\(", re.IGNORECASE),
    re.compile(r"Base64|FromBase64String", re.IGNORECASE),
)


def classify_macro_code(code: str) -> set[str]:
    """对 VBA 源码分级，返回发现项 id 集合（纯函数，可独立测试）。

    发现项：autoexec / shell / download / obfuscated
    """
    findings: set[str] = set()
    if not code:
        return findings
    for name, pat in _MACRO_PATTERNS:
        if pat.search(code):
            findings.add(name)
    chr_hits = len(re.findall(r"\bChrW?\s*\(", code, re.IGNORECASE))
    if chr_hits >= _OBFUSCATION_CHR_MIN or any(r.search(code) for r in _OBFUSCATION_RES):
        findings.add("obfuscated")
    return findings


def _scan_ooxml(data: bytes, info: dict[str, Any]) -> None:
    """OOXML 结构检查：远程模板注入与 DDEAUTO（零依赖）。"""
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:  # noqa: BLE001 - 结构损坏则跳过（类型档位仍在）
        return
    with zf:
        for name in zf.namelist():
            low = name.lower()
            if low.endswith(".rels"):
                try:
                    content = zf.read(name)
                except Exception:  # noqa: BLE001
                    continue
                m = _EXTERNAL_TARGET_RE.search(content)
                if m and not info.get("remote_template"):
                    info["remote_template"] = m.group(1).decode("utf-8", "replace")
            elif low.endswith("document.xml") or low.endswith("workbook.xml"):
                try:
                    if _DDE_RE.search(zf.read(name)):
                        info["dde"] = True
                except Exception:  # noqa: BLE001
                    continue


def _scan_macros(data: bytes, info: dict[str, Any]) -> None:
    """VBA 宏提取（oletools 可选依赖，未安装/失败时静默降级）。"""
    try:
        from oletools.olevba import VBA_Parser
    except ImportError:
        info["oletools"] = False
        return
    info["oletools"] = True
    vba = None
    try:
        vba = VBA_Parser("attachment", data=data)
        if not vba.detect_vba_macros():
            return
        info["has_macro"] = True
        findings: set[str] = set()
        for _file, _stream, _name, code in vba.extract_macros():
            findings |= classify_macro_code(code or "")
        info["macro_findings"] = sorted(findings)
    except Exception:  # noqa: BLE001 - 解析失败不阻断分析
        info["parse_error"] = True
    finally:
        if vba is not None:
            try:
                vba.close()
            except Exception:  # noqa: BLE001
                pass


def analyze_office(data: bytes, extension: str) -> dict[str, Any] | None:
    """Office 附件分析入口；非 Office 类型返回 None（不产生任何字段）。"""
    ext = (extension or "").lower().strip()
    if ext not in OFFICE_EXTS or not data:
        return None
    info: dict[str, Any] = {
        "has_macro": False,
        "macro_findings": [],
        "remote_template": "",
        "dde": False,
        "oletools": False,
        "parse_error": False,
        "container": False,
    }
    is_zip = data.startswith(_ZIP_MAGIC)
    is_ole2 = data.startswith(_OLE2_MAGIC)
    # 扩展名声称 Office 但内容不是 Office 容器（改名的文本/其他格式）时**不做宏提取**：
    # oletools 对纯文本文件会把内容当 VBA 源码"检出宏"（日志 "Opening text file
    # attachment"），实测在含占位 .pptx 附件的现代语料上误报 36/400。
    if not (is_zip or is_ole2):
        return info
    info["container"] = True
    if is_zip:
        _scan_ooxml(data, info)
    _scan_macros(data, info)
    return info
