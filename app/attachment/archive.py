"""压缩包递归分析（P1）：加密标志、内层文件类型、嵌套与 zip 炸弹防护。

设计约束
--------
- **只用 stdlib zipfile**：rar/7z 需要 rarfile/py7zr 等外部依赖（且 7z/rar 加密头
  无密码也无法列目录），本模块对它们只做"是归档容器"的识别（扩展名档位已覆盖），
  不承诺解析内层；
- **防 zip 炸弹**：解压前先看 ZipInfo.file_size 累计值，超过预算直接放弃解压并标记，
  绝不"先解开再看"；深度 ≤3、条目数 ≤200、解压总量 ≤50MB；
- **密码尝试**：只试从邮件正文/主题提取的候选（钓鱼把密码写在正文里是标准玩法），
  不做字典爆破——爆破是攻击行为且没有必要。

多类附件分析的编排（archive/office/pdf 三路合并写回）在 app/attachment/analyzer.py，
由 pipeline 解析后统一调用。
"""
from __future__ import annotations

import io
import re
import zipfile
from typing import Any

_MAX_DEPTH = 3
_MAX_ENTRIES = 200
_MAX_TOTAL_UNCOMPRESSED = 50 * 1024 * 1024   # 解压总量预算（防 zip 炸弹）
_MAX_SINGLE_UNCOMPRESSED = 20 * 1024 * 1024
_MAX_PASSWORD_TRIES = 8

ZIP_MAGIC = b"PK\x03\x04"
RAR_MAGIC = b"Rar!\x1a\x07"
SEVENZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"

# 内层"可执行/脚本"扩展名：命中说明压缩包承载载荷（与 ext_high/medium_risk 同源）
_INNER_DANGEROUS_EXTS = {
    "exe", "scr", "com", "pif", "dll", "cpl", "sys", "ocx", "hta", "lnk", "msi", "vhd",
    "js", "jse", "vbs", "vbe", "wsf", "wsh", "ps1", "bat", "cmd", "jar", "apk", "chm", "reg",
}
_INNER_MACRO_EXTS = {"docm", "xlsm", "pptm", "dotm", "xlam", "xlsb"}

# 密码候选提取：中文与英文常见写法（"解压密码：123456" / "password is abc123"）
_PASSWORD_PATTERNS = (
    re.compile(r"(?:密码|解压码|提取码|解压密码|口令)\s*(?:是|为|[:：=])?\s*"
               r"([A-Za-z0-9@#$%^&*_\-+.]{3,32})"),
    re.compile(r"(?:password|passcode|passwd|pwd)\s*(?:is|[:：=])?\s*"
               r"([A-Za-z0-9@#$%^&*_\-+.]{3,32})", re.IGNORECASE),
)


def extract_password_candidates(text: str) -> list[str]:
    """从正文/主题提取压缩包密码候选（最多 8 个，去重保序）。"""
    out: list[str] = []
    for pat in _PASSWORD_PATTERNS:
        for m in pat.finditer(text or ""):
            cand = m.group(1).strip(".")
            if cand and cand not in out:
                out.append(cand)
    return out[:_MAX_PASSWORD_TRIES]


def is_archive(data: bytes) -> bool:
    return data.startswith((ZIP_MAGIC, RAR_MAGIC, SEVENZIP_MAGIC))


def analyze_archive(data: bytes, passwords: list[str] | None = None,
                    depth: int = 0) -> dict[str, Any]:
    """解析 zip 结构（含嵌套），返回结构化结论。

    返回字段：
      entries / encrypted / password_used / has_executable / has_macro /
      nested_depth / bomb_guard / unreadable
    """
    info: dict[str, Any] = {
        "entries": 0, "encrypted": False, "password_used": "",
        "has_executable": False, "has_macro": False,
        "nested_depth": depth, "bomb_guard": False, "unreadable": False,
    }
    if depth > _MAX_DEPTH:
        return info
    try:
        zf = zipfile.ZipFile(io.BytesIO(data))
    except Exception:  # noqa: BLE001 - 非 zip 或结构损坏（含 rar/7z 被扩展名档位覆盖）
        info["unreadable"] = True
        return info

    with zf:
        infos = zf.infolist()
        info["entries"] = len(infos)
        if len(infos) > _MAX_ENTRIES:
            info["bomb_guard"] = True
            return info
        total_uncompressed = sum(i.file_size for i in infos)
        if (total_uncompressed > _MAX_TOTAL_UNCOMPRESSED
                or any(i.file_size > _MAX_SINGLE_UNCOMPRESSED for i in infos)):
            # 解压前拦截：绝不"先解开再看"
            info["bomb_guard"] = True
            return info

        info["encrypted"] = any(i.flag_bits & 0x1 for i in infos)
        if info["encrypted"] and passwords:
            # 逐个候选试解第一条：ZipCrypto 校验字节不匹配会抛 BadZipFile，
            # 必须吞掉——密码不对是常态，不能让异常穿透分析流水线
            for cand in passwords:
                try:
                    if zf.read(infos[0].filename, pwd=cand.encode("utf-8", "replace")):
                        info["password_used"] = cand
                        break
                except Exception:  # noqa: BLE001 - 密码不对/条目不可解
                    continue

        for inner in infos:
            if inner.is_dir():
                continue
            name = inner.filename.rsplit("/", 1)[-1]
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
            if ext in _INNER_DANGEROUS_EXTS:
                info["has_executable"] = True
            if ext in _INNER_MACRO_EXTS:
                info["has_macro"] = True
            # 嵌套归档：递归（受 depth/总量预算约束）
            if inner.file_size and inner.file_size <= _MAX_SINGLE_UNCOMPRESSED:
                pwd = info["password_used"].encode() if info["password_used"] else None
                try:
                    blob = zf.read(inner.filename, pwd=pwd)
                except Exception:  # noqa: BLE001 - 加密未解出/损坏
                    continue
                if is_archive(blob):
                    sub = analyze_archive(blob, passwords, depth + 1)
                    info["nested_depth"] = max(info["nested_depth"], sub["nested_depth"])
                    info["has_executable"] |= sub["has_executable"]
                    info["has_macro"] |= sub["has_macro"]
                    info["bomb_guard"] |= sub["bomb_guard"]
    return info


def analyze_attachment_bytes(data: bytes, text_for_password: str = "",
                             depth: int = 0) -> dict[str, Any] | None:
    """附件入口：非归档返回 None（不产生任何字段，保持报告干净）。"""
    if not is_archive(data):
        return None
    passwords = extract_password_candidates(text_for_password)
    info = analyze_archive(data, passwords, depth)
    info["password_in_body"] = bool(info["password_used"])
    return info
