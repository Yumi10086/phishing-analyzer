"""YARA 规则加载器：yara-python 为可选依赖，未安装时优雅降级。

规则文件 app/rules/phishing.yar 的语法备忘（都踩过坑）：
- CJK 关键词必须写成 UTF-8 十六进制字节串（regex 字面量不支持 \\xNN 转义）；
- 正则修饰符顺序敏感：/si 会触发词法器解析错误，/is 合法；
- 源码（含注释）不能出现非 ASCII 字符；
- condition 的通配 $x_* 只匹配带下划线后缀的标识符，$x 本身不匹配。

编译实例按进程缓存（compile 一次约数十 ms，不能每封邮件重复编译）。
"""
from __future__ import annotations

import threading
from pathlib import Path
from typing import Any

from app.utils.logger import get_logger

log = get_logger(__name__)

RULES_PATH = Path(__file__).resolve().parent / "phishing.yar"

_lock = threading.Lock()
_rules: Any = None
_failed = False


def _get_rules() -> Any | None:
    """懒加载编译实例；yara-python 未安装/规则损坏时返回 None（降级）。"""
    global _rules, _failed
    if _rules is not None:
        return _rules
    with _lock:
        if _rules is not None or _failed:
            return _rules
        try:
            import yara  # type: ignore
            # 不用 filepath=：yara-python 的 C 层在 Windows 上用 ANSI 打开文件，
            # 项目路径含中文（钓鱼邮件自动化分析）会报 No such file or directory；
            # 由 Python 读入后用 source= 编译绕过
            _rules = yara.compile(source=RULES_PATH.read_text(encoding="utf-8"))
        except ImportError:
            log.debug("yara-python 未安装，跳过 YARA 扫描")
            _failed = True
        except Exception as exc:  # noqa: BLE001 - 规则损坏不阻断主流程
            log.warning("YARA 规则编译失败: %s", exc)
            _failed = True
    return _rules


def scan_bytes(data: bytes) -> list[dict[str, Any]]:
    """对附件字节运行 YARA 规则；不可用时返回空列表（降级）。"""
    rules = _get_rules()
    if rules is None or not data:
        return []
    try:
        matches = rules.match(data=data)
    except Exception as exc:  # noqa: BLE001 - 单次扫描失败不阻断
        log.warning("YARA 扫描失败: %s", exc)
        return []
    return [{"rule": m.rule, "meta": dict(m.meta)} for m in matches]


def scan_text(text: str) -> list[dict[str, Any]]:
    """对正文/HTML 文本运行 YARA 规则（兼容保留：内部转 UTF-8 字节）。"""
    if not text:
        return []
    return scan_bytes(text.encode("utf-8", errors="replace"))
