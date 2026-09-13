"""YARA 规则加载器：yara-python 为可选依赖，未安装时优雅降级。"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from app.utils.logger import get_logger

log = get_logger(__name__)

RULES_PATH = Path(__file__).resolve().parent / "phishing.yar"


def scan_text(text: str) -> list[dict[str, Any]]:
    """对正文/HTML 运行 YARA 规则；未安装 yara-python 时返回空列表。"""
    try:
        import yara  # type: ignore
    except ImportError:
        log.debug("yara-python 未安装，跳过 YARA 扫描")
        return []
    try:
        rules = yara.compile(filepath=str(RULES_PATH))
        matches = rules.match(data=text.encode("utf-8", errors="replace"))
    except Exception as exc:  # noqa: BLE001
        log.warning("YARA 扫描失败: %s", exc)
        return []
    return [{"rule": m.rule, "meta": dict(m.meta)} for m in matches]
