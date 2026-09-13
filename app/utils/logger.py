"""统一日志：控制台输出，格式包含时间、级别、模块名。"""
from __future__ import annotations

import logging
import sys

_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_configured = False


def get_logger(name: str, level: int = logging.INFO) -> logging.Logger:
    global _configured
    if not _configured:
        handler = logging.StreamHandler(sys.stdout)
        handler.setFormatter(logging.Formatter(_FORMAT, datefmt="%H:%M:%S"))
        root = logging.getLogger()
        root.addHandler(handler)
        root.setLevel(level)
        # httpx 每个请求都打 INFO，分析时太吵，只在告警级别以上输出
        for noisy in ("httpx", "httpcore"):
            logging.getLogger(noisy).setLevel(logging.WARNING)
        _configured = True
    return logging.getLogger(name)
