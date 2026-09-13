"""情报富化公共定义：统一结果结构与速率限制器。"""
from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field, asdict
from typing import Any


@dataclass
class IntelResult:
    """单个 IOC 在单个情报源上的查询结果。

    status 取值:
      hit     - 查询成功且有恶意指标
      clean   - 查询成功且无恶意指标（注意：哈希层面的 clean 是确定性结论，
                URL/域名层面的 clean 只是声誉弱负面，评分引擎据此区分可用性）
      unknown - 查询成功但无任何历史记录（新 IOC 常见，不能当作负面证据）
      no_key  - 未配置 API Key（自动降级）
      error   - 网络/解析错误
    """
    source: str
    ioc: str
    ioc_type: str            # url | domain | ip | hash
    status: str = "error"
    malicious_score: int = 0  # 0-100，标准化后的恶意置信度
    summary: str = ""
    raw: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("raw", None)  # 报告中不携带原始响应，控制体积
        return data


class RateLimiter:
    """令牌桶限流器（异步），用于规避免费 API 额度限制。"""

    def __init__(self, rate: int, per_seconds: float = 60.0):
        self.rate = rate
        self.per = per_seconds
        self._lock = asyncio.Lock()
        self._timestamps: list[float] = []

    async def acquire(self) -> None:
        async with self._lock:
            loop = asyncio.get_event_loop()
            now = loop.time()
            self._timestamps = [t for t in self._timestamps if now - t < self.per]
            if len(self._timestamps) >= self.rate:
                wait = self.per - (now - self._timestamps[0]) + 0.05
                await asyncio.sleep(max(wait, 0.05))
                now = time.time()
                self._timestamps = [t for t in self._timestamps if now - t < self.per]
            self._timestamps.append(time.time())
