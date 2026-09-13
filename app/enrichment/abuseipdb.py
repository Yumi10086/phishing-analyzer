"""AbuseIPDB API v2 客户端：IP 信誉查询。"""
from __future__ import annotations

import httpx

from app.config import settings
from app.enrichment.base import IntelResult, RateLimiter
from app.utils.logger import get_logger

log = get_logger(__name__)

_BASE = "https://api.abuseipdb.com/api/v2"


class AbuseIPDBClient:
    def __init__(self):
        self.api_key = settings.abuseipdb_api_key
        self.limiter = RateLimiter(rate=60, per_seconds=60)  # 免费版 60 次/分钟
        self.timeout = settings.intel_timeout

    async def check_ip(self, ip: str) -> IntelResult:
        if not self.api_key:
            return IntelResult("abuseipdb", ip, "ip", status="no_key",
                               summary="未配置 ABUSEIPDB_API_KEY，跳过查询")
        headers = {"Key": self.api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90}
        try:
            await self.limiter.acquire()
            async with httpx.AsyncClient() as client:
                resp = await client.get(f"{_BASE}/check", headers=headers,
                                        params=params, timeout=self.timeout)
            resp.raise_for_status()
        except httpx.HTTPStatusError as exc:
            log.warning("AbuseIPDB 查询 %s 失败: HTTP %s", ip, exc.response.status_code)
            return IntelResult("abuseipdb", ip, "ip", status="error",
                               summary=f"HTTP {exc.response.status_code}")
        except Exception as exc:  # noqa: BLE001
            log.warning("AbuseIPDB 查询 %s 失败: %s", ip, exc)
            return IntelResult("abuseipdb", ip, "ip", status="error", summary=str(exc)[:120])

        data = resp.json().get("data", {})
        confidence = int(data.get("abuseConfidenceScore", 0))
        reports = int(data.get("totalReports", 0))
        status = "hit" if confidence >= 50 else "clean"
        return IntelResult("abuseipdb", ip, "ip", status=status,
                           malicious_score=confidence,
                           summary=f"滥用置信度 {confidence}%，近90天举报 {reports} 次")
