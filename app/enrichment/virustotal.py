"""VirusTotal API v3 客户端：URL / IP / 文件哈希查询，带免费版限流。"""
from __future__ import annotations

import base64

import httpx

from app.config import settings
from app.enrichment.base import IntelResult, RateLimiter
from app.utils.logger import get_logger

log = get_logger(__name__)

_BASE = "https://www.virustotal.com/api/v3"

# 声誉型 IOC（域名/IP/URL）的"检出引擎数 -> 恶意分"阶梯。
# 与文件哈希用不同口径的原因：VT 上标记域名的引擎主要是钓鱼/黑名单 feed，
# 域名被多个引擎同时标记已是强 IoC，若仍按命中比例线性折算，6/89 这类高置信
# 命中会被稀释成 13/100（约 7 分），使情报维度事实上失效。
# 首档刻意保守（单引擎 18/100），避免单一低质量 feed 造成过度定性。
_REPUTATION_TIERS = ((20, 90), (10, 78), (5, 60), (3, 44), (2, 30), (1, 18))

# 声誉型 IOC 类型：引擎检出稀疏，按检出数给分
_REPUTATION_TYPES = ("domain", "ip", "url")


def _url_id(url: str) -> str:
    """VT v3 的 URL 标识 = urlsafe base64（去 padding）。"""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def _stats_to_score(stats: dict, ioc_type: str = "hash") -> int:
    """last_analysis_stats -> 0-100 恶意分（分两类口径）。

    - 文件哈希（AV 型）：几十个引擎都会报毒，少量命中只是弱信号 -> 按命中比例
      线性折算（比例 ×2，多引擎命中接近满分）。
    - 域名/IP/URL（声誉型）：引擎极少标记，命中数本身即置信度 -> 按检出引擎数
      阶梯给分。
    """
    malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
    if malicious <= 0:
        return 0
    total = sum(stats.get(k, 0) for k in ("malicious", "suspicious", "harmless",
                                          "undetected", "timeout"))
    if total == 0:
        return 0
    if ioc_type in _REPUTATION_TYPES:
        for n, score in _REPUTATION_TIERS:
            if malicious >= n:
                return score
        return 0
    return min(100, int(malicious / total * 100 * 2))


class VirusTotalClient:
    def __init__(self, transport: httpx.AsyncBaseTransport | None = None):
        self.api_key = settings.virustotal_api_key
        self.limiter = RateLimiter(settings.vt_rate_limit)  # 免费版 4 次/分钟
        self.timeout = settings.intel_timeout
        self._transport = transport  # 测试可注入 MockTransport

    def _headers(self) -> dict[str, str]:
        return {"x-apikey": self.api_key}

    async def _get(self, client: httpx.AsyncClient, path: str) -> dict | None:
        if not self.api_key:
            return None
        await self.limiter.acquire()
        resp = await client.get(f"{_BASE}{path}", headers=self._headers(), timeout=self.timeout)
        if resp.status_code == 404:
            return {"not_found": True}
        resp.raise_for_status()
        return resp.json()

    async def _query(self, ioc: str, ioc_type: str, path: str, label: str) -> IntelResult:
        if not self.api_key:
            return IntelResult("virustotal", ioc, ioc_type, status="no_key",
                               summary="未配置 VT_API_KEY，跳过查询")
        try:
            async with httpx.AsyncClient(transport=self._transport) as client:
                data = await self._get(client, path)
        except httpx.HTTPStatusError as exc:
            log.warning("VT 查询 %s 失败: HTTP %s", ioc, exc.response.status_code)
            return IntelResult("virustotal", ioc, ioc_type, status="error",
                               summary=f"HTTP {exc.response.status_code}")
        except Exception as exc:  # noqa: BLE001
            log.warning("VT 查询 %s 失败: %s", ioc, exc)
            return IntelResult("virustotal", ioc, ioc_type, status="error", summary=str(exc)[:120])

        if data and data.get("not_found"):
            # 404 = VT 库中从未见过该 IOC。新起钓鱼基础设施的典型现象，
            # 属于"无数据"而非"确认干净"，不能用它压低评分。
            return IntelResult("virustotal", ioc, ioc_type, status="unknown",
                               summary=f"{label} 无历史记录（VT 库中未见过）")

        attrs = (data or {}).get("data", {}).get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        score = _stats_to_score(stats, ioc_type)
        malicious = stats.get("malicious", 0) + stats.get("suspicious", 0)
        total_engines = sum(stats.values())
        status = "hit" if malicious > 0 else "clean"
        summary = f"{malicious}/{total_engines} 引擎标记恶意" if total_engines else "无统计信息"
        return IntelResult("virustotal", ioc, ioc_type, status=status,
                           malicious_score=score, summary=summary)

    async def check_url(self, url: str) -> IntelResult:
        return await self._query(url, "url", f"/urls/{_url_id(url)}", "URL")

    async def check_ip(self, ip: str) -> IntelResult:
        return await self._query(ip, "ip", f"/ip_addresses/{ip}", "IP")

    async def check_hash(self, sha256: str) -> IntelResult:
        return await self._query(sha256, "hash", f"/files/{sha256}", "文件")

    async def check_domain(self, domain: str) -> IntelResult:
        return await self._query(domain, "domain", f"/domains/{domain}", "域名")
