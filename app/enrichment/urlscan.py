"""URLScan.io 客户端：默认仅被动搜索已知扫描记录，不主动提交扫描（合规考虑）。"""
from __future__ import annotations

import httpx

from app.config import settings
from app.enrichment.base import IntelResult
from app.utils.logger import get_logger

log = get_logger(__name__)

_BASE = "https://urlscan.io/api/v1"


class UrlScanClient:
    def __init__(self, transport: httpx.AsyncBaseTransport | None = None):
        self.api_key = settings.urlscan_api_key
        self.allow_submit = settings.urlscan_allow_submit
        self.timeout = settings.intel_timeout
        self._transport = transport  # 测试可注入 MockTransport

    async def check_url(self, url: str) -> IntelResult:
        """被动模式：搜索该 URL/域名的历史公开扫描记录。"""
        try:
            async with httpx.AsyncClient(transport=self._transport) as client:
                resp = await client.get(
                    f"{_BASE}/search/",
                    params={"q": f'page.url:"{url}"', "size": 5},
                    timeout=self.timeout,
                )
                resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            log.warning("URLScan 查询 %s 失败: %s", url, exc)
            return IntelResult("urlscan", url, "url", status="error", summary=str(exc)[:120])

        results = resp.json().get("results", [])
        if not results:
            # 无历史扫描记录 ≠ 确认干净，新钓鱼 URL 普遍如此
            return IntelResult("urlscan", url, "url", status="unknown",
                               summary="URLScan 无历史扫描记录")

        malicious_total = sum(1 for r in results
                              if (r.get("verdicts", {}).get("overall", {}).get("malicious")))
        score = min(100, malicious_total * 60)
        return IntelResult("urlscan", url, "url",
                           status="hit" if malicious_total else "clean",
                           malicious_score=score,
                           summary=f"历史记录 {len(results)} 条，恶意判定 {malicious_total} 条")

    async def submit_url(self, url: str) -> IntelResult:
        """主动提交扫描（需 URLSCAN_ALLOW_SUBMIT=1 且配置 Key）。"""
        if not self.api_key:
            return IntelResult("urlscan", url, "url", status="no_key",
                               summary="未配置 URLSCAN_API_KEY，跳过提交")
        if not self.allow_submit:
            return IntelResult("urlscan", url, "url", status="error",
                               summary="主动扫描未启用（URLSCAN_ALLOW_SUBMIT=1 开启）")
        try:
            async with httpx.AsyncClient() as client:
                resp = await client.post(
                    f"{_BASE}/scan/",
                    headers={"API-Key": self.api_key},
                    json={"url": url, "visibility": "unlisted"},
                    timeout=self.timeout,
                )
                resp.raise_for_status()
                result_uuid = resp.json().get("result", "")
                # 轮询等待扫描完成（最多 30 秒）
                import asyncio
                for _ in range(6):
                    await asyncio.sleep(5)
                    detail = await client.get(f"https://urlscan.io/api/v1/result/{result_uuid.split('/')[-1]}")
                    if detail.status_code == 200:
                        verdicts = detail.json().get("verdicts", {})
                        overall = verdicts.get("overall", {})
                        score = 100 if overall.get("malicious") else (40 if overall.get("suspicious") else 0)
                        return IntelResult("urlscan", url, "url",
                                           status="hit" if score >= 60 else "clean",
                                           malicious_score=score,
                                           summary=f"实时扫描完成: {overall}")
                return IntelResult("urlscan", url, "url", status="error", summary="扫描超时")
        except Exception as exc:  # noqa: BLE001
            log.warning("URLScan 提交 %s 失败: %s", url, exc)
            return IntelResult("urlscan", url, "url", status="error", summary=str(exc)[:120])
