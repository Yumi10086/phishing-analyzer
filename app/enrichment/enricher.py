"""富化编排器：IOC 批量异步查询 + SQLite 缓存 + 并发控制。"""
from __future__ import annotations

import asyncio
from functools import partial
from typing import Any

from app.config import settings
from app.utils.cache import cache
from app.utils.logger import get_logger
from app.enrichment.abuseipdb import AbuseIPDBClient
from app.enrichment.base import IntelResult
from app.enrichment.urlscan import UrlScanClient
from app.enrichment.virustotal import VirusTotalClient

log = get_logger(__name__)


class Enricher:
    """对一批 IOC 并行做威胁情报查询，结果缓存 24h（可配）。"""

    def __init__(self, enabled: bool = True, cache_instance=None):
        self.enabled = enabled
        self.cache = cache_instance or cache  # 可注入独立缓存（测试隔离用）
        self.vt = VirusTotalClient()
        self.abuseipdb = AbuseIPDBClient()
        self.urlscan = UrlScanClient()
        self._semaphore = asyncio.Semaphore(settings.intel_concurrency)

    def _cache_key(self, source: str, ioc: str) -> str:
        # v2：状态语义变更（unknown 与 clean 分离），避免旧版缓存结果干扰
        return f"v2:{source}:{ioc}"

    async def _query_with_cache(self, coro_factory, source: str, ioc: str,
                                ioc_type: str) -> IntelResult:
        """缓存 -> 查询 -> 回写。coro_factory 是无参函数（协程不可复用）。"""
        key = self._cache_key(source, ioc)
        cached = self.cache.get(key)
        if cached:
            result = IntelResult(source=source, ioc=ioc, ioc_type=ioc_type)
            result.status = cached.get("status", "error")
            result.malicious_score = int(cached.get("malicious_score", 0))
            result.summary = cached.get("summary", "")
            result.summary = (result.summary + "（缓存）") if result.summary else "（缓存）"
            return result
        async with self._semaphore:
            result = await coro_factory()
        self.cache.set(key, {"status": result.status, "malicious_score": result.malicious_score,
                        "summary": result.summary}, ttl_hours=settings.cache_ttl_hours)
        return result

    async def enrich(self, iocs: dict[str, Any]) -> list[dict[str, Any]]:
        """返回按 IOC 分组并展开的情报结果列表（dict 形式）。"""
        if not self.enabled:
            log.debug("离线模式：跳过威胁情报富化")
            return []

        tasks: list = []
        # URL：VT + URLScan
        for url in iocs.get("urls", [])[:10]:  # 上限控制，防止免费额度被打爆
            tasks.append(self._query_with_cache(partial(self.vt.check_url, url), "virustotal", url, "url"))
            tasks.append(self._query_with_cache(partial(self.urlscan.check_url, url), "urlscan", url, "url"))
        # 公网 IP：VT + AbuseIPDB
        for ip in iocs.get("ips", [])[:10]:
            tasks.append(self._query_with_cache(partial(self.vt.check_ip, ip), "virustotal", ip, "ip"))
            tasks.append(self._query_with_cache(partial(self.abuseipdb.check_ip, ip), "abuseipdb", ip, "ip"))
        # 文件哈希：VT
        for h in iocs.get("hashes", [])[:10]:
            tasks.append(self._query_with_cache(partial(self.vt.check_hash, h), "virustotal", h, "hash"))
        # 域名：VT domain 端点。
        # 来源有两类，按信号价值排序后去重、统一限流：
        #   1. URL 主机名（domains）——链接指向的基础设施；
        #   2. 发件方身份域名（sender_domains = From/Reply-To/Return-Path）——
        #      钓鱼最该查的就是它，且"只有头部域名、没有 URL/附件"的邮件
        #      （如报告 90b774cd79224e8f）此前完全查不到情报。
        # 不含 to/cc（收件人域，通常就是使用者自己的组织，查它只浪费配额）。
        domain_iocs: list[str] = []
        for d in list(iocs.get("domains", [])) + list(iocs.get("sender_domains", [])):
            if d and d not in domain_iocs:
                domain_iocs.append(d)
        for d in domain_iocs[:8]:
            tasks.append(self._query_with_cache(partial(self.vt.check_domain, d), "virustotal", d, "domain"))

        results = await asyncio.gather(*tasks)
        return [r.to_dict() for r in results]
