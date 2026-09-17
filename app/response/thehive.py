"""TheHive 工单客户端：将高置信度告警自动创建为 TheHive Alert（闭环处置第一步）。"""
from __future__ import annotations

import httpx

from app.config import settings
from app.utils.logger import get_logger

log = get_logger(__name__)


def create_alert(report: dict[str, Any], severity_map: dict[str, int] | None = None) -> dict:
    """将分析报告转为 TheHive Alert。未配置时返回 skipped。"""
    if not settings.thehive_url or not settings.thehive_api_key:
        return {"status": "skipped", "reason": "未配置 THEHIVE_URL / THEHIVE_API_KEY"}

    severity_map = severity_map or {
        "MALICIOUS": 4,   # high
        "SUSPICIOUS": 3,  # medium
        "SPAM": 1,        # low：营销/垃圾分流，正常不应推送工单
        "BENIGN": 2,      # low
    }
    iocs = report.get("iocs", {})
    observables = []
    for url in iocs.get("urls", []):
        observables.append({"dataType": "url", "data": url})
    for domain in iocs.get("domains", []):
        observables.append({"dataType": "domain", "data": domain})
    for ip in iocs.get("ips", []):
        observables.append({"dataType": "ip", "data": ip})
    for h in iocs.get("hashes", []):
        observables.append({"dataType": "sha256", "data": h})

    payload = {
        "type": "phishing-email",
        "source": "phishing-analyzer",
        "sourceRef": report.get("report_id", "unknown"),
        "title": f"[{report.get('verdict')}] {report.get('subject', '(无主题)')} - score {report.get('score')}",
        "description": "\n".join(f"- {r}" for r in report.get("reasons", [])),
        "severity": severity_map.get(report.get("verdict"), 2),
        "tlp": 2,  # amber：内部共享
        "tags": ["phishing", f"score:{report.get('score')}", report.get("verdict", "").lower()],
        "observables": observables,
    }
    try:
        resp = httpx.post(
            f"{settings.thehive_url.rstrip('/')}/api/v1/alert",
            headers={"Authorization": f"Bearer {settings.thehive_api_key}"},
            json=payload, timeout=15,
        )
        resp.raise_for_status()
        log.info("TheHive 告警创建成功: %s", resp.json().get("_id"))
        return {"status": "created", "thehive_id": resp.json().get("_id")}
    except Exception as exc:  # noqa: BLE001
        log.warning("TheHive 告警创建失败: %s", exc)
        return {"status": "error", "reason": str(exc)[:200]}
