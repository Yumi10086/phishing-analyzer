"""分析流水线：解析 -> IOC 提取 -> 认证检查 -> 情报富化 -> 评分 -> 报告。"""
from __future__ import annotations

import time
from typing import Any

from app.enrichment.enricher import Enricher
from app.extractor.auth_checker import check_auth
from app.extractor.ioc_extractor import extract_iocs
from app.parser.eml_parser import parse_eml
from app.parser.msg_parser import parse_msg
from app.response.report import build_report, save_report
from app.scoring.risk_engine import score_mail
from app.utils.logger import get_logger

log = get_logger(__name__)


async def analyze_bytes(raw: bytes, filename: str = "mail.eml",
                        offline: bool = False, save: bool = True) -> dict[str, Any]:
    """核心分析入口：输入邮件原始字节，输出完整分析报告 dict。"""
    start = time.perf_counter()
    lower = filename.lower()

    # 1. 解析
    if lower.endswith(".msg"):
        parsed = parse_msg(raw)
    else:
        parsed = parse_eml(raw)

    # 2. IOC 提取 + 3. 认证检查
    iocs = extract_iocs(parsed)
    auth = check_auth(parsed)

    # 4. 情报富化（离线模式跳过）
    enricher = Enricher(enabled=not offline)
    intel_results = await enricher.enrich(iocs)

    # 5. 评分（离线模式下按可用维度归一化到 0-100）
    scored = score_mail(parsed, iocs, auth, intel_results, offline=offline)

    # 6. 报告
    elapsed_ms = int((time.perf_counter() - start) * 1000)
    report = build_report(filename, parsed, iocs, auth, scored, intel_results, elapsed_ms,
                          offline=offline)
    if save:
        paths = save_report(report)
        report["report_files"] = paths
    return report


async def analyze_file(path: str, offline: bool = False, save: bool = True) -> dict[str, Any]:
    from pathlib import Path
    p = Path(path)
    raw = p.read_bytes()
    return await analyze_bytes(raw, filename=p.name, offline=offline, save=save)
