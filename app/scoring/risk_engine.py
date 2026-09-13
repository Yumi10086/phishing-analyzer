"""加权评分引擎：情报 55% + 认证 15% + 启发式 30%，输出三档结论与可解释原因。

启发式部分已外置：规则定义在 rules/builtin/*.yaml 与 rules/custom/*.yaml，
字典在 rules/dicts/*.txt；本模块只保留评分、归一化与情报/认证维度逻辑。
"""
from __future__ import annotations

from typing import Any

from app.config import settings
from app.scoring.features import (  # noqa: F401 - re-export 供外部/测试使用
    fold_text,
    is_random_filename as _is_random_filename,
    parse_from_header as _parse_from_header,
    has_invisible_obfuscation,
)
from app.scoring.rule_loader import get_rule_engine

# 结论阈值：<30 BENIGN，30-54 SUSPICIOUS，>=55 MALICIOUS
WEIGHTS = {"intel": 55, "auth": 15, "heuristic": 30}

# 认证维度**实际可达的满分**：SPF/DKIM/DMARC 各 4 分 = 12（声明权重仍是 15）。
# 上限与声明权重分开的原因：离线归一化分母必须保持 45——若把分母也压到 42，所有离线
# 分数会整体上浮 7%，把本来贴着阈值的正常邮件（如"短链+凭证词"的营销邮件）推成
# MALICIOUS，等于用一个维度降权换来全局过度定性。这里只要保证"仅认证维度不再单独越线"。
_AUTH_MAX = 12

# 离线（无情报）时可用维度的满分：auth 15 + heuristic 30
_OFFLINE_MAX = WEIGHTS["auth"] + WEIGHTS["heuristic"]


def _intel_usable(intel_results: list[dict[str, Any]]) -> bool:
    """情报是否真正提供了有效数据。

    - hit：情报在主动加分 -> 可用。
    - 文件哈希 clean：确定性结论（该具体文件被分析过且 0 检出）-> 可用。
    - URL/域名/IP 的 clean 只是声誉弱负面：时间性强，且不覆盖邮件中的
      其他工件（如附件），与 unknown 一样不能代表"情报已排除风险"。
    """
    if not intel_results:
        return False
    return any(
        r.get("status") == "hit"
        or (r.get("status") == "clean" and r.get("ioc_type") == "hash")
        for r in intel_results
    )


def _intel_summary(intel_results: list[dict[str, Any]]) -> str | None:
    """生成情报查询汇总行，保证报告能看懂情报到底查了什么。"""
    if not intel_results:
        return None
    counts: dict[str, int] = {}
    for r in intel_results:
        counts[r.get("status", "error")] = counts.get(r.get("status", "error"), 0) + 1
    parts = [f"查询 {len(intel_results)} 条 IOC"]
    label_map = [("hit", "命中"), ("clean", "确认干净"), ("unknown", "无历史"),
                 ("error", "失败"), ("no_key", "未启用")]
    for key, name in label_map:
        if counts.get(key):
            parts.append(f"{name} {counts[key]}")
    return "威胁情报: " + "，".join(parts)


def verdict_for_score(score: int) -> str:
    if score >= settings.threshold_malicious:
        return "MALICIOUS"
    if score >= settings.threshold_suspicious:
        return "SUSPICIOUS"
    return "BENIGN"


def _intel_score(intel_results: list[dict[str, Any]]) -> tuple[float, list[str]]:
    """情报分：取所有命中结果中的最高标准化分，映射到 55 分。"""
    max_score = 0
    reasons: list[str] = []
    for r in intel_results:
        if r.get("status") == "hit":
            s = int(r.get("malicious_score", 0))
            if s > max_score:
                max_score = s
            reasons.append(f"[{r['source']}] {r['ioc']}: {r.get('summary', '')}")
    return (max_score / 100) * WEIGHTS["intel"], reasons


_AUTH_METHOD_WEIGHTS = {"spf": 4, "dkim": 4, "dmarc": 4}


def _auth_score(auth: dict[str, Any]) -> tuple[float, list[str]]:
    """认证分：只看 SPF / DKIM / DMARC 三项结果（满分 12）。

    两处刻意的设计选择（均由权威基线误报归因驱动，见 README「权威基线的误报构成」）：

    1. **不再对 Reply-To / Return-Path 域名不对齐加分**。这两件事此前在认证维度
       （+3 / +2）与启发式规则（`header_reply_mismatch` / `header_return_path_mismatch`）
       各计一次，同一事实被重复计分：Reply-To 不一致一路能拿到
       3(认证) + 3(规则) + 6(reply_to_freemail) = 12 分，而它在正常邮件里极其常见
       （工单系统/客服平台/外包发信）。现在对齐判定**只在 YAML 规则里计一次**，
       运维调权也只需改一处。
    2. **每项权重 5 -> 4（满分 15 -> 12）**。原先三项全 fail 就是 15/15 分，
       离线归一化后 33 分，单靠认证维度就跨过 30 的 SUSPICIOUS 门槛——而
       "三项全 fail"在正常邮件里并不罕见（**转发与邮件列表本来就会破坏 SPF**，
       这是 SPF 的已知局限）。降为 12 后归一化 26.7 分，不再单独致误，
       要触发仍需正文/头部证据配合。
    """
    points = 0.0
    reasons: list[str] = []
    for method, weight in _AUTH_METHOD_WEIGHTS.items():
        value = auth.get(method)
        if value == "fail":
            points += weight
            reasons.append(f"{method.upper()}: fail")
        elif value == "softfail":
            points += weight * 0.6
            reasons.append(f"{method.upper()}: softfail")
        elif value == "none":
            points += weight * 0.3
            reasons.append(f"{method.upper()}: none（未配置）")
        elif value == "neutral":
            # neutral 表示发件方发布了"不作断言"的策略（SPF ?all）或签名无法验证，
            # 对声称自己是正常企业的邮件而言是弱负面证据，与 none 同级计分。
            points += weight * 0.3
            reasons.append(f"{method.upper()}: neutral（未作断言）")
    return min(points, _AUTH_MAX), reasons


def score_mail(parsed: dict[str, Any], iocs: dict[str, Any], auth: dict[str, Any],
               intel_results: list[dict[str, Any]] | None = None,
               offline: bool = False) -> dict[str, Any]:
    """主入口：输入解析结果、IOC、认证、情报，输出评分与结论。

    离线或情报源全部不可用时，auth+heuristic 的原始分会按其满分（_OFFLINE_MAX）归一化到 0-100，
    保证三档阈值语义一致。
    """
    intel_results = intel_results or []

    intel_pts, intel_reasons = _intel_score(intel_results)
    auth_pts, auth_reasons = _auth_score(auth)

    # 启发式：规则外置于 rules/*.yaml，由规则引擎求值
    engine = get_rule_engine()
    signals = engine.evaluate(parsed, iocs, auth)
    heuristic_raw = sum(s["points"] for s in signals)
    heuristic_pts = min(heuristic_raw, WEIGHTS["heuristic"])
    heuristic_reasons = [s["reason"] for s in signals]

    raw_total = intel_pts + auth_pts + heuristic_pts
    if _intel_usable(intel_results) and not offline:
        total = round(raw_total)
        normalized = False
    else:
        total = round(raw_total / _OFFLINE_MAX * 100)
        normalized = True

    verdict = verdict_for_score(total)

    # 可解释输出：情报汇总 -> 命中明细 -> 认证 -> 启发式 -> 归一化说明
    reasons: list[str] = []
    summary = _intel_summary(intel_results)
    if summary:
        reasons.append(summary)
    reasons += [f"威胁情报命中: {r}" for r in intel_reasons]
    reasons += [f"邮件认证: {r}" for r in auth_reasons]
    reasons += [f"启发式: {r}" for r in heuristic_reasons]
    if normalized:
        # 必须区分三种情况，否则使用者无法判断"到底查没查"：
        #   1. 离线模式：本轮根本没查情报；
        #   2. 在线但 IOC 数为 0：没东西可查（此前写成"已查询 0 条 IOC"，读起来像查过了，
        #      会让人以为是提取成功却没送去富化 —— 实际是压根没有可查的 IOC）；
        #   3. 在线且查了，但都没有恶意命中。
        if offline:
            note = ("评分说明: 离线模式（本次未查询威胁情报），已按本地维度"
                    f"（认证+启发式，满分 {_OFFLINE_MAX}）归一化到 0-100")
        elif not intel_results:
            note = ("评分说明: 未发出情报查询（本邮件没有可提取的外部 IOC），"
                    f"已按本地维度（认证+启发式，满分 {_OFFLINE_MAX}）归一化到 0-100")
        else:
            note = (f"评分说明: 威胁情报未提供有效数据（已查询 {len(intel_results)} 条 IOC，"
                    f"均无恶意命中），已按本地维度（认证+启发式，满分 {_OFFLINE_MAX}）归一化到 0-100")
        reasons.insert(1 if summary else 0, note)

    breakdown = {
        "intel": round(intel_pts, 1),
        "auth": round(auth_pts, 1),
        "heuristic": round(heuristic_pts, 1),
        "raw_signals_points": heuristic_raw,
        "weights": WEIGHTS,
        "normalized": normalized,
        "rules_version": engine.version,
    }
    return {
        "score": total,
        "verdict": verdict,
        "reasons": reasons,
        "breakdown": breakdown,
        "signals": signals,
    }
