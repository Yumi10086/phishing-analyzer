"""加权评分引擎：情报 55% + 认证 15% + 启发式 30%，输出三档结论 + SPAM 降档与可解释原因。

启发式部分已外置：规则定义在 rules/builtin/*.yaml 与 rules/custom/*.yaml，
字典在 rules/dicts/*.txt；本模块只保留评分、归一化与情报/认证维度逻辑。

情报命中有**保底**（``_INTEL_HIT_FLOOR``）：命中是既成事实，不再被"检出引擎数少"稀释到
不具意义。详见该常量处的说明。
"""
from __future__ import annotations

import re

from typing import Any

from app.config import settings
from app.scoring.category import (
    MARKETING_SIGNALS,
    classify_category,
    spam_demotion_eligible,
)
from app.scoring.features import (  # noqa: F401 - re-export 供外部/测试使用
    fold_text,
    is_random_filename as _is_random_filename,
    parse_from_header as _parse_from_header,
    has_invisible_obfuscation,
)
from app.scoring.features import build_features
from app.scoring.rule_loader import get_rule_engine
from app.scoring.trust import trust_context_enabled

# 结论阈值：<30 BENIGN，30-54 SUSPICIOUS，>=55 MALICIOUS
WEIGHTS = {"intel": 55, "auth": 15, "heuristic": 30}

# 情报命中保底（归一化置信度，100 分制）。命中即至少按 60/100 计 -> 情报维度 >= 33 分，
# 也就是**命中本身就能把结论推到 SUSPICIOUS**。由报告 bc3045d97c844218 驱动：
# 该校院钓鱼邮件的链接 http://rfgbk.fmausa.com 在 VT 上 2/95 引擎标记恶意，阶梯给到
# 置信度 30 -> 55 * 0.30 = 16.5 分，加上认证 1.2 + 启发式 7 共 24.7 分仍判 BENIGN；
# 而**同一个命中**在类别层（category.classify_category）早已把邮件判成 phishing——
# 于是报告自相矛盾地写着"类别判定: 钓鱼/恶意（phishing）"+"结论 BENIGN"，使用者按
# "情报命中"预期拦截却拿到良性。保底消除的正是这处不一致。
#
# 为什么调这里而不是调 WEIGHTS["intel"]（把 55 拉高）：
#   1）三维权重之和必须保持 100，抬高 intel 就得压低 auth/heuristic，而**离线归一化的
#      分母正是 auth+heuristic**（_OFFLINE_MAX）——分母变小会让所有离线分数整体上浮，
#      直接突破现代/Enron 误报门禁（tests/test_fp_baseline.py），属于用一个维度降权
#      换全局过度定性；
#   2）命中与否是**二值事实**，用"命中保底"表达它比用连续权重表达更准确：55% 的权重
#      对未命中邮件本就该是 0 分，而对命中邮件又偏低，两头都不对。
#
# 代价（已知并接受）：单引擎命中（置信度 18，此前刻意保守）现在也保底到 33 分，
# 单一低质量 feed 的误报会进 SUSPICIOUS（通知 + medium 工单）。判定依据是：类别层
# 早已把任何命中当钓鱼，且真实邮箱实测 1970 份报告里仅 2 份存在命中（同一封钓鱼邮件），
# 命中是稀有事件，漏报（真钓鱼判 BENIGN）的代价高于一次人工复核。要更保守可下调该值：
# **54 是"命中单独即可判可疑"的临界点**（54/100 * 55 = 29.7 -> 取整 30），再往下调
# 则命中需本地证据配合才能越线；下调后失效的只是保底线，阶梯与其余逻辑不变。
_INTEL_HIT_FLOOR = 60

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
    """情报分：取所有命中结果中的最高标准化分，映射到 55 分；命中另有保底。

    保底只**抬高**命中结果，不改变未命中的 0 分，也不动 ``malicious_score`` 本身：
    置信度阶梯（``virustotal._REPUTATION_TIERS``）仍是"检出引擎数 -> 置信度"的诚实标尺，
    报告里照原样展示；保底是叠在其上的**评分策略**。这样分层的好处是调策略无需让情报
    缓存失效——已缓存的旧命中（如 2/95 -> 置信度 30）在新策略下同样被保底，历史报告
    重算即生效，不必重新消耗配额查询。
    """
    max_score = 0
    reasons: list[str] = []
    for r in intel_results:
        if r.get("status") == "hit":
            s = int(r.get("malicious_score", 0))
            if s > max_score:
                max_score = s
            reasons.append(f"[{r['source']}] {r['ioc']}: {r.get('summary', '')}")
    if not reasons:
        return 0.0, reasons
    if max_score < _INTEL_HIT_FLOOR:
        reasons.append(
            f"最高检出置信度 {max_score}/100 低于命中保底 {_INTEL_HIT_FLOOR}，按保底计分"
            f"（{_INTEL_HIT_FLOOR / 100 * WEIGHTS['intel']:.1f} 分）——命中即至少定性为可疑，"
            "检出引擎数只在保底之上继续拉开差距")
        max_score = _INTEL_HIT_FLOOR
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


def _link_domains(parsed: dict[str, Any], iocs: dict[str, Any]) -> list[str]:
    """本次邮件链接到的可注册域（用于"行为一致性"判定）。"""
    from app.scoring.features import registrable_domain

    out: list[str] = []
    for u in iocs.get("urls", []) or []:
        m = re.match(r"^[a-z]+://([^/:?#]+)", str(u).lower())
        reg = registrable_domain(m.group(1).strip(".") if m else "")
        if reg and reg not in out:
            out.append(reg)
    return out


# 邮箱直读档位下不计分的信号：缺失/存在与否由**渠道形态**决定，而非发件方风险行为。
# 实测依据（QQ 邮箱 54 封真实正常邮件）：33 封命中 header_missing_auth——服务商不给
# IMAP 存储副本写 Authentication-Results，邮箱直读时它必然缺失；与 Enron/trec06c 的
# "语料缺头部"同构（那两处是语料缺陷，这里是渠道特性，但都不构成风险证据）。
# 注意：**仅在 mailbox 档位生效**；网关投递的邮件缺认证头仍然是有效信号。
_MAILBOX_PROFILE_DROP = frozenset({
    "header_missing_auth",
})

_PROFILE_NOTE = ("分析档位: mailbox（邮箱直读）——认证结果头缺失属渠道形态，不计分"
                 "（服务商不写 Authentication-Results，非发件方风险行为）")


def _profile_dropped_signals(signals: list[dict[str, Any]]) -> set[str]:
    """按分析档位返回需要剔除的信号 id（gateway 档位恒为空集）。"""
    from app.config import analysis_profile

    if analysis_profile() != "mailbox":
        return set()
    present = {s["id"] for s in signals}
    return set(_MAILBOX_PROFILE_DROP & present)


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

    # 启发式：规则外置于 rules/*.yaml，由规则引擎求值。
    # 信任上下文开启时先构造特征并复用给引擎，避免同一封邮件算两遍特征。
    engine = get_rule_engine()
    trust_on = trust_context_enabled()
    feats = build_features(parsed, iocs, auth) if trust_on else None
    signals = engine.evaluate(parsed, iocs, auth, feats)
    dropped = _profile_dropped_signals(signals)
    if dropped:
        signals = [s for s in signals if s["id"] not in dropped]

    # 信任上下文（仅邮箱直读档位）：按"往来历史"对**话术/结构类**信号降权。
    # 必须在算 heuristic_raw 之前——它是"降权后"的点数之和。硬信号永不动（见 trust.NEVER_DEMOTE）。
    trust_note = ""
    if trust_on:
        from app.scoring.trust import apply as _apply_trust
        from app.scoring.trust import evaluate as _evaluate_trust

        _frm = ((feats.get("mail") or {}).get("from") or {})
        verdict = _evaluate_trust(_frm.get("addr", ""), _frm.get("domain_reg", ""),
                                 _link_domains(parsed, iocs))
        signals, trust_note = _apply_trust(signals, verdict)
        if not trust_note and verdict.tier == "blocked":
            # 人工确认钓鱼 → 不降权。这一条也必须进报告：否则分析师看到"没有降权说明"
            # 会以为系统没查过人工判定，而实际是**有意**不放行。
            trust_note = f"{verdict.reason}（硬信号与话术信号均按原口径计分）"

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

    # 类别标签 + SPAM 降档（营销/垃圾与钓鱼分流，见 app/scoring/category.py）。
    # category 只看信号与情报，与分数无关；降档仅在结论已越过 BENIGN 时生效——
    # 低分营销邮件本来就是 BENIGN，无需降。SPAM 不参与三档阈值语义，属于处置
    # 分流层：营销/垃圾走归档/标记，不进 MALICIOUS 安全工单。
    category = classify_category([s["id"] for s in signals], intel_results)
    demoted = verdict != "BENIGN" and spam_demotion_eligible(category, auth)
    if demoted:
        verdict = "SPAM"

    # 可解释输出：情报汇总 -> 命中明细 -> 认证 -> 启发式 -> 归一化说明
    reasons: list[str] = []
    summary = _intel_summary(intel_results)
    if summary:
        reasons.append(summary)
    reasons += [f"威胁情报命中: {r}" for r in intel_reasons]
    reasons += [f"邮件认证: {r}" for r in auth_reasons]
    reasons += [f"启发式: {r}" for r in heuristic_reasons]
    if dropped:
        # 档位差异必须写进报告：否则分析师会以为"这封真的没有缺认证头的证据"
        reasons.append(f"说明: {_PROFILE_NOTE}（已剔除信号: {', '.join(sorted(dropped))}）")
    if trust_note:
        reasons.append(f"说明: {trust_note}")
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

    if demoted:
        n_mkt = len({s["id"] for s in signals} & MARKETING_SIGNALS)
        reasons.insert(
            1 if summary else 0,
            f"处置降档: 类别判定 marketing（{n_mkt} 项独立营销证据）且发件方认证通过，"
            "无钓鱼强信号与情报命中，结论降为 SPAM（营销/垃圾归档，非安全事件）")

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
        "category": category,
        "reasons": reasons,
        "breakdown": breakdown,
        "signals": signals,
    }
