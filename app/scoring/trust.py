"""信任上下文：按"往来历史"对**话术/结构类**信号降权（绝不免除硬信号）。

设计依据（本机实测；结论只写在这里，不依赖外部未公开材料）：
  - 收益面（个人邮箱 19 封关注）：地址级"同一发件地址 ≥2 封"可降档 10 封、域级（排除共享域）
    11 封、再加"跨度 ≥14 天"只剩 4 封；
  - 风险面（判据作用在真值全是钓鱼的语料上，即"攻击者反复投递农场化信任"的上界）：
    地址级 pot 45.2% / 域级 29.6% / 域级+跨度 18.4%。

结论：**计数即信任不安全**，所以这里做了三重约束：
  1. **共享域只按地址判**（`qq.com` 一个域背后 7 个不同人，含 QQ 官方 `10000@qq.com`）；
     域级信任只对非共享、非 ESP 域生效；
  2. **只降权，不免检**：命中降权的信号仍留在报告里（点数乘以系数），并写明降权理由；
  3. **硬信号永不动**：情报命中、IP 直连 URL、危险附件/类型伪装/宏、仿冒域配对、
     显示名冒充——被信任的发件人同样会被钓鱼或入侵，这些是唯一可靠的那部分证据。

降权分两档（按信任强度）：
  - ``known``（地址见过 ≥2 封）：只降**营销/结构类**（退订头、退订链接、ESP 域、免费邮箱发件）
    ——它们各 1–2 分且钓鱼并不依赖；
  - ``established``（域级 ≥5 封且跨度 ≥14 天且域非共享，或"你回过信"）：额外降**话术类**
    （凭证词、紧迫措辞、验证码话术、品牌冒充）与"独立信号叠加"，并把 `link_domain_mismatch`
    降权**仅当**本次链接域都在该发件人历史用过的链接域里（行为一致）——出现没见过的链接域
    就不降，用于捕捉"信任发件人被入侵后群发"。
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from typing import Any

from app.utils.logger import get_logger

log = get_logger(__name__)

# 结构/信息类：known 档即降。这些信号的语义都是"渠道/寄送形态"或"发件人命名习惯"，
# 对**已建立往来**的发件人没有信息量（银行服务号 `95555ad@`、营销退订头都是常态），
# 各自 1–4 分，钓鱼也不依赖它们。
STRUCTURAL_DEMOTE = frozenset({
    "header_list_unsubscribe", "header_precedence_bulk", "body_unsubscribe_link",
    "sender_esp_domain", "sender_from_freemail",
    # 数字型本地部分：为"陌生发件人用随机数字名"设计；对收过 2 封以上的老发件人是噪声
    # （实测样本：招行 95555ad@message.cmbchina.com，4 分，信任生效时不该再计）
    "from_localpart_numeric_noise",
})
# 兼容旧名（文档与脚本里曾用 MARKETING_DEMOTE）
MARKETING_DEMOTE = STRUCTURAL_DEMOTE
# 话术类：established 档才降（真钓鱼靠它们，降权系数刻意保守）
WORDING_DEMOTE = frozenset({
    "body_credentials", "body_urgency", "body_otp", "body_brand_spoof",
})
# 依赖"行为一致"才降的域关系类信号
BEHAVIOR_DEMOTE = frozenset({"link_domain_mismatch"})
# 多弱信号叠加：对已建立往来的发件人，多个弱信号是常态，不该再叠加成"可疑"
STACK_SIGNAL = "signal_stack"
# 硬信号（永不动）：这里显式列出以自我文档化，任何新增降权都必须先证明不在此列
NEVER_DEMOTE = frozenset({
    "url_ip_literal", "link_domain_lookalike", "from_display_brand_spoof",
    "from_display_email_mismatch", "domain_leet_brand", "att_double_ext",
    "att_ext_high_risk", "att_ext_medium_risk", "att_type_mismatch", "att_yara_hit",
    "att_office_remote_template", "att_office_dde", "att_office_macro_download",
    "att_office_macro_shell", "att_pdf_launch", "att_archive_inner_executable",
    "att_archive_password_in_body", "html_password_field", "html_file_uri",
    "html_massmailer_fingerprint", "body_credential_solicitation", "body_credentials_no_link",
})

MARKETING_FACTOR = 0.0      # 结构类直接不计分（它们本是 1 分信息项）
WORDING_FACTOR = 0.3        # 话术类降为三成（保留证据可见性）


def trust_context_enabled() -> bool:
    """信任上下文开关。

    默认跟随分析档位：gateway（网关投递）下没有"本地往来历史"这回事，默认关闭；
    mailbox（邮箱直读）下默认开启，可用 ``TRUST_CONTEXT=0`` 显式关闭做对照。
    """
    env = os.environ.get("TRUST_CONTEXT", "").strip().lower()
    if env in ("0", "false", "no"):
        return False
    if env in ("1", "true", "yes"):
        return True
    from app.config import analysis_profile

    return analysis_profile() == "mailbox"


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except ValueError:
        return default


@dataclass
class TrustVerdict:
    """一次信任判定的结果（供评分层降权与报告展示）。"""

    tier: str = "none"                  # none | known | established
    reason: str = ""                    # 人类可读依据（写进报告）
    demote: set[str] = field(default_factory=set)
    link_consistent: bool = False

    @property
    def active(self) -> bool:
        """是否有判定结果。注意 ``blocked``（人工确认钓鱼）是"有判定但**不降权**"，
        故 apply() 里靠 demote 为空自然跳过。"""
        return self.tier != "none"


def evaluate(addr: str, domain: str, link_domains: list[str] | None = None,
             own_brands: set[str] | None = None) -> TrustVerdict:
    """查往来历史，给出信任档与可降权信号集合。

    参数都用小写；``addr`` 为发件地址、``domain`` 为可注册域、``link_domains`` 为本次
    邮件链接到的可注册域（用于行为一致性判定）。
    """
    if not trust_context_enabled() or not addr:
        return TrustVerdict()

    from app.scoring.features import load_esp_domains, load_freemail_domains
    from app.utils.cache import cache

    # 人工判定优先于一切自动判据（L1 显式反馈）：
    #   - 人工确认"正常" → 直接按已建立往来处理（不受封数/跨度门槛限制）；
    #   - 人工确认"钓鱼" → **禁止**任何信任降权（否则"先刷历史再钓鱼"只需骗过一次点击）。
    human = cache.get_human_verdict(addr, domain)
    if human and human["verdict"] == "phishing":
        until = (human.get("expires_at") or "")[:10]
        return TrustVerdict(tier="blocked",
                            reason=f"该发件人已被人工确认为钓鱼（{human['scope']}={human['key']}"
                                   + (f"，{until} 到期" if until else "") + "）→ 不适用信任降权")
    human_benign = bool(human and human["verdict"] == "benign")

    row = cache.get_sender(addr)
    if not row and not human_benign:
        return TrustVerdict()
    # 「你给它写过信」直接越过封数门槛——它是最强正向信号（攻击者拿不到"你主动回信"这件事），
    # 而"收到过 N 封"只是弱计数（农场化攻击可刷）。其余情况才要求最低封数。
    # 人工确认过"正常"同样直接越过门槛。
    if not human_benign and not row["replied"] and row["count"] < _env_int("TRUST_MIN_COUNT", 2):
        return TrustVerdict()

    demote = set(STRUCTURAL_DEMOTE)
    # row 可能为空而 human_benign 为真（人工确认过的发件人未必在本机有往来历史）
    notes: list[str] = [f"该发件地址历史收到 {row['count']} 封"] if row else []

    shared = domain and (domain in load_freemail_domains() or domain in load_esp_domains())
    dom_hist = {"count": 0, "span_days": 0} if shared else cache.get_domain_history(domain)
    established = (
        human_benign
        or bool(row and row["replied"])
        or (dom_hist["count"] >= _env_int("TRUST_MIN_DOMAIN_COUNT", 5)
            and dom_hist["span_days"] >= _env_int("TRUST_MIN_SPAN_DAYS", 14))
    )
    name = addr if not domain else f"{addr}（域 {domain}）"
    if human_benign:
        notes.append(f"人工判定 {human['scope']}={human['key']} 为正常"
                     + (f"（{human['note']}）" if human.get("note") else ""))
    if not established:
        return TrustVerdict(tier="known", reason=f"已建立往来: {name}，{'；'.join(notes)}",
                            demote=demote)

    demote |= set(WORDING_DEMOTE) | {STACK_SIGNAL}
    if row and row["replied"]:
        notes.append("你给它写过信")
    elif dom_hist["count"]:
        notes.append(f"域级历史 {dom_hist['count']} 封/跨度 {dom_hist['span_days']} 天")

    # 行为一致性：本次链接域必须都在该发件人历史用过的链接域里，否则不降 link_domain_mismatch
    links = {d for d in (link_domains or []) if d}
    history_links = set((row or {}).get("link_domains") or ())
    link_consistent = bool(links) and links <= history_links
    if link_consistent:
        demote |= set(BEHAVIOR_DEMOTE)
        notes.append("链接域与历史一致")
    tier = "established" if not human_benign else "human_benign"
    return TrustVerdict(tier=tier,
                        reason=f"已建立往来: {name}（{'；'.join(notes)}）",
                        demote=demote, link_consistent=link_consistent)


def apply(signals: list[dict[str, Any]], verdict: TrustVerdict) -> tuple[list[dict[str, Any]], str]:
    """按信任判定降权信号；返回 (新信号列表, 报告说明行)。硬信号不受影响。"""
    if not verdict.active or not verdict.demote:
        return signals, ""
    out: list[dict[str, Any]] = []
    demoted: list[str] = []
    for sig in signals:
        sid = sig.get("id", "")
        if sid in NEVER_DEMOTE or sid not in verdict.demote:
            out.append(sig)
            continue
        factor = MARKETING_FACTOR if sid in STRUCTURAL_DEMOTE else WORDING_FACTOR
        if sid == STACK_SIGNAL:
            factor = 0.0
        new_sig = dict(sig)
        new_sig["points"] = round(float(sig.get("points", 0)) * factor, 2)
        new_sig["trust_demoted"] = factor
        out.append(new_sig)
        demoted.append(sid)
    note = ""
    if demoted:
        note = (f"信任上下文: {verdict.reason} → 降权 {len(demoted)} 项话术/结构信号"
                f"（{', '.join(sorted(demoted))}）；硬信号不受影响")
    return out, note
