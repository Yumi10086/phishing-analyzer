"""邮件类别判定（第一步·标签层）：phishing / marketing / unknown。

设计约束（与 README Roadmap「垃圾/营销邮件与钓鱼分离」一致）：

- 标签只供分流展示与后续降档门槛使用，**不影响三档结论与评分**；
- 钓鱼优先：命中任何钓鱼强信号即判 phishing——钓鱼伪装成营销是危险误判，
  营销被标成 phishing 只是体验问题，两者不对称；
- 营销特征（退订头/批量标识/退订链接/ESP 域）单独均可伪造（List-Unsubscribe
  一分钟就能加上），因此要求 **>=2 项独立营销证据** 才判 marketing；
- 未来第二步的降档门槛必须在此标签之上叠加"发件方可信证据"（认证对齐于
  非一次性域、历史通信记录），本模块不负责该判定。
"""
from __future__ import annotations

from typing import Any

# 钓鱼强信号：正常邮件几乎不可能触发，命中即判 phishing（不给营销特征豁免机会）
STRONG_PHISHING_SIGNALS = frozenset({
    # 凭证表单 / 高危附件（attachment_rules：高危可执行/镜像 + 脚本宏文档 + 双扩展名）
    "html_password_field",
    "att_double_ext", "att_ext_high_risk", "att_ext_medium_risk",
    # 压缩包载荷投递：加密且密码在正文（绕过网关标准玩法）/ 内层可执行
    "att_archive_password_in_body", "att_archive_inner_executable",
    # Office 载荷执行链：远程模板注入 / DDE / 宏下载执行·Shell 调用；PDF 启动外部程序
    "att_office_remote_template", "att_office_dde",
    "att_office_macro_download", "att_office_macro_shell",
    "att_pdf_launch",
    # 群发工具安装路径指纹（file:/// + 群发）：批量伪造 campaign 的铁证
    "html_massmailer_fingerprint",
    # YARA 家族规则命中（已知恶意载荷特征）
    "att_yara_hit",
    # 高精度凭证索取话术（credential_keywords："verify your identity" 级别的明确表述）。
    # 注意 body_credentials 不在列——它匹配低精度 url_keywords（account/update/confirm），
    # ESP 退订页脚 "update your preferences" 会误命中（datacon 127 封降档样本实测
    # 全部属于此类、0 封含高精度短语），用它封杀降档会杀死正常营销分流。
    "body_credential_solicitation", "body_credentials_no_link",
    # URL 形态
    "url_ip_literal",
    # 身份仿冒（显示名/域名层面的品牌仿冒；body_brand_spoof 可被 CSS 字体名误触发，不入列）
    "from_display_brand_spoof", "domain_leet_brand", "link_domain_lookalike",
    # 对抗性混淆
    "text_invisible_obfuscation",
    # 伪造认证头（Authentication-Results 自相矛盾）
    "header_auth_inconsistent",
})

# 营销/批量发送证据：信息性规则 id 集合。
# body_gift_marketing 是内容型营销证据（礼品+采购语境双命中）：群发获客邮件的
# 正文话术本身与退订头部/ESP 域同等级独立，datacon 中礼品营销簇 231 封全部
# 无营销头部但正文退订链接 100% 存在，二者组合即可安全判定 marketing。
MARKETING_SIGNALS = frozenset({
    "header_list_unsubscribe", "header_precedence_bulk",
    "body_unsubscribe_link", "sender_esp_domain",
    "body_gift_marketing",
})

# 判 marketing 所需的最少独立营销证据数。取 2 而非 1：单个特征都易伪造
# （如钓鱼邮件抄一个 List-Unsubscribe 头），两个独立来源同时命中成本高得多。
MARKETING_MIN_SIGNALS = 2

CATEGORY_LABELS = {
    "phishing": "钓鱼/恶意",
    "marketing": "营销/垃圾",
    "unknown": "未分类",
}


def classify_category(signal_ids: list[str] | set[str],
                      intel_results: list[dict[str, Any]] | None = None) -> str:
    """根据规则信号与情报结果判定邮件类别。

    - phishing：命中钓鱼强信号，或威胁情报命中恶意 IOC；
    - marketing：无钓鱼强信号且独立营销证据 >= MARKETING_MIN_SIGNALS；
    - unknown：其余（信息不足时不强行分类）。
    """
    ids = set(signal_ids)
    intel_hit = any(r.get("status") == "hit" for r in (intel_results or []))
    if (ids & STRONG_PHISHING_SIGNALS) or intel_hit:
        return "phishing"
    if len(ids & MARKETING_SIGNALS) >= MARKETING_MIN_SIGNALS:
        return "marketing"
    return "unknown"


def spam_demotion_eligible(category: str, auth: dict[str, Any]) -> bool:
    """是否满足降档为 SPAM 的全部条件（第二步·降档门槛）。

    门槛 = 类别为 marketing **且** 发件方有可信证据。两道条件缺一不可：

    - category == "marketing" 本身已隐含"无钓鱼强信号、无情报命中、≥2 项独立
      营销证据"，这是防钓鱼伪装营销的第一道闸；
    - 发件方可信证据取"三项认证至少一项 pass"：正规 ESP 与正规营销系统会把
      SPF/DKIM/DMARC 配好，而伪造成营销形态的邮件多数连自家域的认证都配不齐。
      注意校院类钓鱼（自建域认证全 pass）不会被降档——它命中情报或强信号，
      category 已是 phishing。

    刻意不做的两件事：
    - 不要求 Reply-To/Return-Path 对齐：营销邮件回信到免费客服邮箱很常见，
      拿对齐做门槛会把大量真营销挡在降档之外；
    - 不看 List-Unsubscribe 等头部本身的可信度：头部可伪造，它们只用于凑
      营销证据数，不作为"可信"依据。

    历史通信记录（收发双方往来）当前无数据源，留待接入邮箱侧上下文后加强。
    """
    if category != "marketing":
        return False
    return any(auth.get(m) == "pass" for m in ("spf", "dkim", "dmarc"))
