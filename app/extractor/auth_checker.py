"""认证检查：解析 Authentication-Results，并检查 From/Return-Path/Reply-To 域名对齐性。"""
from __future__ import annotations

import re
from typing import Any

_EMAIL_DOMAIN_RE = re.compile(r"@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
# 单标签域兜底：公网上发件域不会是无点单标签，但内网中继与脱敏语料（如
# datacon 赛题数据把域名替换成短 token）会产出形如 user@abc12 的地址。
# 若在这里返回 None，对齐判定会因 from_domain is None 被静默跳过，
# Reply-To/Return-Path 伪造信号整条链路失效，因此必须兜底为"域名"参与对齐。
_EMAIL_DOMAIN_LOOSE_RE = re.compile(r"@([A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?)")
_VALID_RESULTS = {"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror", "policy"}

# DMARC 的 pass 只能来自 SPF 或 DKIM 至少一项对齐通过。因此同一条
# Authentication-Results 头里 spf/dkim 都给出了明确结果且都非 pass，却声明
# dmarc=pass，在合规接收方上不可能出现——这是伪造认证头的特征（攻击者手写头部，
# 或中转环节篡改）。注意只在"同一条头内部"判定：跨多条头合并时，不同 authserv-id
# 各自只覆盖部分方法，pass/non-pass 混在一起属正常现象。
_NON_PASS = {"fail", "softfail", "neutral", "none"}


def _parse_single_header(header: str) -> dict[str, str]:
    """从一条 Authentication-Results 头中提取 spf/dkim/dmarc 结果。

    同一方法可能在该头内出现多次（多签名并存，如 dkim=fail + dkim=pass）。
    此时任一项为 pass 即视为该方法通过，避免把"另一条签名失败"误读成整体失败。
    """
    out: dict[str, str] = {}
    for method in ("spf", "dkim", "dmarc", "arc"):
        found = [m.group(1).lower() for m in re.finditer(
            rf"(?<![a-z0-9-]){method}\s*=\s*([a-z]+)", header, re.IGNORECASE)]
        found = [v for v in found if v in _VALID_RESULTS]
        if found:
            out[method] = "pass" if "pass" in found else found[0]
    return out


def dmarc_pass_without_mechanism(header: str) -> bool:
    """单条认证头内部是否自相矛盾（dmarc=pass 但 spf/dkim 均明确非 pass）。"""
    partial = _parse_single_header(header)
    return (partial.get("dmarc") == "pass"
            and partial.get("spf") in _NON_PASS
            and partial.get("dkim") in _NON_PASS)


def check_auth(parsed: dict[str, Any]) -> dict[str, Any]:
    """输出统一的认证结果视图 + 域名对齐性检查。"""
    spf = dkim = dmarc = None
    smtp_mail_domain = None
    for header in parsed.get("authentication_results", []):
        partial = _parse_single_header(header)
        # pass 优先级最高，其次保留任意出现的明确结果
        for method, value in partial.items():
            if method == "spf":
                spf = value if spf != "pass" else spf
            elif method == "dkim":
                dkim = value if dkim != "pass" else dkim
            elif method == "dmarc":
                dmarc = value if dmarc != "pass" else dmarc
        # 信封发件人（SPF 实际校验的对象）：smtp.mail=pcms@iteview.com / smtp.mailfrom=...
        # 与 From 域不一致且 SPF 未通过时是典型伪造特征（报告 36fab11b15c6472a：
        # 信封 iteview.com 发信冒充阿里云，Reply-To 指向 QQ 邮箱）
        if smtp_mail_domain is None:
            m = re.search(r"smtp\.mail(?:from)?\s*[=<]\s*<?\s*"
                          r"([A-Za-z0-9._%+-]*)@([A-Za-z0-9.-]+)", header, re.IGNORECASE)
            if m and m.group(2):
                smtp_mail_domain = m.group(2).lower()

    headers = parsed.get("headers", {}) or {}

    def _domain_of(value: object) -> str | None:
        if isinstance(value, list):
            value = value[0] if value else ""
        text = refang_email(str(value or ""))
        m = _EMAIL_DOMAIN_RE.search(text)
        if m:
            return m.group(1).lower()
        m = _EMAIL_DOMAIN_LOOSE_RE.search(text)
        return m.group(1).lower() if m else None

    from_domain = _domain_of(headers.get("from"))
    return_path_domain = _domain_of(headers.get("return-path"))
    reply_to_domain = _domain_of(headers.get("reply-to"))

    # 对齐性：Return-Path 应与 From 一致（smpt.mailfrom 对齐）；Reply-To 与 From 不一致是典型钓鱼信号。
    # **Reply-To 按可注册域比对**（DMARC/SPF 的 relaxed 对齐口径）：postmaster.bilibili.com
    # 与 service.bilibili.com 是同一主体的两个子域，不是"Reply-To 指向别处"。实测真实邮箱
    # 27 次命中里 24 次属此类（哔哩哔哩 postmaster@、墨墨 maimemo.com vs email.maimemo.com），
    # 而 pot 167 次里只有 4 次同域、datacon 226 次里 0 次，收紧几乎不动召回。
    # Return-Path 刻意**不改**：它在真实邮箱上 0 次命中（无收益），而 pot 有 17 次
    # "同注册域不同子域"（多为 ESP 的 return-path），改判会白丢这些命中。
    from app.scoring.features import registrable_domain

    def _reply_aligned(a: str | None, b: str | None) -> bool:
        if a is None or b is None:
            return True
        ra, rb = registrable_domain(a), registrable_domain(b)
        return (ra or a) == (rb or b)

    alignment = {
        "from_domain": from_domain,
        "return_path_domain": return_path_domain,
        "reply_to_domain": reply_to_domain,
        "smtp_mail_domain": smtp_mail_domain,
        "return_path_aligned": (return_path_domain is None or from_domain is None
                                or return_path_domain == from_domain),
        "reply_to_aligned": _reply_aligned(reply_to_domain, from_domain),
    }
    return {
        "spf": spf, "dkim": dkim, "dmarc": dmarc,
        "has_auth_header": bool(parsed.get("authentication_results")),
        "dmarc_without_mechanism": any(
            dmarc_pass_without_mechanism(h)
            for h in parsed.get("authentication_results", []) or []
            if isinstance(h, str)
        ),
        **alignment,
    }


def refang_email(text: str) -> str:
    """还原头部文本里的混淆，再从中取域名。

    以前这里独立实现了一份（只处理 hxxp），对邮箱地址其实不起作用；现改为直接复用
    IOC 模块的 ``refang()``——这样 ``From: user@evil[.]com`` / 插了零宽字符的发件域
    也能被正常解析出来，且与 URL 侧的反混淆规则永远保持一致（不会各自漂移）。
    """
    from app.extractor.ioc_extractor import refang
    return refang(text)
