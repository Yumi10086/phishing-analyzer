"""测试样本生成器：生成 100% 合成的正常/可疑/钓鱼邮件样本。

合规说明：所有域名均为 RFC 2606 保留域（example.com / .example / .invalid），
IP 均为 RFC 5737 文档保留段（192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24），
附件为占位字节，不含任何真实恶意内容。
"""
from __future__ import annotations

import base64
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

SAMPLES_DIR = Path(__file__).resolve().parent.parent / "data" / "samples"

# 占位"附件"内容（非可执行，仅用于测试哈希/文件名启发式）
PLACEHOLDER_DOCM = b"PK\x03\x04 placeholder-bytes-for-macro-doc-test-only" * 20
PLACEHOLDER_EXE = b"MZ placeholder-bytes-for-executable-test-only" * 20


def _base(msg: EmailMessage, from_addr: str, to_addr: str, subject: str) -> EmailMessage:
    msg["From"] = from_addr
    msg["To"] = to_addr
    msg["Subject"] = subject
    msg["Date"] = formatdate(localtime=False)
    msg["Message-ID"] = make_msgid(domain="mail.example.com")
    return msg


def benign_01() -> EmailMessage:
    msg = EmailMessage()
    _base(msg, "张伟 <zhangwei@corp.example.com>", "project-team@corp.example.com",
          "Q3 安全周报与评审会议安排")
    msg["Authentication-Results"] = "mx.corp.example.com; spf=pass smtp.mailfrom=corp.example.com; dkim=pass; dmarc=pass"
    msg["Return-Path"] = "<zhangwei@corp.example.com>"
    msg.set_content("""各位好：

本周安全评审会议安排在周四下午 2 点，会议室 B302。
请各位提前准备上周的告警复盘材料，重点看钓鱼类告警的处理时长。

附件稍后由王芳单独发送。

张伟
信息安全部
""")
    return msg


def benign_02() -> EmailMessage:
    msg = EmailMessage()
    _base(msg, "Docs Portal <no-reply@docs.example.org>", "li.li@corp.example.com",
          "[Docs] 您的知识库文章已审核通过")
    msg["Authentication-Results"] = "mx.corp.example.com; spf=pass smtp.mailfrom=example.org; dkim=pass header.d=example.org; dmarc=pass"
    msg["Return-Path"] = "<bounces@docs.example.org>"
    msg.set_content("""您好：

您提交的文章《邮件网关策略配置指南》已通过审核并发布。

查看页面: https://docs.example.org/guide/mail-gateway-policy

如有疑问请回复本邮件。
Docs Portal 团队
""")
    return msg


def suspicious_01() -> EmailMessage:
    """可疑样本：正规外观但混入短链接 + 高风险 TLD + HTML 附件。"""
    msg = EmailMessage()
    _base(msg, "Cloud Storage Team <notice@cloudstorage.example>", "li.li@corp.example.com",
          "Action required: your account will be suspended")
    msg["Authentication-Results"] = "mx.corp.example.com; spf=pass smtp.mailfrom=cloudstorage.example; dkim=none; dmarc=pass"
    msg["Return-Path"] = "<notice@cloudstorage.example>"
    msg["Reply-To"] = "support-desk@other-mail.invalid"
    msg.set_content("""Dear user,

Your account storage quota has been exceeded. Please verify your account within 24 hours,
otherwise the account will be suspended and all files will be deleted.

Click to confirm: https://bit.ly/3xFakeAccountVerify

Cloud Storage Team
""")
    html_attachment = """<html><body>
<h2>Account Verification</h2>
<form action="http://backup-notice.example.top/verify" method="post">
<input name="user"><input name="pass" type="password"><button>Verify</button>
</form></body></html>"""
    msg.add_alternative(html_attachment, subtype="html")
    # 把 HTML 部分声明为附件
    for part in msg.iter_parts():
        part.add_header("Content-Disposition", "attachment", filename="account-verify.html")
    return msg


def phishing_01() -> EmailMessage:
    """钓鱼样本 1：品牌冒充 + IP 直连 + Punycode + 认证失败。"""
    msg = EmailMessage()
    _base(msg, "PayPal Service <service@paypal-secure-verify.example>",
          "victim.user@corp.example.com", "Urgent: Unusual activity detected, verify now!")
    msg["Authentication-Results"] = "mx.corp.example.com; spf=fail smtp.mailfrom=paypal-secure-verify.example; dkim=none; dmarc=fail"
    msg["Return-Path"] = "<bounce@mailer-daemon.example.invalid>"
    msg["Reply-To"] = "recover-center@example.invalid"
    msg.set_content("""Dear customer,

We detected unusual activity on your account. Your account will be PERMANENTLY
LOCKED within 24 hours unless you verify your identity immediately.

Confirm your identity here:
  - http://203.0.113.66/account/verify/login
  - https://xn--pypl-secure-cvf.example/login

Enter your password and card details to restore access.

PayPal Security Team
""")
    return msg


def phishing_02() -> EmailMessage:
    """钓鱼样本 2：双扩展名可执行附件 + 混淆 hxxp 链接。"""
    msg = EmailMessage()
    _base(msg, "HR Recruiting <hr-recruit@headhunter-corp.example>",
          "victim.user@corp.example.com", "2026 校园招聘录用通知（请查收 Offer）")
    msg["Authentication-Results"] = "mx.corp.example.com; spf=none; dkim=none; dmarc=none"
    msg.set_content("""同学你好：

恭喜通过我司三轮面试！请立即打开附件查看 Offer 详情，
并在 24 小时内确认入职意向，逾期视为放弃。

电子版确认书请上传至: hxxp://secure-hr-portal.example.top/offer

人力资源部
""")
    msg.add_attachment(PLACEHOLDER_EXE, maintype="application", subtype="octet-stream",
                       filename="Offer_2026.pdf.exe")
    return msg


def phishing_03() -> EmailMessage:
    """钓鱼样本 3：快递代收骗局（DHL 冒充）+ 短链接 + 计费关键词。"""
    msg = EmailMessage()
    _base(msg, "DHL Express <tracking@dhl-parcel-notice.example>",
          "victim.user@corp.example.com", "Final notice: package held at customs, pay now")
    msg["Authentication-Results"] = "mx.corp.example.com; spf=fail smtp.mailfrom=dhl-parcel-notice.example; dkim=none; dmarc=fail"
    msg["Return-Path"] = "<dhl-parcel-notice.example>"
    msg["Reply-To"] = "customs-pay@dhl-parcel-notice.example"
    msg.set_content("""Dear customer,

Your package DE8849205771 is held at customs. An outstanding billing fee of 1.99 EUR
must be paid within 24 hours, otherwise the package will be returned.

Pay now and track: hxxp://bit.ly/3xFakeDhlPay
Alternative: http://198.51.100.23/dhl/billing/verify
Official mirror: https://xn--dhl-express-4ed.example/track

DHL Express Team
""")
    return msg


def suspicious_02() -> EmailMessage:
    """可疑样本 2：营销邮件混入短链接与凭证关键词，无明显身份伪造。"""
    msg = EmailMessage()
    _base(msg, "Deals Weekly <news@deals-weekly.example.info>",
          "li.li@corp.example.com", "Your weekly deals are here")
    # 故意不带 Authentication-Results 头
    msg.set_content("""Hello,

This week's picks are out. Update your account preferences to see more:

https://bit.ly/3xDealsWeekly
http://promo.deals-weekly.example.info/account/update

Unsubscribe anytime.
""")
    return msg


def phishing_04() -> EmailMessage:
    """钓鱼样本 4：显示名品牌冒充 + 锚文本伪装跳转 + 免费邮箱收回复。"""
    msg = EmailMessage()
    _base(msg, '"PayPal Support" <service.alerts@gmail.com>',
          "victim.user@corp.example.com", "Action required: your account has been limited")
    msg["Authentication-Results"] = "mx.corp.example.com; spf=pass smtp.mailfrom=gmail.com; dkim=pass header.d=gmail.com; dmarc=pass"
    msg["Return-Path"] = "<service.alerts@gmail.com>"
    msg["Reply-To"] = "paypal.recovery@outlook.com"
    msg.set_content("""Dear customer,

We detected unusual activity. Confirm your password and card details
to restore full access immediately.

PayPal Security Team
""")
    html = """<html><body>
<p>Dear customer,</p>
<p>Your account has been limited. Verify now:</p>
<p><a href="http://203.0.113.99/paypal/login">https://www.paypal.com/secure-login</a></p>
</body></html>"""
    msg.add_alternative(html, subtype="html")
    return msg


SAMPLES = {
    "benign_01.eml": benign_01,
    "benign_02.eml": benign_02,
    "suspicious_01.eml": suspicious_01,
    "suspicious_02.eml": suspicious_02,
    "phishing_01.eml": phishing_01,
    "phishing_02.eml": phishing_02,
    "phishing_03.eml": phishing_03,
    "phishing_04.eml": phishing_04,
}


def main() -> None:
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)
    (SAMPLES_DIR / "README.md").write_text(
        "# 测试样本\n\n由 `scripts/gen_samples.py` 生成的**纯合成样本**。\n\n"
        "所有域名均为 RFC 2606 保留域，IP 均为 RFC 5737 文档段，附件为占位字节，\n"
        "不含真实恶意内容，可安全用于演示与测试。\n",
        encoding="utf-8")
    for name, factory in SAMPLES.items():
        path = SAMPLES_DIR / name
        path.write_bytes(factory().as_bytes())
        print(f"生成 {path}")


if __name__ == "__main__":
    main()
