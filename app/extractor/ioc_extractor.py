"""IOC 提取：从解析结果中提取 URL / 域名 / IP / 文件哈希，支持 hxxp 混淆还原。"""
from __future__ import annotations

import html
import ipaddress
import re
import unicodedata
from typing import Any

# ---- 正则定义 ----
_URL_RE = re.compile(
    r"\b(?:https?|ftp)://[^\s\"'<>{}\[\]|\\^\x60]+",
    re.IGNORECASE,
)
# 常见混淆：hxxp:// 、hXXps://
_OBFUSCATED_URL_RE = re.compile(r"\bh(?:xx|tt)p?s?://[^\s\"'<>{}\[\]|\\^\x60]+", re.IGNORECASE)
_HREF_RE = re.compile(r"""href\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_SRC_RE = re.compile(r"""src\s*=\s*["']https?://[^"']+["']""", re.IGNORECASE)
_EMAIL_RE = re.compile(r"[\w.+-]+@([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
_IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}"
                      r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b")
_SHA256_RE = re.compile(r"\b[a-fA-F0-9]{64}\b")
_MD5_RE = re.compile(r"\b[a-fA-F0-9]{32}\b")

_SHORTENER_DOMAINS = {
    "bit.ly", "t.co", "tinyurl.com", "goo.gl", "is.gd", "ow.ly", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "t.ly", "s.id", "urlz.fr",
}

PRIVATE_NETWORKS = [ipaddress.ip_network(n) for n in (
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "127.0.0.0/8", "169.254.0.0/16", "100.64.0.0/10",
)]

# 计入「IOC 数」的类别：
#   - private_ips 不算（内网地址不是威胁指标）
#   - sender_domains 不单列（它是 header_domains 的子集，单列会重复计数）
_IOC_COUNT_KEYS = ("urls", "domains", "header_domains", "ips", "hashes")


def count_iocs(iocs: dict[str, Any]) -> int:
    """已提取 IOC 的总条数（统一口径）。

    回归背景：「IOC 数」此前各处都用 ``urls+domains+ips+hashes`` 统计，把
    ``header_domains`` 排除在外——于是"只有头部域名、正文无链接"的邮件会显示
    IOC 数 = 0，使用者据此认为"IOC 没提取出来"，其实已经提取到了发件域/收件域。
    """
    return sum(len(iocs.get(k) or []) for k in _IOC_COUNT_KEYS)


# ---- 反混淆（refang）规则 ----
#
# 只还原「攻击者在用、且不破坏链接可点击性」的混淆。
#
# 为什么不做分析员的"防呆"写法（hxxp、example[.]com、[:]、[/]、dot 单词、标点插空格）：
#   1. 防呆是威胁情报**报告**的书写约定（IETF draft-grimminck-safe-ioc-sharing；
#      MITRE/STIX 亦推荐），目的是让链接不可点击、避免误点与自动预览暴露调查行为；
#   2. 而攻击者的目标是让受害者点开链接——hxxp://evil[.]com 根本点不开，
#      所以真实钓鱼不会在自己的载荷里做防呆；
#   3. 把防呆当真实 IOC 还原还会造成**反向误报**：转发一份脱敏的安全通告，
#      里面的 example[.]com 会被提取、送去情报查询、可能命中，于是这封正常邮件被判恶意。
# 真实攻击改用「保持可点击、只绕过文本匹配」的手法，见下。
_INVISIBLE_RE = re.compile(r"[\u00ad\u200b-\u200f\u2060\u2061-\u2064\ufeff]")
# 反斜杠转义（JSON/JS 字符串里的 http:\/\/）——不是防呆惯例，而是真实的转义产物
_ESCAPED_SLASH_RE = re.compile(r"\\+/")


def refang(text: str) -> str:
    """还原真实的 URL 混淆（有公开案例支撑的手法）。

    覆盖：
      1. **不可见字符插入** —— ZWSP/ZWNJ/ZWJ/WORD JOINER/软连字符(SHY)：SANS ISC 2025-01-27
         的 "shy z-wasp" 案例中，零宽字符被插进超链接以绕过 URL 安全检查，
         **且完全不影响链接可用性**（这正是与防呆的本质区别）；
      2. **软连字符 U+00AD** —— 自 2010 年起被用于切断可疑词，让关键词/URL 匹配失效；
      3. **未渲染的 HTML 实体** —— ``&#104;ttp://`` 这类写法同样用于切断可疑词；
      4. **全角/兼容字符** —— ``ｈｔｔｐ：／／`` 经 NFKD 归一化 + 去除组合记号还原
         （组合记号插入如 ``A<记号>mazon`` 亦在此处理）。

    不处理防呆写法，理由见上方注释。
    """
    if not text:
        return ""
    text = _INVISIBLE_RE.sub("", text)
    text = html.unescape(text)
    # 性能：NFKD 与"去组合记号"对纯 ASCII 都是恒等变换，先判 ASCII 即可整段跳过
    # （实体解码要放在判断之前：&#x200b; 这类会解码出非 ASCII 字符）。
    # 非 ASCII 时也不逐字符遍历：只对实际出现的非 ASCII 字符建表 + C 层 translate
    # （2.5 MB 正文实测 300 ms -> ~34 ms，且多数文档根本没有组合记号）。
    if not text.isascii():
        text = unicodedata.normalize("NFKD", text)
        table = {ord(c): None for c in set(text)
                 if ord(c) > 127 and unicodedata.category(c) == "Mn"}
        if table:
            text = text.translate(table)
    return _ESCAPED_SLASH_RE.sub("/", text)


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    if addr.version == 4:
        return any(addr in net for net in PRIVATE_NETWORKS)
    return addr.is_private


def _domain_from_url(url: str) -> str | None:
    m = re.match(r"^[a-z]+://([^/:?#]+)", url, re.IGNORECASE)
    if not m:
        return None
    host = m.group(1).strip("._-").lower()
    if _IPV4_RE.fullmatch(host):
        return None  # IP 直连不算域名
    return host if "." in host else None


def _has_usable_host(url: str) -> bool:
    """URL 的主机是否"可用"：含点（域名）或为 IP 字面量。

    过滤掉 ``http://example`` 这类主机——它们通常是防呆/脱敏残留、内网主机名，
    或正文里被空格截断的产物（如 "http://example dot com"）。送去做威胁情报查询
    没有意义，还会污染 IOC 列表。此前不过滤，``http://cheap`` 这类残片会被当成 IOC。
    """
    m = re.match(r"^[a-z]+://([^/:?#]+)", url, re.IGNORECASE)
    if not m:
        return False
    host = m.group(1).strip("[]").strip(".")
    if "." in host or ":" in host:      # 域名 / IPv6 字面量
        return True
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


# 结构性 URL（XML 命名空间 / DTD / Open Graph / schema.org 元数据）：它们出现在**每一个**
# 正常 HTML 邮件的骨架里，不是"邮件让收件人访问的地址"。此前会进 IOC 列表、被送去查威胁
# 情报（白耗配额），也让分析师在报告里看到 `www.w3.org` 这种"这是哪门子 IOC"的条目。
# 判定按**主机名**后缀比对（不用可注册域：ns.adobe.com 的可注册域是 adobe.com，按注册域
# 会连带把邮件里真实的 adobe.com 链接一起滤掉）。清单与 scoring 侧 link_allowlist 中的
# 同名条目保持一致。
_STRUCTURAL_HOSTS = frozenset({
    "w3.org", "w3c.org", "ogp.me", "schema.org", "purl.org",
    "openxmlformats.org", "ns.adobe.com", "xmlsoap.org", "xmlns.com",
})


def _is_structural_url(url: str) -> bool:
    """是否结构性/元数据 URL（见 _STRUCTURAL_HOSTS）。"""
    m = re.match(r"^[a-z]+://([^/:?#]+)", url, re.IGNORECASE)
    if not m:
        return False
    host = m.group(1).strip("[]").strip(".").lower()
    return any(host == h or host.endswith("." + h) for h in _STRUCTURAL_HOSTS)


def _extract_urls(parsed: dict[str, Any]) -> list[str]:
    """从正文、HTML、头部提取 URL 并去重还原。"""
    candidates: list[str] = []

    def _scan(text: str) -> None:
        if not text:
            return
        unobfuscated = refang(text)
        candidates.extend(m.group(0).rstrip(".,;:!?)）】") for m in _URL_RE.finditer(unobfuscated))

    _scan(parsed.get("body_text", ""))
    _scan(parsed.get("body_html", ""))

    html = parsed.get("body_html", "")
    if html:
        unobfuscated = refang(html)
        candidates.extend(m.group(1) for m in _HREF_RE.finditer(unobfuscated)
                          if m.group(1).lower().startswith(("http", "ftp")))

    headers = parsed.get("headers", {}) or {}
    for key in ("reply-to", "return-path", "list-unsubscribe"):
        value = headers.get(key)
        if isinstance(value, str):
            _scan(value)
        elif isinstance(value, list):
            for v in value:
                _scan(str(v))

    seen: set[str] = set()
    urls: list[str] = []
    for u in candidates:
        u = u.rstrip("/")
        if not u or u.lower() in seen or not _has_usable_host(u):
            continue
        if _is_structural_url(u):
            continue
        seen.add(u.lower())
        urls.append(u)
    return urls


def extract_iocs(parsed: dict[str, Any]) -> dict[str, Any]:
    """主入口：输入 parse_eml/parse_msg 的输出，输出四类 IOC。"""
    urls = _extract_urls(parsed)

    domains: list[str] = []
    ips: list[str] = []
    private_ips: list[str] = []

    for url in urls:
        m = re.match(r"^[a-z]+://([^/:?#]+)", url, re.IGNORECASE)
        if not m:
            continue
        host = m.group(1).strip("._-").lower()
        if _IPV4_RE.fullmatch(host):
            (private_ips if _is_private_ip(host) else ips).append(host)
        elif "." in host:
            domains.append(host)

    # 头部中的邮箱域名（From/Reply-To 是判断伪造的关键）
    headers = parsed.get("headers", {}) or {}
    header_domains: list[str] = []
    sender_domains: list[str] = []
    for key in ("from", "to", "cc", "reply-to", "return-path"):
        value = headers.get(key)
        text = value if isinstance(value, str) else " ".join(value) if isinstance(value, list) else ""
        for d in _EMAIL_RE.finditer(refang(text)):
            header_domains.append(d.group(1).lower())
            # 发件方身份域名（可被伪造，是情报查询的重点）；to/cc 是收件人域，
            # 通常就是使用者自己的组织，查它只是浪费配额，故单独归类。
            if key in ("from", "reply-to", "return-path"):
                sender_domains.append(d.group(1).lower())

    # 正文中的裸 IP 与哈希
    body = refang(parsed.get("body_text", "")) + "\n" + refang(parsed.get("body_html", ""))
    for m in _IPV4_RE.finditer(body):
        ip = m.group(0)
        (private_ips if _is_private_ip(ip) else ips).append(ip)
    hashes = sorted({m.group(0).lower() for m in _SHA256_RE.finditer(body)}
                    | {m.group(0).lower() for m in _MD5_RE.finditer(body)})
    for att in parsed.get("attachments", []):
        hashes.append(att["sha256"])

    def _dedupe(items: list[str]) -> list[str]:
        seen: set[str] = set()
        return [i for i in items if not (i in seen or seen.add(i))]

    return {
        "urls": _dedupe(urls),
        "domains": _dedupe(domains),
        "header_domains": _dedupe(header_domains),
        "sender_domains": _dedupe(sender_domains),
        "ips": _dedupe(ips),
        "private_ips": _dedupe(private_ips),
        "hashes": _dedupe(hashes),
    }
