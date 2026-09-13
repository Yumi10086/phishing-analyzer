"""特征工程层：从解析结果构建规则引擎可用的特征字典。

设计原则：特征在代码里（fold、解析、计数、比率），策略在 YAML 里（规则/分值）。
所有文本特征默认经过 fold_text() 混淆还原，规则匹配在折叠后的文本上进行。
"""
from __future__ import annotations

import html
import re
import unicodedata
from typing import Any

# ---- HTML 隐藏文字（hidden text salting）----
# Cisco Talos 自 2024 下半年起观察到该手法激增：用 CSS 把内容藏起来，收件人看不见，
# 但解析器/过滤器会读到，用来干扰品牌名提取、语种判定与关键词检测（还可用于 HTML
# smuggling：在 base64 串里插注释让防御方解码失败）。
# 注意：正常邮件也会用 display:none 放"预览摘要"(preheader)，所以这里只负责**取出**
# 隐藏文字，是否可疑交给规则判定（品牌错位、篇幅异常）。
_HIDING_CSS_RE = re.compile(
    r"(?:display\s*:\s*none|visibility\s*:\s*hidden|(?:max-)?height\s*:\s*0(?:px)?|"
    r"width\s*:\s*0(?:px)?|font-size\s*:\s*(?:0|1)(?:px)?|opacity\s*:\s*0(?![\d.])|"
    r"text-indent\s*:\s*-\d{2,}|mso-hide\s*:\s*all)",
    re.IGNORECASE,
)
_HIDDEN_ELEM_RE = re.compile(
    r"<([a-z][a-z0-9]*)\b[^>]*?style\s*=\s*[\"']([^\"']*)[\"'][^>]*?>(.*?)</\1\s*>",
    re.IGNORECASE | re.DOTALL,
)
_TAG_STRIP_RE = re.compile(r"<[^>]+>")
_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
# base64 串（只用于长度比较，量词简单，不存在嵌套回溯）
_B64_RUN_RE = re.compile(r"[A-Za-z0-9+/=]{20,}")


def hidden_html_text(html: str) -> str:
    """取出 HTML 正文里靠 CSS 隐藏的文字（拼接返回，无则空串）。

    基于正则的同标签匹配（不处理嵌套），足以覆盖该手法的常见写法。
    """
    out: list[str] = []
    for _tag, style, inner in _HIDDEN_ELEM_RE.findall(html or ""):
        if not _HIDING_CSS_RE.search(style):
            continue
        text = _TAG_STRIP_RE.sub("", inner).strip()
        if text:
            out.append(text)
    return " ".join(out)


def strip_hidden_html(html: str) -> str:
    """去掉被 CSS 隐藏的元素，剩下收件人真正能看到的 HTML。"""
    return _HIDDEN_ELEM_RE.sub(
        lambda m: "" if _HIDING_CSS_RE.search(m.group(2)) else m.group(0), html or "")


def has_comment_split_base64(html: str) -> bool:
    r"""HTML 注释是否把 base64 串切断（HTML smuggling 特征）。

    实现上**刻意不用**"把注释与 base64 写进同一个正则"的写法：那种带嵌套量词的
    模式（注释与 base64 交替重复）在文档缺少注释闭合时会发生灾难性回溯——实测一个
    196 KB、**0 个 HTML 注释**的样本直接把整封分析挂死（>20s 不返回）。

    改用线性判据：注释字符本身不是 base64 字符，所以它会**打断** base64 串；
    把注释去掉后若出现了明显更长的 base64 串，说明注释是被用来切断 base64 的。
    """
    html = html or ""
    if "<!--" not in html:               # 绝大多数邮件走这条快路径
        return False
    joined = _HTML_COMMENT_RE.sub("", re.sub(r"\s+", "", html))
    merged_max = max((len(r) for r in _B64_RUN_RE.findall(joined)), default=0)
    if merged_max < 40:
        return False
    plain_max = max((len(r) for r in _B64_RUN_RE.findall(re.sub(r"\s+", "", html))), default=0)
    return merged_max > plain_max
# 零宽/方向控制字符：肉眼不可见，专用于绕过关键词检测。
# 含软连字符 U+00AD —— SANS ISC 2025-01-27 "shy z-wasp" 案例用它切断可疑词；
# 它属 Cf 类且码位低于 \u036f，因此下面那条组合记号兜底抓不到，必须显式列出。
_INVISIBLE_RE = re.compile(r"[\u00ad\u200b-\u200f\u2060\u2061-\u2064\ufeff]")
# 数学字母数字符号（𝐓𝐡𝐞𝐫𝐞 这类）与全角字母数字：垃圾/钓鱼常用字形混淆
_MATH_ALNUM_RE = re.compile(r"[\U0001D400-\U0001D7FF]")
_FULLWIDTH_ALNUM_RE = re.compile(r"[\uFF10-\uFF19\uFF21-\uFF3A\uFF41-\uFF5A]")
# 西里尔/希腊同形字 -> 拉丁字母（Sаmsung、РayPal 这类）
_HOMOGLYPH_MAP = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x",
    "к": "k", "м": "m", "н": "h", "т": "t", "в": "b", "і": "i", "ѕ": "s",
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "К": "K", "М": "M",
    "О": "O", "Р": "P", "Т": "T", "Х": "X", "І": "I", "Ѕ": "S",
    "α": "a", "ο": "o", "ε": "e", "ν": "v", "ρ": "p", "τ": "t",
})
_CONSONANT_RUN_RE = re.compile(r"[bcdfghjklmnpqrstvwxyz]{4,}", re.IGNORECASE)
_VOWELS = set("aeiou")

_FROM_ADDR_RE = re.compile(r"<([^>]+)>")
_URL_HOST_RE = re.compile(r"^[a-z]+://([^/:?#]+)")

# 主流 ccTLD 的二级注册结构：用于把 eTLD+1 判定从"最后两段"修正为三段
_TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "com.au", "net.au", "org.au", "edu.au",
    "co.nz", "net.nz", "org.nz", "co.za", "org.za", "com.cn", "net.cn",
    "org.cn", "gov.cn", "com.tw", "com.hk", "co.kr", "or.kr", "com.mx",
    "com.ar", "com.tr", "com.sg", "com.my", "co.in", "net.in", "org.in",
    "com.pl", "com.ua", "co.id", "com.vn", "com.ph", "com.co", "com.pe",
}


def strip_combining(text: str) -> str:
    """去掉组合记号（Mn），如 A<记号>mazon 这类插入。

    性能：原先 ``"".join(c for c in text if category(c) != "Mn")`` 逐字符遍历，
    2.5 MB 正文实测 **260 ms**，而文档里往往一个组合记号都没有，等于白扫一遍。
    改为"只对实际出现的非 ASCII 字符建表 + C 层 translate"后降到 ~34 ms，
    没有组合记号时直接跳过。
    """
    table = {ord(c): None for c in set(text)
             if ord(c) > 127 and unicodedata.category(c) == "Mn"}
    return text.translate(table) if table else text


def fold_text(text: str) -> str:
    """混淆还原：去零宽字符 -> NFKD 去组合记号（处理 A<隐藏记号>m<..>azon）->
    去变音符号 -> 同形字折叠。所有关键词匹配都应在折叠后的文本上进行。"""
    if not text:
        return ""
    text = _INVISIBLE_RE.sub("", text)
    if text.isascii():
        return text      # ASCII 下 NFKD / 去组合记号 / 同形字映射都是恒等变换
    text = unicodedata.normalize("NFKD", text)
    text = strip_combining(text)
    return text.translate(_HOMOGLYPH_MAP)


def has_invisible_obfuscation(text: str) -> bool:
    """零宽字符、U+036F 以上组合记号、数学字母数字符号、全角字母数字。"""
    if _INVISIBLE_RE.search(text):
        return True
    if _MATH_ALNUM_RE.search(text) or _FULLWIDTH_ALNUM_RE.search(text):
        return True
    if text.isascii():
        return False      # ASCII 里不存在组合记号
    # 只需在"出现过的字符种类"上判定，与逐字符扫描语义等价但快得多
    # （2.5 MB 正文实测 108 ms -> 约 24 ms，即一次 set() 的代价）
    return any(ord(c) > 0x36F and unicodedata.category(c) == "Mn" for c in set(text))


def parse_from_header(headers: dict[str, Any]) -> tuple[str, str, str]:
    """返回 (显示名, 完整地址, 发件域名)。"""
    value = headers.get("from")
    if isinstance(value, list):
        value = value[0] if value else ""
    value = str(value or "")
    m = _FROM_ADDR_RE.search(value)
    if m:
        name, addr = value[:m.start()], m.group(1)
    else:
        name, addr = value, value
    name = name.strip().strip('"').strip("'").strip()
    addr = addr.strip().lower()
    domain = addr.rsplit("@", 1)[-1].strip(">").strip() if "@" in addr else ""
    return name, addr, domain


def max_consonant_run(s: str) -> int:
    runs = _CONSONANT_RUN_RE.findall(s)
    return max((len(r) for r in runs), default=0)


def is_random_filename(stem: str) -> bool:
    """判断附件主文件名是否疑似随机生成（恶意载荷常见命名）。

    特征：长度 >=10、大小写混杂、含数字，且发音结构异常
    （元音占比 <30% 且无相邻元音，或存在 >=4 的连续辅音串）。
    正常命名如 ReportQ3Final2026（元音占比 0.33、含 readable 词根）不会命中。
    """
    if len(stem) < 10 or not any(c.isdigit() for c in stem):
        return False
    if not (any(c.islower() for c in stem) and any(c.isupper() for c in stem)):
        return False
    letters = [c.lower() for c in stem if c.isalpha()]
    if not letters:
        return False
    vowel_ratio = sum(c in _VOWELS for c in letters) / len(letters)
    adjacent_vowels = any(letters[i] in _VOWELS and letters[i + 1] in _VOWELS
                          for i in range(len(letters) - 1))
    return ((vowel_ratio < 0.30 and not adjacent_vowels)
            or max_consonant_run(stem) >= 4)


def registrable_domain(host: str) -> str:
    """取可注册域名（eTLD+1 的近似实现，无 PSL 依赖）。

    用于判断"发件域"与"链接域"是否属同一主体：mail.example.com 与 example.com
    同属 example.com，不应判为不一致；而 bizsupport.co 与 support.co 属不同主体。
    """
    labels = [x for x in fold_text(host or "").lower().strip(".").split(".") if x]
    if len(labels) < 2:
        return ""
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_lookalike_pair(a: str, b: str) -> bool:
    """判断两个可注册域名是否构成"标签内前后缀注入"仿冒配对。

    bizsupport.co 与 support.co   -> True（在标签内部插入前缀，同一主体不会这样互链）
    foo-example.com 与 example.com -> False（连字符分隔，属独立命名，误报风险高）
    mail.example.com 与 example.com -> 不会走到这里（可注册域已相同，先被排除）
    """
    if not a or not b or a == b:
        return False
    longer, shorter = (a, b) if len(a) >= len(b) else (b, a)
    if not longer.endswith(shorter):
        return False
    return longer[-len(shorter) - 1].isalnum()


def _upper_ratio(text: str) -> float:
    letters = [c for c in text if c.isalpha()]
    if not letters:
        return 0.0
    return sum(c.isupper() for c in letters) / len(letters)


def _fold_lower(text: str) -> str:
    return fold_text(text).lower()


def build_features(parsed: dict[str, Any], iocs: dict[str, Any],
                   auth: dict[str, Any]) -> dict[str, Any]:
    """构建规则引擎特征字典：mail / url / domain / attachment 四个作用域。"""
    headers = parsed.get("headers", {}) or {}
    attachments = parsed.get("attachments", [])
    urls = iocs.get("urls", [])
    domains = iocs.get("domains", [])

    from_name_raw, from_addr, from_domain = parse_from_header(headers)
    from_name = _fold_lower(from_name_raw)
    localpart = from_addr.split("@")[0] if "@" in from_addr else from_addr
    # 数字混淆折叠：paypa1 -> paypal（用于品牌仿冒检测）
    domain_leet = from_domain.translate(str.maketrans("01345", "olesa"))

    subject_raw = str(headers.get("subject", "") or "")
    subject = _fold_lower(subject_raw)
    body_text = parsed.get("body_text", "") or ""
    body_html = parsed.get("body_html", "") or ""
    # HTML 实体解码版正文：钓鱼会用 &#x90AE;&#x4EF6; 这类数字实体切散中文关键词
    # （URL 提取侧已在 ioc_extractor 做 unescape，此处补齐关键词匹配侧），body 仍
    # 保留原始 HTML 以便 raw_html 类规则继续工作。
    body_unescaped = html.unescape(body_html) if "&" in body_html else body_html
    body = _fold_lower(body_text + "\n" + body_html + "\n" + body_unescaped)
    text = subject + "\n" + body

    brands = load_brand_set()  # 延迟导入避免循环
    brandless_domains = [d for d in domains if not any(b in d for b in brands)]

    # HTML 隐藏文字（hidden text salting）：取出隐藏文本，并判断"品牌错位"
    # —— 隐藏文本里有品牌、收件人可见的正文里没有，这正是 Talos 记录的品牌提取规避。
    hidden_text = hidden_html_text(body_html)
    visible_text = _fold_lower(
        body_text + "\n" + _TAG_STRIP_RE.sub(" ", strip_hidden_html(body_html)))
    hidden_text_folded = _fold_lower(hidden_text)
    hidden_brand_mismatch = bool(
        hidden_text_folded and any(b in hidden_text_folded for b in brands)
        and not any(b in visible_text for b in brands))

    # 链接域 vs 发件域：钓鱼常把链接域做成发件域的"标签内注入"（bizsupport.co -> support.co），
    # 或直接跳到与发件方无关的域名。可注册域相同（mail.example.com 与 example.com）不算不一致；
    # 已由 url_shortener 计分的短链、以及已知合法的第三方服务域由白名单排除，避免重复计分/误报。
    from_reg = registrable_domain(from_domain)
    allowlist = load_link_allowlist()
    link_regs: list[str] = []
    for u in urls:
        m = _URL_HOST_RE.match(u.lower())
        reg = registrable_domain(m.group(1).strip(".") if m else "")
        if reg and reg not in link_regs:
            link_regs.append(reg)
    link_domain_lookalike = ""
    link_domain_mismatch = ""
    for reg in link_regs:
        if not from_reg or reg == from_reg or reg in allowlist:
            continue
        if is_lookalike_pair(reg, from_reg):
            link_domain_lookalike = link_domain_lookalike or f"{reg} ←→ {from_reg}"
        elif not link_domain_mismatch:
            link_domain_mismatch = f"{reg}（发件域 {from_reg}）"

    mail = {
        "subject": subject,
        "subject_raw": subject_raw,
        "subject_letter_count": sum(c.isalpha() for c in subject_raw),
        "subject_upper_ratio": _upper_ratio(subject_raw),
        "body": body,
        "raw_html": body_html,
        "text": text,
        "body_text_length": len(body_text.strip()),
        "url_count": len(urls),
        "attachment_count": len(attachments),
        "image_count": sum(1 for a in attachments if a["content_type"].startswith("image/")),
        "domain_count": len(domains),
        "brandless_domain_count": len(brandless_domains),
        # HTML 隐藏文字（hidden text salting）：字数与"品牌错位"供规则判定
        "hidden_html_text": hidden_text,
        "hidden_html_text_len": len(hidden_text),
        "hidden_html_brand_mismatch": hidden_brand_mismatch,
        "html_comment_split_base64": has_comment_split_base64(body_html),
        # 链接域与发件域的对应关系（由 link_rules.yaml 计分，空串表示无异常）
        "link_domains": link_regs,
        "link_domain_lookalike": link_domain_lookalike,
        "link_domain_mismatch": link_domain_mismatch,
        # 嵌套结构：字段路径 from.domain / auth.spf / reply_to.domain 由此解析
        "from": {
            "display_name": from_name,
            "display_name_raw": from_name_raw,
            "display_letter_count": sum(c.isalpha() for c in from_name_raw),
            "display_upper_ratio": _upper_ratio(from_name_raw),
            "display_word_count": len(from_name_raw.split()),
            "domain": from_domain,
            "localpart": localpart,
            "domain_leet": domain_leet,
            "raw": str(headers.get("from", "") or ""),
        },
        "reply_to": {"domain": (auth.get("reply_to_domain") or "").lower()},
        "return_path": {"domain": (auth.get("return_path_domain") or "").lower()},
        "auth": {
            "spf": auth.get("spf") or "",
            "dkim": auth.get("dkim") or "",
            "dmarc": auth.get("dmarc") or "",
            "has_auth_header": bool(auth.get("has_auth_header")),
            "reply_to_aligned": bool(auth.get("reply_to_aligned", True)),
            "return_path_aligned": bool(auth.get("return_path_aligned", True)),
            "dmarc_without_mechanism": bool(auth.get("dmarc_without_mechanism", False)),
        },
    }

    url_items = []
    for u in urls:
        m = _URL_HOST_RE.match(u.lower())
        host = m.group(1).strip(".") if m else ""
        labels = host.split(".") if host else []
        # 层级计数忽略开头的 www：www 不携带任何异常信号，算进去会让
        # www.<dept>.<uni>.edu 这类正常地址被判成"子域名层级异常"。
        # 回归背景：还原混淆 URL 后 Enron ham 首次能提取到 URL，
        # url_many_subdomains 立刻在 www.ssc.upenn.edu 这类正常链接上误报。
        depth_labels = labels[1:] if labels[:1] == ["www"] else labels
        url_items.append({
            "url": u,
            "host": host,
            "tld": labels[-1] if labels else "",
            "label_count": len(depth_labels),
        })

    att_items = []
    for att in attachments:
        original_name = att["filename"]
        att_items.append({
            "filename": original_name,
            "filename_lower": original_name.lower(),
            "stem": original_name.rsplit(".", 1)[0],
            "extension": att["extension"],
            "content_type": att["content_type"],
            "size": att["size"],
        })

    return {
        "mail": mail,
        "url": url_items,
        "domain": [{"domain": d} for d in domains],
        "attachment": att_items,
    }

_BRAND_SET_CACHE: set[str] | None = None
_LINK_ALLOWLIST_CACHE: set[str] | None = None


def load_brand_set() -> set[str]:
    """品牌字典（供特征计算使用），从规则目录加载并缓存。"""
    global _BRAND_SET_CACHE
    if _BRAND_SET_CACHE is None:
        from app.scoring.rule_loader import get_rule_engine
        _BRAND_SET_CACHE = {v.lower() for v in get_rule_engine().dicts.get("brands", [])}
    return _BRAND_SET_CACHE


def load_link_allowlist() -> set[str]:
    """链接域白名单（正常邮件常链接的第三方服务域），从规则目录加载并缓存。"""
    global _LINK_ALLOWLIST_CACHE
    if _LINK_ALLOWLIST_CACHE is None:
        from app.scoring.rule_loader import get_rule_engine
        _LINK_ALLOWLIST_CACHE = {v.lower() for v in get_rule_engine().dicts.get("link_allowlist", [])}
    return _LINK_ALLOWLIST_CACHE


def reset_feature_caches() -> None:
    global _BRAND_SET_CACHE, _LINK_ALLOWLIST_CACHE
    _BRAND_SET_CACHE = None
    _LINK_ALLOWLIST_CACHE = None
