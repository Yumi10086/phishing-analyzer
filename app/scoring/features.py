"""特征工程层：从解析结果构建规则引擎可用的特征字典。

设计原则：特征在代码里（fold、解析、计数、比率），策略在 YAML 里（规则/分值）。
所有文本特征默认经过 fold_text() 混淆还原，规则匹配在折叠后的文本上进行。
"""
from __future__ import annotations

import html
import os
import re
import unicodedata
from typing import Any

from app.attachment.detector import (
    BIDI_CONTROLS,
    extension_type_mismatch,
    generic_mime_known_ext,
    max_space_run,
    mime_type_conflict,
)

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
_STYLE_BLOCK_RE = re.compile(r"<(style|script)\b[^>]*>.*?</(style|script)>", re.IGNORECASE | re.DOTALL)
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

# 平台类品牌与其"引用语境"提示语（2026-09 规则语义审查，Xmind 欢迎邮件实证）。
# 真实邮箱 28 次"正文冒充品牌"里 25 次是这类引用：页脚"微信:扫描左侧二维码 微博:
# http://weibo.com/xxx"（Oray）、收据"支付方式: 微信支付"（Steam）、
# "关注我们的微信公众号/微博"（Xmind）。平台名在正常邮件里被引用得太频繁，单凭
# "正文出现平台名"不构成"冒充该平台"；钓鱼冒充平台时的写法是"您的微信账户…"/"微信安全中心"，
# 命中的平台名附近没有这类引用提示语，仍会计分（datacon 中文钓鱼的 微信/支付宝 命中保留）。
_SOCIAL_PLATFORM_BRANDS = frozenset({
    "微信", "微信支付", "微博", "支付宝", "知乎", "抖音", "小红书", "朋友圈",
    "wechat", "weixin", "weibo", "alipay", "zhihu", "instagram", "facebook",
    "twitter", "linkedin", "youtube", "tiktok", "whatsapp",
})
_SOCIAL_REFERENCE_CUES = frozenset({
    # 社交页脚 / 关注我们
    "关注我们", "公众号", "微信号", "扫码", "二维码", "扫描", "订阅号", "服务号",
    "官方微博", "微博:", "微信:", "follow us", "find us on", "official account",
    # 收据里的付款方式
    "支付方式", "付款方式", "支付渠道", "payment method", "paid with",
})
_SOCIAL_REF_WINDOW = 60

_FROM_ADDR_RE = re.compile(r"<([^>]+)>")
_URL_HOST_RE = re.compile(r"^[a-z]+://([^/:?#]+)")
# 资源引用：img/script/iframe 等的 src、background 属性、CSS url()。用 ASCII 字符类
# 划界，避免把 CJK 当分隔符。
_ASSET_URL_RE = re.compile(
    r"""(?:src|background)\s*=\s*["']?([^"'\s>]+)|url\(\s*["']?([^"')\s]+)""",
    re.IGNORECASE)

# 主流 ccTLD 的二级注册结构：用于把 eTLD+1 判定从"最后两段"修正为三段
_TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "net.uk", "sch.uk",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "com.br", "net.br", "org.br", "com.au", "net.au", "org.au", "edu.au",
    "co.nz", "net.nz", "org.nz", "co.za", "org.za",
    # 中文域名：漏了 edu.cn/ac.cn 会让 www.tsinghua.edu.cn 的可注册域被算成
    # "edu.cn"，与发件域比对必然"不一致"（trec06c 正常邮件误报实证）
    "com.cn", "net.cn", "edu.cn", "org.cn", "gov.cn", "ac.cn", "mil.cn",
    "com.tw", "com.hk", "org.hk", "edu.hk", "gov.hk", "idv.hk",
    "co.kr", "or.kr", "com.mx",
    "com.ar", "com.tr", "com.sg", "com.my", "co.in", "net.in", "org.in",
    "com.pl", "com.ua", "co.id", "com.vn", "com.ph", "com.co", "com.pe",
}


def has_double_extension(filename: str) -> bool:
    """双扩展名伪装判定：**末段扩展名是可执行/脚本类**，且文件名前面还有别的扩展名段。

    原先的规则是"文件名里有两个点"（正则 ``\\..+\\.``），在真实语料上误报严重：
      - QQ 附件重命名产物 ``D531AA5F@ED440C33.898B3D67.jpg``（多段随机名）；
      - 中文常见命名 ``简历.最终版.pdf``、``2024.09 报表.xlsx``（点当分隔符用）。
    这两类都跟"伪装"无关。真正的双扩展名伪装（``发票.pdf.exe``）特征是**末段是
    可执行/脚本类**——用户看到的是前一个扩展名（.pdf），双击执行的却是最后一个。

    取舍：``evil.exe.pdf``（危险扩展名在前、安全在后）不再命中。该形态极少见，
    且真把 exe 改名成 pdf 时，``att_type_mismatch``（声明/扩展名/magic 三方核对）
    会独立抓到，不靠这条规则兜底。
    """
    if not filename:
        return False
    parts = filename.lower().strip().split(".")
    if len(parts) < 3:                     # 至少 名字.伪装扩展名.真实扩展名
        return False
    return parts[-1] in load_risk_extensions()


def load_risk_extensions() -> set[str]:
    """可执行/脚本类扩展名（高危 + 中危档），按规则版本缓存。"""
    global _RISK_EXT_CACHE
    entries = _dict_entries("ext_high_risk") + _dict_entries("ext_medium_risk")
    if _RISK_EXT_CACHE is None:
        _RISK_EXT_CACHE = {v.lower() for v in entries}
    return _RISK_EXT_CACHE


# 码值：4-10 位字母数字、且至少含一个数字（"050200" / "897873" / Steam 令牌 "xg9gk"）。
# 边界必须写成 [A-Za-z0-9]，**不能用 \w**：Python 的 \w 含中日韩文字，`(?![\w])` 会在
# "您好,897873是您绑定帐号的验证码"上失败（数字后紧跟汉字），实测把 13 封本可豁免的
# 正常验证码通知全部变成"未豁免"。
_OTP_CODE_RE = re.compile(r"(?<![A-Za-z0-9])(?=[A-Za-z0-9]{4,10}(?![A-Za-z0-9]))[A-Za-z0-9]*\d[A-Za-z0-9]*")
# 码值与条款必须出现在验证码关键词附近（窗口 ±80 字符），否则"正文别处有个数字"
# 也会凑成豁免——豁免放宽的是"验证码话术"这条 5 分规则，不能变成任意含数字即可
_OTP_WINDOW = 80


def find_otp_notice(text: str, otp_words: list[str] | None = None,
                    clause_words: list[str] | None = None) -> str:
    """判定"通知式验证码投递"：**给出码值 + 附带有效期/防泄露/忽略条款**。

    背景（QQ 邮箱 54 封真实邮件实测）：合法通知（余额/验证码/账户变更）天然含
    account/verify/验证码/账户 这些词，`body_otp`(5) 与 `body_credentials`(7) 因此在
    真实验证码投递上误报。而"告知"与"索取"的区别不能只看祈使句——真实验证码通知也会写
    "请您在 5 分钟内完成验证"，钓鱼也会写"您的验证码是"。可靠的区别是：**真投递必然
    给出码值，并说明有效期或"请勿泄露/如非本人操作请忽略"**；只提"验证码"三字却要求
    点击/回填的才是话术诱饵。

    返回命中的关键词（供报告展示与调试），未命中返回空串。
    """
    if not text:
        return ""
    otp_words = otp_words if otp_words is not None else load_otp_keywords()
    clause_words = clause_words if clause_words is not None else load_otp_notice_clauses()
    if not otp_words or not clause_words:
        return ""
    low = text.lower()
    for word in otp_words:
        if not word or word not in low:
            continue
        start = 0
        while True:
            i = low.find(word, start)
            if i < 0:
                break
            start = i + len(word)
            window = low[max(0, i - _OTP_WINDOW): i + len(word) + _OTP_WINDOW]
            if not _OTP_CODE_RE.search(window):
                continue
            if any(c in window for c in clause_words):
                return word
    return ""


def load_otp_keywords() -> list[str]:
    """验证码话术词表（字典 otp_keywords），按规则版本缓存。"""
    global _OTP_KEYWORDS_CACHE
    entries = _dict_entries("otp_keywords")
    if _OTP_KEYWORDS_CACHE is None:
        _OTP_KEYWORDS_CACHE = [v.lower() for v in entries]
    return _OTP_KEYWORDS_CACHE


def load_otp_notice_clauses() -> list[str]:
    """验证码投递的"有效期/防泄露/忽略"条款词表，按规则版本缓存。"""
    global _OTP_CLAUSES_CACHE
    entries = _dict_entries("otp_notice_clauses")
    if _OTP_CLAUSES_CACHE is None:
        _OTP_CLAUSES_CACHE = [v.lower() for v in entries]
    return _OTP_CLAUSES_CACHE


def _env_on(name: str, default: str = "1") -> bool:
    """读取布尔型环境开关（"0"/"false"/"no"/空 视为关闭）。"""
    return os.environ.get(name, default).strip().lower() not in ("0", "false", "no", "")


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

    只对纯 ASCII 的 stem 生效：中文等非拉丁字符的 isalpha() 为 True，却不参与
    元音结构——混入后 vowel_ratio 被压到接近 0，"Python（3月份）学习通知.docx"
    这类正常中文文件名会被误判为随机名（真实误报：报告 567a83ac64ab4000，
    vowel_ratio=1/12、max_consonant_run=4 双双误命中）。随机载荷命名是纯
    ASCII 乱串，该放宽不会漏掉目标形态。
    """
    if len(stem) < 10 or not any(c.isdigit() for c in stem):
        return False
    if not stem.isascii():
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


def _is_platform_reference(text: str, spans: list[tuple[int, int]]) -> bool:
    """平台名是否只出现在**引用语境**里（"关注我们的微信公众号"、"支付方式: 微信支付"）。

    平台类品牌（微信/微博/支付宝/知乎/抖音…）在正常邮件里被引用得非常频繁——页脚写
    "关注我们的微信公众号 X"、收据写"支付方式: 微信支付"——这都不是"冒充该平台"。
    判定要求**每一处命中**都在引用提示语附近（±_SOCIAL_REF_WINDOW 字符）；只要有一处
    出现在别处（"您的微信账户已被限制"），就仍按品牌提及计。
    """
    for start, end in spans:
        window = text[max(0, start - _SOCIAL_REF_WINDOW): end + _SOCIAL_REF_WINDOW]
        if not any(c in window for c in _SOCIAL_REFERENCE_CUES):
            return False
    return bool(spans)


def find_brand_mentions(text: str, brands: set[str] | None = None) -> list[str]:
    """在文本中找品牌提及，带边界判定。

    朴素的 ``b in text`` 子串匹配在真实语料上会误命中（trec06c 中文正常邮件实证）：
      - ``shinapple``（新闻组发信人 ID）里命中 ``apple``；
      - ``北京东四十条``（北京地址）里命中 ``京东``，``东京都`` 里也会命中 ``京东``。
    两类误命中会直接喂给 body_brand_spoof / hidden_html_brand_mismatch，
    造成"正文冒充品牌"的假信号。因此：
      - ASCII 品牌词：要求两侧不是字母/数字（``apple.com``、``Apple 账户`` 仍命中）；
      - 中文品牌词：无词边界可用，改用 brand_shadow.txt 的"同形上下文"清单，
        命中位置若与某个同形串重叠则丢弃；
      - 平台类品牌（微信/微博/支付宝…）：再用"引用语境"过滤，见 _is_platform_reference
        （"关注我们的微信公众号"、"支付方式: 微信支付"是引用，不是冒充该平台）。
    """
    if not text:
        return []
    brands = brands if brands is not None else load_brand_set()
    shadows = load_brand_shadows()
    hits: list[str] = []
    for b in brands:
        if "." in b:
            # 带点词条是"域名形式"（qq.com / cmbchina.com）：它们只服务**域侧**判定
            # （is_brand_domain 的带点分支、brandless_domains），不该参与正文文本匹配。
            # 正文里出现 "qq.com" 通常就是收件人自己的地址或一个 URL——把它当成"正文冒充品牌"
            # 毫无证据价值。实测：452 封真实邮件的正文里 109 封会命中，绝大多数是用户自己的
            # 收件地址（yumi0030@qq.com）被读成"冒充腾讯"（一封 Google 验证码邮件因此判 56 分 MALICIOUS）。
            continue
        if b.isascii():
            # ASCII 品牌词：大小写不敏感 + 词边界（调用方通常已折叠，这里再兜一层）
            spans = [m.span() for m in _ascii_brand_pattern(b).finditer(text)]
            if not spans:
                continue
            if b in _SOCIAL_PLATFORM_BRANDS and _is_platform_reference(text, spans):
                continue
            hits.append(b)
            continue
        spans = [m.span() for m in re.finditer(re.escape(b), text)]
        if not spans:
            continue
        if b in shadows:
            # 同形上下文与命中位置重叠则视为误命中
            shadow_pat = _shadow_pattern(b, shadows[b])
            overlapping = set()
            for sm in shadow_pat.finditer(text):
                for sp in spans:
                    if sm.start() < sp[1] and sp[0] < sm.end():
                        overlapping.add(sp)
            if all(sp in overlapping for sp in spans):
                continue
        if b in _SOCIAL_PLATFORM_BRANDS and _is_platform_reference(text, spans):
            continue
        hits.append(b)
    return hits


def _ascii_brand_pattern(brand: str) -> re.Pattern[str]:
    """ASCII 品牌词的词边界正则（缓存）。大小写不敏感：调用方给的文本通常已折叠，
    但该函数也允许直接对原文调用（如显示名）。"""
    pat = _ASCII_BRAND_PATTERNS.get(brand)
    if pat is None:
        pat = re.compile(r"(?<![a-z0-9])" + re.escape(brand) + r"(?![a-z0-9])", re.IGNORECASE)
        _ASCII_BRAND_PATTERNS[brand] = pat
    return pat


def _shadow_pattern(brand: str, contexts: list[str]) -> re.Pattern[str]:
    pat = _SHADOW_PATTERNS.get(brand)
    if pat is None:
        pat = re.compile("|".join(re.escape(s) for s in contexts))
        _SHADOW_PATTERNS[brand] = pat
    return pat


def load_brand_shadows() -> dict[str, list[str]]:
    """品牌同形上下文清单（``品牌=同形串``），按规则版本缓存。"""
    global _BRAND_SHADOW_CACHE
    _dict_entries("brands")  # 触发版本号比对，字典改写后缓存随之失效
    if _BRAND_SHADOW_CACHE is None:
        from app.config import RULES_DIR

        table: dict[str, list[str]] = {}
        path = RULES_DIR / "dicts" / "brand_shadow.txt"
        if path.is_file():
            for line in path.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                brand, _, ctx = line.partition("=")
                brand, ctx = fold_text(brand.strip()).lower(), fold_text(ctx.strip()).lower()
                if brand and ctx:
                    table.setdefault(brand, []).append(ctx)
        _BRAND_SHADOW_CACHE = table
    return _BRAND_SHADOW_CACHE


def is_same_owner(a: str, b: str) -> bool:
    """两个可注册域是否同一主体：**首标签完全相同**。

    实测动机（QQ 邮箱真实邮件）：残留的"链接域与发件域不一致"里绝大多数是同一家公司
    自有域之间的互链——``apple.com.cn`` ↔ ``apple.com``、``oray.com`` ↔ ``oray.com.cn``、
    ``jd100.cn`` ↔ ``jd100.com``，它们的首标签完全相同（apple/apple、oray/oray、
    jd100/jd100），属同一主体，不该按"跳到无关域名"计分。

    刻意只认同词首标签，**不做品牌词包含判断**：后者会把 ``paypal-secure.top`` ↔
    ``paypal.com`` 这类"品牌词 + 后缀"的仿冒域判成同一主体（首标签含品牌词但不等），
    恰好放行该抓的形态——这一点在实现后自测中发现并修正，故写死为相等判定。

    已知边界与代价：
      - 覆盖不到跨品牌自有域（``riotgames.com`` ↔ ``leagueoflegends.com``、
        ``etrack01.com`` ↔ ``bilibili.com``），它们只能靠白名单或发件方上下文；
      - 同名不同主体（``nova.com`` ↔ ``nova.co``）会被当作同一主体放行——这是 4 分弱
        信号的精度换稳定性的取舍，仿冒形态仍由 link_domain_lookalike 独立兜底。
    """
    if not a or not b:
        return False
    return a.split(".")[0] == b.split(".")[0]


def is_brand_domain(host: str, brands: set[str] | None = None) -> bool:
    """发件域是否"**就是品牌自己的域**"——先折叠到可注册域，再按**标签**比对。

    **先折叠再比对**是关键（实现后自测发现）：``apple.com.evil.top`` 的标签里含
    ``apple``，但它的可注册域是 ``evil.top``，必须判 False —— 否则"品牌词塞进子域"
    的显式冒充反而拿到免检。函数自己折叠，调用方传原始主机即可，不依赖调用方先算。

    判定两条：
      ① 可注册域的任一**标签恰好等于**品牌词：``apple.com`` / ``apple.com.cn`` → apple；
      ② 可注册域等于"带点词条"或为其子域：``qq.com`` 这类带点词条是早先特地为
         "腾讯官方邮箱的域排除"加的（中英异名品牌 —— 显示名写"腾讯企业微信"而域名是
         ``qq.com`` —— 靠标签比对兜不住，只能靠带点词条）。

    为什么必须是标签级而不是子串：``from_display_brand_spoof`` 的排除原写作
    ``from.domain contains_any @dict:brands``（子串），于是
      - ``apple.com.evil.top``（品牌词塞进子域）被放行 —— 显式冒充反而免检；
      - ``pontosliveloacumulados.com.br`` 冒充 Bradesco 被放行 —— 域名里含**另一个**
        品牌词 ``livelo`` 就整体豁免（pot 实测 1 例真实漏判）；
      - ``myapple.com`` 这类"名字里带 apple 但不是 Apple"的域也拿到免检。
    """
    if not host:
        return False
    brands = brands if brands is not None else load_brand_set()
    registrable = registrable_domain(host) or host.lower()
    labels = registrable.split(".")
    label_brands = {b for b in brands if "." not in b}
    if any(l in label_brands for l in labels):
        return True
    dotted = [b for b in brands if "." in b]
    return any(registrable == b or registrable.endswith("." + b) for b in dotted)


def host_is_freemail(host: str, freemail: set[str] | None = None) -> bool:
    """host 是否属免费邮箱域（**子域折叠到可注册域**后比较）。

    原先 ``sender_from_freemail`` / ``reply_to_freemail`` 用 ``equals_any`` 直接比原始主机，
    于是 ``mail.qq.com`` / ``email.163.com`` / ``mail.gmail.com`` 一律漏判（只有裸域
    ``qq.com`` 命中）。同一批规则里 ``sender_esp_domain`` 用的是
    ``cand == e or cand.endswith("." + e)``（正确），三种口径并存本身就是缺陷。
    这些子域实践上由服务商自己使用，实测三份语料 0 例，故影响小；改它是为了口径统一。
    """
    if not host:
        return False
    freemail = freemail if freemail is not None else load_freemail_domains()
    reg = registrable_domain(host) or host.lower()
    return any(reg == e or reg.endswith("." + e) for e in freemail)


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


def _url_host(url: str) -> str:
    """URL 的主机名（小写、去首尾点）；解析不出返回空串。"""
    m = _URL_HOST_RE.match((url or "").lower())
    return m.group(1).strip(".") if m else ""


def _asset_urls_in(body_html: str) -> set[str]:
    """HTML 里出现过的**资源 URL 串**（<img src>、CSS url()、background），归一化后返回。

    用途见 build_features 里链接域的判定。**按 URL 串而非按主机**收敛：同一主机
    既可能是资源又可能是点击目标（pot sample-1035：bsq2.firiri.shop 的 href 与
    src 路径不同），按主机会把整域误判为资源、连带丢掉真实的"链接域不一致"
    （实测按主机过滤时 pot 的 MALICIOUS 从 237 掉到 199，按 URL 串只掉到 229）。
    """
    if not body_html:
        return set()
    out: set[str] = set()
    for m in _ASSET_URL_RE.finditer(body_html):
        raw = html.unescape(m.group(1) or m.group(2) or "")
        if raw:
            out.add(_norm_url(raw))
    return out


def _norm_url(url: str) -> str:
    """URL 归一化（仅用于资源/链接的同一性比对）：小写 + 去尾随标点与斜杠。"""
    return (url or "").strip().rstrip(".,;:!?)）】").rstrip("/").lower()


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
    # OCR 回收的图内文字已由 analyzer 并入 body_text（且先于 IOC 提取，图内
    # URL/域名可进情报链路），此处不再重复处理
    body_html = parsed.get("body_html", "") or ""
    # HTML 实体解码版正文：钓鱼会用 &#x90AE;&#x4EF6; 这类数字实体切散中文关键词
    # （URL 提取侧已在 ioc_extractor 做 unescape，此处补齐关键词匹配侧），body 仍
    # 保留原始 HTML 以便 raw_html 类规则继续工作。
    body_unescaped = html.unescape(body_html) if "&" in body_html else body_html
    body = _fold_lower(body_text + "\n" + body_html + "\n" + body_unescaped)
    text = subject + "\n" + body

    brands = load_brand_set()  # 延迟导入避免循环
    # brandless_domains（"链接指向的其他域名"）在下面算出 link_regs 之后再统计——
    # 口径必须是"可点击、非白名单、非发件方自有"，见该处注释。

    # HTML 隐藏文字（hidden text salting）：取出隐藏文本，并判断"品牌错位"
    # —— 隐藏文本里有品牌、收件人可见的正文里没有，这正是 Talos 记录的品牌提取规避。
    hidden_text = hidden_html_text(body_html)
    # 可见文本额外剔除 <style>/<script> 块：CSS 里的 font-family: 'Microsoft
    # YaHei' 会让品牌匹配把所有正常中文邮件判成"冒充 microsoft"（trec06c 与
    # 校院样本双重实证）。标签内联样式随 _TAG_STRIP_RE 一并去除。
    visible_html = _STYLE_BLOCK_RE.sub(" ", strip_hidden_html(body_html))
    visible_text = _fold_lower(
        body_text + "\n" + _TAG_STRIP_RE.sub(" ", visible_html))
    hidden_text_folded = _fold_lower(hidden_text)
    # 品牌提及一律走边界判定（子串匹配会把 shinapple 认成 apple、北京东四十条认成京东）
    visible_brand_hits = find_brand_mentions(visible_text, brands)
    hidden_brand_mismatch = bool(
        hidden_text_folded and find_brand_mentions(hidden_text_folded, brands)
        and not visible_brand_hits)

    # 链接域 vs 发件域：钓鱼常把链接域做成发件域的"标签内注入"（bizsupport.co -> support.co），
    # 或直接跳到与发件方无关的域名。可注册域相同（mail.example.com 与 example.com）不算不一致；
    # 已由 url_shortener 计分的短链、以及已知合法的第三方服务域由白名单排除，避免重复计分/误报。
    # 邮件列表豁免：列表邮件 From 是发帖人、链接指向列表站或被转载站点，
    # 域不一致是列表的正常形态（trec06c 中文正常邮件误报实证）。
    # 关键细节：List-Unsubscribe 是营销邮件与钓鱼邮件都会照抄的头部，只有 list-id/
    # list-post 才是列表软件（Mailman/Groups.io 等）写入的。实测宽口径（认 List-
    # Unsubscribe）零误报收益却损失 pot 召回，故默认关闭；需要时用
    # LINK_EXEMPT_LISTMAIL=1（宽）/ strict（仅 list-id|list-post）逐项实测。
    _list_mode = os.environ.get("LINK_EXEMPT_LISTMAIL", "0").strip().lower()
    _is_list_mail = False
    if _list_mode in ("1", "true", "all"):
        _is_list_mail = any(headers.get(k) for k in ("list-unsubscribe", "list-id", "list-post"))
    elif _list_mode == "strict":
        _is_list_mail = any(headers.get(k) for k in ("list-id", "list-post"))
    from_reg = registrable_domain(from_domain)
    # 免费邮箱豁免：免费邮箱发件人本就不拥有可比对的域名。实测在 trec06c 中文正常邮件上
    # 只多压掉 1 封误报，却让 pot 贴线钓鱼从"可疑"落到"未拦截"，代价大于收益，
    # 故默认关闭（LINK_EXEMPT_FREEMAIL=1 可开启做语料回归对照）。
    _from_is_freemail = (_env_on("LINK_EXEMPT_FREEMAIL", "0")
                         and bool(from_reg) and from_reg in load_freemail_domains())
    allowlist = load_link_allowlist()
    # 链接域只看"收件人会被引导点过去的目标"：正文里的图片/内容资源（<img src>、CSS
    # url()）与发件域不一致是邮件模板的正常形态，不是"跳到无关域名"。实测真实邮箱
    # 339 次"链接域不一致"里约 210 次是资源域（steamstatic.com 117、epsilon.com 63、
    # aliyuncs.com、sfmc-content.com、google-analytics.com…），而钓鱼侧的链接是
    # href。**按 URL 串判资源**，不是按主机（同主机可能既作资源又作点击目标）。
    asset_urls = _asset_urls_in(body_html)
    clickable_regs: set[str] = set()
    for u in urls:
        if _norm_url(u) in asset_urls:
            continue  # 该 URL 只以资源形式出现
        clickable_regs.add(registrable_domain(_url_host(u)))
    link_regs: list[str] = []
    for u in urls:
        reg = registrable_domain(_url_host(u))
        if reg and reg not in link_regs and reg in clickable_regs:
            link_regs.append(reg)
    # 用户内容托管平台上的**点击目标**：主机是平台的子域/桶（非 apex）、与发件方无关、
    # 且不是资源引用（<img src> 在 CDN 上是正常形态）。钓鱼站常寄居在免费建站与对象存储上
    # （`protonmail-6e3725.webflow.io`、`xxx.cdn.digitaloceanspaces.com`），而正常邮件
    # 的点击目标很少落在"陌生人可自由创建的站点"上——实测邮箱 0.8% / pot 2.6% / datacon 0%。
    user_content_link = ""
    _user_content = load_user_content_hosting()
    if _user_content:
        for u in urls:
            if _norm_url(u) in asset_urls:
                continue
            host = _url_host(u)
            reg = registrable_domain(host)
            if not host or not reg or reg not in _user_content:
                continue
            if host == reg or host == "www." + reg:
                continue           # 平台自己的主页不算"托管在平台上的内容"
            if from_reg and reg == from_reg:
                continue           # 发件方自有平台域（如 AWS 自己发的通知）
            user_content_link = f"{host}（{reg}）"
            break
    link_domain_lookalike = ""
    link_domain_mismatch = ""
    for reg in link_regs:
        if not from_reg or reg == from_reg or reg in allowlist:
            continue
        if is_lookalike_pair(reg, from_reg):
            # 同形/仿冒域即使出现在列表邮件里也是钓鱼信号，不豁免
            link_domain_lookalike = link_domain_lookalike or f"{reg} ←→ {from_reg}"
        elif is_same_owner(reg, from_reg):
            continue  # 同一主体的自有域互链（apple.com.cn ↔ apple.com），不计不一致
        elif _is_list_mail or _from_is_freemail:
            continue  # 列表邮件 / 免费邮箱发件：普通链接域差异属正常行为，不计
        elif not link_domain_mismatch:
            link_domain_mismatch = f"{reg}（发件域 {from_reg}）"

    # "链接指向其他域名"（body_brand_spoof 的第二个条件）排除**白名单里的基础设施域**
    # （ESP 追踪域、图片/内容 CDN、结构性元数据域）。此前统计"全部 IOC 域里不含品牌词的"，
    # 于是 sctrack.sendcloud.net（ESP）、s3.cn-north-1.amazonaws.com.cn（图片 CDN）都算作
    # "其他域名"。注意 domains 是**主机名**、白名单是**可注册域**，比较前要归一。
    # **刻意不排除发件方自有域**：攻击者用自己域名发信、正文提品牌正是最常见的钓鱼形态
    # （护栏测试 test_third_party_sender_impersonating_brand_still_fires 锁定）。
    brandless_domains = [d for d in domains
                         if registrable_domain(d) not in allowlist
                         and not any(b in d for b in brands)]

    # 营销/批量发送特征（类别标签层的营销证据，信息性；规则侧各仅计 1 分）。
    # 注意这些特征单独存在都易伪造，只在组合达标（>=2 项）时才参与类别判定。
    esp_domains = load_esp_domains()
    esp_domain = ""
    precedence_value = headers.get("precedence")
    if isinstance(precedence_value, list):
        precedence_value = precedence_value[0] if precedence_value else ""
    for cand in (from_domain, (auth.get("return_path_domain") or "").lower()):
        if not cand:
            continue
        hit = next((e for e in esp_domains if cand == e or cand.endswith("." + e)), "")
        if hit:
            esp_domain = hit
            break
    has_unsub_text = any(t in body for t in ("unsubscribe", "退订", "取消订阅", "取消訂閱"))
    xmailer_value = headers.get("x-mailer")
    if isinstance(xmailer_value, list):
        xmailer_value = xmailer_value[0] if xmailer_value else ""

    _inline_image_count = len(parsed.get("_inline_images") or [])
    # 信封发件域 vs From 域：均有值且不一致才算（单标签脱敏域与真实域比较时
    # 以"不一致"处理——脱敏语料里 From 域是 token，与真实信封域必然不同）
    _smtp_domain = (auth.get("smtp_mail_domain") or "").lower()
    _from_reg = registrable_domain(from_domain) or (from_domain or "").lower()
    _smtp_reg = registrable_domain(_smtp_domain) or _smtp_domain
    _smtp_mail_mismatch = bool(_smtp_domain and _from_reg and _smtp_reg
                               and _smtp_reg != _from_reg)
    _image_count = (sum(1 for a in attachments if a["content_type"].startswith("image/")
                        or a.get("real_type") in ("jpeg", "png", "gif"))
                    + _inline_image_count)
    mail = {
        "subject": subject,
        "subject_raw": subject_raw,
        "subject_letter_count": sum(c.isalpha() for c in subject_raw),
        "subject_upper_ratio": _upper_ratio(subject_raw),
        "body": body,
        "raw_html": body_html,
        "text": text,
        # 去除 style/script 后的可见文本：品牌冒充类规则匹配用，防 CSS 字体名误报
        "visible_text": visible_text,
        # 可见文本中的品牌提及（边界判定后），body_brand_spoof 等规则用
        "text_brand_hits": ",".join(visible_brand_hits),
        # 通知式验证码投递（给出码值 + 有效期/防泄露条款）：body_otp 与 body_credentials
        # 据此豁免——真投递既不是"验证码话术诱饵"也不是"凭证索取"（见函数注释）
        "otp_notice": find_otp_notice(visible_text),
        "body_text_length": len(body_text.strip()),
        "url_count": len(urls),
        "attachment_count": len(attachments),
        # 图片计数：附件（声明 image/* 或 real_type 嗅探为图片，钓鱼常给图片标
        # octet-stream，报告 8f7a759ca71d4575 实测）+ 内嵌 CID 图（此前直接被丢弃）
        "image_count": _image_count,
        # 纯图正文：图（附件图+内嵌图）存在且占全部附件（正文文字在图内是钓鱼的
        # 标准规避手法——正文无文字无链接，image_heavy_body 因 url>0 不触发）
        "image_only_attachments": 0 < _image_count == len(attachments) + _inline_image_count,
        # 信封发件人（Authentication-Results 的 smtp.mail）与 From 域不一致：
        # 报告 36fab11b15c6472a 实证（信封 iteview.com 冒充阿里云）。规则侧再叠
        # "SPF 未通过"条件——ESP 正规代发（信封=ESP 域且 SPF pass）不误伤
        "smtp_mail_mismatch": _smtp_mail_mismatch,
        # HTML 中的 file:/// 本地路径：邮件群发工具的安装路径指纹
        # （报告 36fab11b15c6472a：file:///C:/Users/.../超级邮件群发机13.2正式版+注册机/）
        "html_file_uri": "file:///" in body,
        # 营销/批量发送特征（类别标签层）
        "has_list_unsubscribe": bool(headers.get("list-unsubscribe")),
        "precedence_bulk": str(precedence_value or "").strip().lower() in ("bulk", "junk", "list"),
        "has_unsubscribe_link": has_unsub_text,
        "esp_domain": esp_domain,
        # 群发垃圾软件的随机伪词 X-Mailer（如 "Axbkgg Ccerhjm 85.26"）
        "xmailer_junk": is_junk_xmailer(str(xmailer_value or "")),
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
        "user_content_link": user_content_link,
        # 嵌套结构：字段路径 from.domain / auth.spf / reply_to.domain 由此解析
        "from": {
            "display_name": from_name,
            # 完整发件地址（小写）：信任上下文按地址查往来历史（见 app/scoring/trust.py）
            "addr": (from_addr or "").lower(),
            "display_brand": ",".join(find_brand_mentions(from_name, brands)),
            "display_name_raw": from_name_raw,
            "display_letter_count": sum(c.isalpha() for c in from_name_raw),
            "display_upper_ratio": _upper_ratio(from_name_raw),
            "display_word_count": len(from_name_raw.split()),
            "domain": from_domain,
            # 可注册域（eTLD+1）：用于"发件域即品牌方"判定。必须用可注册域而不是原始域，
            # 否则 apple.com.evil.top 会因为子域里带 apple 而被当成品牌方放行。
            "domain_reg": registrable_domain(from_domain),
            # 发件域是否"就是品牌自己的域"（标签级）：显示名冒充规则的排除条件，
            # 用它替掉原先的子串匹配（见 is_brand_domain 注释里的三个实测反例）
            "domain_is_brand": is_brand_domain(from_domain),
            # 是否免费邮箱域（子域折叠到可注册域：mail.qq.com 属 qq.com）
            "is_freemail": host_is_freemail(from_domain),
            "localpart": localpart,
            "domain_leet": domain_leet,
            "raw": str(headers.get("from", "") or ""),
        },
        "reply_to": {
            "domain": (auth.get("reply_to_domain") or "").lower(),
            "domain_reg": registrable_domain(auth.get("reply_to_domain") or ""),
            "is_freemail": host_is_freemail(auth.get("reply_to_domain") or ""),
        },
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
        # 再扣除可注册域（eTLD+1）本身的标签：中国二级后缀（com.cn/edu.cn/...）
        # 会把 mail.sinamail.sina.com.cn 之类正常地址虚增到 5 层（trec06c ham
        # 误报 123 次）。只统计"可注册域之外的子域层数"才是真实异常信号。
        reg = registrable_domain(host)
        reg_labels = reg.split(".") if reg else []
        if reg_labels and host.endswith(".".join(reg_labels)):
            sub_count = max(len(depth_labels) - len(reg_labels), 0)
        else:
            sub_count = len(depth_labels)
        url_items.append({
            "url": u,
            "host": host,
            "tld": labels[-1] if labels else "",
            "label_count": sub_count,
        })

    att_items = []
    for att in attachments:
        original_name = att["filename"]
        extension = att["extension"]
        content_type = att["content_type"]
        # P0 附件深度分析：真实类型三重核对（声明 MIME / 扩展名 / magic bytes）
        # 与文件名欺骗检查。real_type 由解析器签名表嗅探写入。
        real_type = att.get("real_type", "unknown")
        att_items.append({
            "filename": original_name,
            "filename_lower": original_name.lower(),
            "stem": original_name.rsplit(".", 1)[0],
            "extension": extension,
            "content_type": content_type,
            "size": att["size"],
            "real_type": real_type,
            "type_mismatch": extension_type_mismatch(real_type, extension),
            "mime_type_conflict": mime_type_conflict(content_type, real_type),
            "generic_mime_known_ext": generic_mime_known_ext(content_type, extension),
            # 双扩展名：末段必须是可执行/脚本类才算（见 has_double_extension 注释）
            "double_ext": has_double_extension(original_name),
            "has_bidi_control": any(c in BIDI_CONTROLS for c in original_name),
            "filename_length": len(original_name),
            "max_space_run": max_space_run(original_name),
            "oversized": bool(att.get("oversized", False)),
            # P1 压缩包递归结论（pipeline 的 annotate_attachments 写入；
            # 非归档附件无此键，全部按 False 兜底）
            "archive_encrypted": bool((att.get("archive") or {}).get("encrypted", False)),
            "archive_password_in_body": bool((att.get("archive") or {}).get("password_in_body", False)),
            "archive_has_executable": bool((att.get("archive") or {}).get("has_executable", False)),
            "archive_has_macro": bool((att.get("archive") or {}).get("has_macro", False)),
            "archive_nested_depth": int((att.get("archive") or {}).get("nested_depth", 0)),
            "archive_bomb_guard": bool((att.get("archive") or {}).get("bomb_guard", False)),
            # P1 Office 分析（app/attachment/office.py）：宏分级 + 远程模板 + DDE
            "office_has_macro": bool((att.get("office") or {}).get("has_macro", False)),
            "office_macro_findings": (att.get("office") or {}).get("macro_findings", []),
            "office_macro_autoexec": "autoexec" in ((att.get("office") or {}).get("macro_findings") or []),
            "office_macro_shell": "shell" in ((att.get("office") or {}).get("macro_findings") or []),
            "office_macro_download": "download" in ((att.get("office") or {}).get("macro_findings") or []),
            "office_macro_obfuscated": "obfuscated" in ((att.get("office") or {}).get("macro_findings") or []),
            "office_remote_template": str((att.get("office") or {}).get("remote_template", "")),
            "office_dde": bool((att.get("office") or {}).get("dde", False)),
            # P2 PDF 关键字扫描（app/attachment/pdf.py）
            "pdf_javascript": bool((att.get("pdf") or {}).get("javascript", False)),
            "pdf_launch": bool((att.get("pdf") or {}).get("launch", False)),
            "pdf_embedded": bool((att.get("pdf") or {}).get("embedded", False)),
            # P2 YARA 家族检测（app/rules/loader.py 扫描附件字节）
            "yara_hit": bool(att.get("yara")),
            "yara_rules": (att.get("yara") or {}).get("rules", []),
            "yara_severity": (att.get("yara") or {}).get("severity", ""),
        })

    return {
        "mail": mail,
        "url": url_items,
        "domain": [{"domain": d} for d in domains],
        "attachment": att_items,
    }

def is_junk_xmailer(value: str) -> bool:
    """随机伪词 X-Mailer 判定（群发垃圾软件特征，如 "Axbkgg Ccerhjm 85.26"）。

    datacon 全 7 天抽样实测 16% 命中，modern ham/spam 各 600 封 0 命中。
    已知正常Mailer按名称排除；自研Mailer（"Foo Bar 1.0"）会命中但仅 4 分弱信号，
    不参与定性。
    """
    if not value:
        return False
    value = str(value).strip()
    known = ("outlook", "foxmail", "thunderbird", "apple", "gmail", "microsoft",
             "smtp", "esmtp", "qq", "163", "coremail", "alimail", "swiftmailer",
             "phpmailer", "postfix", "sendmail", "exim", "mailagent", "easymail",
             "iphone", "ipad", "netease", "aliyun", "mime", "mailer", "webmail",
             "exchange", "lotus", "kmail", "mutt", "pine", "claws", "sylpheed")
    low = value.lower()
    if any(k in low for k in known):
        return False
    words = re.findall(r"[A-Za-z]+", value)
    cap_words = [w for w in words if w[0].isupper() and 3 <= len(w) <= 9]
    return len(cap_words) >= 2


_BRAND_SET_CACHE: set[str] | None = None
_LINK_ALLOWLIST_CACHE: set[str] | None = None
_ESP_DOMAIN_CACHE: set[str] | None = None
_FREEMAIL_CACHE: set[str] | None = None
_BRAND_SHADOW_CACHE: dict[str, list[str]] | None = None
_RISK_EXT_CACHE: set[str] | None = None
_OTP_KEYWORDS_CACHE: list[str] | None = None
_OTP_CLAUSES_CACHE: list[str] | None = None
_TRUSTED_DOMAINS_CACHE: set[str] | None = None
_USER_CONTENT_CACHE: set[str] | None = None
_ASCII_BRAND_PATTERNS: dict[str, re.Pattern[str]] = {}
_SHADOW_PATTERNS: dict[str, re.Pattern[str]] = {}
# 字典缓存对应的规则版本哈希：字典文件被改写（GUI/rule_admin 热更新）后
# 版本号会变，缓存随之失效。缺了它会出真问题——改了 brands.txt 但品牌特征
# （from.display_brand / text_brand_hits）仍用旧词表，规则引擎却已加载新词表。
_DICT_CACHE_VERSION: str = ""


def _dict_entries(name: str) -> list[str]:
    """按规则版本号缓存的字典读取（版本变化即失效）。"""
    global _DICT_CACHE_VERSION, _BRAND_SET_CACHE, _LINK_ALLOWLIST_CACHE
    global _ESP_DOMAIN_CACHE, _FREEMAIL_CACHE, _BRAND_SHADOW_CACHE, _RISK_EXT_CACHE
    global _OTP_KEYWORDS_CACHE, _OTP_CLAUSES_CACHE, _TRUSTED_DOMAINS_CACHE, _USER_CONTENT_CACHE
    from app.scoring.rule_loader import get_rule_engine

    engine = get_rule_engine()
    if _DICT_CACHE_VERSION != engine.version:
        _DICT_CACHE_VERSION = engine.version
        _BRAND_SET_CACHE = _LINK_ALLOWLIST_CACHE = None
        _ESP_DOMAIN_CACHE = _FREEMAIL_CACHE = None
        _BRAND_SHADOW_CACHE = None
        _RISK_EXT_CACHE = None
        _OTP_KEYWORDS_CACHE = None
        _OTP_CLAUSES_CACHE = None
        _TRUSTED_DOMAINS_CACHE = None
        _USER_CONTENT_CACHE = None
        _ASCII_BRAND_PATTERNS.clear()
        _SHADOW_PATTERNS.clear()
    return engine.dicts.get(name, [])


def load_brand_set() -> set[str]:
    """品牌字典（供特征计算使用），按规则版本缓存。

    注意 `entries = _dict_entries(...)` 必须在 `if 缓存 is None` **之前**：版本比对写在
    _dict_entries 里，缓存预热后若跳过该调用就永远不失效——字典热更新（GUI/rule_admin
    改 brands.txt）后特征会一直用旧词表，而规则引擎已换新词表。此前 reload 测试能过，
    只是因为那个用例运行时缓存恰好为空（同进程里先有别的用例调过一次就露馅）。
    """
    global _BRAND_SET_CACHE
    entries = _dict_entries("brands")
    if _BRAND_SET_CACHE is None:
        _BRAND_SET_CACHE = {v.lower() for v in entries}
    return _BRAND_SET_CACHE


def load_link_allowlist() -> set[str]:
    """链接域白名单（正常邮件常链接的第三方服务域），按规则版本缓存。"""
    global _LINK_ALLOWLIST_CACHE
    entries = _dict_entries("link_allowlist")     # 先比对版本，再决定是否重建
    if _LINK_ALLOWLIST_CACHE is None:
        _LINK_ALLOWLIST_CACHE = {v.lower() for v in entries}
    return _LINK_ALLOWLIST_CACHE


def load_user_content_hosting() -> set[str]:
    """用户内容托管平台（**任何人都能在此发布内容**）：免费建站/静态托管、对象存储与用户内容
    CDN、网盘、粘贴板。按规则版本缓存。

    与 `load_trusted_domains()` 用的 `abuse_prone_platforms.txt` 不同：那份是超集（还含短链、
    社区论坛、SaaS 客户子域），只用于生成可信清单时排除；本份是**规则专用子集**——点击目标
    落在这些平台的**子域/桶**上才构成"链接托管在他人可自由创建的站点"。
    刻意不含 `typeform.com`/`airtable.com` 这类 SaaS 客户子域：`ollama.typeform.com` 是正常
    厂商表单，与 `protonmail-6e3725.webflow.io` 结构相同但性质相反。
    """
    global _USER_CONTENT_CACHE
    entries = _dict_entries("user_content_hosting")
    if _USER_CONTENT_CACHE is None:
        _USER_CONTENT_CACHE = {v.lower() for v in entries}
    return _USER_CONTENT_CACHE


def load_trusted_domains() -> set[str]:
    """可信域名清单（Tranco/Cisco/Cloudflare 榜单，去掉易滥用平台），按规则版本缓存。

    用途（**只当"知名"用，不当"安全"用**）：
      1. 情报富化时跳过这些域的 **VT 域名端点查询**——它们的域名记录本来就是 clean，
         查了也没有信息量（实测真实邮箱 3047 次域查询里 46.8% 属此类）；
      2. 报告里把命中的域标成"已知知名域（未查询）"，避免分析师以为漏查。
    **URL 级查询（URLScan / VT URL）不受影响**——钓鱼寄居在知名平台的子域/路径上时，
    只有 URL 级查询才看得出来（`evil.pages.dev`、`drive.google.com/...`）。

    生成方式见 `scripts/update_trusted_domains.py`（源：MISP warninglists，CC0）。
    """
    global _TRUSTED_DOMAINS_CACHE
    entries = _dict_entries("trusted_domains")     # 先比对版本，再决定是否重建
    if _TRUSTED_DOMAINS_CACHE is None:
        _TRUSTED_DOMAINS_CACHE = {v.lower() for v in entries}
    return _TRUSTED_DOMAINS_CACHE


def load_esp_domains() -> set[str]:
    """ESP（邮件营销/批量发送平台）发信域，按规则版本缓存。"""
    global _ESP_DOMAIN_CACHE
    entries = _dict_entries("esp_domains")
    if _ESP_DOMAIN_CACHE is None:
        _ESP_DOMAIN_CACHE = {v.lower() for v in entries}
    return _ESP_DOMAIN_CACHE


def load_freemail_domains() -> set[str]:
    """免费邮箱域，按规则版本缓存（供链接域对齐判定用）。"""
    global _FREEMAIL_CACHE
    entries = _dict_entries("freemail")
    if _FREEMAIL_CACHE is None:
        _FREEMAIL_CACHE = {v.lower() for v in entries}
    return _FREEMAIL_CACHE


def reset_feature_caches() -> None:
    global _BRAND_SET_CACHE, _LINK_ALLOWLIST_CACHE, _ESP_DOMAIN_CACHE, _FREEMAIL_CACHE
    global _BRAND_SHADOW_CACHE, _RISK_EXT_CACHE, _DICT_CACHE_VERSION
    global _OTP_KEYWORDS_CACHE, _OTP_CLAUSES_CACHE, _TRUSTED_DOMAINS_CACHE, _USER_CONTENT_CACHE
    _BRAND_SET_CACHE = None
    _LINK_ALLOWLIST_CACHE = None
    _ESP_DOMAIN_CACHE = None
    _FREEMAIL_CACHE = None
    _BRAND_SHADOW_CACHE = None
    _RISK_EXT_CACHE = None
    _OTP_KEYWORDS_CACHE = None
    _OTP_CLAUSES_CACHE = None
    _TRUSTED_DOMAINS_CACHE = None
    _USER_CONTENT_CACHE = None
    _DICT_CACHE_VERSION = ""
    _ASCII_BRAND_PATTERNS.clear()
    _SHADOW_PATTERNS.clear()
