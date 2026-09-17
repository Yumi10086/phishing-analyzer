"""规则加载器：从 rules/ 目录加载字典与 YAML 规则，供评分引擎消费。

目录约定：
  rules/builtin/*.yaml  内置规则（随项目分发，升级可能覆盖）
  rules/custom/*.yaml   用户自定义规则（同 id 覆盖内置，升级安全）
  rules/dicts/*.txt     可编辑字典（每行一个词条，# 注释）

版本哈希：对所有规则与字典文件内容做 sha256，写入分析报告，保证复盘可复现。
"""
from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.config import settings
from app.scoring.features import (
    build_features,
    fold_text,
    has_invisible_obfuscation,
    is_random_filename,
    parse_from_header,
    registrable_domain,
)
from app.scoring.rule_schema import (
    MatchSpec,
    RuleDef,
    RuleLoadError,
    render_reason,
)
from app.utils.logger import get_logger

log = get_logger(__name__)

_ANCHOR_RE = re.compile(r"<a\s[^>]*?href\s*=\s*[\"']([^\"']+)[\"'][^>]*>(.*?)</a>",
                        re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")
# 点击追踪链接里"自带落地地址"的两种常见形态：
#   ① 路径里塞 zlib+base64 载荷（SendCloud / 多数国产 ESP：/click2/eNpFT8tu...html）
#   ② 查询参数带目标地址（?url=<percent-encoded>）
_B64_BLOB_RE = re.compile(r"/([A-Za-z0-9_\-=]{40,}?)(?:\.html?|$)")


def _tracking_destination(url: str) -> str:
    """解出追踪链接里自带的落地地址（解不出返回空串）。

    用途：判断"锚文本写的域"是不是**最终落地域**。正常营销邮件会把链接包一层
    ESP 追踪域（`xmind.cn` → `sctrack.sendcloud.net/track/click2/<zlib+base64>.html`），
    载荷里就写着 `https://xmind.cn/verifyemail/...`；钓鱼则不会把受害者域名写进载荷。
    只解 zlib/base64 载荷，**不认 ?url= 这类查询参数**——参数里写什么完全由发件方控制，
    钓鱼可以照样写 `?u=https://bank.com` 当诱饵。
    """
    if not url:
        return ""
    import base64
    import zlib

    out: list[str] = []
    for m in _B64_BLOB_RE.finditer(url):
        blob = m.group(1).replace("-", "+").replace("_", "/")
        blob += "=" * (-len(blob) % 4)
        try:
            raw = base64.b64decode(blob)
        except Exception:  # noqa: BLE001 - 非 base64 路径段很常见（普通长 URL）
            continue
        for decode in (zlib.decompress, lambda b: b):
            try:
                out.append(decode(raw).decode("utf-8", "replace"))
                break
            except Exception:  # noqa: BLE001
                continue
    return "\n".join(out).lower()


def _host_of(url_or_domain: str) -> str | None:
    m = re.match(r"^[a-z]+://([^/:?#]+)", url_or_domain.strip().lower())
    if m:
        return m.group(1).strip(".")
    token = url_or_domain.strip().lower().strip(".")
    if re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,}", token) and " " not in token:
        return token
    return None


# ---- 内置探测器（结构性检查无法用"字段+算子"表达，代码实现、YAML 管分值/开关） ----
# 签名: ctx -> list[(display | None, points_override | None)]

def _detector_text_invisible_obfuscation(ctx: "DetectorContext"):
    sources = [
        str(ctx.parsed.get("headers", {}).get("subject", "") or ""),
        parse_from_header(ctx.parsed.get("headers", {}) or {})[0],
        (ctx.parsed.get("body_text", "") or "")[:2000],
    ]
    if any(has_invisible_obfuscation(src) for src in sources):
        return [(None, None)]
    return []


def _detector_from_display_email_mismatch(ctx: "DetectorContext"):
    from_name_raw, _, from_domain = parse_from_header(ctx.parsed.get("headers", {}) or {})
    if not ("@" in from_name_raw and from_domain):
        return []
    display_domains = [d.lower().strip(".") for d in
                       re.findall(r"[\w.+-]+@([A-Za-z0-9.-]*[A-Za-z])[A-Za-z0-9.-]*", from_name_raw)]
    if not display_domains or all(d != from_domain for d in display_domains):
        return [(from_domain, None)]
    return []


def _detector_anchor_text_mismatch(ctx: "DetectorContext"):
    """锚文本里写的域名与 href 实际跳转域不一致（锚文本伪装）。

    判定**按可注册域**，并带三条"这不是伪装"的豁免（都来自真实邮箱误报实证）：
      1. 同一主体的不同子域（help.epicgames.com → accts.epicgames.com）——真实邮箱
         74 次命中里 69 次属此类；
      2. href 是白名单里的 ESP/追踪域（营销邮件把链接包一层，最终回官方域名）；
      3. 锚文本写的是**发件方自己的域名**且追踪载荷里也带着该域（`xmind.cn` →
         `sctrack.sendcloud.net/track/click2/<zlib载荷含 xmind.cn 落地地址>`）。
         钓鱼冒充的是**别人**的域名，发件域与锚文本域不同，因此不受这条豁免影响。
    """
    from app.scoring.features import load_link_allowlist

    html = ctx.parsed.get("body_html", "") or ""
    if not html:
        return []
    from_reg = ((ctx.features or {}).get("mail", {}).get("from") or {}).get("domain_reg", "")
    allowlist = load_link_allowlist()
    for href, text in _ANCHOR_RE.findall(html):
        plain = _TAG_RE.sub("", text).strip()
        shown = _host_of(plain)
        actual = _host_of(href)
        if not (shown and actual):
            continue
        shown_reg = registrable_domain(shown)
        actual_reg = registrable_domain(actual)
        if shown_reg == actual_reg:
            continue  # 同一注册域的不同子域：主体相同，不是伪装
        if shown == actual or shown.endswith("." + actual) or actual.endswith("." + shown):
            continue
        if actual_reg and actual_reg in allowlist:
            continue  # 已知 ESP/追踪域：包裹式链接是营销常态
        if shown_reg and from_reg and shown_reg == from_reg:
            dest = _tracking_destination(href)
            if dest and (shown_reg in dest or shown in dest):
                # 锚文本是发件方自己的域名，且追踪载荷里确实带着该落地域 → 邮件是让
                # 收件人回自家站，不是"显示 A 跳到 B"。**要求载荷证据**：仅凭
                # "显示域 == 发件域"就放行会漏掉"伪造 From + 显示品牌域"的经典伪装。
                continue
        return [(f"{shown} -> {actual}", None)]
    return []


def _detector_att_random_name(ctx: "DetectorContext"):
    hits = []
    for att in ctx.features.get("attachment", []):
        if att["size"] > 0 and is_random_filename(att["stem"]):
            hits.append((att["filename"], None))
    return hits


# 环境噪声信号：渠道/寄送环境特征，不构成"行为异常"，不参与叠加计数。
# 背景（trec06c ham 误报归因）：2005 年邮件普遍无 Authentication-Results、正常
# 邮件列表带 List-Unsubscribe+Precedence，三者 + link/URL 规则即可堆过 SUSPICIOUS
# 线（37 封 FP 同一组合）。这些信号各自计分展示，但不再为 signal_stack 供数。
_STACK_NOISE = frozenset({
    "header_missing_auth",
    "header_list_unsubscribe",
    "header_precedence_bulk",
    "body_unsubscribe_link",
    "sender_esp_domain",
    "sender_from_freemail",
})


def _detector_signal_stack(ctx: "DetectorContext"):
    """弱信号叠加加分：门槛由 3/4/5 提到 4/5/6。

    背景：100k 现代邮件误报基线显示，3 个弱信号（Reply-To 不匹配 + 附件诱饵 +
    主题词）在正常商务邮件里很常见，过早叠加会把单信号误报放大成 SUSPICIOUS。
    提高门槛要求更多独立证据才升级。计数只含风险行为信号，环境噪声见
    _STACK_NOISE。
    """
    n = len([s for s in ctx.fired_signals
             if (s.get("id") if isinstance(s, dict) else s) not in _STACK_NOISE])
    if n >= 6:
        return [(str(n), 12)]
    if n >= 5:
        return [(str(n), 8)]
    if n >= 4:
        return [(str(n), 4)]
    return []


DETECTORS: dict[str, Any] = {
    "text_invisible_obfuscation": _detector_text_invisible_obfuscation,
    "from_display_email_mismatch": _detector_from_display_email_mismatch,
    "anchor_text_mismatch": _detector_anchor_text_mismatch,
    "att_random_name": _detector_att_random_name,
    "signal_stack": _detector_signal_stack,
}


@dataclass
class DetectorContext:
    parsed: dict[str, Any]
    iocs: dict[str, Any]
    auth: dict[str, Any]
    features: dict[str, Any]
    fired_signals: list[dict[str, Any]] = field(default_factory=list)


def load_dict_file(path: Path) -> list[str]:
    """加载字典文件：每行一个词条，# 注释，词条做混淆还原 + 小写。"""
    entries = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        entries.append(fold_text(line).lower())
    return entries


def load_ruleset(rules_dir: Path) -> tuple[list[RuleDef], dict[str, list[str]], str, dict[str, str]]:
    """加载规则与字典。返回 (规则列表, 字典, 版本哈希, 规则id->来源)。"""
    builtin_dir, custom_dir, dicts_dir = rules_dir / "builtin", rules_dir / "custom", rules_dir / "dicts"

    dicts: dict[str, list[str]] = {}
    hasher = hashlib.sha256()
    if dicts_dir.is_dir():
        for p in sorted(dicts_dir.glob("*.txt")):
            dicts[p.stem] = load_dict_file(p)
            hasher.update(f"{p.name}:{p.read_bytes()}".encode())

    def _load_dir(d: Path, source_tag: str) -> list[RuleDef]:
        rules: list[RuleDef] = []
        if not d.is_dir():
            return rules
        for p in sorted(d.glob("*.yaml")) + sorted(d.glob("*.yml")):
            hasher.update(f"{p.name}:{p.read_bytes()}".encode())
            try:
                data = yaml.safe_load(p.read_text(encoding="utf-8")) or []
            except yaml.YAMLError as exc:
                raise RuleLoadError(f"{source_tag}/{p.name} YAML 语法错误: {exc}") from exc
            if not isinstance(data, list):
                raise RuleLoadError(f"{source_tag}/{p.name} 顶层必须是规则数组")
            for i, raw in enumerate(data):
                try:
                    rules.append(RuleDef.model_validate(raw))
                except Exception as exc:
                    raise RuleLoadError(f"{source_tag}/{p.name} 第 {i + 1} 条规则无效: {exc}") from exc
        return rules

    builtin = _load_dir(builtin_dir, "builtin")
    custom = _load_dir(custom_dir, "custom")

    merged: dict[str, RuleDef] = {}
    source_map: dict[str, str] = {}
    for r in builtin:
        if r.id in merged:
            raise RuleLoadError(f"规则 id 重复: {r.id}")
        merged[r.id] = r
        source_map[r.id] = "builtin"
    for r in custom:
        merged[r.id] = r  # 自定义同 id 覆盖内置
        source_map[r.id] = "custom"

    # 校验探测器存在 + 正则可编译 + 字典引用存在
    for r in merged.values():
        if r.kind == "detector" and r.detector and r.detector not in DETECTORS:
            raise RuleLoadError(f"规则 {r.id} 引用未注册探测器: {r.detector}")
        for spec in r.iter_specs():
            _validate_match(spec, dicts)

    version = hasher.hexdigest()[:16]
    return list(merged.values()), dicts, version, source_map


def _validate_match(spec: MatchSpec, dicts: dict[str, list[str]]) -> None:
    from app.scoring.rule_schema import _resolve_values
    values = _resolve_values(spec.values, dicts)
    for v in values:
        if spec.operator == "regex_any" and isinstance(v, str):
            try:
                re.compile(v)
            except re.error as exc:
                raise RuleLoadError(f"字段 {spec.field} 正则无效 {v!r}: {exc}") from exc
    if spec.exclude:
        _validate_match(spec.exclude, dicts)


class RuleEngine:
    """规则引擎：加载规则集并求值，产出与旧 _heuristic_signals 兼容的信号列表。"""

    def __init__(self, rules_dir: Path | None = None):
        self.rules_dir = rules_dir or settings.rules_dir
        self.reload()

    def reload(self) -> None:
        self.rules, self.dicts, self.version, self.source_map = load_ruleset(self.rules_dir)
        log.info("规则引擎加载完成: %d 条规则, 版本 %s", len(self.rules), self.version)

    def list_rules(self) -> list[dict[str, Any]]:
        return [{
            "id": r.id, "name": r.name, "description": r.description,
            "category": r.category, "scope": r.scope, "kind": r.kind,
            "detector": r.detector, "points": r.points, "enabled": r.enabled,
            "reason": r.reason, "source": self.source_map.get(r.id, "?"),
            "version": self.version,
        } for r in self.rules]

    def evaluate(self, parsed: dict[str, Any], iocs: dict[str, Any],
                 auth: dict[str, Any], features: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        """求值全部启用的规则，输出 [{id, points, reason}]，顺序 = 规则文件顺序。"""
        if features is None:
            features = build_features(parsed, iocs, auth)
        ctx = DetectorContext(parsed=parsed, iocs=iocs, auth=auth, features=features)

        signals: list[dict[str, Any]] = []
        for rule in self.rules:
            if not rule.enabled:
                continue

            if rule.kind == "detector":
                if not rule.detector:
                    continue
                if rule.detector == "signal_stack":
                    ctx.fired_signals = signals
                for display, points_override in DETECTORS[rule.detector](ctx):
                    points = points_override if points_override is not None else rule.points
                    signals.append({
                        "id": rule.id,
                        "points": points,
                        "reason": render_reason(rule.reason, rule, features["mail"], display),
                    })
                continue

            items = [features["mail"]] if rule.scope == "mail" else features.get(rule.scope, [])
            hit, display, item = _evaluate_rule(rule, items, self.dicts)
            if hit:
                signals.append({
                    "id": rule.id,
                    "points": rule.points,
                    "reason": render_reason(rule.reason, rule, item, display),
                })
        return signals


def _item_repr(scope: str, item: dict[str, Any]) -> str:
    return str(item.get("url") or item.get("filename") or item.get("domain") or "")


def _evaluate_rule(rule: RuleDef, items: list[dict[str, Any]],
                   dicts: dict[str, list[str]]) -> tuple[bool, str | None, dict[str, Any]]:
    """对作用域内所有条目求值，任一条目满足全部条件（AND）即触发。

    返回 (是否命中, 展示值, 命中条目)——条目用于填充 reason 里的 {字段路径} 占位。
    """
    specs = rule.match_specs
    if not specs:
        return False, None, {}
    for item in items:
        display: str | None = None
        all_hit = True
        for spec in specs:
            hit, d = spec.evaluate(item, dicts)
            if not hit:
                all_hit = False
                break
            if d is not None and display is None:
                display = d
        if all_hit:
            return True, (display if display is not None else _item_repr(rule.scope, item)), item
    return False, None, {}


# ---- 进程级单例与热重载 ----
_engine: RuleEngine | None = None


def get_rule_engine() -> RuleEngine:
    global _engine
    if _engine is None:
        _engine = RuleEngine()
    return _engine


def reload_rules() -> RuleEngine:
    """从磁盘重新加载规则集（API /rules/reload 与管理界面使用）。"""
    global _engine
    _engine = RuleEngine()
    return _engine
