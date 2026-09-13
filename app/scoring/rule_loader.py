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
    html = ctx.parsed.get("body_html", "") or ""
    if not html:
        return []
    for href, text in _ANCHOR_RE.findall(html):
        plain = _TAG_RE.sub("", text).strip()
        shown = _host_of(plain)
        actual = _host_of(href)
        if shown and actual and shown != actual \
                and not shown.endswith(actual) and not actual.endswith(shown):
            return [(f"{shown} -> {actual}", None)]
    return []


def _detector_att_random_name(ctx: "DetectorContext"):
    hits = []
    for att in ctx.features.get("attachment", []):
        if att["size"] > 0 and is_random_filename(att["stem"]):
            hits.append((att["filename"], None))
    return hits


def _detector_signal_stack(ctx: "DetectorContext"):
    """弱信号叠加加分：门槛由 3/4/5 提到 4/5/6。

    背景：100k 现代邮件误报基线显示，3 个弱信号（Reply-To 不匹配 + 附件诱饵 +
    主题词）在正常商务邮件里很常见，过早叠加会把单信号误报放大成 SUSPICIOUS。
    提高门槛要求更多独立证据才升级。
    """
    n = len(ctx.fired_signals)
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
