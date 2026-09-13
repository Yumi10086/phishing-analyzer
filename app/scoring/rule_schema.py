"""规则模式定义与声明式规则求值（pydantic v2）。

规则分两类：
  declarative - 字段 + 算子 + 值 的声明式匹配（YAML 完整描述）
  detector    - 内置探测器（Python 函数），YAML 只管控分值/开关

字段路径基于 build_features() 的输出，支持 "mail.url_count"、
"url.host"、"attachment.filename" 这类点路径。
"""
from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.scoring.features import fold_text

MISSING = object()  # 字段不存在的哨兵


class RuleLoadError(ValueError):
    """规则加载/校验失败。"""


OPERATORS = {
    "contains_any",     # 字段包含任意值（子串）
    "contains_all",     # 字段包含全部值
    "regex_any",        # 任一正则在字段中命中（search）
    "equals_any",       # 字段等于任意值（不区分大小写）
    "suffix_any",       # 字段以某值结尾（或等于该值），用于域名匹配
    "exists",           # 字段真值性：values 为空或 [true] 要求真，[false] 要求假
    "gt", "lt",         # 数值比较
    "length_gt", "length_lt",   # 字符串/列表长度比较
    "count_gt",         # 子串出现次数 > n，values: [needle, n]
    "regex_count_gt",   # 正则命中次数 > n，values: [pattern, n]
}


def get_path(item: dict[str, Any], path: str) -> Any:
    """按点路径取字段值，不存在返回 MISSING。"""
    cur: Any = item
    for part in path.split("."):
        if not isinstance(cur, dict) or part not in cur:
            return MISSING
        cur = cur[part]
    return cur


def _resolve_values(values: list[Any], dicts: dict[str, list[str]]) -> list[Any]:
    """解析 "@dict:name" 引用为字典内容。"""
    out: list[Any] = []
    for v in values:
        if isinstance(v, str) and v.startswith("@dict:"):
            name = v[len("@dict:"):]
            if name not in dicts:
                raise RuleLoadError(f"未知字典引用 @dict:{name}")
            out.extend(dicts[name])
        else:
            out.append(v)
    return out


class MatchSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")

    field: str
    operator: str
    values: list[Any] = Field(default_factory=list)
    case_sensitive: bool = False
    exclude: "MatchSpec | None" = None

    @field_validator("operator")
    @classmethod
    def _check_operator(cls, v: str) -> str:
        if v not in OPERATORS:
            raise ValueError(f"未知算子 {v!r}，可选: {', '.join(sorted(OPERATORS))}")
        return v

    def evaluate(self, item: dict[str, Any], dicts: dict[str, list[str]]) -> tuple[bool, str | None]:
        """返回 (是否命中, 展示值)。展示值用于填充 reason 模板的 {value}。"""
        raw = get_path(item, self.field)
        if raw is MISSING:
            return False, None

        values = _resolve_values(self.values, dicts)
        matched_display: str | None = None

        if self.operator == "exists":
            want = True
            if values:
                want = str(values[0]).lower() not in ("false", "0", "no")
            hit = bool(raw) == want
            # 供 reason 的 {value} 使用：字符串/数字字段展示其值，布尔字段不展示
            if hit and not isinstance(raw, bool):
                matched_display = str(raw)
        elif self.operator in ("gt", "lt"):
            try:
                num = float(raw)
                ref = float(values[0])
            except (TypeError, ValueError):
                return False, None
            hit = num > ref if self.operator == "gt" else num < ref
            matched_display = str(raw)
        elif self.operator in ("length_gt", "length_lt"):
            try:
                n = int(values[0])
            except (TypeError, ValueError):
                return False, None
            length = len(raw) if isinstance(raw, (str, list)) else 0
            hit = length > n if self.operator == "length_gt" else length < n
            matched_display = str(length)
        elif self.operator == "count_gt":
            if len(values) < 2:
                raise RuleLoadError("count_gt 需要 values: [子串, 阈值]")
            needle, n = str(values[0]), int(values[1])
            hit = str(raw).lower().count(needle.lower()) > n
            matched_display = str(raw)
        elif self.operator == "regex_count_gt":
            if len(values) < 2:
                raise RuleLoadError("regex_count_gt 需要 values: [pattern, 阈值]")
            flags = 0 if self.case_sensitive else re.IGNORECASE
            hits = len(re.findall(str(values[0]), str(raw), flags))
            hit = hits > int(values[1])
            matched_display = str(raw)
        else:
            # 字符串类算子：统一在 str 上做（大小写折叠由 case_sensitive 控制）
            hay = raw if isinstance(raw, str) else str(raw)
            needles = [str(v) for v in values]
            if not self.case_sensitive:
                hay_cmp, needles_cmp = fold_text(hay).lower(), [fold_text(n).lower() for n in needles]
            else:
                hay_cmp, needles_cmp = hay, needles

            if self.operator == "contains_any":
                hit = any(n in hay_cmp for n in needles_cmp)
                matched_display = next((needles[i] for i, n in enumerate(needles_cmp) if n in hay_cmp), None)
            elif self.operator == "contains_all":
                hit = all(n in hay_cmp for n in needles_cmp)
            elif self.operator == "regex_any":
                flags = 0 if self.case_sensitive else re.IGNORECASE
                for pat in needles_cmp:
                    try:
                        if re.search(pat, hay_cmp, flags):
                            hit = True
                            matched_display = needles[needles_cmp.index(pat)]
                            break
                    except re.error as exc:
                        raise RuleLoadError(f"正则无效 {pat!r}: {exc}") from exc
                else:
                    hit = False
            elif self.operator == "equals_any":
                hit = hay_cmp in needles_cmp
                matched_display = hay if hit else None
            elif self.operator == "suffix_any":
                hit = any(hay_cmp == n or hay_cmp.endswith("." + n) for n in needles_cmp)
                matched_display = hay if hit else None
            else:  # pragma: no cover - OPERATORS 集合已约束
                raise RuleLoadError(f"未实现的算子 {self.operator!r}")

        if not hit:
            return False, None
        if self.exclude is not None and self.exclude.evaluate(item, dicts)[0]:
            return False, None
        return True, matched_display


class RuleDef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-z0-9_]+$")
    name: str
    description: str = ""
    category: str = "misc"
    scope: Literal["mail", "url", "domain", "attachment"] = "mail"
    kind: Literal["declarative", "detector"] = "declarative"
    detector: str | None = None
    points: int = Field(default=0, ge=0, le=30)
    enabled: bool = True
    reason: str | None = None
    # 单条件 dict 或多条件 list（list = AND 语义）
    match: MatchSpec | list[MatchSpec] | None = None

    @field_validator("match")
    @classmethod
    def _match_required_for_declarative(cls, v, info):
        if info.data.get("kind", "declarative") == "declarative" and v is None:
            raise ValueError("declarative 规则必须提供 match")
        return v

    @property
    def match_specs(self) -> list[MatchSpec]:
        """统一为条件列表（AND）。"""
        if self.match is None:
            return []
        if isinstance(self.match, list):
            return self.match
        return [self.match]

    def iter_specs(self):
        """遍历所有条件（含嵌套 exclude）供校验。"""
        for spec in self.match_specs:
            yield spec
            cur = spec.exclude
            while cur is not None:
                yield cur
                cur = cur.exclude


def render_reason(template: str | None, rule: RuleDef, item: dict[str, Any],
                  display: str | None) -> str:
    """渲染研判依据：支持 {value} 与 {字段路径}（如 {from.domain}）占位。"""
    if not template:
        return rule.name
    out = template.replace("{value}", display or "")
    out = re.sub(r"\{([a-z_.0-9]+)\}",
                 lambda m: str(get_path(item, m.group(1)))
                 if get_path(item, m.group(1)) is not MISSING else "",
                 out)
    return out
