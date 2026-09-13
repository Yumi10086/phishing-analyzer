"""规则管理：CRUD / 热重载 / 试跑。供 FastAPI 端点与 Streamlit 管理页共用。

写入策略：
  POST（新建/整体覆盖）与 PUT（局部修改）都落到 rules/custom/<id>.yaml，
  自定义同 id 覆盖内置 -> 内置规则升级时不会被用户修改冲掉；
  DELETE 只删除自定义覆盖文件，内置规则本身不可删除（可禁用）。
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from app.config import settings
from app.extractor.auth_checker import check_auth
from app.extractor.ioc_extractor import extract_iocs
from app.parser.eml_parser import parse_eml
from app.parser.msg_parser import parse_msg
from app.scoring.features import build_features
from app.scoring.rule_loader import RuleEngine, get_rule_engine, reload_rules
from app.scoring.rule_schema import RuleDef, RuleLoadError
from app.utils.logger import get_logger

log = get_logger(__name__)

# PUT 局部修改允许的字段（match 等结构性修改走 POST 整体覆盖）
_PATCHABLE = {"enabled", "points", "name", "description", "reason"}


class RuleAdminError(ValueError):
    """规则管理操作失败。"""


def _custom_path(rule_id: str) -> Path:
    if not rule_id or not Path(f"{rule_id}.yaml").name == f"{rule_id}.yaml":
        raise RuleAdminError(f"非法规则 id: {rule_id!r}")
    return settings.rules_dir / "custom" / f"{rule_id}.yaml"


def list_rules() -> dict[str, Any]:
    engine = get_rule_engine()
    return {"version": engine.version, "rules": engine.list_rules()}


def upsert_custom_rule(rule_dict: dict[str, Any]) -> dict[str, Any]:
    """新建或整体覆盖一条自定义规则（写入 rules/custom/，立即生效）。"""
    try:
        rule = RuleDef.model_validate(rule_dict)
    except Exception as exc:
        raise RuleAdminError(f"规则定义无效: {exc}") from exc
    if rule.kind == "declarative" and rule.match is None:
        raise RuleAdminError("declarative 规则必须提供 match")

    path = _custom_path(rule.id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump([rule.model_dump(exclude_none=True)], allow_unicode=True,
                       sort_keys=False),
        encoding="utf-8",
    )
    try:
        engine = reload_rules()
    except RuleLoadError:
        path.unlink(missing_ok=True)  # 回滚坏规则，保证引擎可用
        reload_rules()
        raise
    log.info("自定义规则已写入: %s -> %s", rule.id, path)
    return {"status": "saved", "id": rule.id, "file": str(path), "version": engine.version}


def update_rule(rule_id: str, patch: dict[str, Any]) -> dict[str, Any]:
    """局部修改规则（enabled/points/name/description/reason），落到 custom 覆盖文件。"""
    engine = get_rule_engine()
    current = next((r for r in engine.rules if r.id == rule_id), None)
    if current is None:
        raise RuleAdminError(f"规则不存在: {rule_id}")

    bad = set(patch) - _PATCHABLE
    if bad:
        raise RuleAdminError(f"不支持修改的字段: {', '.join(sorted(bad))}（结构性修改请用 POST 整体覆盖）")

    merged = current.model_dump(exclude_none=True)
    merged.update(patch)
    # 来源标记为 custom（即使内容不变，写入覆盖文件保证升级安全）
    return upsert_custom_rule(merged)


def delete_rule(rule_id: str) -> dict[str, Any]:
    """删除自定义覆盖文件（恢复内置默认）；纯内置规则不允许删除。"""
    path = _custom_path(rule_id)
    engine = get_rule_engine()
    if rule_id not in engine.source_map:
        raise RuleAdminError(f"规则不存在: {rule_id}")
    if not path.is_file():
        raise RuleAdminError("内置规则不可删除（可禁用，或删除其自定义覆盖以恢复默认）")
    path.unlink()
    engine = reload_rules()
    log.info("自定义规则覆盖已删除: %s", rule_id)
    return {"status": "deleted", "id": rule_id, "version": engine.version}


def reload() -> dict[str, Any]:
    engine = reload_rules()
    return {"status": "reloaded", "version": engine.version, "count": len(engine.rules)}


def list_dicts() -> dict[str, list[str]]:
    return get_rule_engine().dicts


def append_dict_entries(dict_name: str, entries: list[str]) -> dict[str, Any]:
    """向字典文件追加词条（管理界面"添加品牌/TLD"等场景）。"""
    dicts = get_rule_engine().dicts
    if dict_name not in dicts:
        raise RuleAdminError(f"字典不存在: {dict_name}，可选: {', '.join(sorted(dicts))}")
    clean = [e.strip() for e in entries if e.strip() and not e.strip().startswith("#")]
    if not clean:
        raise RuleAdminError("没有可追加的词条")
    existing = set(dicts[dict_name])
    new = [e for e in clean if e.lower() not in existing]
    if not new:
        return {"status": "noop", "added": 0, "reason": "词条均已存在"}

    path = settings.rules_dir / "dicts" / f"{dict_name}.txt"
    with path.open("a", encoding="utf-8") as fh:
        fh.write("\n".join(new) + "\n")
    engine = reload_rules()
    from app.scoring.features import reset_feature_caches
    reset_feature_caches()
    return {"status": "appended", "added": len(new), "version": engine.version}


def test_on_bytes(raw: bytes, filename: str = "mail.eml",
                  rule_id: str | None = None) -> dict[str, Any]:
    """用一封样本邮件试跑当前规则集（离线，不落盘、不查情报）。"""
    lower = filename.lower()
    parsed = parse_msg(raw) if lower.endswith(".msg") else parse_eml(raw)
    iocs = extract_iocs(parsed)
    auth = check_auth(parsed)
    features = build_features(parsed, iocs, auth)
    engine = get_rule_engine()
    signals = engine.evaluate(parsed, iocs, auth, features)

    if rule_id:
        signals = [s for s in signals if s["id"] == rule_id]

    from app.scoring.risk_engine import score_mail
    scored = score_mail(parsed, iocs, auth, intel_results=[], offline=True)
    raw_total = sum(s["points"] for s in signals)
    return {
        "version": engine.version,
        "signals": signals,
        "raw_signals_points": raw_total,
        "heuristic_score": min(raw_total, 30),
        "score": scored["score"],
        "verdict": scored["verdict"],
    }


def remove_dict_entries(dict_name: str, entries: list[str]) -> dict[str, Any]:
    """从字典文件移除词条（保留注释与空行），并热重载。"""
    engine = get_rule_engine()
    if dict_name not in engine.dicts:
        raise RuleAdminError(f"字典不存在: {dict_name}，可选: {', '.join(sorted(engine.dicts))}")
    remove_set = {e.strip().lower() for e in entries if e.strip()}
    if not remove_set:
        raise RuleAdminError("没有选择要移除的词条")

    path = settings.rules_dir / "dicts" / f"{dict_name}.txt"
    kept_lines: list[str] = []
    removed = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if stripped and not stripped.startswith("#") and stripped.lower() in remove_set:
            removed += 1
            continue
        kept_lines.append(line)
    path.write_text("\n".join(kept_lines).rstrip("\n") + "\n", encoding="utf-8")

    engine = reload_rules()
    from app.scoring.features import reset_feature_caches
    reset_feature_caches()
    return {"status": "removed", "removed": removed, "version": engine.version}
