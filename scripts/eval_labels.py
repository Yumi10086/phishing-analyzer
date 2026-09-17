"""标注集评估（L4 第二步）：把人工标注变成"该不该降权这条规则"的建议。

输入 `data/labeled/`（由 `app/mailbox/labels.py` 导出，或手工整理的同结构目录）：
  benign/  人工确认正常的邮件    fishing/ 或 phishing/ 人工确认钓鱼的邮件

三种口径（与 `analyze_fp_causes.py` 同一思路，但吃的是人工标注而不是评测 CSV）：
  1. **区分度**：每条信号在正常样本/钓鱼样本上的触发率。正常侧高、钓鱼侧低 = 噪声候选；
     钓鱼侧高、正常侧低 = 有效信号（不该动）。
  2. **降权模拟（真实重算）**：对候选信号临时把它的分值乘系数（默认 0.3），**用真实流水线
     重跑**整个标注集，看正常样本里有多少落回 BENIGN、钓鱼样本里有多少掉出阈值。
     净收益 = 消掉的误报 − 丢掉的召回。
  3. **建议**：净收益为正且不伤召回的信号，给出"可降权"建议；伤召回的标注"不建议"。

用法：
  python scripts/eval_labels.py                          # 默认 data/labeled，系数 0.3
  python scripts/eval_labels.py --factor 0 --top 8       # 试"直接清零"、只看前 8 个候选
"""
from __future__ import annotations

import argparse
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

LABELED = Path("data/labeled")
# 与 analyze_fp_causes.py 一致的离线归一化口径
_OFFLINE_MAX = 45
_THRESHOLD_SUSPICIOUS = 30
_FLAGGED = ("MALICIOUS", "SUSPICIOUS")


def _load(sub: str, root: Path | None = None) -> list[Path]:
    d = (root or LABELED) / sub
    if not d.is_dir():
        return []
    return sorted(p for p in d.rglob("*") if p.is_file() and p.suffix.lower() in (".eml", ".msg"))


def _analyze(files: list[Path]) -> list[dict]:
    """在**标注来源的部署语境**下评估：mailbox 档位 + 信任上下文（可用 --gateway 切换）。

    这一点必须对齐，否则测的是用户永远看不到的口径：网关档位下 `header_missing_auth`
    会照常计分、信任降权不生效，模拟出的"降权收益"就全是假的。
    """
    import asyncio

    from app.pipeline import analyze_bytes
    from app.scoring.features import reset_feature_caches

    reset_feature_caches()
    out = []
    for p in files:
        try:
            r = asyncio.run(analyze_bytes(p.read_bytes(), p.name, offline=True, save=False))
            out.append({"file": p.name, "verdict": r["verdict"], "score": r["score"],
                        "signals": [(s["id"], s["points"]) for s in r["signals"]]})
        except Exception:  # noqa: BLE001
            continue
    return out


def _flagged(rows: list[dict]) -> int:
    return sum(1 for r in rows if r["verdict"] in _FLAGGED)


def _simulate(rule_id: str, factor: float, files: list[Path], label: str) -> dict:
    """临时把某规则分值乘系数，用真实流水线重跑该标注集。"""
    from app.scoring.rule_loader import get_rule_engine

    engine = get_rule_engine()
    rule = next((r for r in engine.rules if r.id == rule_id), None)
    if rule is None:
        return {"label": label, "flagged": None}
    original = rule.points
    rule.points = round(float(original) * factor, 2)
    try:
        rows = _analyze(files)
    finally:
        rule.points = original
    return {"label": label, "flagged": _flagged(rows), "n": len(rows)}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dir", default=str(LABELED))
    ap.add_argument("--factor", type=float, default=0.3, help="降权系数（0 = 直接清零）")
    ap.add_argument("--top", type=int, default=12, help="输出前 N 个候选信号")
    ap.add_argument("--simulate", action="store_true", help="跑降权模拟（较慢：每个候选重跑一遍）")
    ap.add_argument("--gateway", action="store_true",
                    help="按网关档位评估（默认 mailbox 档位 + 信任上下文，即标注的来源语境）")
    ap.add_argument("--no-trust", action="store_true",
                    help="关闭信任上下文（只看未经降权的原始分数）")
    args = ap.parse_args()

    import os

    if args.gateway:
        os.environ["ANALYSIS_PROFILE"] = "gateway"
    else:
        os.environ.setdefault("ANALYSIS_PROFILE", "mailbox")
    if args.no_trust:
        os.environ["TRUST_CONTEXT"] = "0"
    else:
        os.environ.setdefault("TRUST_CONTEXT", "1")
    print(f"评估语境：档位 {os.environ['ANALYSIS_PROFILE']} / 信任上下文 "
          f"{'开' if os.environ.get('TRUST_CONTEXT') != '0' else '关'}")

    root = Path(args.dir)
    benign_files = _load("benign", root)
    phish_files = _load("phishing", root) or _load("fishing", root)
    if not benign_files and not phish_files:
        print(f"未找到标注集：{LABELED}/benign 与 {LABELED}/phishing 都为空。\n"
              "先分析邮件并在 GUI「人工判定」里标注，然后用导出功能生成标注集。")
        return 1
    print(f"标注集：正常 {len(benign_files)} 封 / 钓鱼 {len(phish_files)} 封")

    benign = _analyze(benign_files)
    phish = _analyze(phish_files)
    if benign:
        print(f"正常样本被关注（误报）: {_flagged(benign)}/{len(benign)} "
              f"= {_flagged(benign) / len(benign) * 100:.1f}%")
    if phish:
        print(f"钓鱼样本被拦截（召回）: {_flagged(phish)}/{len(phish)} "
              f"= {_flagged(phish) / len(phish) * 100:.1f}%")

    # ① 区分度
    b_hits: Counter = Counter(sid for r in benign for sid, _ in r["signals"])
    p_hits: Counter = Counter(sid for r in phish for sid, _ in r["signals"])
    candidates = sorted(b_hits, key=lambda s: -b_hits[s])
    print(f"\n【区分度】触发率：正常侧 / 钓鱼侧（按正常侧触发数排序，候选=正常侧 >0）")
    print(f"  {'信号':<34}{'正常':>8}{'钓鱼':>8}   判读")
    for sid in candidates[:args.top]:
        bn, pn = b_hits[sid], p_hits[sid]
        b_rate = bn / max(len(benign), 1)
        p_rate = pn / max(len(phish), 1)
        verdict = ("噪声候选（正常侧高、钓鱼侧低）" if b_rate > p_rate
                   else "有效信号（钓鱼侧不低，勿动）")
        print(f"  {sid:<34}{bn:>8}{pn:>8}   {verdict}")

    if not args.simulate:
        print("\n（加 --simulate 跑降权模拟：每个候选按系数重跑标注集，给出净收益排序）")
        return 0

    # ② 降权模拟 + ③ 建议
    from app.scoring.trust import NEVER_DEMOTE

    base_b, base_p = _flagged(benign), _flagged(phish)
    print(f"\n【降权模拟】系数 ×{args.factor}（基线：正常误报 {base_b}、钓鱼拦截 {base_p}）")
    print(f"  {'信号':<34}{'误报减少':>10}{'召回损失':>10}{'净收益':>8}  建议")
    results = []
    for sid in candidates[:args.top]:
        if sid in NEVER_DEMOTE:
            continue
        nb = _simulate(sid, args.factor, benign_files, "benign")["flagged"]
        np_ = _simulate(sid, args.factor, phish_files, "phishing")["flagged"] if phish_files else base_p
        if nb is None:
            continue
        gain, loss = base_b - nb, base_p - (np_ if np_ is not None else base_p)
        advice = ("可降权" if gain > 0 and loss == 0
                  else f"伤召回 {loss} 封，不建议" if loss else "无收益")
        results.append((gain, loss, sid, advice))
        print(f"  {sid:<34}{gain:>10}{loss:>10}{gain - loss:>8}  {advice}")
    if results:
        best = max(results)
        print(f"\n结论：净收益最高的是 {best[2]}（+{best[0]} 误报 / -{best[1]} 召回）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
