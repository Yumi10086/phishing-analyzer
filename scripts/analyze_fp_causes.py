"""误报归因分析：读基线评估产出的误报明细 CSV，量化每条规则对误报的贡献。

与 `eval_modern_baseline.py` 配套：先跑基线得到误报明细，再用本脚本回答
"误报主要由谁造成、各占多少、修掉某条规则能消掉多少"。

归因口径（三种互补，避免单一视角误导）：
  1. **出现占比**：某规则出现在多少比例的误报里（易高估：弱信号常与强信号同时出现）；
  2. **单信号致误**：只有一条信号就跨过阈值的误报——归因唯一、最干净；
  3. **留一法（leave-one-out）**：把某条规则从误报邮件的信号里去掉后重新算分，
     看有多少例会落回 BENIGN。这是"调这条规则能省多少人工"的直接估计。
     注意 signal_stack 是按其之前求值的信号数动态给分的，留一后需重算。

用法：
  python scripts/analyze_fp_causes.py                       # 默认读 data/eval_modern_baseline.csv
  python scripts/analyze_fp_causes.py --csv path/to/fp.csv
"""
from __future__ import annotations

import argparse
import csv
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.scoring.rule_loader import get_rule_engine  # noqa: E402

# 离线归一化下的判定：score = round(raw / 45 * 100)，BENIGN < 30 -> raw < 13.5
_OFFLINE_MAX = 45
_THRESHOLD_SUSPICIOUS = 30
_STACK_ID = "signal_stack"
_STACK_TIERS = ((6, 12), (5, 8), (4, 4))   # 与 rules/builtin/header_rules.yaml 一致


def _raw_for(signals: list[str], points: dict[str, int], pre_stack: set[str]) -> int:
    """给定**启发式信号**集合，重算启发式部分原始分（signal_stack 动态求值）。"""
    base = [s for s in signals if s != _STACK_ID]
    raw = sum(points.get(s, 0) for s in base)
    n = len([s for s in base if s in pre_stack])
    for need, pts in _STACK_TIERS:
        if n >= need:
            raw += pts
            break
    return raw


# 离线归一化：total = round((intel + auth + heuristic) / 45 * 100)
# CSV 只带启发式原始分，故用 score 反推总分：total_raw ≈ score / 100 * 45，
# 差额即"认证维度（+情报）"的分数——它不随启发式信号增删而变，可作为常量保留。
def _total_raw(score: int) -> float:
    return score / 100 * _OFFLINE_MAX


def _is_fp(total_raw: float) -> bool:
    """raw >= 13.5 才会被判为可疑/恶意（round(13.5/45*100)=30）。"""
    return total_raw >= 13.5


def main() -> int:
    ap = argparse.ArgumentParser(description="误报归因分析")
    ap.add_argument("--csv", default="data/eval_modern_baseline.csv",
                    help="基线误报明细 CSV（eval_modern_baseline.py --out 产出）")
    args = ap.parse_args()

    path = Path(args.csv)
    if not path.is_file():
        print(f"未找到误报明细 {path}；请先运行："
              f"python scripts/eval_modern_baseline.py --out {path}")
        return 1

    rows = list(csv.DictReader(path.open(encoding="utf-8-sig")))
    if not rows:
        print("误报明细为空（该语料零误报）")
        return 0

    engine = get_rule_engine()
    points = {r.id: r.points for r in engine.rules}
    order = [r.id for r in engine.rules]
    pre_stack = set(order[:order.index(_STACK_ID)])

    total = len(rows)
    verdicts = Counter(r["verdict"] for r in rows)
    scores = [int(r["score"]) for r in rows]
    print(f"误报总数 {total}（SUSPICIOUS {verdicts.get('SUSPICIOUS', 0)}、"
          f"MALICIOUS {verdicts.get('MALICIOUS', 0)}）")
    print(f"分数区间 {min(scores)}–{max(scores)}，中位 {sorted(scores)[total // 2]}")

    # ---- 口径 1：出现占比 ----
    present = Counter()
    for r in rows:
        for s in filter(None, (r["signals"] or "").split(";")):
            present[s] += 1
    print(f"\n【口径 1】出现在误报中的次数（共 {total} 例，可多信号叠加）")
    print(f"  {'规则':<34}{'例数':>6}{'占比':>9}")
    for sid, n in present.most_common():
        print(f"  {sid:<34}{n:>6}{n / total:>8.1%}")

    # ---- 口径 2：单信号致误 ----
    single = Counter()
    for r in rows:
        sigs = [s for s in filter(None, (r["signals"] or "").split(";"))]
        if len(sigs) == 1:
            single[sigs[0]] += 1
    n_single = sum(single.values())
    print(f"\n【口径 2】单信号即跨阈值（归因唯一）：{n_single} 例（{n_single / total:.1%}）")
    for sid, n in single.most_common():
        print(f"  {sid:<34}{n:>6} 例")

    # ---- 口径 3：留一法 ----
    print(f"\n【口径 3】留一法：去掉该规则后落回 BENIGN 的例数（= 调它可消除的误报）")
    print(f"  {'规则':<34}{'可消除':>8}{'占误报':>9}{'剩余仍误报':>12}")
    # 每封误报的"非启发式部分"（认证维度 + 情报，离线时情报为 0），
    # 用 score 反推总分再减去启发式原始分得到；它不随启发式信号增删变化。
    others = {}
    for i, r in enumerate(rows):
        sigs = [s for s in filter(None, (r["signals"] or "").split(";"))]
        others[i] = _total_raw(int(r["score"])) - _raw_for(sigs, points, pre_stack)

    loo = {}
    for sid in present:
        saved = 0
        for i, r in enumerate(rows):
            sigs = [s for s in filter(None, (r["signals"] or "").split(";"))]
            if sid not in sigs:
                continue
            rest = [s for s in sigs if s != sid]
            new_raw = others[i] + _raw_for(rest, points, pre_stack)
            if not _is_fp(new_raw):
                saved += 1
        loo[sid] = saved
    for sid, saved in sorted(loo.items(), key=lambda kv: -kv[1]):
        print(f"  {sid:<34}{saved:>8}{saved / total:>8.1%}{present[sid] - saved:>12}")

    # ---- 组合视角 ----
    combos = Counter()
    for r in rows:
        sigs = tuple(sorted(filter(None, (r["signals"] or "").split(";"))))
        combos[sigs] += 1
    print(f"\n【组合】最常见的信号组合 TOP10")
    for sigs, n in combos.most_common(10):
        print(f"  {n:>4} 例  {' + '.join(sigs)}")

    # ---- 可归为"语料认证噪声"的部分 ----
    noise_only = sum(
        1 for r in rows
        if set(filter(None, (r["signals"] or "").split(";"))) == {"header_auth_inconsistent"})
    noise_dep = loo.get("header_auth_inconsistent", 0)
    print(f"\n【语料噪声】完全由 header_auth_inconsistent 单独触发：{noise_only} 例"
          f"（{noise_only / total:.1%}）")
    print(f"          去掉该规则即可落回 BENIGN：{noise_dep} 例（{noise_dep / total:.1%}）")
    real_fp = total - noise_dep
    print(f"          扣除后其余误报：{real_fp} 例"
          f"（按 ham 5 万封算，误报率约 {real_fp / 50000:.2%}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
