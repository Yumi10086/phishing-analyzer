"""现代邮件语料基线评估（**权威误报/召回门禁**）：`data/dataset_eml` 混淆矩阵。

约定（见 README「基线语料约定」）：本语料是项目**主基线**——含完整头部与认证结果，
是唯一能同时覆盖头部/认证/正文字段规则的语料。Enron 语料降为**补充**参考
（它只剩 Subject+正文，且正文里的 URL 是被脱敏过的空格写法，URL 类规则在它上面空转）。

用法：
  python scripts/eval_modern_baseline.py                       # 全量 5 万 ham + 5 万 spam
  python scripts/eval_modern_baseline.py --limit 1500          # 抽样快速跑（与回归测试同口径）
  python scripts/eval_modern_baseline.py --out data/eval_modern.csv

输出：混淆矩阵、精确率/召回率/F1、误报驱动规则 TOP、最严重误报样本明细。
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.pipeline import analyze_bytes  # noqa: E402

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DIR = PROJECT_ROOT / "data" / "dataset_eml"


async def _run(kind: str, files: list[Path], limit: int) -> list[dict]:
    rows: list[dict] = []
    t0 = time.perf_counter()
    for i, f in enumerate(files, 1):
        try:
            r = await analyze_bytes(f.read_bytes(), filename=f.name, offline=True, save=False)
        except Exception as exc:  # noqa: BLE001 - 单封失败不中断基线
            print(f"  [解析失败] {f.name}: {str(exc)[:80]}", flush=True)
            continue
        rows.append({
            "filename": f.name, "verdict": r["verdict"], "score": r["score"],
            "raw_points": r.get("score_breakdown", {}).get("raw_signals_points", 0),
            "signals": ";".join(s["id"] for s in r["signals"]),
        })
        if i % 5000 == 0:
            el = time.perf_counter() - t0
            print(f"  {kind} {i}/{len(files)} ({i / el:.0f}/s, 已用 {el:.0f}s)", flush=True)
    return rows


def _collect(d: Path, limit: int, seed: int) -> list[Path]:
    fs = sorted(p for p in d.rglob("*") if p.is_file() and p.suffix.lower() == ".eml")
    if limit and limit < len(fs):
        import random
        random.seed(seed)
        return random.sample(fs, limit)
    return fs


def _summarize(label: str, rows: list[dict]) -> None:
    n = len(rows)
    if not n:
        print(f"{label}: 无样本")
        return
    c = Counter(r["verdict"] for r in rows)
    flagged = n - c.get("BENIGN", 0)
    print(f"{label}: n={n}  flagged={flagged} ({flagged / n:.2%})  "
          f"MALICIOUS={c.get('MALICIOUS', 0)} ({c.get('MALICIOUS', 0) / n:.2%})  "
          f"平均分={sum(r['score'] for r in rows) / n:.1f}")


def main() -> int:
    ap = argparse.ArgumentParser(description="现代邮件语料基线评估（离线）")
    ap.add_argument("--dir", default=str(DEFAULT_DIR))
    ap.add_argument("--limit", type=int, default=0, help="每类最多 N 封（0=全量）")
    ap.add_argument("--seed", type=int, default=20260913)
    ap.add_argument("--out", default="", help="误报明细 CSV 输出路径（可选）")
    args = ap.parse_args()

    root = Path(args.dir)
    ham_dir, spam_dir = root / "ham", root / "spam"
    if not (ham_dir.is_dir() and spam_dir.is_dir()):
        print(f"语料目录结构不符（需 {root}/ham 与 {root}/spam），请先运行 "
              f"scripts/csv_to_eml.py 生成")
        return 1

    ham_files = _collect(ham_dir, args.limit, args.seed)
    spam_files = _collect(spam_dir, args.limit, args.seed)
    print(f"基线语料: {root}\n  ham {len(ham_files)} 封 / spam {len(spam_files)} 封（离线模式）\n",
          flush=True)

    ham = asyncio.run(_run("ham", ham_files, args.limit))
    spam = asyncio.run(_run("spam", spam_files, args.limit))

    print("\n========== 混淆矩阵 ==========")
    ham_fp = sum(1 for r in ham if r["verdict"] != "BENIGN")
    ham_mal = sum(1 for r in ham if r["verdict"] == "MALICIOUS")
    spam_tp = sum(1 for r in spam if r["verdict"] != "BENIGN")
    print(f"ham  {len(ham):6d}: FP={ham_fp} ({ham_fp / len(ham):.2%})  "
          f"MALICIOUS误报={ham_mal} ({ham_mal / len(ham):.2%})  TN={len(ham) - ham_fp}")
    print(f"spam {len(spam):6d}: TP={spam_tp} 召回={spam_tp / len(spam):.2%}  "
          f"FN={len(spam) - spam_tp} ({1 - spam_tp / len(spam):.2%})")

    prec = spam_tp / (spam_tp + ham_fp) if (spam_tp + ham_fp) else 0.0
    rec = spam_tp / len(spam) if spam else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    print(f"\n精确率 {prec:.2%} ｜ 召回率 {rec:.2%} ｜ F1 {f1:.2%}")
    print("\n门禁阈值：ham FP ≤2.5%、ham MALICIOUS ≤0.3%、spam flagged ≥93%")

    fp_rows = [r for r in ham if r["verdict"] != "BENIGN"]
    if fp_rows:
        sig = Counter()
        for r in fp_rows:
            for s in (r["signals"] or "").split(";"):
                if s:
                    sig[s] += 1
        print(f"\n误报驱动规则 TOP10（共 {len(fp_rows)} 例误报）:")
        for sid, cnt in sig.most_common(10):
            print(f"  {sid:34s} {cnt:5d}")
        print("\n最严重误报样本:")
        for r in sorted(fp_rows, key=lambda x: -x["score"])[:8]:
            print(f"  [{r['score']:3d}] {r['verdict']:10s} {r['filename']}  {r['signals'][:90]}")

    if args.out:
        out = Path(args.out)
        out.parent.mkdir(parents=True, exist_ok=True)
        with out.open("w", newline="", encoding="utf-8-sig") as fh:
            w = csv.DictWriter(fh, fieldnames=list(ham[0].keys()))
            w.writeheader()
            w.writerows(fp_rows)
        print(f"\n误报明细已写入 {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
