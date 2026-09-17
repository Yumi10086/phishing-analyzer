"""trec06c 中文语料评估：ham 误报率 / spam 召回率 / 误降档检查。

语料：TREC 2006 中文邮件集（CCERT），data/trec06c，full/index 每行 `[标签] [路径]`。
用途：中文规则的 FP 门禁基线——此前中文规则（补贴/礼品/品牌冒充等）从未在真实
中文正常邮件上校准过。

用法：
  python scripts/eval_trec06c.py --sample 3000 --seed 20260914
  python scripts/eval_trec06c.py --sample 0   # 全量（约 6.5 万封，慢）

正文不可用（解码后 text+html 均为空，多为语料内二进制损坏件）的邮件按约定
直接排除出评估，单独计数留痕——它们既无法贡献正文信号，统计 FP/召回也会失真。
"""
from __future__ import annotations

import argparse
import asyncio
import csv
import random
import sys
from collections import Counter
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.pipeline import analyze_bytes  # noqa: E402

CORPUS = Path(__file__).resolve().parent.parent / "data" / "trec06c"


def _eval_one(path_str: str, label: str) -> dict | None:
    """worker：单封分析。正文不可用返回 None（排除计数）。"""
    try:
        p = Path(path_str)
        raw = p.read_bytes()
        r = asyncio.run(analyze_bytes(raw, p.name, offline=True, save=False))
        return {
            "label": label,
            "file": str(p),
            "score": r["score"],
            "verdict": r["verdict"],
            "category": r.get("category", "unknown"),
            "signals": ";".join(s["id"] for s in r["signals"]),
            "subject": r.get("subject", ""),
        }
    except Exception as exc:  # noqa: BLE001
        print(f"[跳过] {path_str}: {exc}", file=sys.stderr)
        return None


def _usable(path_str: str) -> bool:
    """正文可用性判定（排除二进制损坏件）。"""
    from app.parser.eml_parser import parse_eml
    try:
        parsed = parse_eml(Path(path_str).read_bytes())
        return bool((parsed.get("body_text", "") + parsed.get("body_html", "")).strip())
    except Exception:  # noqa: BLE001
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="trec06c 中文语料评估")
    parser.add_argument("--sample", type=int, default=3000, help="每类抽样 N 封（0=全量）")
    parser.add_argument("--seed", type=int, default=20260914)
    parser.add_argument("--workers", type=int, default=8)
    parser.add_argument("--out", default="data/eval_trec06c.csv")
    args = parser.parse_args()

    index = CORPUS / "full" / "index"
    entries: list[tuple[str, Path]] = []
    for line in index.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) == 2:
            label, rel = parts
            entries.append((label, (CORPUS / rel.replace("../", "")).resolve()))

    rng = random.Random(args.seed)
    picked: list[tuple[str, Path]] = []
    for label in ("ham", "spam"):
        pool = [e for e in entries if e[0] == label]
        if args.sample and args.sample < len(pool):
            pool = rng.sample(pool, args.sample)
        picked += pool
    print(f"抽样 {len(picked)} 封（ham/spam 各约 {len(picked)//2}，seed={args.seed}），workers={args.workers}")

    # 先过滤正文不可用件（worker 内做太浪费进程，这里串行快速判定）
    usable: list[tuple[str, Path]] = []
    dropped = Counter()
    for label, p in picked:
        if _usable(str(p)):
            usable.append((label, p))
        else:
            dropped[label] += 1
    print(f"正文不可用（二进制损坏/空）排除: ham {dropped['ham']} / spam {dropped['spam']}（按约定不计入评估）")
    print(f"参与评估 {len(usable)} 封，开始分析...")

    with ProcessPoolExecutor(max_workers=args.workers) as pool:
        results = pool.map(_eval_one, [str(p) for _, p in usable],
                           [l for l, _ in usable], chunksize=16)
    rows = [r for r in results if r]
    if not rows:
        print("无可用结果")
        return

    by_label: dict[str, list[dict]] = {"ham": [], "spam": []}
    for r in rows:
        by_label.setdefault(r["label"], []).append(r)

    print("\n===== HAM（中文正常邮件）=====")
    ham = by_label["ham"]
    n_ham = len(ham)
    vc_ham = Counter(r["verdict"] for r in ham)
    fp = vc_ham.get("SUSPICIOUS", 0) + vc_ham.get("MALICIOUS", 0)
    print(f"共 {n_ham} 封 | verdict: {dict(vc_ham.most_common())}")
    print(f"误报率（SUSPICIOUS+MALICIOUS）: {fp}/{n_ham} = {fp / n_ham * 100:.2f}%")
    demoted = vc_ham.get("SPAM", 0)
    print(f"误降档（正常邮件被判 SPAM=误进垃圾箱）: {demoted}/{n_ham} = {demoted / n_ham * 100:.2f}%")
    bad = [r for r in ham if r["verdict"] in ("SUSPICIOUS", "MALICIOUS", "SPAM")]
    print("FP/误降档驱动信号 TOP:")
    for s, c in Counter(sig for r in bad for sig in r["signals"].split(";") if sig).most_common(10):
        print(f"    {s}: {c}")
    print("最严重误报样本 TOP10:")
    for r in sorted(bad, key=lambda x: -x["score"])[:10]:
        print(f"    [{r['verdict'][:4]} {r['score']:3d}] {r['subject'][:46]}")

    print("\n===== SPAM（中文垃圾邮件）=====")
    spam = by_label["spam"]
    n_spam = len(spam)
    vc_spam = Counter(r["verdict"] for r in spam)
    flagged = n_spam - vc_spam.get("BENIGN", 0)
    print(f"共 {n_spam} 封 | verdict: {dict(vc_spam.most_common())}")
    print(f"flagged 召回: {flagged}/{n_spam} = {flagged / n_spam * 100:.1f}%")
    print(f"其中 MALICIOUS {vc_spam.get('MALICIOUS', 0)} / SPAM 档 {vc_spam.get('SPAM', 0)}")

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", newline="", encoding="utf-8-sig") as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    print(f"\n明细已写入 {out}")


if __name__ == "__main__":
    main()
