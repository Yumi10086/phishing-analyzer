"""Enron-Spam 语料 -> .eml 转换器。

源数据结构（Metsis 版）：
  enron{1..6}/{ham,spam}/NNNN.YYYY-MM-DD.username.{ham,spam}.txt
  文件内容**只有一行 `Subject:` + 正文**——出题方在制作语料时剥离了全部邮件头部
  （From / To / Received / Return-Path / Authentication-Results 均不存在）。

转换策略（保真优先，绝不虚构事实）：
  ✅ 还原 Subject（源文件首行）与正文（其余内容）
  ✅ 还原 Date（来自文件名中的 YYYY-MM-DD——数据集文档化的命名约定）
  ✅ 以 X-Enron-* 头保留溯源信息（fold / owner / 原文件名）
  ❌ **不虚构 From / To / Reply-To / Authentication-Results**：这些字段源数据中不存在，
     凭空生成会制造出原邮件没有的信号（如伪造的 SPF 结果、伪造的发件域），
     从而污染误报基线。缺失头部是本语料的既有特征，已在 README 中说明。

编码：先按 UTF-8 解码，失败则退到 cp1252（该年代邮件常见），最后 latin-1 兜底；
     写出时统一以 UTF-8 编码并声明 charset，字符内容不丢失。

用法：
  python scripts/enron_to_eml.py --src ../enron --out data/enron_eml
  python scripts/enron_to_eml.py --src ../enron --out data/enron_eml --limit 500
"""
from __future__ import annotations

import argparse
import datetime
import re
import sys
from email.message import EmailMessage
from email.utils import format_datetime
from pathlib import Path

# 文件名：0001.1999-12-10.farmer.ham.txt
_NAME_RE = re.compile(
    r"^(?P<seq>\d+)\.(?P<date>\d{4}-\d{2}-\d{2})\.(?P<owner>.+?)\.(?P<kind>ham|spam)\.txt$",
    re.IGNORECASE,
)


def decode_bytes(raw: bytes) -> tuple[str, str]:
    """返回 (文本, 使用的编码名)。"""
    for enc in ("utf-8", "cp1252", "latin-1"):
        try:
            return raw.decode(enc), enc
        except UnicodeDecodeError:
            continue
    return raw.decode("utf-8", errors="replace"), "utf-8/replace"


def split_subject_body(text: str) -> tuple[str, str]:
    """源文件首行是 `Subject: ...`，其余为正文。"""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    subject = ""
    body_start = 0
    if lines and lines[0].lower().startswith("subject:"):
        subject = lines[0].split(":", 1)[1].strip()
        body_start = 1
    # 去掉标题后的首个空行
    while body_start < len(lines) and not lines[body_start].strip():
        body_start += 1
    return subject, "\n".join(lines[body_start:])


def build_eml(subject: str, body: str, date: str, fold: str, owner: str,
              source_name: str) -> EmailMessage:
    msg = EmailMessage()
    msg["Subject"] = subject or "(no subject)"
    # 注意：Date 头必须是 RFC 2822 格式。写成 ISO 8601（1999-12-10T00:00:00+00:00）
    # 会让 policy.default 下的解析器判定为非法日期并返回空值。
    if date:
        try:
            dt = datetime.datetime.strptime(date, "%Y-%m-%d").replace(
                tzinfo=datetime.timezone.utc)
            msg["Date"] = format_datetime(dt)
        except ValueError:
            pass  # 文件名日期异常时宁可不写，也不写入非法值
    # 溯源信息（不影响任何评分规则——规则不读取 X- 头）
    msg["X-Enron-Fold"] = fold
    msg["X-Enron-Owner"] = owner
    msg["X-Enron-Source"] = source_name
    msg.set_content(body or "")
    return msg


def main() -> int:
    ap = argparse.ArgumentParser(description="Enron 语料 -> .eml 转换")
    ap.add_argument("--src", required=True, help="Enron 根目录（含 enron1..6）")
    ap.add_argument("--out", required=True, help="输出目录（生成 ham/ spam/）")
    ap.add_argument("--limit", type=int, default=0, help="每个子集最多转换 N 封（0=全部）")
    ap.add_argument("--quiet", action="store_true")
    args = ap.parse_args()

    src = Path(args.src)
    if not src.is_dir():
        print(f"源目录不存在: {src}")
        return 1
    out_root = Path(args.out)
    for kind in ("ham", "spam"):
        (out_root / kind).mkdir(parents=True, exist_ok=True)

    folds = sorted(d for d in src.iterdir() if d.is_dir() and d.name.startswith("enron"))
    if not folds:
        print(f"{src} 下未找到 enron1..6 子目录")
        return 1

    counts = {"ham": 0, "spam": 0}
    enc_stats: dict[str, int] = {}
    skipped = 0

    for fold in folds:
        for kind in ("ham", "spam"):
            sub = fold / kind
            if not sub.is_dir():
                continue
            n_this = 0
            for f in sorted(sub.iterdir()):
                if f.suffix.lower() != ".txt" or f.name == "Summary.txt":
                    continue
                if args.limit and n_this >= args.limit:
                    break
                m = _NAME_RE.match(f.name)
                if not m:
                    skipped += 1
                    continue
                text, enc = decode_bytes(f.read_bytes())
                enc_stats[enc] = enc_stats.get(enc, 0) + 1
                subject, body = split_subject_body(text)
                msg = build_eml(subject, body, m.group("date"), fold.name,
                                m.group("owner"), f.name)
                counts[kind] += 1
                dest = out_root / kind / f"{fold.name}-{kind}-{counts[kind]:06d}.eml"
                dest.write_bytes(msg.as_bytes())
                n_this += 1
            if not args.quiet:
                print(f"  {fold.name}/{kind}: {n_this} 封")

    total = counts["ham"] + counts["spam"]
    print(f"\n完成: ham={counts['ham']}, spam={counts['spam']}, 合计={total}"
          f"{f', 文件名不合规跳过={skipped}' if skipped else ''}")
    print(f"编码分布: {enc_stats}")
    print(f"输出: {out_root}")
    print("说明: 未生成 From/To/Reply-To/认证头——源语料不存在这些字段，虚构会污染基线。")
    return 0


if __name__ == "__main__":
    sys.exit(main())
