"""CSV 邮件数据集 -> .eml 批量转换器。

适配 email_dataset_100k.csv（raw_text, subject, body_plain, body_html,
from_address, from_domain, reply_to, ..., spf/dkim/dmarc_result, label 等 30 列）：
重建为标准 MIME .eml，供分析流水线（parser -> extractor -> 评分）消费。

转换要点（与真实 MTA 投递尽可能对齐）：
  - From / To / Reply-To / Return-Path / Message-ID / Date 原样重建
  - SPF/DKIM/DMARC 重建为标准 Authentication-Results 头（auth_checker 的解析目标）
  - body_html 存在时构造 multipart/alternative（text + html）
  - attachment_types 列（"a.pdf;b.ics"）以占位字节生成附件（文件名保留，类型真实）
  - ham -> out_dir/ham/，spam -> out_dir/spam/（目录隔离，误报基线只吃 ham）

用法：
  python scripts/csv_to_eml.py --csv ../email_dataset_100k.csv --out data/dataset_eml --limit-ham 3000 --limit-spam 3000
"""
from __future__ import annotations

import argparse
import csv
import re
import sys
from email.message import EmailMessage
from email.utils import formatdate, make_msgid
from pathlib import Path

# 占位附件内容（非可执行，仅保留文件名/类型供启发式与哈希提取）
_PLACEHOLDER = b"csv-dataset-placeholder-attachment-bytes" * 8


def _clean_addr(value: str) -> str:
    value = (value or "").strip()
    return value.strip("<>").strip()


def _auth_header(spf: str, dkim: str, dmarc: str, from_domain: str) -> str:
    domain = (from_domain or "unknown.invalid").strip()
    return (f"mx.receiver.example; spf={spf or 'none'} smtp.mailfrom={domain}; "
            f"dkim={dkim or 'none'} header.d={domain}; dmarc={dmarc or 'none'} "
            f"header.from={domain}")


def row_to_eml(row: dict) -> EmailMessage:
    msg = EmailMessage()
    from_addr = _clean_addr(row.get("from_address")) or "unknown@unknown.invalid"
    from_domain = (row.get("from_domain") or "").strip() or from_addr.rsplit("@", 1)[-1]

    msg["From"] = from_addr
    to_addr = _clean_addr(row.get("to_addresses"))
    msg["To"] = to_addr if to_addr else "undisclosed-recipients:;"
    if _clean_addr(row.get("reply_to")):
        msg["Reply-To"] = _clean_addr(row["reply_to"])
    # Return-Path 用 from 域（数据集未提供 envelope-from，与 From 同域为最常见形态）
    msg["Return-Path"] = f"<bounce@{from_domain}>"
    msg["Subject"] = (row.get("subject") or "").strip() or "(no subject)"
    msg["Message-ID"] = (row.get("message_id") or "").strip("<>") or make_msgid(domain=from_domain)
    date = (row.get("date") or "").strip()
    if date:
        msg["Date"] = date
    else:
        msg["Date"] = formatdate(localtime=False)
    msg["Authentication-Results"] = _auth_header(
        row.get("spf_result"), row.get("dkim_result"), row.get("dmarc_result"), from_domain)
    ua = (row.get("user_agent") or "").strip()
    if ua:
        msg["User-Agent"] = ua

    # 正文：plain + html -> multipart/alternative
    plain = (row.get("body_plain") or "").strip()
    html = (row.get("body_html") or "").strip()
    if plain and html:
        msg.set_content(plain)
        msg.add_alternative(html, subtype="html")
    elif html:
        msg.set_content(html, subtype="html")
    else:
        msg.set_content(plain or "")

    # 附件：attachment_types "a.pdf;b.ics" -> 占位附件
    att_types = (row.get("attachment_types") or "").strip()
    if att_types and row.get("has_attachments", "").strip().lower() in ("true", "1", "yes"):
        for name in re.split(r"[;]", att_types):
            name = name.strip()
            if not name:
                continue
            ext = name.rsplit(".", 1)[-1].lower() if "." in name else "bin"
            maintype = ("image" if ext in {"png", "jpg", "jpeg", "gif"}
                        else "application")
            subtype = {"pdf": "pdf", "ics": "calendar", "zip": "zip",
                       "doc": "msword", "docx": "vnd.openxmlformats-officedocument"
                                             ".wordprocessingml.document"}.get(ext, "octet-stream")
            msg.add_attachment(_PLACEHOLDER, maintype=maintype, subtype=subtype,
                               filename=name)
    return msg


def main() -> int:
    parser = argparse.ArgumentParser(description="CSV 邮件数据集 -> .eml 转换")
    parser.add_argument("--csv", required=True)
    parser.add_argument("--out", required=True, help="输出根目录（生成 ham/ spam/ 子目录）")
    parser.add_argument("--limit-ham", type=int, default=0, help="最多转换 N 封 ham（0=全部）")
    parser.add_argument("--limit-spam", type=int, default=0, help="最多转换 N 封 spam（0=全部）")
    parser.add_argument("--sample", type=int, default=0, help="随机抽样总量 N 后再分 ham/spam")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    src = Path(args.csv)
    if not src.is_file():
        print(f"CSV 不存在: {src}")
        return 1

    out_root = Path(args.out)
    (out_root / "ham").mkdir(parents=True, exist_ok=True)
    (out_root / "spam").mkdir(parents=True, exist_ok=True)

    rows = []
    with src.open(encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    print(f"读取 CSV: {len(rows)} 行")

    if args.sample and args.sample < len(rows):
        import random
        random.seed(args.seed)
        rows = random.sample(rows, args.sample)
        print(f"随机抽样: {len(rows)} 行")

    n_ham = n_spam = 0
    for row in rows:
        label = (row.get("label") or "").strip()
        kind = "ham" if label == "0" else "spam"
        if kind == "ham" and args.limit_ham and n_ham >= args.limit_ham:
            continue
        if kind == "spam" and args.limit_spam and n_spam >= args.limit_spam:
            continue
        try:
            msg = row_to_eml(row)
        except Exception as exc:  # noqa: BLE001
            print(f"  转换失败（跳过）: {exc}")
            continue
        idx = n_ham + n_spam
        dest = out_root / kind / f"{kind}-{idx:06d}.eml"
        dest.write_bytes(msg.as_bytes())
        if kind == "ham":
            n_ham += 1
        else:
            n_spam += 1

    print(f"完成: ham={n_ham}, spam={n_spam} -> {out_root}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
