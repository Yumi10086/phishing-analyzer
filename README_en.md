# 🛡️ Phishing Analyzer — Automated Phishing Email Triage & Response

[**中文**](README.md) ｜ **English**

An automated phishing-email triage pipeline for SOC workflows: **ingest → parse → IOC extraction → threat-intel enrichment → weighted scoring → 3-tier verdict → report / ticket**. It also supports **read-only ingestion of personal mailboxes (IMAP)**, **deep attachment analysis**, and a **human-feedback loop**.

![Python](https://img.shields.io/badge/Python-3.9%2B-blue) ![FastAPI](https://img.shields.io/badge/API-FastAPI-009688) ![Streamlit](https://img.shields.io/badge/GUI-Streamlit-FF4B4B) ![Offline](https://img.shields.io/badge/offline-capable-brightgreen)

> 🔐 **Security notice**: every bundled sample is **100% synthetic** (RFC 2606 reserved domains, RFC 5737 documentation IPs, placeholder attachments). Safe to clone, run, demo and open-source.

## Features

- **Parsing**: `.eml` (stdlib) and `.msg` (extract-msg); headers, SPF/DKIM/DMARC results, body, attachment hashes. Includes Chinese-encoding fixes (declared `gb2312` that is really GBK/UTF-8, broken MIME structure, RFC2047 filenames).
- **IOC extraction**: URLs, domains, IPs, file hashes; reverses real attacker obfuscation (zero-width, soft hyphens, full-width chars, HTML entities, Cyrillic homoglyphs); detects shorteners, punycode and raw-IP URLs; separates public from private IPs.
- **Threat-intel enrichment**: VirusTotal v3 + AbuseIPDB + URLScan.io (passive search by default, never auto-submits scans); async fan-out + SQLite cache + token-bucket rate limiting. Results are scored by semantics — `hit` / `clean` / `unknown` — so "never seen by intel" is never treated as "confirmed clean". **Well-known domains skip the domain-endpoint lookup** (`rules/dicts/trusted_domains.txt`, sourced from MISP warninglists / CC0): their domain records are clean anyway, and skipping them saved **46.8%** of domain lookups on a real mailbox. URL-level lookups are unaffected (that is how phishing hosted on a subdomain/path of a well-known platform stays visible), and the report marks them as "known well-known domain, not queried" rather than dropping them silently.
- **Weighted scoring**: intel 55% + auth 15% + heuristics 30% → `BENIGN / SUSPICIOUS / MALICIOUS` with a full **explainable reason list**. Offline mode normalizes across available dimensions while keeping threshold semantics.
- **Rules as data (SIEM style)**: **88** scoring rules declared in `rules/builtin/*.yaml` (points and enable/disable adjustable at runtime); custom rules in `rules/custom/` override by id; **19** dictionaries (brands, TLDs, shorteners, keywords, risky extensions, freemail, link allowlist…). Rule CRUD API + hot reload; reports record a ruleset version hash for reproducibility.
- **Deep attachment analysis**: pure-Python magic-byte type sniffing (no libmagic), three-way type cross-check (declared MIME / extension / real type), tiered risky extensions, archive recursion (encryption flag, password candidates, **pre-extraction bomb guard**), Office (remote template injection / DDE / graded VBA macros via optional oletools), PDF markers (`/JavaScript`, `/Launch`, `/EmbeddedFile`), **YARA** (optional), **image OCR and QR decoding** (optional, in-image URLs feed the intel chain).
- **Spam/marketing vs phishing separation**: category labelling plus conditional `SPAM` demotion, so marketing mail is archived instead of paged to analysts. Demotion requires passing authentication and no strong phishing signals; forgeable headers alone never demote.
- **Personal mailbox ingestion (read-only IMAP)**: incremental fetch, no mailbox side effects, self-sent mail excluded from analysis, and a **sender trust context** that softens wording-class signals for established senders while **hard signals are never suppressed**. The contact history itself is maintained **incrementally** (only newly fetched mail is counted; unchanged input is skipped entirely — ~0.03s per round instead of a 2.9s full rescan).
- **Human feedback loop**: batch-label senders as "legitimate/marketing" or "confirmed phishing" in the GUI (traced, expirable, revocable); export the labelled set as evaluation data to answer "should this rule be down-weighted?".
- **Response**: JSON + HTML reports on disk, optional TheHive ticket creation.
- **Interfaces**: FastAPI (Swagger) + Streamlit multi-page GUI (dashboard / batch / mailbox / review / rules).
- **Performance**: 2–5 ms per offline analysis; multi-process batch; capped OCR session threads to avoid core contention.

## Quick start

```bash
# 1. Install (Python 3.9+, Windows / Linux)
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt      # Linux: .venv/bin/pip

# 2. Configure API keys (optional — empty means offline mode)
cp .env.example .env

# 3. Analyze one mail (8 synthetic samples included)
python -m app.cli analyze data/samples/phishing_01.eml --offline

# 4. Batch a directory
python -m app.cli batch <mail_dir> --offline --limit 100 --out data/results.csv

# 5. Run the API (Swagger: http://127.0.0.1:8000/docs)
python -m app.cli serve --port 8000

# 6. Run the GUI (dashboard / batch / mailbox / review / rules)
pip install streamlit
streamlit run dashboard.py      # http://localhost:8501

# 7. Purge analysis data (reports + index; --include-intel-cache also clears the intel cache)
python -m app.cli purge --yes
```

**Optional dependencies** (missing ones degrade silently without breaking anything):

```bash
pip install streamlit                            # GUI
pip install yara-python                          # YARA rule scanning
pip install oletools                             # Office VBA macro extraction
pip install rapidocr-onnxruntime opencv-python   # image OCR and QR decoding
```

### Personal mailbox (read-only IMAP)

```bash
python -m app.mailbox.fetch --list                                   # folders + sync progress
python -m app.mailbox.fetch --folder INBOX --recent 50               # newest 50 (does not move the cursor)
python -m app.mailbox.fetch --folder INBOX --since-date 2026-08-01 --until-date 2026-08-31
                                                                     # a full month, both ends inclusive
python -m app.mailbox.fetch --folder Junk --folder "Sent Messages"   # junk + sent
python -m app.mailbox.fetch --analyze-only                           # re-analyze already-fetched mail
python -m app.mailbox.fetch --watch --interval 60                    # polling real-time analysis (Ctrl+C to stop)
```

**Fetching analyzes only new mail**: the fetch path hands the analyzer only the **.eml files it just
wrote** (previously it re-scanned every file in the folder — a 1-mail fetch cost a full re-analysis of
several hundred mails: 134 ms each, ~30 s for 600+ with 8 workers, growing linearly). To recompute past
verdicts after a rule change, use the explicit `--analyze-only` entry (GUI: 「重跑本地已取邮件」).

**Fetching by date**: `--since-date` / `--until-date` are **inclusive** endpoints filtered
server-side (`SINCE` / `BEFORE`, so unwanted mail is never downloaded); dates accept
`2026-08-01` or `01-Aug-2026`. This mode **ignores the sync cursor** (a historical window would
otherwise be cut off), and the cursor only ever moves **forward** — so scanning history first and
then running an incremental fetch never re-downloads. The GUI exposes the same semantics as
**“按日期区间”** with a **calendar range picker** (pick a start and an end day, both inclusive).

**Desktop notifications** (`--notify`): pushes `MALICIOUS`/`SUSPICIOUS` as system notifications
(cross-platform, zero extra deps: Windows PowerShell Toast / macOS Notification Center / Linux
`notify-send`; a failed notification is only logged and never blocks analysis). Noise is controlled by
default: only those two verdicts, **one alert per sender per 12h** (`--notify-window`, 0 = off), and at
most 3 pushes per round with a single summary line for the rest. The GUI exposes the same entry
(邮箱取信分析 → 实时监控: start/stop, check-now, test notification, recent alerts, run log).

**Polling real-time analysis** (`--watch`): every `--interval` seconds (default 60, minimum 15) it fetches
new mail and analyzes it, printing one line per round (`N new -> MALICIOUS 1 | BENIGN 2`); `--bell` rings on
suspicious/malicious verdicts. Two properties make it safe to run as a long-lived process: **the UID cursor
advances only after analysis succeeds** (a failed batch is retried next round instead of being silently
skipped) and **it reconnects by itself** on connection errors. Deploy it with your OS scheduler — Windows
Task Scheduler / NSSM service, a systemd unit, or a container sidecar (`restart: unless-stopped`).

Three constraints keep your mailbox untouched: **read-only** (`select(readonly=True)` + `BODY.PEEK[]` — no read flags, no flag writes, no deletes), **incremental** (UID-based with `UIDVALIDITY` tracking, full rescan when it changes), and **size-aware fetch**. Analysis is **offline by default**; `--online` opts into sending IOCs to third-party intel platforms. The GUI exposes the same flow.

## Scoring model

Total 0–100: `< 30 BENIGN ｜ 30–54 SUSPICIOUS ｜ ≥ 55 MALICIOUS` (tunable via `TH_SUSPICIOUS` / `TH_MALICIOUS`)

| Dimension | Weight | Evidence |
|---|---|---|
| Threat-intel hits | 55% | VT engine detections (tiered for reputation IOCs, proportional for AV-style), AbuseIPDB confidence, URLScan verdicts |
| Mail authentication | 15% | SPF/DKIM/DMARC fail/softfail/neutral/none, contradictory auth headers |
| Heuristic rules | 30% | 88 external rules: sender identity, URL traits, link-vs-sender domain lookalike pairing, attachments, body wording, independent-signal stacking |

**Spam/marketing demotion**: when a verdict is above BENIGN, the category is `marketing` (≥2 independent marketing signals, no strong phishing signal, no intel hit) and at least one auth check passes, the verdict becomes `SPAM` (archived, never a security ticket). BENIGN is unaffected.

**Explainability**: every verdict carries a complete `reasons` list; all keyword matching runs on de-obfuscated text; URL de-obfuscation only reverses **real attacker techniques** and deliberately leaves analyst-defanging forms (`hxxp://`, `example[.]com`) alone to avoid reverse false positives.

## Evaluation (measured locally, offline rules only)

Corpora are public datasets you need to fetch yourself; the evaluation scripts live in `scripts/`.

| Corpus | Metric | Result |
|---|---|---|
| **Authority baseline** (100k modern mails: 50k ham + 50k spam) | Precision / Recall / F1 | **99.03% / 99.13% / 99.08%** |
| | ham false-positive / severe (MALICIOUS) FP | **0.97% / 0.00%** |
| [phishing_pot](https://github.com/xffxd/phishing_pot) real phish (first 500) | flagged recall | **74.0%** (80.0% including SPAM demotion) |
| [trec06c](https://trec.nist.gov/data/spam.html) Chinese legitimate mail (652 sampled) | FP / wrong demotion | **0.15% / 0.00%** |
| Enron legitimate mail (16,545) | FP | **0.00%** |
| Personal mailbox (108 real mails, mailbox profile + trust context) | flagged ratio | **9.3%** |

## Configuration

Copy `.env.example` to `.env`; every value may stay empty (the matching intel source degrades, local analysis still works).

| Variable | Default | Description |
|---|---|---|
| `VT_API_KEY` / `ABUSEIPDB_API_KEY` / `URLSCAN_API_KEY` | empty | Threat-intel API keys |
| `URLSCAN_ALLOW_SUBMIT` | `0` | Allow active URLScan submissions (passive search only by default) |
| `INTEL_TIMEOUT` / `INTEL_CONCURRENCY` | `15` / `8` | Intel request timeout / concurrency |
| `VT_RATE_LIMIT` | `4` | VT requests per minute (free-tier limit) |
| `CACHE_TTL_HOURS` | `24` | Intel cache TTL |
| `TH_SUSPICIOUS` / `TH_MALICIOUS` | `30` / `55` | Verdict thresholds |
| `THEHIVE_URL` / `THEHIVE_API_KEY` | empty | TheHive integration |
| `MAILBOX_IMAP_HOST` / `MAILBOX_IMAP_PORT` | `imap.qq.com` / `993` | IMAP server |
| `MAILBOX_IMAP_USER` / `MAILBOX_IMAP_AUTH_CODE` | empty | Account / app-specific authorization code (**not** your login password) |
| `MAILBOX_MAX_BYTES` | `20971520` | Per-mail download cap (checks `RFC822.SIZE` first) |
| `MAILBOX_SKIP_SELF_SENT` / `MAILBOX_OWN_ADDRESSES` | `1` / empty | Exclude self-sent mail / your other addresses (comma-separated) |
| `ANALYSIS_PROFILE` | `gateway` | `gateway` (mail-gateway delivery) or `mailbox` (direct mailbox reads) |
| `TRUST_CONTEXT` | follows profile | Sender trust context switch (`=0` disables, for A/B) |
| `TRUST_MIN_COUNT` / `TRUST_MIN_DOMAIN_COUNT` / `TRUST_MIN_SPAN_DAYS` | `2` / `5` / `14` | Trust thresholds |

## REST API

Interactive docs at `http://127.0.0.1:8000/docs`.

| Method | Path | Purpose |
|---|---|---|
| POST | `/analyze?offline=&create_thehive=` | Upload `.eml`/`.msg` (multipart `file`) → score / verdict / IOCs / reasons |
| GET | `/report/{id}` (`?format=html`) | Fetch a stored report |
| GET | `/report/{id}/download` | Download report file |
| GET | `/reports` / `/reports/stats` | Report index + overview |
| DELETE | `/reports?confirm=true` | Purge analysis data |
| GET | `/health` | Health check |
| GET/POST | `/rules`, `/rules/{id}`, `/rules/reload`, `/rules/dicts`, `/rules/test` | Rule CRUD, dictionaries, hot reload, dry-run |

```bash
curl -X POST "http://127.0.0.1:8000/analyze?offline=true" -F "file=@data/samples/phishing_01.eml"
```

## Architecture

> 🔍 **Interactive diagram**: [`架构图/architecture.html`](架构图/architecture.html) — open in a browser (dark/light themes, pan & zoom, node search, trace, export).

```text
.eml/.msg → parser → extractor (IOC + auth)
   → attachment (type sniffing / archive / Office / PDF / YARA / OCR + QR)
   → enrichment (VT / AbuseIPDB / URLScan, async + SQLite cache + rate limit)
   → scoring (weighted scoring + YAML rules + dictionaries + trust context)
   → response (JSON/HTML report + TheHive ticket)
   → FastAPI / Streamlit dashboard
```

## Layout

```text
phishing-analyzer/
├── app/            # parser / extractor / attachment / enrichment / mailbox / scoring / response
├── rules/          # builtin/*.yaml (89 rules), custom/*.yaml, dicts/*.txt (22 dictionaries)
├── gui/            # Streamlit pages: dashboard / batch / mailbox / review / rules
├── data/samples/   # 8 synthetic samples
├── scripts/        # sample generation + dataset evaluation + FP/attribution analysis
├── 架构图/          # interactive architecture diagram (HTML + JSON spec)
├── dashboard.py    # Streamlit entry point
├── Dockerfile / docker-compose.yml
└── requirements.txt
```

**Custom rule example** (`rules/custom/my_rule.yaml` — takes effect on save; also available via the GUI rules page or `POST /rules`):

```yaml
- id: internal_sensitive_word
  name: internal sensitive word
  category: custom
  scope: mail
  points: 10
  reason: "subject hits internal sensitive word: {value}"
  match:
    field: subject          # see features.py for available fields
    operator: contains_any  # operators: contains/exists/gt/regex_any/equals_any/suffix_any...
    values:
      - 项目代号凤凰
      - "@dict:brands"     # dictionaries can be referenced directly
```

## Docker

```bash
cp .env.example .env    # keys optional
docker compose up -d    # API :8000, dashboard :8501
```

`data/` (reports, caches) and `rules/` (rules, dictionaries) are volume-mounted so containers can be recreated without losing state.

## Compliance & data notes

- All bundled samples are **synthetic** — reserved domains/IPs and placeholder attachments, no real malicious content.
- Prefer **offline mode** for real datasets; whether to upload their IOCs to third-party intel platforms is a decision and authorization of your own.
- URLScan performs passive history search by default; active scanning requires `URLSCAN_ALLOW_SUBMIT=1`.
- **Never upload un-redacted production mail to any third-party API.**

---

> 🌐 Chinese version: [`README.md`](README.md) (equivalent content)
