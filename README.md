# 🛡️ Phishing Analyzer — 钓鱼邮件自动化研判与响应系统

**中文** ｜ [**English**](README_en.md)

面向安全运营（SOC）场景的钓鱼邮件自动化分析流水线：**上报 → 解析 → IOC 提取 → 威胁情报富化 → 加权评分 → 三档结论 → 报告/工单**。同时支持**个人邮箱只读取信**、**附件深度分析**与**人工反馈闭环**。

![Python](https://img.shields.io/badge/Python-3.9%2B-blue) ![FastAPI](https://img.shields.io/badge/API-FastAPI-009688) ![Streamlit](https://img.shields.io/badge/GUI-Streamlit-FF4B4B) ![Offline](https://img.shields.io/badge/offline-capable-brightgreen)

> 🔐 **安全声明**：仓库内置的测试样本均为 **100% 合成数据**（RFC 2606 保留域名 + RFC 5737 文档 IP + 占位附件），可安全克隆、运行、演示与开源。

## 功能特性

- **邮件解析**：`.eml`（标准库）与 `.msg`（extract-msg）；提取头部、SPF/DKIM/DMARC 认证结果、正文、附件哈希（SHA256/MD5）。针对中文语料做了编码链修复（声明 `gb2312` 实为 GBK/UTF-8、MIME 结构残缺、RFC2047 文件名）
- **IOC 提取**：URL / 域名 / IP / 文件哈希；还原真实攻击混淆（零宽字符、软连字符、全角字符、HTML 实体、西里尔同形字），识别短链接、Punycode、IP 直连，区分公网/私网 IP
- **威胁情报富化**：VirusTotal v3 + AbuseIPDB + URLScan.io（默认**被动搜索**，不主动提交扫描）；异步并行 + SQLite 缓存 + 令牌桶限流。情报结果按「命中 / 确定干净 / 无历史」语义分层计分——「情报没见过」不会被当成「确认干净」。**知名域自动跳过域名端点查询**（`rules/dicts/trusted_domains.txt`，源 MISP warninglists / CC0）：这类域的记录本来就是 clean，实测真实邮箱可省下 **46.8%** 的域名查询；URL 级查询不受影响（钓鱼寄居在知名平台子域/路径上时靠它才看得见），报告里标为「已知知名域，未查情报」而非静默消失
- **加权评分引擎**：情报 55% + 认证 15% + 启发式 30%，输出 `BENIGN / SUSPICIOUS / MALICIOUS` 与**可解释研判依据**；**情报命中设保底**（命中即至少 `SUSPICIOUS`，不被"检出引擎数少"稀释，详见「评分模型」）；离线模式按可用维度自动归一化，阈值语义保持一致
- **规则外置（SIEM 式）**：**89 条**评分规则全部声明在 `rules/builtin/*.yaml`（分值/开关可在线调整）；自定义规则放 `rules/custom/`（同 id 覆盖内置，升级安全）；**22 个**字典（品牌/TLD/短链/关键词/危险扩展名/免费邮箱/链接域白名单等）独立维护；规则 CRUD API + 热重载；报告记录规则版本哈希，复盘可复现
- **附件深度分析**：magic bytes 真实类型嗅探（纯 Python，无 libmagic 依赖）+ 声明 MIME/扩展名/真实类型三方核对；危险扩展名三档；压缩包递归（加密标识、密码候选试解、**解压前炸弹防护**）；Office（远程模板注入 / DDE / VBA 宏分级，oletools 可选）；PDF 关键字（`/JavaScript` `/Launch` `/EmbeddedFile`）；**YARA**（可选依赖）；**图片 OCR 与二维码解码**（RapidOCR/OpenCV 可选，图内 URL 走完整情报链路）
- **垃圾/营销与钓鱼分流**：类别判定（phishing / marketing）+ 有条件 `SPAM` 降档，营销邮件归档而非进安全工单；降档需认证通过且无钓鱼强信号，可伪造头部单独存在永不降档
- **个人邮箱接入（IMAP 只读）**：增量取信、不打扰邮箱、自己投递的信不参与分析、**发件人信任上下文**（按往来历史降权话术类信号，硬信号永不免除；往来历史**增量维护**——只计入新邮件，输入未变时整体跳过，实测每轮 0.03s 而非全量 2.9s）
- **人工反馈闭环**：GUI 可批量标注发件人为「正常·营销 / 确认钓鱼」（留痕、可到期、可撤销）；标注集可导出为评测语料，用于回答「某条规则该不该降权」
- **响应闭环**：JSON + HTML 报告落盘、TheHive 工单自动创建（可配置）
- **接口与看板**：FastAPI（Swagger 自动文档）+ Streamlit 多页 GUI（看板 / 批量分析 / 邮箱取信分析 / 人工研判 / 规则管理）
- **性能**：单封离线分析 2–5 ms；批量多进程并行；OCR 会话线程上限可控（避免多 worker 抢核）

## 快速开始

```bash
# 1. 安装（Python 3.9+，Windows / Linux 通用）
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt      # Linux: .venv/bin/pip

# 2. 配置 API Key（可选，留空则自动降级为离线模式）
copy .env.example .env                              # Linux: cp

# 3. 分析单封邮件（仓库已内置 8 封合成样本）
python -m app.cli analyze data/samples/phishing_01.eml            # 在线（需 Key）
python -m app.cli analyze data/samples/phishing_01.eml --offline  # 离线

# 4. 批量分析目录
python -m app.cli batch <邮件目录> --offline --limit 100 --out data/results.csv

# 5. 启动 API 服务（Swagger: http://127.0.0.1:8000/docs）
python -m app.cli serve --port 8000

# 6. 图形界面（看板 / 批量分析 / 邮箱取信分析 / 人工研判 / 规则管理）
pip install streamlit
streamlit run dashboard.py      # http://localhost:8501

# 7. 清空分析数据（报告 + 索引；--include-intel-cache 连情报缓存一起清）
python -m app.cli purge --yes
```

**可选依赖**（不装则对应能力静默降级，不影响其他功能）：

```bash
pip install streamlit                            # 图形界面
pip install yara-python                          # YARA 规则检测
pip install oletools                             # Office VBA 宏提取（结构检查零依赖）
pip install rapidocr-onnxruntime opencv-python   # 图片 OCR 与二维码解码
```

### 个人邮箱取信（IMAP 只读）

```bash
python -m app.mailbox.fetch --list                                   # 列文件夹与同步进度
python -m app.mailbox.fetch --folder INBOX --recent 50               # 看最新 50 封（不动游标）
python -m app.mailbox.fetch --folder INBOX --since-date 2026-08-01 --until-date 2026-08-31
                                                                     # 取 8 月整月（含两端）
python -m app.mailbox.fetch --folder Junk --folder "Sent Messages"   # 垃圾箱 + 已发送
python -m app.mailbox.fetch --analyze-only                           # 不连邮箱，重跑本地已取邮件
python -m app.mailbox.fetch --watch --interval 60                    # 轮询式实时分析（Ctrl+C 退出）
```

**取信只分析新邮件**：取信路径只把**本次新落盘的 .eml** 交给分析器（此前是把目录下全部邮件
重扫一遍——取 1 封也要分析几百封，实测单封 134ms、600+ 封 8 进程约 30s 且随邮箱线性变差）。
规则更新后要按新规则重算历史结论，用显式入口 `--analyze-only`（GUI 上是「重跑本地已取邮件」）。

**按日期取信**：`--since-date` / `--until-date` 都是**含当天**的闭区间端点，走服务端
`SINCE`/`BEFORE` 过滤（先筛后下，比全量下载再筛快得多）；日期可写 `2026-08-01` 或 `01-Aug-2026`。
该模式**不套同步游标**——回扫历史窗口不会被"增量到哪儿了"截断；而游标**只前进不回退**，
所以先扫历史再跑增量不会重复下载。图形界面对应「取信范围 → **按日期区间**」，是一个
**日历区间选择器**（点开选起止两天，含两端），与 CLI 共用同一套日期语义。

**桌面通知**（`--notify`）：把 `MALICIOUS`/`SUSPICIOUS` 推成系统通知（跨平台零依赖：Windows
PowerShell Toast / macOS 通知中心 / Linux `notify-send`；发送失败只记日志，不影响分析）。**默认已降噪**：
只推这两档、**同一发件人 12h 内只提醒一次**（`--notify-window` 可调，0=不去重）、单轮超 3 条只发一条
汇总——不做去重的话营销邮件会把人吵到关掉通知。图形界面同一入口（「邮箱取信分析 → 实时监控」，
含启动/停止、立即检查一次、测试通知、最近告警表与运行日志）。

**轮询式实时分析**（`--watch`）：每 `--interval` 秒（默认 60，最小 15）取一次新邮件并自动分析，
终端实时打印每轮结果（`新邮件 N 封 -> MALICIOUS 1 | BENIGN 2`，`--bell` 可在发现可疑/恶意时响铃）。
两条保证让它适合长驻：**分析成功才推进游标**（分析失败的那批下一轮重取重试，绝不静默漏掉）、
**断线自愈**（连接异常自动重连继续，不退出）。部署上交给系统即可——Windows 任务计划/NSSM 注册为
服务、Linux systemd、或容器里当 sidecar（`restart: unless-stopped`）。

三条约束都是「不打扰用户邮箱」：**只读**（`select(readonly=True)` + `BODY.PEEK[]`，不标已读、不动标志位、不删除）、**增量**（按 UID 取信并记录 `UIDVALIDITY`，变化则从头重扫）、**先看大小再下载**。默认**离线**分析；`--online` 才会把邮件中的 IOC 发往第三方情报平台，需使用者自行确认授权。图形界面同一入口（侧栏「邮箱取信分析」）。

## 评分模型

总分 0–100：`< 30 BENIGN ｜ 30–54 SUSPICIOUS ｜ ≥ 55 MALICIOUS`（阈值可用 `TH_SUSPICIOUS` / `TH_MALICIOUS` 调整）

| 维度 | 权重 | 依据 |
|---|---|---|
| 威胁情报命中 | 55% | VT 引擎检出（声誉型按检出数阶梯 / AV 型按比例折算）、AbuseIPDB 滥用置信度、URLScan 历史判定；**命中另设保底**（见下） |
| 邮件认证 | 15% | SPF/DKIM/DMARC fail/softfail/neutral/none，认证头自相矛盾检测 |
| 启发式规则 | 30% | 89 条外置规则：身份伪造、URL 特征、链接域与发件域仿冒配对、附件特征、正文话术、独立信号叠加 |

**情报命中保底**：命中是二值事实，不因"检出引擎数少"被稀释——任何命中都至少按 `60/100` 置信度计（即情报维度 ≥ 33 分），**命中本身即可判 `SUSPICIOUS`**。这样调策略不必让情报缓存失效：已缓存的旧命中（如 `2/95` → 置信度 30）在重算时同样被保底。检出引擎数仍在保底之上继续拉开差距（10 引擎 92 分 → 50.6 分，20 引擎 100 分 → 55 分）。保底值见 `app/scoring/risk_engine.py` 的 `_INTEL_HIT_FLOOR`，下调即更保守（`<60` 时命中需本地证据配合才能越线）。

**为什么是保底而不是继续抬高 55% 的权重**：三维权重之和须保持 100，抬高情报就得压低认证/启发式，而**离线归一化的分母正是这两者之和**——分母变小会让所有离线分数整体上浮，突破误报门禁。详见 `_INTEL_HIT_FLOOR` 处的说明。

**垃圾/营销分流（`SPAM` 档）**：结论已过 BENIGN 且类别判定为 `marketing`（≥2 项独立营销证据、无钓鱼强信号、无情报命中）且认证至少一项 pass 时，降为 `SPAM`（归档/标记，不进安全工单）。BENIGN 不受影响。

**可解释性**：每条结论附带完整 `reasons`；关键词匹配前统一做混淆还原；URL 反混淆只还原**攻击者真实手法**，**不还原**分析员防呆写法（`hxxp://`、`example[.]com`），避免反向误报。

## 评估指标（本机实测，离线纯规则）

语料均为公开数据集，需自行下载；评估脚本在 `scripts/`（`eval_modern_baseline.py` / `eval_dataset.py` / `eval_fp_baseline.py` / `eval_trec06c.py`）。

| 语料 | 指标 | 结果 |
|---|---|---|
| **权威基线**（现代邮件 10 万封：50k ham + 50k spam） | 精确率 / 召回率 / F1 | **99.03% / 99.13% / 99.08%** |
| | ham 误报率 / 严重误报（MALICIOUS） | **0.97% / 0.00%** |
| [phishing_pot](https://github.com/xffxd/phishing_pot) 真实钓鱼（前 500 封） | flagged（恶+可疑）召回 | **74.0%**（含 SPAM 降档的拦截口径 80.0%） |
| [trec06c](https://trec.nist.gov/data/spam.html) 中文正常邮件（652 封抽样） | 误报率 / 误降档 | **0.15% / 0.00%** |
| Enron 正常邮件（16545 封，补充哨兵） | 误报率 | **0.00%** |
| 个人邮箱实测（108 封真实邮件，邮箱档位 + 信任上下文） | 需要关注比例 | **9.3%** |

> 指标随规则迭代变动，本表只保留当前构建的实测值。

## 配置

复制 `.env.example` 为 `.env`，所有项均可留空（对应情报源自动降级，本地离线分析不受影响）：

| 变量 | 默认 | 说明 |
|---|---|---|
| `VT_API_KEY` / `ABUSEIPDB_API_KEY` / `URLSCAN_API_KEY` | 空 | 威胁情报 API Key |
| `URLSCAN_ALLOW_SUBMIT` | `0` | 主动提交 URLScan 扫描（默认仅被动搜索历史记录） |
| `INTEL_TIMEOUT` / `INTEL_CONCURRENCY` | `15` / `8` | 情报查询超时与并发 |
| `VT_RATE_LIMIT` | `4` | VT 每分钟请求上限（免费版限流） |
| `CACHE_TTL_HOURS` | `24` | 情报缓存有效期（小时） |
| `TH_SUSPICIOUS` / `TH_MALICIOUS` | `30` / `55` | 评分三档阈值 |
| `THEHIVE_URL` / `THEHIVE_API_KEY` | 空 | TheHive 工单系统对接 |
| `MAILBOX_IMAP_HOST` / `MAILBOX_IMAP_PORT` | `imap.qq.com` / `993` | 邮箱取信服务器（IMAP） |
| `MAILBOX_IMAP_USER` / `MAILBOX_IMAP_AUTH_CODE` | 空 | 邮箱地址 / 授权码（QQ 邮箱为「设置 → 账户 → 开启 IMAP/SMTP 服务」生成的 16 位授权码，**非登录密码**） |
| `MAILBOX_MAX_BYTES` | `20971520` | 单封邮件下载上限（先取 `RFC822.SIZE` 再决定是否下正文） |
| `MAILBOX_SKIP_SELF_SENT` / `MAILBOX_OWN_ADDRESSES` | `1` / 空 | 自己投递的信不参与分析 / 本人其它地址（逗号分隔，识别自寄副本） |
| `ANALYSIS_PROFILE` | `gateway` | 分析档位：`gateway`（网关/SOC 投递）或 `mailbox`（邮箱直读；取信 CLI 与 GUI 自动切换） |
| `TRUST_CONTEXT` | 跟随档位 | 发件人信任上下文开关（gateway 默认关、mailbox 默认开；`=0` 关闭做对照） |
| `TRUST_MIN_COUNT` / `TRUST_MIN_DOMAIN_COUNT` / `TRUST_MIN_SPAN_DAYS` | `2` / `5` / `14` | 信任门槛：地址封数 / 域级封数 / 域级时间跨度 |

## REST API

启动服务后访问 `http://127.0.0.1:8000/docs` 查看交互式文档。

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/analyze?offline=&create_thehive=` | 上传 `.eml`/`.msg`（multipart 字段 `file`），返回评分/结论/IOC/原因 |
| GET | `/report/{id}`（`?format=html`） | 获取历史报告 |
| GET | `/report/{id}/download` | 下载报告文件 |
| GET | `/reports` / `/reports/stats` | 分析记录列表 + 统计概览 |
| DELETE | `/reports?confirm=true` | 清空分析数据（可选 `include_intel_cache`） |
| GET | `/health` | 健康检查 |
| GET/POST | `/rules`、`/rules/{id}`、`/rules/reload`、`/rules/dicts`、`/rules/test` | 规则 CRUD、字典维护、热重载、用样本试跑 |

```bash
curl -X POST "http://127.0.0.1:8000/analyze?offline=true" -F "file=@data/samples/phishing_01.eml"
```

## 架构

> 🔍 **交互式架构图**：[`架构图/architecture.html`](架构图/architecture.html) — 浏览器直接打开，支持深浅色切换、平移缩放、节点搜索、关系追踪与图片导出。

```text
.eml/.msg 上报 → parser（eml/msg）→ extractor（IOC + 认证）
   → attachment（类型嗅探 / 归档 / Office / PDF / YARA / OCR + 二维码）
   → enrichment（VT / AbuseIPDB / URLScan，异步 + SQLite 缓存 + 限流）
   → scoring（加权评分 + YAML 规则目录 + 字典 + 信任上下文）
   → response（JSON/HTML 报告 + TheHive 工单）
   → FastAPI / Streamlit 看板
```

## 目录结构

```text
phishing-analyzer/
├── app/
│   ├── main.py               # FastAPI 入口（分析 + 规则管理端点）
│   ├── pipeline.py           # 分析流水线编排（含批量 worker）
│   ├── cli.py                # 命令行（analyze / batch / serve / purge）
│   ├── config.py             # 环境变量配置
│   ├── parser/               # .eml/.msg 解析（中文编码链修复）
│   ├── extractor/            # IOC 提取 + 认证检查
│   ├── attachment/           # 附件深度分析（类型/归档/Office/PDF/OCR/YARA）
│   ├── enrichment/           # VT / AbuseIPDB / URLScan + 缓存与限流
│   ├── mailbox/              # IMAP 只读取信 + 往来历史 + 标注集导出
│   ├── scoring/
│   │   ├── risk_engine.py    # 加权评分 / 归一化 / 档位与降档
│   │   ├── features.py       # 特征工程（混淆还原 / 计数 / 域关系）
│   │   ├── trust.py          # 发件人信任上下文（按往来历史降权）
│   │   ├── category.py       # 钓鱼 / 营销 / 未知 类别判定
│   │   ├── rule_schema.py    # 规则模型与算子求值
│   │   ├── rule_loader.py    # 规则加载 / 版本哈希 / 探测器注册表
│   │   └── rule_admin.py     # 规则 CRUD / 热重载 / 试跑
│   ├── response/             # 报告生成 + TheHive 客户端
│   └── rules/                # YARA 规则（可选依赖）
├── rules/
│   ├── builtin/*.yaml        # 89 条内置评分规则
│   ├── custom/*.yaml         # 用户自定义规则（同 id 覆盖内置）
│   └── dicts/*.txt           # 19 个字典（品牌/TLD/短链/关键词/危险扩展名…）
├── gui/                      # Streamlit 页面：看板 / 批量 / 邮箱取信 / 人工研判 / 规则管理
├── data/samples/             # 8 封合成测试样本
├── scripts/                  # 样本生成 + 数据集评估 + 误报与归因分析
├── 架构图/                    # 交互式架构图（HTML + 源规格 JSON）
├── dashboard.py              # Streamlit 入口
├── Dockerfile / docker-compose.yml
└── requirements.txt
```

**自定义规则示例**（`rules/custom/my_rule.yaml`，保存即生效，也可在 GUI 规则管理页或 `POST /rules` 完成）：

```yaml
- id: internal_sensitive_word
  name: 内部敏感词
  category: custom
  scope: mail
  points: 10
  reason: "主题命中内部敏感词: {value}"
  match:
    field: subject          # 字段路径见 features.py
    operator: contains_any  # 算子：contains/exists/gt/regex_any/equals_any/suffix_any...
    values:
      - 项目代号凤凰
      - "@dict:brands"     # 可直接引用字典
```

## Docker 部署

```bash
cp .env.example .env    # 填入 API Key（可留空）
docker compose up -d    # API :8000，看板 :8501
```

`data/`（报告与缓存）与 `rules/`（规则与字典）通过 volume 挂载持久化，容器重建不丢数据。

## 合规与数据说明

- 内置样本全部为**合成数据**，使用保留域名/保留 IP，附件为占位字节，不含真实恶意内容。
- 真实数据集建议**离线模式**批量分析；是否将其中 IOC 上传第三方情报平台由使用者自行评估授权。
- URLScan 默认仅做历史记录搜索（被动），主动扫描需显式设置 `URLSCAN_ALLOW_SUBMIT=1`。
- 请勿将未脱敏的生产邮件上传至任何第三方 API。

---

> 🌐 英文版：[`README_en.md`](README_en.md)（内容与本文对应）
