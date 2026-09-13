# 🛡️ Phishing Analyzer — 钓鱼邮件自动化研判与响应系统

面向安全运营（SOC）场景的钓鱼邮件自动化分析流水线：**上报 → 解析 → IOC 提取 → 威胁情报富化 → 加权评分 → 三档结论 → 报告/工单**。

> 所有内置测试样本均为 100% 合成数据（RFC 2606 保留域名 + RFC 5737 文档 IP + 占位附件），可安全运行、演示与开源。

## 功能特性

- **邮件解析**：`.eml`（标准库）与 `.msg`（extract-msg），提取头部、SPF/DKIM/DMARC 认证结果、正文、附件哈希（SHA256/MD5）
- **IOC 提取**：URL / 域名 / IP / 文件哈希，支持 `hxxp://` 混淆还原、短链接、Punycode、IP 直连识别，区分公网/私网 IP
- **威胁情报富化**：VirusTotal v3 + AbuseIPDB + URLScan.io（默认**被动搜索**，不主动提交扫描），`aiohttp/httpx` 异步并行 + SQLite 24h 缓存 + 令牌桶限流（VT 免费版 4 次/分钟）
- **加权评分引擎**：情报 55% + 认证 15% + 启发式 30%，输出 `BENIGN / SUSPICIOUS / MALICIOUS` 三档结论 + **可解释研判依据**；离线模式自动归一化
- **响应闭环**：JSON + HTML 报告落盘、TheHive 工单自动创建（可配置）
- **接口与看板**：FastAPI（Swagger 自动文档）+ Streamlit 多页 GUI（批量分析 + 规则管理）
- **SIEM 式规则外置**：启发式规则全部声明在 `rules/builtin/*.yaml`，分值/开关可在线调整；自定义规则写入 `rules/custom/`（同 id 覆盖内置，升级安全）；品牌/TLD/短链接/关键词字典独立维护（`rules/dicts/*.txt`）；规则 CRUD API + 热重载；报告记录规则版本哈希，复盘可复现
- **批量能力**：CLI 与 GUI 均支持一键批量分析目录（GUI 提供系统文件夹选择框，已在 phishing_pot 真实公开数据集上验证）

## 快速开始

```bash
# 1. 安装（Windows / Linux 通用）
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt      # Linux: .venv/bin/pip

# 2. 配置 API Key（可选，留空则自动降级为离线模式）
copy .env.example .env                              # Linux: cp

# 3. 生成合成测试样本（可选，仓库已内置）
python scripts/gen_samples.py

# 4. 分析单封邮件
python -m app.cli analyze data/samples/phishing_01.eml            # 在线（需 Key）
python -m app.cli analyze data/samples/phishing_01.eml --offline  # 离线

# 5. 批量分析
python -m app.cli batch ../phishing_pot-main/email --offline --limit 100 --out data/results.csv

# 6. 启动 API 服务
python -m app.cli serve --port 8000
# Swagger: http://127.0.0.1:8000/docs

# 7. 图形界面（看板 + 批量分析 + 规则管理）
pip install streamlit
streamlit run dashboard.py      # http://localhost:8501

# 8. 清空分析数据（报告文件 + 报告索引；--include-intel-cache 连情报缓存一起清）
python -m app.cli purge                 # 交互确认
python -m app.cli purge --yes           # 脚本/CI 用，跳过确认
```

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/analyze?offline=&create_thehive=` | 上传 `.eml`/`.msg`（multipart 字段 `file`），返回评分/结论/IOC/原因 |
| GET | `/report/{id}` | 获取历史报告（`?format=html` 可选） |
| GET | `/reports` | 分析记录列表 + 统计概览 |
| GET | `/reports/stats` | 预览分析数据规模（清理前确认用） |
| DELETE | `/reports` | 清空分析数据（需 `confirm=true`，可选 `include_intel_cache`） |
| GET | `/health` | 健康检查 |
| GET | `/rules` | 列出规则集（id/分值/开关/来源 builtin\|custom） |
| POST | `/rules` | 新建/整体覆盖自定义规则（写入 `rules/custom/`，立即生效） |
| PUT | `/rules/{id}` | 局部修改（enabled/points/name/description/reason） |
| DELETE | `/rules/{id}` | 删除自定义覆盖（恢复内置默认） |
| POST | `/rules/reload` | 热重载规则集与字典 |
| GET/POST | `/rules/dicts` | 查看字典 / 追加词条 |
| POST | `/rules/test` | 用样本邮件试跑规则集（离线、不落盘） |

```bash
curl -X POST "http://127.0.0.1:8000/analyze?offline=true" -F "file=@data/samples/phishing_01.eml"
```

响应示例：

```json
{
  "score": 100, "verdict": "MALICIOUS",
  "reasons": [
    "邮件认证: SPF: fail",
    "启发式: URL 使用 IP 直连而非域名: http://203.0.113.66/account/verify/login",
    "启发式: URL 含 Punycode 域名（可能的同形字伪造）"
  ],
  "iocs": {"urls": [...], "ips": ["203.0.113.66"], "hashes": [...]},
  "intel": [...], "report_files": {"json": "...", "html": "..."}
}
```

## 评分模型

总分 0–100：`< 30 BENIGN ｜ 30–54 SUSPICIOUS ｜ ≥ 55 MALICIOUS`

| 维度 | 权重 | 依据 |
|---|---|---|
| 威胁情报命中 | 55% | VT 引擎命中比、AbuseIPDB 滥用置信度、URLScan 历史判定（取最高分） |
| 邮件认证 | 15% | SPF/DKIM/DMARC fail/softfail/none，Reply-To / Return-Path 域名不对齐 |
| 启发式规则 | 30% | 25+ 条规则：身份伪造（显示名品牌冒充/内嵌假邮箱/数字混淆域名/免费邮箱回信）、URL 特征（IP 直连/Punycode/短链接/高风险 TLD/@ 混淆）、附件特征（双扩展名/宏文档/可执行/随机命名/HTML 诱饵）、正文特征（字符混淆还原/紧急措辞/验证码话术/锚文本伪装/内嵌密码表单/诱饵文档投递模式）、独立信号叠加 |

- 每条结论附带完整 `reasons` 列表（含情报查询汇总），可解释、可审计。
- 所有关键词匹配先经 `fold_text()` 混淆还原（零宽字符、组合记号插入 `Aܿmܿaܿzܿon`、西里尔同形字 `Sаmsung`、变音符号）。
- **情报结果的语义分层**：`hit`（命中）会主动加分；文件哈希 `clean` 是确定性负面证据；而 URL/域名的 `clean` 只是声誉弱负面，与 `unknown`（无历史，新钓鱼 IOC 的常态）一样**不会**压低评分——避免"情报没见过"被误当"情报确认干净"。
- **离线/情报无有效数据时**：auth+heuristic 原始分（满分 45）自动归一化到 0–100，阈值语义保持一致。
- 阈值可通过 `TH_SUSPICIOUS` / `TH_MALICIOUS` 环境变量调整。

## 架构

> 🔍 **交互式架构图**：[`架构图/architecture.html`](架构图/architecture.html) — 浏览器直接打开，支持深浅色切换、平移缩放、节点搜索、关系追踪与图片导出。源规格见 [`架构图/architecture.architecture.json`](架构图/architecture.architecture.json)。

```text
.eml/.msg 上报 → parser（eml/msg）→ extractor（IOC + 认证）
   → enrichment（VT / AbuseIPDB / URLScan，异步 + SQLite 缓存 + 限流）
   → scoring（加权评分 + 启发式规则目录）
   → response（JSON/HTML 报告 + TheHive 工单）
   → FastAPI / Streamlit 看板
```

## 目录结构

```text
phishing-analyzer/
├── app/
│   ├── main.py               # FastAPI 入口（分析 + 规则管理端点）
│   ├── pipeline.py           # 分析流水线编排
│   ├── cli.py                # 命令行（analyze/batch/serve）
│   ├── config.py             # 环境变量配置
│   ├── parser/               # .eml/.msg 解析
│   ├── extractor/            # IOC 提取 + 认证检查
│   ├── enrichment/           # VT/AbuseIPDB/URLScan + 缓存编排
│   ├── scoring/
│   │   ├── risk_engine.py    # 评分/归一化（启发式策略已外置）
│   │   ├── features.py       # 特征工程（混淆还原/计数/比率）
│   │   ├── rule_schema.py    # 规则模型与 12 种算子求值
│   │   ├── rule_loader.py    # 规则加载/版本哈希/探测器注册表
│   │   └── rule_admin.py     # 规则 CRUD/热重载/试跑
│   ├── response/             # 报告生成 + TheHive 客户端
│   └── rules/                # YARA 规则（可选依赖）
├── rules/
│   ├── builtin/*.yaml        # 43 条内置评分规则（分值/开关可在线调整）
│   ├── custom/*.yaml         # 用户自定义规则（同 id 覆盖内置）
│   └── dicts/*.txt           # 品牌/TLD/短链/关键词/链接域白名单字典
├── gui/                      # Streamlit 页面：看板首页 + 批量分析 + 规则管理
├── data/samples/             # 合成测试样本
├── tests/                    # pytest（157 个用例，离线可跑）
├── scripts/                  # 样本生成 + 数据集评估 + 误报基线 + CSV 转 eml
├── dashboard.py              # Streamlit 入口（看板首页）
├── Dockerfile / docker-compose.yml
└── requirements.txt
```

自定义规则示例（`rules/custom/my_rule.yaml`）：

```yaml
- id: internal_sensitive_word
  name: 内部敏感词
  category: custom
  scope: mail
  points: 10
  reason: "主题命中内部敏感词: {value}"
  match:
    field: subject          # 字段路径见 features.py
    operator: contains_any  # 12 种算子：contains/regex/equals/suffix/gt/exists...
    values:
      - 项目代号凤凰
      - "@dict:brands"     # 也可引用字典
```

改完保存即生效（热重载），也可在 GUI 规则管理页或 `POST /rules` 完成。

## Docker 部署

```bash
cp .env.example .env    # 填入 API Key
docker compose up -d    # API :8000，看板 :8501
```

## 测试与评估

```bash
.venv/Scripts/python -m pytest        # 57 passed
```

单元测试覆盖：解析/哈希、IOC 提取与混淆还原、认证解析与对齐性、评分三档阈值、离线归一化、情报命中路径、API 端到端往返，以及数据集评估中发现的全部攻击模式（字符混淆、显示名冒充、锚文本伪装、随机文件名、诱饵附件）。

**数据集基准评估**（离线模式，纯本地规则，不含威胁情报）：

```bash
python scripts/eval_dataset.py --dir ../phishing_pot-main/email --limit 500
```

在 [phishing_pot](https://github.com/xffxd/phishing_pot) 真实钓鱼数据集上的规则迭代过程（前 500 封抽样，评估-归因-迭代-回归闭环）：

| 轮次 | MALICIOUS | SUSPICIOUS | 漏判 BENIGN | flagged（恶+可疑） |
|---|---|---|---|---|
| 基线 | 39.2% | 29.4% | 31.4% | 68.6% |
| 迭代 1（混淆还原 + 8 条新规则 + 信号叠加） | 57.0% | 19.6% | 23.4% | 76.6% |
| 迭代 2（随机文件名/诱饵附件/免费邮箱发件等） | 61.0% | 21.0% | 18.0% | 82.0% |
| 迭代 3（数学粗体混淆/礼品卡话术/From 头畸形/数字噪声） | 63.4% | 18.8% | 17.8% | **82.2%** |

全量 8614 封（涵盖更多样的攻击活动）：flagged 71.4%（MALICIOUS 42.9% + SUSPICIOUS 28.4%）。

迭代驱动的规则（均可在漏判样本中找到原型）：`fold_text` 混淆还原（零宽字符/组合记号插入/西里尔同形字/数学粗体）、显示名品牌冒充、From 头多地址畸形、锚文本伪装、随机文件名检测（元音结构分析）、诱饵文档投递模式、独立信号叠加加分。

**误报基线评估**（负样本，正常邮件语料）：

```bash
# 语料 1：Enron —— 可直接读原始 .txt，也可先转成 .eml（二者行为等价，见下）
python scripts/enron_to_eml.py   --src ../enron --out data/enron_eml
python scripts/eval_fp_baseline.py --dir data/enron_eml --out data/eval_fp_enron.csv

# 语料 2：现代邮件（含完整头部/认证，主误报基线）
python scripts/csv_to_eml.py --csv ../email_dataset_100k.csv --out data/dataset_eml --sample 6000
python scripts/eval_fp_baseline.py --dir data/dataset_eml --out data/eval_fp_modern.csv
```

**Enron 的 .eml 转换**（`scripts/enron_to_eml.py`）：源文件仅含 `Subject:` + 正文，转换还原
Subject 与正文，并从文件名 `NNNN.YYYY-MM-DD.owner.{ham,spam}.txt` 还原 **Date**（RFC 2822 格式），
另以 `X-Enron-Fold/Owner/Source` 头保留溯源。**不虚构 From/To/Reply-To/认证头**——这些字段源语料
中不存在，凭空生成会制造原邮件没有的信号并污染基线。

> 已实测转换保真度：33716 封全部解析成功；随机 400 封主题/正文/日期逐字段一致；**同一批邮件在
> `.txt` 与 `.eml` 两种形态下分析结果逐封完全相同（400/400 零差异）**，即转换不引入任何行为偏差。
> （注：Date 必须写 RFC 2822；早期写成 ISO 8601 会导致解析器判定非法并返回空值。）

> ⚠️ **Enron 语料的两个硬性限制**（实测确认，决定了它的适用范围）：
> 1. **头部被全部剥离**——From/To/Received/Return-Path/Authentication-Results 均不存在，
>    身份类规则（显示名冒充、免费邮箱发件、Reply-To 不一致）与认证维度（占评分 15%）**无法触发**；
> 2. **URL 被空格混淆**——**75.1% 的 spam 含 `http : / / host . tld` 形式的 URL**，
>    这是语料制作方为防误点所做的**脱敏**（与分析员防呆同源），不是可点击的真实链接。
>    按迭代 5 的决策，`refang()` **有意不还原**这类写法，因此该语料可提取 URL 仍为 0%，
>    URL 类规则在它上面依旧是空转的。
>
> 叠加其 spam 本质是 **2003–2005 年的广告垃圾邮件**（保健品、艺术品拍卖、房贷），而非凭证钓鱼，
> 实测 Enron spam **召回 0%**（触发的最强组合仅 9 原始分，归一化 20 < 阈值 30）。
> **结论：Enron 只可用于 ham 侧误报基线，不可用于召回评估。**

两套语料**互补**，共同构成误报门禁：

| 语料 | 规模 | 头部/认证 | 作用 |
|---|---|---|---|
| Enron-Spam ham（1999–2002） | 16545 封 | ❌ 已被剥离 | 只能验证内容类规则；**不可用于召回评估** |
| email_dataset_100k（2024） | 全量 50000 ham + 50000 spam | ✅ 完整 SPF/DKIM/DMARC、Reply-To、附件类型 | 覆盖头部/认证类规则，含现代邮件形态 |

### 基线语料约定（2026-09 定）

> **以 `data/dataset_eml` 为权威基线。** 它含完整头部与认证结果，是唯一能同时覆盖
> 「头部 / 认证 / 正文」字段规则、且带 spam 标签可同时验证召回与误报的语料。
> 调整规则权重或新增规则时，**以它上面的指标为准**做取舍。

Enron 语料降为**补充哨兵**（阈值宽松，异常升高时提示可能有跨语料的普遍性回归），
原因是它有结构性盲区：头部被全部剥离（认证维度占评分 15% 根本无法触发）、正文 URL
被作者脱敏成不可点击写法（可提取 URL 恒为 0%，**链接类规则的误报它测不出来**）、
且是 1999–2005 年的广告垃圾邮件。

⚠️ **`dataset_eml` 自身的两处盲区**（既然以它为准，就必须知道它测不到什么）：

1. **ham 正文里没有任何 URL**（实测 1500 封抽样 `has_url = 0`）——因此 `link_domain_*`、
   `url_*`、`body_*_lure`、HTML 隐藏文字等**链接/HTML 类规则在它上面完全没有覆盖**；
2. **认证三列是合成器独立随机赋值的**（实测 50000 封 ham 上，任意 `(spf, dkim)` 组合下
   dmarc 取值严格均分为 pass/none/fail 各 33.3%），出现的 `spf=fail dkim=fail dmarc=pass`
   不是真实 MTA 行为，会给语义正确的认证一致性规则产生**假误报**。

结论：它适合守「头部/认证/正文关键词」维度的回归，**不能替代链接类规则的真实语料验证**。
接入自有正常邮件语料后，应优先用它校准 `rules/dicts/link_allowlist.txt` 与
HTML 隐藏文字检测的阈值。

**语料 2（现代邮件，全量 ham 50000 封）—— 主基线，经历两轮实测驱动的修复：**

| 指标 | 迭代 3 前（3000 抽样） | 迭代 3 后（全量 50000） | 迭代 4 后（全量 50000） |
|---|---|---|---|
| 误报率 FP（恶+可疑） | 6.27% | 0.95% | 2.10% |
| 严重误报 MALICIOUS | 0.37% | 0.00% | 0.01% |
| 正确放行 BENIGN | 93.73% | 99.05% | 97.90% |
| 平均分 / 中位分 / 最高分 | 9.7 / 9 / 73 | 6.0 / 3 / 49 | — |

全量 10 万封混淆矩阵（离线模式，迭代 4 后）：

|  | 判为可疑/恶意 | 判为正常 |
|---|---|---|
| **spam 50000** | 49729（TP） | 271（FN，漏判 0.54%） |
| **ham 50000** | 1050（FP，误伤 2.10%） | 48950（TN） |

→ **精确率 97.93% ｜ 召回率 99.46% ｜ F1 98.69%**

（迭代 3 后同口径为 精确率 99.02% ｜ 召回率 96.32% ｜ F1 97.65%。迭代 4 以 **+1.15pp 误报**
换来 **+3.14pp 召回**，F1 净增 1.04pp；误报上升的构成与真伪见下文"迭代 4"一节。）

修复定位到的两项根因（Enron 语料**测不出来**，因为缺头部 + 年代词汇差异）：

1. **正文关键词误用 URL 字典**：`body_credentials` 等规则复用 `url_keywords`（含 `invoice`/`account`/`confirm` 等词）。这些词出现在 URL 路径里是有效信号，但出现在**正文**里只是商务邮件常用词——典型的类别错误。已新建高精度 `credential_keywords` 字典，正文侧只匹配"verify your identity"这类多词短语。
2. **Reply-To 不同域权重过高**：现代正常邮件里「发信域 ≠ 回信域」极其常见（工单系统、客服平台、外包发信）。该信号在误报中占比 68%，权重 6→3，`reply_to_freemail` 6→4。

同时收敛了 `subject_suspicious`（4→2）、`lure_attachment_pattern`（4→3 并追加紧迫话术条件，避免"简短正文+附件"的正常邮件误报）。

**代价与取舍**（同一批规则改动后回测）：

| 语料 | 指标 | 修复前 | 修复后 | 变化 |
|---|---|---|---|---|
| 现代 ham 全量 50000 封 | 误报率 | 6.27% | 0.95% | **−5.32pp** ✅ |
| 现代 spam 全量 50000 封 | flagged 召回 | 97.0%* | 96.32% | −0.7pp |
| phishing_pot 500 封 | flagged 召回 | 82.2% | 79.6% | −2.6pp |

\* 97.0% 为 2976 封抽样口径。

以 5.2pp 的误报下降换取 0.6–2.6pp 的召回下降是划算的：误报消耗每一次人工复核工时，而漏判样本中 49/102 落在 20–29 分（紧贴 30 分阈值），且离线评估**不含威胁情报环节**——生产环境这些样本的 URL/哈希大概率会被情报源命中而回升至 MALICIOUS。

> **Enron 语料的注意事项**：该语料制作时**剥离了全部邮件头部**（From/Received/Return-Path/Authentication-Results 均不存在），仅保留 `Subject:` 与正文。因此它只能验证内容类规则，且缺失认证头会让 `header_missing_auth`（+2 分）在 **100% 样本**上触发，因此该语料天然带噪声。**正因如此，误报门禁以语料 2 为准。**（迭代 5 实测 Enron 误报 0.00%、零严重误报）

### 误报构成与修正（`scripts/analyze_fp_causes.py`）

全量 10 万封实测 ham 误报 **1050 例（2.10%）**：SUSPICIOUS 1045、MALICIOUS 5，分数 30–62（中位 36）。
按**根因**归组后，95.8% 的误报由三件事覆盖：

| 根因 | 例数 | 占误报 | 说明 |
|---|---|---|---|
| 认证头自相矛盾 | 518 | 49.3% | **语料合成噪声**：spf/dkim/dmarc 三列独立随机赋值造出的不可能组合。其中 256 例（24.4%）由它单独触发。真实邮件不会出现 |
| Reply-To 与发件域不一致 | 586 | 55.8% | 现实中最常见：工单系统 / 客服平台 / 外包发信 |
| 免费邮箱发件域 | 229 | 21.8% | 正常用户用 gmail / outlook 发信 |
| 仅认证维度触发（无任何启发式信号） | 44 | 4.2% | 认证三项全 fail 即 15 分（满分），归一化 33 分直接越线 |

**留一法**（把该规则从误报邮件里去掉后落回 BENIGN 的例数 = 调它能省下的人工）：

| 规则 | 可消除 | 占误报 | 去掉后仍误报 |
|---|---|---|---|
| `header_auth_inconsistent` | 453 | 43.1% | 65 |
| `reply_to_freemail` | 333 | 31.7% | 36 |
| `header_reply_mismatch` | 269 | 25.6% | 317 |
| `sender_from_freemail` | 143 | 13.6% | 86 |

→ **扣除语料噪声后，真实误报约 597 例 / 1.19%**（而非 2.10%）。

**上述归因直接驱动了迭代 6 的两项修正**（详见下文「迭代 6」），修正后的实测：

| 指标 | 修正前 | 修正后 |
|---|---|---|
| ham 误报 | 1050（2.10%） | **483（0.97%）** |
| ham 严重误报（MALICIOUS） | 5（0.01%） | **0（0.00%）** |
| 误报分数区间 / 中位 | 30–62 / 36 | **30–51 / 31** |
| spam flagged 召回 | 99.45% | 99.13% |
| 精确率 / F1 | 97.93% / 98.69% | **99.03% / 99.08%** |
| **扣除语料认证噪声后的真实误报** | 597（1.19%） | **86（0.17%）** |

⚠️ **发现的设计缺陷：Reply-To 不匹配被跨维度重复计分三次**。同一件事实在
`header_reply_mismatch`(3) + `reply_to_freemail`(6) + 认证维度 `reply_to_aligned=False`(3) 各计一次，
合计 **12 分**。实测一封 SPF/DKIM/DMARC 全部 pass、仅 Reply-To 指向 gmail 的正常邮件
能拿到 27 分（门槛 30），再叠加任何弱信号就误报——这正是 586 例的成因。
这与 README 早先"现代正常邮件里发信域≠回信域极其常见"的结论一致，当初调低了权重，
但**跨维度的重复计分把那次修复基本抵消了**。

### 迭代 4：一处线上漏判的归因与修复（VT 命中却判 BENIGN）

线上报告 `94bc4906453b4d6f`（样本 `spam-000005.eml`）中，VirusTotal 对域名 `support.co`
报 **6/89 引擎标记恶意**，最终结论却是 **BENIGN（7 分）**。逐层归因后确认是四处独立空缺叠加，
四项修复均已落地：

| # | 缺口 | 修复 |
|---|---|---|
| 1 | 域名命中被按引擎比例线性折算成 13/100，只值 7.2 分 | `_stats_to_score` 按 IOC 类型分口径：**域名/IP/URL（声誉型）按检出引擎数阶梯给分**（6 个引擎 → 60/100），文件哈希（AV 型）保持比例折算 |
| 2 | SPF/DKIM=`neutral` 计 0 分；伪造的 `dmarc=pass` 被无条件信任 | `neutral` 计入等同于 `none` 的弱负面分（5×0.3）；新增 **`header_auth_inconsistent`**：同一条认证头内 `dmarc=pass` 但 SPF/DKIM 均明确非 pass —— DMARC 的 pass 只能来自 SPF 或 DKIM 对齐通过，合规接收方不会这样写（仅单头内判定，跨头合并不触发） |
| 3 | 发件域 `bizsupport.co` 与链接域 `support.co` 的仿冒配对无任何规则 | 新增 **`link_domain_lookalike`**（标签内前后缀注入仿冒，10 分）与 **`link_domain_mismatch`**（与发件域无关，4 分）；按**可注册域名**比对，`mail.example.com → example.com` 不算不一致；短链与已知合法第三方服务域由新增字典 `rules/dicts/link_allowlist.txt` 排除 |
| 4 | 正文 `claim reward` / `Submit your details` 均无字典覆盖；主题 `parcel` 缺词 | 新增正文侧字典 `reward_keywords.txt` + 规则 **`body_reward_lure`**（奖励话术且含链接）；`credential_keywords.txt` 补 `submit your details` 等表述 + 规则 **`body_credential_solicitation`**（凭证索取且含链接）；`subject_keywords` 补 `parcel`/`shipment`/`delivery failed` 等快递话术；`suspicious_tlds` 补 `biz`。**裸词 `important` 有意不收**（正常商务邮件高频，会大面积误报；该样本由上述两条规则覆盖，理由已写入 `rules/dicts/urgency_keywords.txt` 并有测试锁定） |

同一封样本的结论：**7 分 BENIGN → 66 分 MALICIOUS**（情报 33.0 + 认证 3.0 + 启发式 30），
命中 `link_domain_lookalike`、`header_auth_inconsistent`、`body_reward_lure`、
`body_credential_solicitation`、`subject_suspicious`、`signal_stack`。

回归对比（同一抽样口径 `SAMPLE_SIZE=1500, SEED=20260913`，离线模式）：

| 指标 | 修复前 | 修复后 | 门禁 |
|---|---|---|---|
| 现代 ham 误报率（1500 抽样） | 0.73% | 1.87% | ≤2.5% ✅ |
| 现代 ham 误报率（全量 50000） | 0.95% | 2.10% | — |
| 现代 ham MALICIOUS | 0.00% | 0.07% | ≤0.3% ✅ |
| 现代 spam flagged 召回（全量 50000） | 96.32% | **99.46%** | ≥93% ✅ |
| 现代 spam flagged 召回（1500 抽样） | 96.93% | **99.67%** | ≥93% ✅ |
| 现代 spam MALICIOUS 占比（1500 抽样） | 60.40% | **87.93%** | — |
| phishing_pot flagged 召回 | 79.60% | **85.80%** | — |
| Enron ham 误报率 | 0.00% | 0.00% | ≤3% ✅ |

**误报上升的归因（重要）**：新增的 28 例抽样误报中 15 例由 `header_auth_inconsistent` 驱动，
而它们**全部来自语料的合成噪声**——`email_dataset_100k` 的 `spf/dkim/dmarc` 三列由生成器
**独立随机**赋值：实测 50000 封 ham 上，任意 `(spf, dkim)` 组合下 dmarc 取值都严格均分为
pass/none/fail 各 **33.3%**，不存在协议联动。因此这些样本里的 `spf=fail dkim=fail dmarc=pass`
不是真实 MTA 行为。该规则在真实邮件上不应触发，**此处计入的误报属假误报**。

**如果该规则的误报在你的真实语料上同样偏高**，无需改代码，两种在线调整方式：
`rules/builtin/header_rules.yaml` 把 `header_auth_inconsistent` 的 `points` 由 6 降到 3，
或在 `rules/custom/` 里同 id 覆盖为 `enabled: false`。降到 3 可让上述合成噪声样本
（10 分认证 + 3 分规则 = 13，离线归一化 29）回到 BENIGN，即完整消除这批假误报。

> ⚠️ **语料 2 的门禁盲区**：除上述认证噪声外，该语料的 **ham 完全不含 URL**
> （1500 封抽样实测 `has_url = 0`），因此 `link_domain_*` / `url_*` / `body_reward_lure`
> 等**链接类规则在该门禁上没有覆盖**，其真实误报率无法由它衡量。链接类规则目前的误报控制
> 手段是 `rules/dicts/link_allowlist.txt`，接入自有正常邮件语料后应优先校准该字典。

三项基线已固化为回归测试 `tests/test_fp_baseline.py`（固定种子抽样 1500 封）：Enron FP ≤3%、现代 FP ≤2.5%、现代 MALICIOUS-FP ≤0.3%、现代 spam 召回 ≥93%。调整规则权重时若引入误报或牺牲召回，CI 会立即拦截。四项修复的行为边界另由 `tests/test_link_and_auth_rules.py`（26 个用例）锁定。

> **门禁的可信度边界**（迭代 4 实测发现，务必连同上面的"门禁盲区"一起理解）：
> 语料 2 只覆盖**头部/认证/正文**维度的规则，**不覆盖任何链接类规则**（其 ham 无 URL）；
> 且其认证列是随机的，会为语义正确的认证一致性规则产生**假误报**。因此该门禁的
> "误报率"数字只能用于**同一语料上的横向对比**，不能直接当作生产误报率。

### 迭代 6：误报归因驱动的评分修正

用 `scripts/analyze_fp_causes.py` 对权威基线的 1050 例误报做归因后，落地了两项修正、
**否决了一项**（都记在这里，避免后人反复试）：

**① 消除对齐判定的跨维度重复计分**（采纳）

`Reply-To 域名不一致`此前被计三次：认证维度 +3、`header_reply_mismatch` +3、
`reply_to_freemail` +6 = **12 分**。而它在正常邮件里极其常见（工单系统 / 客服平台 /
外包发信），是 586 例误报的成因。现在对齐判定**只在 YAML 规则里计一次**，
运维调权也只需改一处（`Return-Path` 的 +2 同理移除，只在 `header_return_path_mismatch` 计分）。

**② 收敛认证维度满分 15 -> 12**（采纳）

三项全 fail 原先就是 15/15 分、离线归一化 33 分，**单靠认证维度**即可跨过 30 门槛；
而"三项全 fail"在正常邮件里并不罕见（**转发与邮件列表本来就会破坏 SPF**，这是 SPF 的
已知局限）。改为 SPF/DKIM/DMARC 各 4 分后归一化 26.7 分，不再单独致误。

注意**归一化分母仍保持 45**（声明权重仍是 15）：若把分母一并压到 42，所有离线分数会整体
上浮 7%，把贴着阈值的正常邮件（如"短链+凭证词"的营销样本）推成 MALICIOUS——那是用
一个维度降权换来全局过度定性。修正后 `suspicious_02` 仍为 51 SUSPICIOUS，未越线。

**③ `sender_from_freemail` 按 DMARC 排除（否决）**

原设想：DMARC 通过说明该免费邮箱域确实授权了这封信，此时不计分。
**实测否决**：权威基线上三种变体（不改 / 排除 dmarc=pass / 降到 1 分）的 ham 误报
**完全相同**（13/1500 = 0.87%，前置两项修正已把这批贴线样本压到阈值下），
却让 phishing_pot 前 500 封召回从 **84.0% 掉到 82.8%（排除）/ 83.2%（降分）**；
且概念上不成立——典型免费邮箱钓鱼「PayPal Support `<x@gmail.com>`」里 gmail.com 的
SPF/DKIM 本来就是通过的，按 dmarc=pass 排除恰好杀掉该规则要抓的场景。
规则保持原样，理由写进了 `rules/builtin/sender_rules.yaml` 与其回归测试。

### 迭代 5：URL 反混淆收敛到「真实攻击手法」

**决策**：`refang()` 只还原「攻击者在用、且不破坏链接可点击性」的混淆，**不再**还原
分析员的防呆写法。后者是威胁情报**报告**的书写约定（IETF `draft-grimminck-safe-ioc-sharing`，
MITRE/STIX 亦推荐），目的是让链接不可点击、避免误点与自动预览暴露调查行为；而攻击者
恰恰需要受害者点开链接——`hxxp://evil[.]com` 根本点不开，真实钓鱼不会这样写自己的载荷。
把防呆当真实 IOC 还原还会造成**反向误报**：转发一份脱敏的安全通告，里面的
`example[.]com` 会被提取、送去情报查询、可能命中，于是这封正常邮件被判恶意。

| | 手法 | 依据 |
|---|---|---|
| ✅ 还原 | 零宽字符（ZWSP/ZWNJ/ZWJ/WORD JOINER）插入 | SANS ISC 2025-01-27 "shy z-wasp"：零宽字符插进超链接可绕过 URL 安全检查，**且完全不影响链接可用性**——这正是与防呆的本质区别 |
| ✅ 还原 | 软连字符 SHY（U+00AD） | 同一案例的另一半；攻击者至少自 2010 年起在用 |
| ✅ 还原 | 未渲染的 HTML 实体、全角/兼容字符、组合记号插入 | 同属「切断可疑词但链接照样能点」 |
| ✅ 还原 | 反斜杠转义 `http:\/\/` | JSON/JS 字符串里的真实转义产物，非防呆惯例 |
| ❌ 不还原 | `hxxp`/`h**p`、`example[.]com`、`[:]`、`[/]`、`dot` 单词、标点插空格 | 分析员防呆惯例（见上） |

**新增检测（针对上述真实手法）**

1. **软连字符纳入不可见字符集合**。此前 `_INVISIBLE_RE` 不含 U+00AD，且它属 Cf 类、
   码位低于 `ͯ`，组合记号兜底也抓不到——于是 `PASS<SHY>WORD` 既不判为混淆，
   也匹配不到 `password`。现检测与 `fold_text` 归一化都已覆盖。
2. **HTML 隐藏文字（hidden text salting）**。Cisco Talos 记录该手法自 2024 下半年激增：
   用 `display:none`/`visibility:hidden`/`width:0`/`font-size:0` 藏入内容，干扰品牌名提取
   与语种判定；并在 base64 串里插 HTML 注释做 HTML smuggling。新增 3 条规则，只对
   高置信情形计分（**品牌错位** 8 分：隐藏文本含品牌而可见正文不含；**隐藏文字超 200 字**
   5 分；**注释切断 base64** 8 分）。正常邮件用 `display:none` 放预览摘要是常见做法，
   不误报——有反例测试守着。

**迭代 5 回归实测**（同口径抽样）：

| 指标 | 迭代 4 | 迭代 5 |
|---|---|---|
| Enron ham 误报率 | 0.00% | **0.00%**（零严重误报） |
| 现代 ham 误报率 | 1.87% | 1.87% |
| 现代 spam flagged 召回 | 99.67% | 99.60% |
| phishing_pot flagged 召回 | 85.80% | **86.60%** |

（反混淆收敛后 Enron 误报回到 0：上一轮出现的 1.53% 全部来自"给该语料去脱敏"这一测量假象，
而非真实误报。因此当时为压制它而做的 `body_credentials` 降分也已回退，只保留"不与高精度
规则重复计分"的去重条件。）

**顺带修掉**：`_has_usable_host()` 过滤主机不含点也不是 IP 的 URL（如 `http://example`、
`http://cheap`）。这类残片多来自防呆/脱敏残留或正文里被空格截断的产物，送去做威胁情报
查询没有意义，此前会污染 IOC 列表。

**实测（迭代 5 定稿）**

| 语料 | 指标 | 迭代 4 | 迭代 5 |
|---|---|---|---|
| **`data/dataset_eml`（权威基线，全量 10 万封）** | ham 误报率 | 2.10% | **2.10%** |
| | spam flagged 召回 | 99.46% | **99.45%** |
| | 精确率 / F1 | 97.93% / 98.69% | **97.93% / 98.69%** |
| Enron ham（补充哨兵） | 误报率 / 严重误报 | 0.00% / 0 | **0.00% / 0** |
| phishing_pot 前 500 封 | flagged 召回 | 85.8% | **86.6%** |

迭代 5 对权威基线的数字没有实质影响（该语料 ham 无 URL，链接类与 HTML 隐藏文字类规则
在它上面不触发），收益体现在真实钓鱼语料（phishing_pot +0.8pp）与新增的检测能力上。
三个新规则在正常邮件上零误报：`display:none` 预览摘要与「可见正文里已出现品牌」两种
常见情形都有反例测试守着。

**性能与一处自伤的正则回溯**（本轮实测发现并修复）

为新增的隐藏文字检测引入了两类性能问题，都已修掉：

1. **逐字符 Unicode 遍历**。`refang` / `fold_text` / `has_invisible_obfuscation` 都在用
   `"".join(ch for ch in text if …)` 这类逐字符 Python 循环。同一封 2.5 MB 正文的邮件：
   fold_text 340 ms、has_invisible 130 ms，而我新加的 refang 又添了 312 ms。改为
   **ASCII 快路径 + 只对"实际出现的非 ASCII 字符"建 `translate` 表**后，同一条件下
   整封分析约 **2.4 倍**加速。
2. **正则灾难性回溯（我引入的）**。`has_comment_split_base64` 最初把注释与 base64 写进
   同一个正则（带嵌套量词）；真实样本 `phishing_pot/sample-1053.eml`（196 KB、**0 个
   HTML 注释**）因此把整封分析挂死 **>20 s 不返回**，表现为"批量扫描卡住不动"。
   改为线性判据（去注释后是否出现明显更长的 base64 串）后该文件 0.1 ms 返回，
   phishing_pot 前 500 封整体 **从挂死变为 10 秒跑完**。回归测试用"无注释大 HTML"
   与"无注释长 base64 垃圾"两类输入守住（断言 <1s 返回）。

**性能基线（CPU 空闲实测，2026-09）**：2.5 MB 正文的整封离线分析 **2.3 s**
（`refang` 146 ms + `fold_text` 170 ms + 可见性检查 40 ms + 隐藏文字扫描 57 ms）；
phishing_pot 前 500 封（含多个 MB 级样本）**10 s**；权威基线全量 10 万封约 7 分钟。
> 注：早先曾发布过 6.5 s / 2.9 s / 11 s 等数字，那是机器上残留了并发分析进程时的测量值
> （实测干扰约 15–20%）；此处为清理后的复测值。

**关于 Enron 语料的 URL**：其 spam 里的 `http : / / host . tld` 正是数据集作者做的**脱敏**
（与防呆同源），不是可点击的真实链接。上一轮曾把它当检测能力还原出来，已按本决策移除——
因此该语料的 URL 提取率仍为 0%，URL 类规则在它上面依旧是空转的，这一点没有变。

## 已验证指标（本机实测）

- 单封离线分析耗时 **2–5 ms**（不含网络情报查询）
- 合成测试集 8 封：BENIGN/SUSPICIOUS/MALICIOUS 分档全部符合预期
- phishing_pot 真实钓鱼数据集前 500 封（离线）：flagged **85.8%**（迭代 4 前为 79.6%）
- **权威基线** `data/dataset_eml` **全量 10 万封**（离线，`scripts/eval_modern_baseline.py`）：
  ham 误报率 **0.97%**、严重误报 **0.00%**、spam flagged **99.13%**、精确率 **99.03%**、召回率 **99.13%**、F1 **99.08%**；
  扣除语料认证噪声后真实误报约 **0.17%**
  - 误报构成：`header_reply_mismatch` 586、`header_auth_inconsistent` 518、`reply_to_freemail` 369、
    `sender_from_freemail` 229（共 1050 例）。**其中约一半来自语料自身的合成噪声**——
    `header_auth_inconsistent` 命中的正是那批「三列独立随机赋值」产生的假组合，详见「基线语料约定」
- Enron 正常邮件语料全量 16545 封（离线）：**误报率 0.00%**，零严重误报
- Enron 的 `.eml` 转换与 `.txt` 原文件分析结果逐封一致（400/400），可放心统一为 .eml 形态
- 漏判修复验证：报告 `94bc4906453b4d6f` 同一输入下 **7 分 BENIGN → 66 分 MALICIOUS**

## 合规与数据说明

- 内置样本全部为**合成数据**，使用保留域名/保留 IP，附件为占位字节，不含真实恶意内容。
- 真实数据集（如 [phishing_pot](https://github.com/xffxd/phishing_pot)，`../phishing_pot-main`）仅建议**离线模式**批量分析；是否将其中 IOC 上传第三方情报平台由使用者自行评估授权。
- URLScan 默认仅做历史记录搜索（被动），主动扫描需显式设置 `URLSCAN_ALLOW_SUBMIT=1`。
- 请勿将未脱敏的生产邮件上传至任何第三方 API。

## Roadmap

- [x] 规则引擎外置：声明式 YAML 规则（字段/算子/分值）+ 内置探测器受控调参，字典文件独立维护，规则 CRUD API 与热重载，报告中记录规则版本哈希
- [x] 管理界面：批量分析页（多文件上传/目录、进度、结果表、CSV 导出）+ 规则管理页（行内调分值/开关、新建规则、字典维护、样本试跑）
- [x] 批量分析-本地目录**选择文件夹**：与"上传文件"对称的单一控件（「📂 浏览文件夹…」弹出系统原生文件夹选择框 + 路径框展示与手工兜底），选中后即显示可分析邮件数与递归开关
- [x] 目录发现性能：`iter_mail_files` 改用 `os.scandir`（免逐条 stat，8615 条目 523ms→26ms、10 万条目 6334ms→310ms，结果与 `rglob` 参考实现逐项一致并有等价测试）；`discover_cached` 按 (路径, 递归) 缓存 30s，消除「每次控件交互都重走目录树」导致的按钮长时间变灰（切换 offline 重跑：8614 封 558ms→11ms、10 万封 7352ms→10ms）
- [x] 批量分析详情显示修复：`SELECT RECORD` 改用**下标选项 + 固定 key**（此前直接传 `rows` 的 dict，无 key 的 selectbox 会返回上一轮的 option 对象，而 report_id 每轮都是新 uuid，按 id 回查必然落空 -> 详情块整体不渲染，即「第二次点击分析后报告消失」）；分析模式落盘为 `report["offline"]`，并区分「离线未查询」与「已查询但无有效数据」（此前共用一句"离线模式或全部无历史"，取消 offline 后仍显示「离线模式」，易被误认为调用了旧报告）
- [x] 清理重置：清空分析产物（`data/reports` 下的 .json/.html + 报告索引，可选情报查询缓存），三处入口一致——看板「MAINTENANCE // 清理重置」（需勾选确认才可执行）、`DELETE /reports?confirm=true`、`python -m app.cli purge`；只清理分析产物，不触碰规则/字典/样本/评估语料，且不递归删子目录
- [x] IOC 计数口径统一：新增 `count_iocs()`（含 `header_domains`，排除 `private_ips`，`sender_domains` 作为子集不重复计），替换看板「IOC数」列、CLI 批量 CSV 的 `iocs` 列与报告索引三处的旧口径 `urls+domains+ips+hashes`——此前「只有头部域名、正文无链接」的邮件会显示 IOC 数 = 0，使用者据此误以为 IOC 未被提取
- [x] 报告文案区分三种"无情报"成因：离线未查询 / 在线但无可查 IOC / 已查询但无有效命中。此前第三种与前两种混用「已查询 N 条 IOC」，N=0 时读起来像"提取到 IOC 却没送去富化"（真实工单 4c6c21d1bc6e4573：`enron1-spam-000029.eml` 只有一行主题、无正文，可提取 IOC 为 0）
- [x] 误报基线：Enron（16545 封）+ 现代邮件（3000 封，含完整头部）双语料，实测定位并修复 6.27%→1.10% 误报，固化为召回/误报双向门禁
- [x] 迭代 4：线上漏判（VT 命中域名却判 BENIGN）归因修复——情报按 IOC 类型分口径折算、认证头自相矛盾检测、发件域/链接域仿冒配对规则、奖励诱饵字典；phishing_pot 召回 79.6%→85.8%
- [x] 情报覆盖发件方域名：`extract_iocs` 新增 `sender_domains`（From/Reply-To/Return-Path），`Enricher.enrich()` 按"URL 主机名 + 发件方域"去重后查询（上限 8），不再漏查"只有头部域名、无 URL/附件"的邮件；to/cc 收件人域有意不查（通常就是使用者自己的组织，只浪费配额）
- [ ] 链接类规则的真实误报校准：以带 URL 的自有正常邮件语料校准 `link_allowlist`（现门禁语料 ham 无 URL，无法覆盖）
- [ ] 情报折算的更多语料验证：域名阶梯分值（现为硬编码常量）接入真实 VT 命中分布后回标
- [ ] YARA 检测接入评分引擎（规则已就绪，`yara-python` 可选安装后自动生效）
- [ ] Shuffle/SOAR 自动封禁联动
- [ ] 附件真实类型嗅探（magic bytes）与沙箱接口
- [ ] 情报源扩展（MISP、AlienVault OTX）
- [ ] 垃圾/营销邮件与钓鱼分离·第一步（类别标签层）：营销特征做成低分/信息性 signals（`List-Unsubscribe` 头、`Precedence: bulk/junk`、退订链接文本、已知 ESP 发信域），报告输出 `category`（marketing/phishing/…）标签供分析师分流；不动三档结论与阈值，零风险增量
- [ ] 垃圾/营销邮件与钓鱼分离·第二步（降档门槛 + SPAM 档）：`category=marketing` 且**无任何钓鱼强信号**（凭证表单/恶意附件/IP 直连 URL/情报命中/链接域不一致/品牌冒充）且**发件方可信证据成立**（认证对齐于非一次性域、历史通信记录）时，结论封顶新增的 `SPAM` 档。注意：`List-Unsubscribe` 等可伪造头部单独存在永不降档（防钓鱼伪装营销绕过），总分乘系数方案否决（破坏既有阈值校准且不可解释）
- [ ] 垃圾/营销邮件与钓鱼分离·第三步（分类别评估基线）：Enron spam（2003–2005 广告邮件，现召回 0%）与 100k spam 语料转为 SPAM 档评估集；datacon day1（钓鱼+垃圾混装 611 封，基线召回 52.7%→72.7%）校验"钓鱼被判 SPAM 率 ≈ 0"红线；核心指标按"钓鱼召回 / 垃圾入档率 / 营销误定性率"三线拆分
