# 🛡️ Phishing Analyzer — 钓鱼邮件自动化研判与响应系统

面向安全运营（SOC）场景的钓鱼邮件自动化分析流水线：**上报 → 解析 → IOC 提取 → 威胁情报富化 → 加权评分 → 三档结论 → 报告/工单**。

![Python](https://img.shields.io/badge/Python-3.9%2B-blue) ![FastAPI](https://img.shields.io/badge/API-FastAPI-009688) ![Streamlit](https://img.shields.io/badge/GUI-Streamlit-FF4B4B) ![Tests](https://img.shields.io/badge/tests-150%20%2B%20offline%20runnable-brightgreen)

> 🔐 **安全声明**：仓库内置的测试样本均为 **100% 合成数据**（RFC 2606 保留域名 + RFC 5737 文档 IP + 占位附件），可安全克隆、运行、演示与开源。

## 功能特性

- **邮件解析**：`.eml`（标准库）与 `.msg`（extract-msg），提取头部、SPF/DKIM/DMARC 认证结果、正文、附件哈希（SHA256/MD5）
- **IOC 提取**：URL / 域名 / IP / 文件哈希，支持零宽字符、软连字符等真实攻击混淆还原，短链接、Punycode、IP 直连识别，区分公网/私网 IP
- **威胁情报富化**：VirusTotal v3 + AbuseIPDB + URLScan.io（默认**被动搜索**，不主动提交扫描），异步并行 + SQLite 24h 缓存 + 令牌桶限流（VT 免费版 4 次/分钟）；情报结果按「命中 / 确定干净 / 无历史」语义分层计分
- **加权评分引擎**：情报 55% + 认证 15% + 启发式 30%，输出 `BENIGN / SUSPICIOUS / MALICIOUS` 三档结论 + **可解释研判依据**；离线模式自动归一化
- **SIEM 式规则外置**：**54 条**启发式规则全部声明在 `rules/builtin/*.yaml`，分值/开关可在线调整；自定义规则写入 `rules/custom/`（同 id 覆盖内置，升级安全）；品牌/TLD/短链接/关键词字典独立维护（`rules/dicts/*.txt`，13 个）；规则 CRUD API + 热重载；报告记录规则版本哈希，复盘可复现
- **响应闭环**：JSON + HTML 报告落盘、TheHive 工单自动创建（可配置）
- **接口与看板**：FastAPI（Swagger 自动文档）+ Streamlit 多页 GUI（看板 / 批量分析 / 规则管理）
- **批量能力**：CLI 与 GUI 均支持一键批量分析目录（GUI 提供系统文件夹选择框）；单封离线分析 2–5 ms

## 快速开始

```bash
# 1. 安装（Python 3.9+，Windows / Linux 通用）
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt      # Linux: .venv/bin/pip

# 2. 配置 API Key（可选，留空则自动降级为离线模式）
copy .env.example .env                              # Linux: cp

# 3. 分析单封邮件（仓库已内置合成样本）
python -m app.cli analyze data/samples/phishing_01.eml            # 在线（需 Key）
python -m app.cli analyze data/samples/phishing_01.eml --offline  # 离线

# 4. 批量分析整个目录
python -m app.cli batch <邮件目录> --offline --limit 100 --out data/results.csv

# 5. 启动 API 服务
python -m app.cli serve --port 8000
# Swagger: http://127.0.0.1:8000/docs

# 6. 图形界面（看板 + 批量分析 + 规则管理）
pip install streamlit
streamlit run dashboard.py      # http://localhost:8501

# 7. 清空分析数据（报告 + 索引；--include-intel-cache 连情报缓存一起清）
python -m app.cli purge                 # 交互确认
python -m app.cli purge --yes           # 脚本/CI 用，跳过确认
```

## REST API

启动服务后访问 `http://127.0.0.1:8000/docs` 查看交互式文档。

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/analyze?offline=&create_thehive=` | 上传 `.eml`/`.msg`（multipart 字段 `file`），返回评分/结论/IOC/原因 |
| GET | `/report/{id}` | 获取历史报告（`?format=html` 可选） |
| GET | `/report/{id}/download` | 下载报告文件 |
| GET | `/reports` | 分析记录列表 + 统计概览 |
| GET | `/reports/stats` | 预览分析数据规模（清理前确认用） |
| DELETE | `/reports` | 清空分析数据（需 `confirm=true`，可选 `include_intel_cache`） |
| GET | `/health` | 健康检查 |
| GET | `/rules` | 列出规则集（id/分值/开关/来源 builtin\|custom） |
| POST | `/rules` | 新建/整体覆盖自定义规则（写入 `rules/custom/`，立即生效） |
| PUT | `/rules/{id}` | 局部修改（enabled/points/name/description/reason） |
| DELETE | `/rules/{id}` | 删除自定义覆盖（恢复内置默认） |
| POST | `/rules/reload` | 热重载规则集与字典 |
| GET | `/rules/dicts` | 查看字典 |
| POST | `/rules/dicts/{dict_name}` | 向指定字典追加词条 |
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

总分 0–100：`< 30 BENIGN ｜ 30–54 SUSPICIOUS ｜ ≥ 55 MALICIOUS`（阈值可通过 `TH_SUSPICIOUS` / `TH_MALICIOUS` 环境变量调整）

| 维度 | 权重 | 依据 |
|---|---|---|
| 威胁情报命中 | 55% | VT 引擎检出（按 IOC 类型分口径：声誉型阶梯给分 / AV 型按比例折算）、AbuseIPDB 滥用置信度、URLScan 历史判定 |
| 邮件认证 | 15% | SPF/DKIM/DMARC fail/softfail/neutral/none，认证头自相矛盾检测 |
| 启发式规则 | 30% | 54 条外置规则：身份伪造（显示名品牌冒充/内嵌假邮箱/数字混淆域名/免费邮箱发件）、URL 特征（IP 直连/Punycode/短链接/高风险 TLD/@ 混淆）、链接域与发件域仿冒配对、附件特征（双扩展名/宏文档/可执行/随机命名/HTML 诱饵）、正文特征（混淆还原/紧急措辞/凭证与奖励话术/锚文本伪装/HTML 隐藏文字/内嵌密码表单）、独立信号叠加 |

- 每条结论附带完整 `reasons` 列表（含情报查询汇总），可解释、可审计。
- 所有关键词匹配先经 `fold_text()` 混淆还原（零宽字符、组合记号插入 `Aܿmܿaܿzܿon`、西里尔同形字 `Sаmsung`、变音符号、软连字符）。
- **情报语义分层**：`hit` 主动加分；文件哈希 `clean` 是确定性负面证据；URL/域名的 `clean` 只是声誉弱负面，与 `unknown`（新钓鱼 IOC 的常态）一样**不会**压低评分——避免"情报没见过"被误当"情报确认干净"。
- **离线/情报无有效数据时**：auth+heuristic 原始分自动归一化到 0–100，阈值语义保持一致。
- URL 反混淆只还原**攻击者真实手法**（零宽字符/软连字符/HTML 实体/全角字符等，切断可疑词但链接照样能点），**不还原**分析员防呆写法（`hxxp://`、`example[.]com`）——后者会造成反向误报。

## 架构

> 🔍 **交互式架构图**：[`架构图/architecture.html`](架构图/architecture.html) — 浏览器直接打开，支持深浅色切换、平移缩放、节点搜索、关系追踪与图片导出。

```text
.eml/.msg 上报 → parser（eml/msg）→ extractor（IOC + 认证）
   → enrichment（VT / AbuseIPDB / URLScan，异步 + SQLite 缓存 + 限流）
   → scoring（加权评分 + YAML 规则目录 + 字典）
   → response（JSON/HTML 报告 + TheHive 工单）
   → FastAPI / Streamlit 看板
```

## 目录结构

```text
phishing-analyzer/
├── app/
│   ├── main.py               # FastAPI 入口（分析 + 规则管理端点）
│   ├── pipeline.py           # 分析流水线编排
│   ├── cli.py                # 命令行（analyze/batch/serve/purge）
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
│   ├── builtin/*.yaml        # 54 条内置评分规则（分值/开关可在线调整）
│   ├── custom/*.yaml         # 用户自定义规则（同 id 覆盖内置）
│   └── dicts/*.txt           # 品牌/TLD/短链/关键词/链接域白名单字典
├── gui/                      # Streamlit 页面：看板首页 + 批量分析 + 规则管理
├── data/samples/             # 合成测试样本（8 封：钓鱼/可疑/正常）
├── tests/                    # pytest（150+ 用例，离线可跑）
├── scripts/                  # 样本生成 + 数据集评估 + 误报基线 + CSV/Enron 转 eml
├── 架构图/                    # 交互式架构图（HTML + 源规格 JSON）
├── dashboard.py              # Streamlit 入口（看板首页）
├── Dockerfile / docker-compose.yml
└── requirements.txt
```

**自定义规则示例**（`rules/custom/my_rule.yaml`）：

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

## Docker 部署

```bash
cp .env.example .env    # 填入 API Key
docker compose up -d    # API :8000，看板 :8501
```

`data/`（报告与缓存）与 `rules/`（规则与字典）通过 volume 挂载持久化，容器重建不丢数据。

## 测试与评估

```bash
python -m pytest    # 150+ 用例，全程离线可跑
```

覆盖：解析/哈希、IOC 提取与混淆还原、认证解析与对齐性、评分三档阈值、离线归一化、情报命中路径、API 端到端往返、GUI 组件，以及真实数据集评估中发现的全部攻击模式（字符混淆、显示名冒充、锚文本伪装、随机文件名、诱饵附件、HTML 隐藏文字）。另含**误报/召回双向回归门禁**（`tests/test_fp_baseline.py`），调整规则权重引入回退时会被立即拦截。

**数据集基准评估**（离线模式，纯本地规则，不含威胁情报）：

```bash
python scripts/eval_dataset.py --dir <phishing_pot 邮件目录> --limit 500      # 真实钓鱼召回
python scripts/eval_modern_baseline.py                                        # 权威基线（含 ham 误报）
python scripts/eval_fp_baseline.py --dir data/enron_eml --out data/eval_fp_enron.csv   # 补充哨兵
```

本机实测指标：

| 语料 | 指标 | 结果 |
|---|---|---|
| **权威基线**（现代邮件 10 万封：50k ham + 50k spam） | 精确率 / 召回率 / F1 | **99.03% / 99.13% / 99.08%** |
| | ham 误报率 / 严重误报（MALICIOUS） | **0.97% / 0.00%**（扣除语料自身认证噪声后约 0.17%） |
| [phishing_pot](https://github.com/xffxd/phishing_pot) 真实钓鱼（前 500 封） | flagged（恶+可疑）召回 | **86.6%** |
| Enron 正常邮件（16545 封，补充哨兵） | 误报率 | **0.00%** |

> 评估的完整过程——规则迭代史、逐轮归因与修复、语料局限分析（如权威基线 ham 无 URL、认证列随机赋值带来的"假误报"）、反混淆手法的取舍依据——见 [`README_dev.md`](README_dev.md)。

## 合规与数据说明

- 内置样本全部为**合成数据**，使用保留域名/保留 IP，附件为占位字节，不含真实恶意内容。
- 真实数据集建议**离线模式**批量分析；是否将其中 IOC 上传第三方情报平台由使用者自行评估授权。
- URLScan 默认仅做历史记录搜索（被动），主动扫描需显式设置 `URLSCAN_ALLOW_SUBMIT=1`。
- 请勿将未脱敏的生产邮件上传至任何第三方 API。

## Roadmap

- [ ] 链接类规则的真实误报校准：以带 URL 的自有正常邮件语料校准 `link_allowlist`
- [ ] 情报折算的更多语料验证：域名阶梯分值接入真实 VT 命中分布后回标
- [ ] YARA 检测接入评分引擎（规则已就绪，`yara-python` 可选安装后自动生效）
- [ ] Shuffle/SOAR 自动封禁联动
- [ ] 附件真实类型嗅探（magic bytes）与沙箱接口
- [ ] 情报源扩展（MISP、AlienVault OTX）
- [ ] 垃圾/营销邮件与钓鱼分离：营销特征识别（`List-Unsubscribe` 等头部信号）→ 类别标签 → 有条件降档 `SPAM` 档（防钓鱼伪装营销绕过）

## 开发文档

- [`README_dev.md`](README_dev.md) — 完整开发记录：规则迭代史（6 轮评估-归因-修复-回归闭环）、误报根因分析、基线语料约定与盲区、性能优化记录、设计决策与被否决的方案
