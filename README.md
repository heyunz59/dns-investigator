# DNS 调查助手

报告层验收修复：.invalid 背景与实际观测分开；HTTP 摘要保留错误、跳转、最终 URL 和证书类别；假设身份不按类别重写，具体范围内的证据关系另行约束。[验证与边界](docs/report-acceptance-fixes.md)。

九案例修复：正式事实与结论按实际 E 测量逐行生成，执行错误使用独立 A 引用；模型草稿另存，不作为已验证结论展示。候选原因保持待验证，单项查询简化；HTTP 安全异常链和 Windows IPv6 地址处理已修正。日志格式 v4，[逐项记录与边界](docs/manual-review-fixes.md)。

v0.3 针对性修复：并发测量按调用 ID 归属，保留独立 HTTP/DNS 证据；CNAME 转介、未完成别名和链末端负回答明确区分。见 [修复与验证](docs/v0.3-targeted-fixes.md)。

## v0.3 DNS 深度诊断

当前实现为 **1 个 DeepSeek/PydanticAI Agent + 5 个正式工具**：增强的 query_dns（A/AAAA/CNAME/NS/SOA）、compare_resolvers、query_authoritative，以及保留的 check_tcp/check_http。新增确定性 DNS Finding 引擎；不是第二个 Agent，也不是第六个工具。完整验收、实际结果及边界见 [v0.3 交付记录](docs/dns-v3.md)。下文 v0.2 实验是历史材料，不代表 v0.3 的诊断准确率。

新增能力：比较系统/Cloudflare/Google 的响应状态、记录、别名、TTL 和耗时；递归辅助发现最近 SOA 区域与 NS，再向有限公共权威地址发起 RD=0 查询并检查 AA；生成响应差异、递归/权威差异、权威记录及 SOA Serial 差异等可追溯 Finding。CDN 地址不同、Serial 不同、TIMEOUT 都不直接确认故障根因。

配置通过 `.env` 注入：DNS_RESOLVERS（逗号分隔，system 表示系统，可移除某公共解析器）、DNS_QUERY_BUDGET=32、DNS_TOOL_TIMEOUT=20、MAX_AUTH_SERVERS=2。每个工具单项 DNS 超时最多 5 秒；默认外层 10 次尝试，实际 DNS UDP/TCP 请求另计 Q 预算，复合工具内部子查询不隐藏。权威最多 3 台、同请求每种传输最多重复 2 次；配置范围有校验。模型不能指定权威端口或任意权威 IP。

```powershell
.\.venv\Scripts\python.exe -m dns_investigator.main "查询 example.com 的 SOA 记录"
.\.venv\Scripts\python.exe -m dns_investigator.main "example.com 解析失败，请比较递归解析路径，必要时查询权威 DNS"
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe scripts/verify_dns_v3.py
.\.venv\Scripts\python.exe evaluation/dns_v3.py
```

后两条会实际访问网络，模型测试还会消耗 DeepSeek 额度。新评测每案例先运行 1 次，保留全部状态及 Finding；人工语义指标明确待复核，不生成虚假准确率。本轮未推送 GitHub。

基于 DeepSeek 和 PydanticAI 的命令行单 Agent。工具与证据来自运行程序的电脑；外部网络状态不能保证可复现。

实现：三个网络工具、模型自主工具循环、CLI、诊断结构与证据校验、独立调用尝试日志、受限超时与调用预算、八个可重放场景、离线 CI 和同模型 A/B 实验入口。v0.2 修复说明见 [docs/reliability-v2.md](docs/reliability-v2.md)，验证状态见 [docs/validation.md](docs/validation.md)。课程报告不在本项目范围内。

需求见 [docs/PRD.md](docs/PRD.md)。真实密钥仅存放在本地 `.env`，不要提交原始运行日志。

## 安装与运行

Python 3.11+（本次验证 Python 3.12），在项目根目录执行：

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
.\.venv\Scripts\python.exe -m pip install --no-deps -e .
Copy-Item .env.example .env
notepad .env
```

在 `.env` 第一行等号后填写本人的 DeepSeek API Key。不要将密钥发到聊天、截图或 GitHub。API 账户需要可用额度。默认 `deepseek-flash`、非思考模式、服务地址 `https://api.deepseek.com`，环境变量可覆盖配置；程序不会静默换模型。

```powershell
.\.venv\Scripts\python.exe -m dns_investigator.main "其他网站正常，但 https://example.com/ 打不开，请调查"
.\.venv\Scripts\python.exe -m dns_investigator.main "查询 example.com 的 A 记录"
```

没有问题参数时进入交互输入，缺目标时补充；也可通过 `--target example.com` 明确指定目标。裸域名默认 HTTPS，完整 URL 保留路径，不自动降级 HTTP。输出包含观察、假设、证据编号、结论、局限与建议。DNS/网络失败与模型服务故障分别记录。运行前在项目根目录操作，避免加载其他目录的配置。

## 无密钥检查与测试

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m dns_investigator.main "检查 example.com" --tools-only
.\.venv\Scripts\python.exe -m dns_investigator.main "检查 example.com" --tools-only --fixture data/fixtures/C5.json
```

`--tools-only` 以固定顺序检查工具，不调用模型，不算 Agent 或模型实验。带 `--fixture` 的 Agent 调查仍会调用真实 DeepSeek；只有工具数据是预设的。fixture 不含正确根因。脚本模型只用于自动测试基础设施。

## 评测与材料

```powershell
.\.venv\Scripts\python.exe evaluation/run_eval.py --repeats 3
# 人工检查真实回答，按 evaluation/cases.json 填写 review.csv
.\.venv\Scripts\python.exe evaluation/summarize.py results/evaluation-raw/review.csv
```

具体评分、调用遗漏、零调用 N/A 与信息差异见 [evaluation/README.md](evaluation/README.md)。同模型对照必须是真实运行，CSV 和图表仅在实际运行并人工评分后生成。不要把 fixture 设计或框架测试的通过率当成模型效果。

旧版 14 次真实模型对照的[原始记录](results/published/evaluation-20261031/README.md)保留。旧版以 evidence 数量估计工具调用总数，遗漏校验拒绝等尝试，因此历史工具正确率不能视为完整统计。v0.2 使用独立 attempts 分母；旧日志无法补齐时输出 INCOMPLETE，不猜测。新实验结果见验证记录。

v0.2 已完成 [48 次真实模型对照](results/published/evaluation-reliability-20261031T035848Z/README.md)：每场景每组 3 次。自动规则筛查 A=24/24、B=22/24；B 全部尝试 83 次，规则建议合理 78 次。**这是待人工复核的机械筛查，不能视为完整语义任务成功率**。两次 B 总结引用错误都保留为失败；新版真实 live 验证也已保存。

架构见 [docs/architecture.md](docs/architecture.md)，实际公开材料在 `results/published/`。原始日志位于 `results/runs/` 和 `results/evaluation-raw/`，均被 Git 忽略；仍须自行保管。工具日志公开导出可用 `scripts/publish_tools.py`，它会隐藏本地 DNS 配置，其他用户输入、路径等仍需逐项审核。首次及后续推送前运行 `python scripts/check_public.py`，并人工检查待提交文件。

## 已知边界

- 本机测量不代表用户浏览器、DoH、缓存、hosts、代理或历史状态。
- DNS 服务器、TCP 地址、HTTP 实际后端可能不同，日志不把它们合并为同一后端。
- HTTP 关闭环境代理；模型 SDK 使用自身网络设置，两个网络路径可能不同。必要时为模型进程设置本地 `HTTPS_PROXY`，不要提交个人代理配置。
- HTTP 总预算 15 秒、单次 DNS/TCP 最多 5 秒，默认最多 10 次工具调用；模型调用有单次超时和整次运行预算。
- 重定向最多 5 次、正文最多读取 64 KiB；不渲染网页、不读取正文给模型、不执行修复或扫描无关端口。
- 证据编号验证不能保证语义正确；质量以保留原始回答的人工案例评分为准。
- `status=completed` 表示模型输出通过本地结构和证据要求，`limited` 表示信息不足，`failed` 表示执行失败；另记 execution_status、requirements_met、result_origin。结构检查不能保证假设合理性和全部语义判断正确。
- CLI 退出码：0=通过本地结构要求，3=信息不足的有限结果，1=运行失败，2=输入/配置错误。有限结果不会被伪装成确定性根因诊断。
- 原始记录格式 v2 的 attempts 是全部已观察到的网络工具调用尝试，evidence 仅含有效测量。框架参数拒绝、工具内部失败、重复与预算拒绝仍计入尝试；结构化最终输出不计入网络工具分母。
- 网络测量具有时效性，公开仓库只存代码和材料，不会自动部署在线服务。
