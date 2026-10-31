# DNS 调查助手

基于 DeepSeek 和 PydanticAI 的命令行单 Agent。工具与证据来自运行程序的电脑；外部网络状态不能保证可复现。

实现：三个网络工具、模型自主工具循环、CLI、证据引用校验、JSON/JSONL 日志、受限超时与调用预算、七个可重放场景、离线 CI 和同模型 A/B 实验入口。验证状态见 [docs/validation.md](docs/validation.md)。课程报告不在本项目范围内。

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

架构见 [docs/architecture.md](docs/architecture.md)，实际公开材料在 `results/published/`。原始日志位于 `results/runs/` 和 `results/evaluation-raw/`，均被 Git 忽略；仍须自行保管。工具日志公开导出可用 `scripts/publish_tools.py`，它会隐藏本地 DNS 配置，其他用户输入、路径等仍需逐项审核。首次及后续推送前运行 `python scripts/check_public.py`，并人工检查待提交文件。

## 已知边界

- 本机测量不代表用户浏览器、DoH、缓存、hosts、代理或历史状态。
- DNS 服务器、TCP 地址、HTTP 实际后端可能不同，日志不把它们合并为同一后端。
- HTTP 关闭环境代理；模型 SDK 使用自身网络设置，两个网络路径可能不同。必要时为模型进程设置本地 `HTTPS_PROXY`，不要提交个人代理配置。
- HTTP 总预算 15 秒、单次 DNS/TCP 最多 5 秒，默认最多 10 次工具调用；模型调用有单次超时和整次运行预算。
- 重定向最多 5 次、正文最多读取 64 KiB；不渲染网页、不读取正文给模型、不执行修复或扫描无关端口。
- 证据编号验证不能保证语义正确；质量以保留原始回答的人工案例评分为准。
- 网络测量具有时效性，公开仓库只存代码和材料，不会自动部署在线服务。
