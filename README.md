# DNS 调查助手

公网日志反例修复：正式报告按实际解析器、来源、测量位置和可靠时间窗口聚合递归超时；原始名称/类型、E/Q/Finding 保留。Web、CLI 和 JSON 同时展示正常对照、TCP/HTTP 已测结果及未完成环节，不把局部路径超时说成网站整体故障。旧完整日志可在 Web 导入后只读回放；导出保留旧 result 为 original_result，原始账本不变。原 Web 进程如仍运行，重启后导入原 JSON 即可使用新逻辑。[百度样本对照、截图及验收记录](results/published/public-path-aggregation/20261102-baidu/review-summary.md)。本轮仅回放旧日志，无新增公网测量或模型调用。

v0.4 有限协议诊断（2026-11-02，0.4.0.dev0）：保持一个 Agent、五个工具；query_authoritative 默认 basic，按需选择 trace/dnssec。新增 EDNS/EDE 来源分析、从 Root Hints 出发的有界 RD=0 委派追踪、认证根锚下的签名/信任链及限定 NSEC/NSEC3 证明验证。最终业务源码133b49a：356项离线通过；Unbound1.26.2对照37例，其中30个声明核心场景状态一致，其余策略/畸形差异与参考超时如实列出；真实DeepSeek受控实验逐轮保存，不是语义准确率。公网 nic.cz 完成独立路径与本地 SECURE 验证，另有路径未完成记录；不保证任意公网域名均可追踪。完整支持矩阵、失败记录、成本和复测见[v0.4验证与边界](docs/v0.4-validation.md)。本轮仅本地提交，未推送/合并/发布，远程CI未验证。

不支持自动 CNAME 全链 DNSSEC、DNAME、NSEC ENT NODATA、NSEC3非零迭代/非空salt/Opt-Out及策略之外算法；未完成/能力受限保留未知。跨区 NS 循环引导可能停止，不暗中调用递归。EDE服务器自报、程序规则、本地密码学V、外部参考分开；不能据此确认运维根因。旧版本以下为历史记录，当前日志v7及支持范围以上文为准。

最终核验（2026-11-01）：补齐正文完整性/上限状态、权威直查中断计数与选中范围、未知时间的别名/超时对照及跨时区Finding边界；完善调用范围和记录全集摘要。最终离线 **271 passed**。新增同环境真实DeepSeek受控对照两版各7次均通过输出校验，但新版A=38高于基线30，**未证明调用更合理或语义准确率提高**。完整反例、AI辅助复核、源码对应及课程演示边界见[最终核验记录](docs/final-verification.md)。本轮仅本地提交，未推送；新提交远程CI未验证。

2026-11-01 安全与稳定性修复：HTTP 每跳按 origin 授权，解析后仅连接通过地址策略的数值 IP，保留 Host/SNI/证书校验；权威发现保存明确完成阶段；缺少有效时间的历史证据不参与同期冲突定位。模型只输出决策草稿，程序生成正式证据报告，日志 v6 区分 Agent 总结失败与报告可用。完整离线 **249 passed**，真实 DeepSeek + 本机受控 DNS 新旧各7次，新版校验输出7/7、旧版6/7；不是诊断准确率。见[修复、实测与限制](docs/security-stability-fixes.md)。本轮在工作分支本地提交，按本轮要求未自动推送或创建 PR，远程 Actions 尚未验证。

fcd1d52 验收补修：CNAME 后续完整回答通过证据链收敛，原始响应不改写；权威发现的预算/执行失败进入正式 A 问题、比较和摘要，不伪造 Q/E。[本轮验证与边界](docs/fcd-acceptance-fixes.md)。

2026-11-01 DNS 判断与范围定位升级：区分传输结果和真实 RCODE；超时不参与内容/TTL 冲突比较，部分失败不隐藏有效子集。Finding 按目标、类型、来源及时间范围聚合；正式输出分为 measured_facts、findings、diagnostic_assessment 和 recommendations。调查不再按假设数量机械降级，保留候选身份和证据关系。仅 query_dns 可跟进已观测、同来源、与原目标连通的 CNAME 链（深度/目标数均最多8），不扩展为任意扫描。模型总结失败仍保留程序生成的事实与范围摘要。[本轮实际对照、运行方法与边界](docs/dns-accuracy-upgrade.md)。此前按要求仅本地提交；本次验收补修已获用户推送授权，远程 Actions 以实际提交运行结果为准。

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

实现：五个正式工具、模型自主工具循环、CLI、诊断结构与证据校验、独立调用尝试日志、受限超时与调用预算、可重放场景、离线 CI 和同模型 A/B 实验入口。当前日志格式 v7，旧正式报告字段保留可读默认值，不修改原文件。v0.2 修复说明见 [docs/reliability-v2.md](docs/reliability-v2.md)，验证状态见 [docs/validation.md](docs/validation.md)。课程报告不在本项目范围内。

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

HTTP 默认只授权输入 URL 的 scheme/host/port；同主机标准 HTTP:80 → HTTPS:443 可升级。其他跨域或端口跳转会保留已收到的响应并明确拒绝。确需授权时由用户在本地配置 `HTTP_ALLOWED_ORIGINS`（逗号分隔完整 origin），内网还需单独配置 `HTTP_ALLOWED_NETWORKS`（逗号分隔精确 CIDR）；两者默认均空。允许 origin 不等于允许其解析到内网，模型不能扩大这两个配置。HTTP 不使用环境代理，不关闭证书验证。

TCP 同时要求本次目标范围内、有效且有时效限制的 DNS 地址证据、授权端口与独立网络访问许可。默认只允许公共地址；需诊断可信内网时，由用户配置 `TCP_ALLOWED_NETWORKS=10.20.0.0/16` 等严格 CIDR（默认空，非法 CIDR 导致配置错误）。它与 HTTP CIDR、系统 DNS 解析器许可相互独立。链路本地、组播、未指定、已知元数据地址和受限 IPv6 过渡地址即使有宽 CIDR 也拒绝。fixture 不会授权真实 TCP 连接；安全拒绝记录为调用问题，不冒充目标连接失败。

本轮 [TCP/NSEC3 专项复核材料](results/published/v0.4-security-nsec3-followup/review-summary.md)包含 410 项本地测试、TCP 修复前后矩阵及 28 个签名 DNS 场景的独立 Unbound 对照。NSEC3 未知 Hash/保留 Flags 候选不再毒化其余充分证明；过滤候选不等于证明成立。迭代、盐、Opt-Out、跨区及多 RData 等支持边界仍可能返回 INDETERMINATE。Unbound 状态相同不代表完整协议正确，具体分歧与未决风险均保留在材料中。

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

## v0.5 结构化诊断与修复建议

收尾验收要求在测试前正常安装项目：`python -m pip install -e .`，不能仅依赖 pytest 的 `pythonpath`。CI 同时构建 wheel，在项目目录外、清除 `PYTHONPATH` 后验证模块入口和 `dns-investigator` 命令的 JSON 输出及全部模块/资产；本地可执行 `python scripts/check_installation.py --wheel-dir dist --output results/runs/install.json --restore-editable`（先构建 wheel；脚本实际安装 wheel 后恢复 editable）。

系统 DNS 建议从父调用确认路径后使用 `resolver=None`；显式解析器按原工具准入规则检查，历史来源不全或系统/显式路径重叠时不标为当前工具可执行。`supported_by_current_tools` 表示能力/当前参数检查，不是已经执行；`can_execute_now=false`，新调查仍须重新校验目标、解析器及预算。并列摘要先为每个异常分配 CHECK，最多三项，超额明确提示；完整 JSON 不截断。v0.5 进入冻结，跨平台验收见 [最终收尾材料](results/published/v05-finalization/20261102-crossplatform/review-summary.md)。

本地报告质量补修：默认 CLI 为摘要，不再重复输出完整 JSON；`--verbose` 追加详情，`--format json` 输出单一完整 JSON 对象（进度到 stderr，不能与 `--verbose` 组合）。JSON/非交互模式缺目标直接返回错误，不等待输入；`--tools-only --format json` 输出独立工具记录对象，仍不调用模型。完整日志与原退出码保留。

诊断新增直接依据/验证依赖与结构化位置；明确关注点只影响展示相关性，不影响授权或验证等级。无充分主次依据时 `diagnosis_selection_mode=parallel`、`diagnostic_conclusion=null`，所有并列观测保存在 `secondary_diagnoses`，不虚构综合根因。CHECK 的 `branches` 将未来检查条件、解释、下一步和变更前提绑定；建议尚未执行。完整材料见 [本地专项修复记录](results/published/v05-report-quality-fixes/20261102-report-quality/review-summary.md)。该记录保留当时的本地验收状态；后续推送及跨平台 CI 成功结果见上方最终收尾材料。

调查结束后，普通 Python 规则模块从已有 Evidence/Finding/V 构造 `diagnostic_conclusion`、`secondary_diagnoses` 和 `remediation_plan`，不新增工具、网络测量或第二次模型调用。CLI 优先显示结论、位置、原因等级和行动，再显示完整调查详情；单项查询继续优先显示记录。

诊断状态与 Agent 执行状态独立：`CONFIRMED_PROTOCOL_ISSUE` 仅确认支持范围内的本地协议异常，`FAULT_LOCALIZED` 只定位已测环节，`NO_FAULT_OBSERVED` 不代表用户问题不存在，`INSUFFICIENT_EVIDENCE` 不当作故障。`LIKELY_CAUSE` 为兼容的候选状态，目前规则不凭症状强行提升到该等级。建议分 CHECK、条件性 POSSIBLE_FIX 和 VERIFY，全部尚未执行，不自动修改配置。旧日志的新字段默认空，不把回放生成字段当历史事实。

完整中文技术报告、十个受控新旧对照和边界见 [v0.5 专项报告](results/published/v05-diagnostic-upgrade/technical-report.md)。本轮是报告层升级，发行包版本元数据仍为 0.4.0.dev0，尚未发布正式 0.5 包。

## 已知边界

- 本机测量不代表用户浏览器、DoH、缓存、hosts、代理或历史状态。
- DNS 服务器、TCP 地址、HTTP 实际后端可能不同，日志不把它们合并为同一后端。
- HTTP 关闭环境代理；模型 SDK 使用自身网络设置，两个网络路径可能不同。必要时为模型进程设置本地 `HTTPS_PROXY`，不要提交个人代理配置。
- HTTP 总预算 15 秒、单次 DNS/TCP 最多 5 秒，默认最多 10 次工具调用；模型调用有单次超时和整次运行预算。
- 重定向最多 5 次、正文最多读取 64 KiB；不渲染网页、不读取正文给模型、不执行修复或扫描无关端口。
- 证据编号验证不能保证语义正确；质量以保留原始回答的人工案例评分为准。
- `status=completed` 表示模型输出通过本地结构和证据要求，`limited` 表示信息不足，`failed` 表示执行失败；另记 execution_status、requirements_met、result_origin。结构检查不能保证假设合理性和全部语义判断正确。
- 日志 v6 另记 agent_execution_status、report_availability、report_origin、fallback_reason；Agent 总结失败仍可能有可用程序报告，但保持 failed，不统计为 Agent 成功。raw_model_drafts 保留所有最终输出尝试，output_resubmissions 只数结构化输出重交，不冒充 SDK/HTTP 重试数。
- CLI 退出码：0=通过本地结构要求，3=信息不足的有限结果，1=运行失败，2=输入/配置错误。有限结果不会被伪装成确定性根因诊断。
- 原始记录格式 v2 的 attempts 是全部已观察到的网络工具调用尝试，evidence 仅含有效测量。框架参数拒绝、工具内部失败、重复与预算拒绝仍计入尝试；结构化最终输出不计入网络工具分母。
- 网络测量具有时效性，公开仓库只存代码和材料，不会自动部署在线服务。

## v0.6 本机 Web 界面

在项目根目录安装并启动（Python 3.11+）：

```powershell
.venv\Scripts\python.exe -m pip install -e ".[web]"
.venv\Scripts\python.exe -m dns_investigator.web
```

打开 http://127.0.0.1:8765 。也可使用安装后的 `dns-investigator-web` 命令。服务固定监听回环地址；不支持公网部署。

在本机 `.env` 配置 `DEEPSEEK_API_KEY` 后，输入域名或 HTTP/HTTPS URL 即可启动现有 Agent。问题描述可选。进度来自 Agent 的实际证据回调；完成、受限、失败均保留真实状态。模型总结失败时仍可查看已有证据。原有工具授权、预算和网络策略不变，页面没有自动修复或任意命令接口。

页面只有“解析与证据 / 排障详情 / 调查时间线”三个标签页。检查与修正建议均标为尚未执行。解析器对照只展示实际日志；没有时间或测量时明确标为未记录/未测量。证据按五项分页展开，可查看完整 A/Q/E/V 关联数据。故障位置使用已有结论中的文本，不推测 Root/TLD 节点。

“历史记录”读取 `results/runs` 下最多 100 份最近 JSON；“导入历史 JSON 报告”接收最多 16 MB 的报告副本，生成随机本地 ID，不能指定服务器文件路径。支持脱敏 JSON 与独立 HTML 导出。HTML 无脚本、无外部依赖，可双击离线打开和打印。JSON 保持既有正式报告及回放兼容格式。

受控历史/构造场景可单独准备（始终显示“示例数据 / 非真实公网测量”）：

```powershell
.venv\Scripts\python.exe -m scripts.prepare_web_demos
```

验证：`python -m pytest -q`。浏览器检查需另装 `playwright`，运行 `python scripts/check_web_browser.py`（先准备演示报告、启动服务）。Windows 自动使用 Chrome/Edge；其他平台运行 `python -m playwright install chromium`，或通过 `WEB_BROWSER` 指定浏览器路径。此脚本检查三种场景、三个标签页和移动端溢出，并生成截图。

最新产品化交付见 [docs/v06-polish/README.md](docs/v06-polish/README.md)，初版资料见 [docs/v06-web/README.md](docs/v06-web/README.md)。回放只反映保存时刻，历史字段不补造。首页使用受控短摘要，正常/异常路径限实际查询范围；三个标签页保留完整解释、按解析器分组的测量、友好证据与纵向时间线。


调查期间显示真实证据回调、已记录的工具调用数及持续时间。取消会向后台任务发送异步取消请求，待上下文退出并保存证据后显示“已取消”，不会将取消解释为 DNS 故障。页面刷新或短暂断线后可在同一浏览器会话恢复任务；服务重启后旧任务返回不存在，并提示查看已保存历史。当前仍为单机串行调查，没有持久化任务队列。取消不能撤回已经发送的网络请求；同步清理操作完成前会保持停止中状态。

历史记录支持域名筛选和实际测量时间排序，缺失测量时间明确标注未知，导入时间不冒充测量时间。取消接口要求本机令牌和所属浏览器会话，其他会话不能查询或取消该任务。已有建议不自动执行，历史授权必须重新校验。

产品浏览器验收：启动服务并准备演示报告后运行 `python scripts/check_web_product_browser.py`。追加 `--live` 会真实调用本机 DeepSeek 配置并进行新的 example.com 公网测量，以及第二次真实取消检查；默认仅回放/导入已有报告。截图、离线 HTML、打印验证和浏览器结果写入 `docs/v06-polish/`。
