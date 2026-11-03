# DNS Investigator

### DNS 故障排查与分析工具

[English](README.md) · 简体中文

[![CI](https://github.com/heyunz59/dns-investigator/actions/workflows/tests.yml/badge.svg?branch=main)](https://github.com/heyunz59/dns-investigator/actions/workflows/tests.yml)
![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue)
[![MIT License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

DNS Investigator 是一个开源的 DNS 故障排查工具，支持命令行和本机 Web 界面。输入域名或 URL，并说明遇到的问题，程序会借助 DeepSeek 选择合适的检查：查询 DNS 记录、比较不同解析器的回答、检查权威服务器，必要时继续检查 TCP、TLS 和 HTTP。

每次检查的目标、时间、结果和来源都会写入报告。遇到解析失败或网站无法访问时，可以先对照各条路径的结果，再查看 DNSSEC 验证和连接检查的细节，逐步缩小排查范围。报告也会说明尚未查明的问题，并给出后续检查建议。

![DNS Investigator 诊断界面](docs/images/diagnosis.png)
*百度历史调查的脱敏回放。系统解析器地址已替换，结果反映的是当时的网络情况。*

**导航：** [快速开始](#快速开始) · [Web 使用](#web-使用) · [命令行](#命令行使用) · [诊断能力](#诊断能力) · [工作原理](#工作原理) · [报告解读](#如何阅读调查报告) · [开发与测试](#开发与测试)

## 诊断能力

| 调查环节 | 主要能力 | 报告内容 |
| --- | --- | --- |
| DNS 查询 | A、AAAA、CNAME、NS、SOA；保存 Answer、Authority、Additional、TTL、标志位和 CNAME 链 | 应答状态、记录、实际解析器、查询时间与传输结果 |
| 递归解析器对照 | 使用系统 DNS 和配置的公共解析器查询同一名称 | 比较响应码、是否返回记录，以及地址、别名、TTL 和耗时的差异 |
| 权威 DNS | 查找域名所属区域和 NS，选取部分服务器直接查询，检查 AA 与 SOA | 比较递归和权威回答，以及所查权威服务器之间的差异 |
| 委派追踪 | 从根服务器开始，以 RD=0 查询逐级追踪委派，检查转介地址是否符合 bailiwick 规则 | 展示已查询的委派路径、别名、地址依赖和停止位置 |
| DNSSEC | 获取 DS、DNSKEY、RRSIG 和否定证明，在本地验证已支持的场景 | 说明验证结果、失败步骤、所用材料和未能完成验证的原因 |
| TCP / TLS / HTTP | 检查 IPv4/IPv6 TCP 连接、HTTPS 证书、HTTP 响应、重定向和正文读取 | 分别记录连接是否成功、证书是否通过验证，以及请求完成到哪一步 |
| 报告与排障 | 汇总同一路径上的异常，整理可能原因和处理建议 | 说明下一步检查什么、何时可以修改配置，以及如何复测 |

例如，系统 DNS 能解析、某个公共解析器却超时时，报告会分别列出两条路径的结果。对于 NXDOMAIN、NODATA、SERVFAIL、REFUSED、别名解析未完成和超时，也会作出区分，便于判断应继续检查解析器、权威服务器还是后续连接。

如果同时出现 DNS 超时和 HTTP 503，报告会把两项结果一起列出。只有现有证据足以判断时，才会给出主次关系；否则会分别说明需要继续检查的方向。

## 快速开始

### 环境要求

- Python **3.11 或更高版本**；CI 覆盖 Linux Python 3.11/3.12 和 Windows Python 3.12。
- Git；使用 Web 界面时需要现代浏览器。
- DeepSeek API Key，用于 Agent 调查。API 调用按服务商规则计费。
- 对调查目标及所需网络访问具有授权。

当前包版本为 `0.6.0rc1`。下列命令从默认 `main` 分支安装；版本变化见 [CHANGELOG](CHANGELOG.md)。

### 1. 获取源码

```bash
git clone https://github.com/heyunz59/dns-investigator.git
cd dns-investigator
python -m venv .venv
```

### 2. 安装

Windows PowerShell：

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[web]"
Copy-Item .env.example .env
```

Linux / macOS：

```bash
.venv/bin/python -m pip install -e ".[web]"
cp .env.example .env
```

`[web]` 包含本机 Web 所需依赖。仅使用 CLI 时，将安装参数改为 `-e .`。在项目根目录运行后续命令；以下示例中的 `python` 应指向项目虚拟环境：

```powershell
# Windows PowerShell
.\.venv\Scripts\Activate.ps1
```

```bash
# Linux / macOS
source .venv/bin/activate
```

若 PowerShell 禁止执行激活脚本，可直接使用 `.\.venv\Scripts\python.exe -m ...` 运行模块。

### 3. 配置 DeepSeek

用文本编辑器打开本地 `.env`，填写自己的密钥：

```dotenv
DEEPSEEK_API_KEY=
DEEPSEEK_MODEL=deepseek-flash
DEEPSEEK_BASE_URL=https://api.deepseek.com
```

默认关闭模型思考模式。其余配置可保留 `.env.example` 中的默认值。密钥只保存在本机；`.env` 已加入 Git 忽略规则。完整配置及网络授权方式见 [配置指南](docs/configuration.md)。

### 4. 启动

```bash
python -m dns_investigator.web
```

浏览器打开 **http://127.0.0.1:8765**。安装后的 `dns-investigator-web` 命令提供相同入口。

## Web 使用

1. 输入域名或 HTTP/HTTPS URL。URL 可包含端口、路径和查询参数。
2. 按需添加问题描述，例如“系统 DNS 偶尔解析失败，请比较递归路径”或“检查 DNSSEC 验证失败的位置”。
3. 启动调查，查看实际执行进度、已记录的工具调用和当前结果。
4. 从首页查看异常范围、正常路径及优先检查方向，再进入详情核对证据。

| 界面 | 用途 |
| --- | --- |
| 诊断首页 | 主要/并列观测、故障位置、解析路径对照和优先行动 |
| 解析与证据 | 按解析器查看查询名称、类型、结果、RCODE、耗时及 E/Q/A 关联 |
| 排障详情 | 完整结论、确认等级、检查分支、变更前提和验证步骤 |
| 调查时间线 | 实际工具调用、参数、执行状态、耗时和关联证据 |
| 历史记录 | 按目标筛选已保存调查，重新查看报告 |

调查过程中可以取消任务，已经取得的结果仍会保存。报告可导出为 JSON，供程序读取或进一步分析；也可导出为包含完整样式的 HTML，离线查看和打印。分享前请检查其中的目标、URL 和解析器等网络信息。

Web 默认只监听本机回环地址，适用于单机调查。部署边界和访问控制见 [安全说明](docs/security.md)。

## 命令行使用

### 单项查询

```bash
dns-investigator "查询 example.com 的 A 记录"
```

单项查询会返回所需记录、TTL 和查询来源。排查故障时，可以直接描述遇到的现象：

```bash
dns-investigator "example.com 解析失败，请比较系统 DNS 和公共解析器"
dns-investigator "检查 example.com 的委派链及 DNSSEC 验证情况"
dns-investigator "https://example.com/ 无法访问，请判断故障发生在哪个环节"
```

这些命令会调用 DeepSeek，并可能在授权范围内发起网络请求。Agent 根据已有结果和剩余调用次数，决定是否需要进一步检查。

### JSON 与详细输出

```bash
dns-investigator "调查 example.com 的 DNS 解析" --target example.com --format json > investigation.json
dns-investigator "调查 example.com 的 DNS 解析" --verbose
python -m dns_investigator.main --help
```

`--format json` 启用非交互输出，stdout 仅包含一个 JSON 对象，进度写入 stderr。交互式 CLI 在缺少目标时会请求补充；脚本调用应显式提供目标。

| 参数 | 行为 |
| --- | --- |
| `question` | 自然语言问题，可作为第一个位置参数 |
| `--target` | 显式指定域名或 HTTP(S) URL |
| `--format text\|json` | 选择文字或机器可读输出，默认 `text` |
| `--verbose` | 展开完整文字报告；与 `--format json` 互斥 |
| `--fixture PATH` | 使用受控测量数据；Agent 模式仍调用模型 |
| `--tools-only` | 按固定顺序运行工具独立验证，跳过模型 |
| `--save-tools PATH` | 保存 tools-only 模式的测量证据 |
| `-h`、`--help` | 查看命令帮助 |

| 退出码 | 含义 |
| --- | --- |
| `0` | 调查满足本地完成要求，或工具独立验证执行结束 |
| `3` | 信息不足的有限调查结果 |
| `1` | 调查执行失败 |
| `2` | 参数、目标或必要配置无效 |

运行日志默认保存在 `results/runs/`，该目录已加入 Git 忽略规则。如果模型未能完成总结，程序仍会保存已经取得的证据，并在能够生成报告时提供回退结果，同时注明执行失败。

## 无 API Key 体验

使用仓库自带的 C1 测试数据验证 DNS、TCP、HTTP 工具链：

```bash
python -m dns_investigator.main --target example.com --tools-only --fixture data/fixtures/C1.json --format json
```

这条命令不调用模型，也不访问公网；结果中的 `source_mode` 为 `fixture`。`--tools-only` 使用固定测试流程，去掉 `--fixture` 后会运行真实网络检查。

查看 Web 示例：

```bash
python -m scripts.prepare_web_demos
python -m dns_investigator.web
```

在“历史记录”中打开示例，页面会标注“示例数据 / 非真实公网测量”。使用 fixture 调查并让 Agent 自主选择工具时，仍需配置 DeepSeek 密钥。

## 工作原理

```mermaid
flowchart TD
    U[用户问题：CLI / 本机 Web] --> A[DeepSeek + PydanticAI Agent]
    A --> T[query_dns / compare_resolvers / query_authoritative / check_tcp / check_http]
    T --> B[ToolBackend：目标授权、超时、调用与请求预算]
    B --> M[DNS / TCP / HTTP 测量]
    M --> L[A / Q / E 调查账本]
    L -->|请求 DNSSEC 时| V[本地 DNSSEC 验证与 V 记录]
    L --> R[确定性 Finding、范围定位与报告]
    V --> R
    L -->|事实摘要与 Finding| A
    A -->|调查结束或程序回退| R
    R --> O[CLI / JSON / Web / 离线 HTML]
```

调查由一个基于 PydanticAI 的 Agent 完成。它读取用户问题和工具返回的结果，决定下一步做什么。例如，查询 A 记录通常只需调用 DNS 工具；发现递归回答有明显差异后，可以继续查询权威服务器；涉及网站访问的问题则可能需要 TCP 或 HTTP 检查。

网络请求由 ToolBackend 执行，目标授权、超时和调用次数都在程序中控制。DNSSEC 验证也由本地程序完成，并设有独立的计算限制。最后，报告器根据记录下来的测量和验证结果整理结论，将模型提出的可能原因单独列出，供进一步核对。

### 五个工具

| 工具 | 主要参数 | 作用 |
| --- | --- | --- |
| `query_dns` | `domain`、`record_type`、`resolver`、`timeout` | 查询授权名称及已允许跟进的别名目标 |
| `compare_resolvers` | `domain`、`record_type`、`timeout` | 查询配置的递归解析路径并比较结果 |
| `query_authoritative` | `domain`、`record_type`、`mode`、`timeout` | `basic` 权威发现/直查，`trace` 委派追踪，`dnssec` 支持范围内的验证 |
| `check_tcp` | `ip`、`port`、`timeout` | 检查已有 DNS 依据且通过网络授权的端点 |
| `check_http` | `url`、`timeout` | 带证书验证、目标固定与重定向授权的 GET 检查 |

以上是 Agent 的工具接口。解析器集合、预算和网络许可由本地配置管理；CLI 参数见前文。

### 证据与来源

| 编号 | 含义 | 说明 |
| --- | --- | --- |
| A | 工具调用尝试 | 包括参数拒绝、执行错误及重复调用 |
| Q | 实际 DNS 请求尝试 | 关联父工具调用；复合工具可能产生多个 Q |
| E | 测量证据 | 保存响应或超时等实际测量结果及来源 |
| V | 本地验证结果 | 关联 E/V 依赖、策略、信任锚和验证时间 |

一次工具调用可能发出多次 DNS 请求，每次请求都会单独记录并计入限额。并发执行时，结果通过调用 ID 与原请求对应。打开历史报告时，程序使用保存的记录和调查上下文，不会把当前机器的配置当作当时的测量结果。

## 如何阅读调查报告

报告首页会说明发现了什么异常，以及目前查明到了哪一步。查看结论时，可以结合下面的等级说明，继续核对引用的测量结果。

| 诊断等级 | 解读方式 |
| --- | --- |
| 已确认协议异常 | 具备相应的直接协议验证依据，例如受信任上下文中的 DS/DNSKEY 不匹配 |
| 已定位异常范围 | 已观测到超时、连接拒绝或 HTTP 错误等现象，具体运维原因仍需检查 |
| 候选原因 | 现有材料支持进一步调查的解释 |
| 未观察到明确故障 | 本次已测范围未出现相应异常 |
| 证据不足 | 需要补充测量、修正执行问题或处理能力限制 |

排障建议按 **CHECK（检查）→ POSSIBLE_FIX（修正）→ VERIFY（复测）** 组织。每项建议都会说明适用条件：先通过检查确认问题，再由有权限的人员修改相应配置，最后复测。配置变更需要用户自行执行。

### 实际案例：解析路径超时

仓库保留了一份[脱敏后的百度历史调查](data/regressions/baidu-investigation.json)。它包含 6 次工具尝试、17 次 DNS 请求、19 条测量证据：

| 已测结果 | 报告中的处理 |
| --- | --- |
| 一条系统解析路径发生 5 次超时 | 归为一个路径异常组，保留所有查询名称与类型 |
| `1.1.1.1` 路径发生 2 次超时 | 形成另一组观测 |
| 其他 DNS 路径和独立 TCP 检查成功 | 作为相应范围的正常观测保留 |
| HTTP 收到 301，后续跳转被策略拒绝 | 同时展示已收到的响应和未完成的后续检查 |

报告据此归纳为“部分 DNS 解析路径超时”，并分别给出检查方向。示例系统解析器身份已替换为文档地址 `192.0.2.53`；原始与脱敏哈希、来源和转换说明保存在样本中。

<details>
<summary>查看 DNSSEC 验证与调查时间线</summary>

![受控 DNSSEC 验证](docs/images/dnssec.png)
*受控签名 DNS 数据的实际回放：定位父侧 DS 与子侧 DNSKEY 的关联验证失败。*

![调查时间线](docs/images/timeline.png)
*上述脱敏历史调查的实际调用记录。*

</details>

## 配置

常用配置如下，完整格式、有效范围和示例见 [配置指南](docs/configuration.md)。

| 配置项 | 默认值 | 用途 |
| --- | --- | --- |
| `DEEPSEEK_MODEL` | `deepseek-flash` | 调查模型 |
| `MODEL_TIMEOUT` | `60` | 单次模型请求超时，秒 |
| `MAX_TOOL_CALLS` | `10` | 工具调用尝试预算 |
| `DNS_RESOLVERS` | `system,1.1.1.1,8.8.8.8` | 递归解析器集合 |
| `DNS_QUERY_BUDGET` | `32` | 实际 DNS 请求预算 |
| `DNS_TOOL_TIMEOUT` | `20` | 复合 DNS 操作总时限，秒 |
| `MAX_AUTH_SERVERS` | `2` | 选中权威服务器数量上限 |

`HTTP_ALLOWED_ORIGINS`、`HTTP_ALLOWED_NETWORKS` 和 `TCP_ALLOWED_NETWORKS` 用于受信任的显式授权，默认留空。HTTP 工具使用直连路径，可能与浏览器代理或模型 SDK 的联网路径不同。

## 支持范围与安全边界

- **DNSSEC**：支持签名算法 8/13/14/15、DS 摘要 2/4，以及已实现的 NSEC 和 NSEC3 证明场景。NSEC3 限零迭代、空 salt、非 Opt-Out；超出支持范围或材料不足时返回明确的能力限制/INDETERMINATE。完整范围见 [支持矩阵](docs/limitations.md)。
- **测量解释**：DNS 超时是未及时取得应答；地址、TTL、SOA Serial 差异可能来自缓存、更新或调度。DNS、TCP、TLS 和 HTTP 结果应按各自目标、时间及路径解读。
- **网络权限**：仅对已授权目标操作。HTTP 保留 Host/SNI 和证书校验，独立检查解析地址及跳转；TCP 有独立地址与端口控制。
- **数据处理**：日志默认留在本机。分享前检查凭证、私有地址、URL 和模型文本；自动脱敏与结构检查不能替代内容审核。

`completed` 表示调查已满足程序的输出要求，不代表已经找到唯一根因。目前尚无独立的诊断准确率评估。更多说明见 [安全政策](SECURITY.md)、[网络安全设计](docs/security.md) 和 [已知限制](docs/limitations.md)。

## 开发与测试

```bash
python -m pip install -e ".[web,dev]"
python -m pytest -q
python scripts/check_repository.py
```

CI 在 Linux Python 3.11/3.12 和 Windows Python 3.12 上运行完整测试、依赖检查、wheel 构建和安装验证。目前自动化套件包含 604 个用例，覆盖 DNS 报文、DNSSEC/NSEC3、网络授权、并发与预算、Agent、报告、Web 和 CLI。测试使用固定样本、脚本模型及本机受控服务，不需要付费 API 或公网目标。

构建并验证安装包：

```bash
python -m pip wheel --no-deps . --wheel-dir dist
python scripts/check_installation.py --wheel-dir dist --restore-editable --output results/runs/installation.json
```

运行安装验证前，请确认 `dist` 中只有一个项目 wheel。脚本会在源码目录外检查 CLI 命令和模块入口、JSON 输出、Web 应用及随包资源。浏览器检查、历史报告重放和模型评测的运行方法见 [开发指南](docs/development.md) 与 [评测说明](docs/evaluation.md)。

## 项目结构

```text
dns-investigator/
├── src/dns_investigator/  # Agent、工具、协议验证、诊断和 Web
├── tests/                # 自动化测试与固定回归输入
├── data/                 # 工具 fixture 与脱敏历史样本
├── evaluation/           # 受控服务、报告重放与评测程序
├── scripts/              # 安装、资源、仓库及浏览器检查
├── docs/                 # 架构、配置、安全、开发与支持说明
└── results/              # 本机生成结果（不进入版本控制）
```

## 文档与贡献

- [架构与数据流](docs/architecture.md)
- [配置与网络授权](docs/configuration.md)
- [CLI 与 Web 操作指南](docs/usage.md)
- [支持范围与限制](docs/limitations.md)
- [开发与测试](docs/development.md) · [评测方法](docs/evaluation.md)
- [变更记录](CHANGELOG.md) · [历史材料索引](docs/archive/README.md)

发现问题时，请在 Issue 中提供复现步骤，并在提交日志前删除敏感信息。代码、测试和文档修改可通过 PR 提交，具体要求见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全漏洞请通过 [GitHub 私密漏洞报告](https://github.com/heyunz59/dns-investigator/security/advisories/new) 提交。

## 许可证

项目原创代码与文档采用 [MIT License](LICENSE)。依赖和随包分发的 IANA/ICANN 资源保留各自的权利及来源说明，详见 [第三方声明](THIRD_PARTY_NOTICES.md)。
