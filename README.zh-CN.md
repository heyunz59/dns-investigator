# DNS Investigator

**基于 AI Agent 与可追溯证据的 DNS 故障调查助手**

[English](README.md) · 简体中文

![Tests](https://github.com/heyunz59/dns-investigator/actions/workflows/tests.yml/badge.svg?branch=chore%2Fopen-source-release-prep)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

DNS Investigator 结合 DeepSeek、PydanticAI、DNS 协议分析和结构化证据，在授权范围内执行 DNS、TCP、HTTP 检查，帮助定位**实际观测到的异常范围**、区分事实与候选解释，并选择下一项检查。它是调查辅助工具，不保证找到唯一根因。

> **候选版本 0.6.0rc1** 位于 chore/open-source-release-prep 分支。main 尚未同步 v0.6；本轮没有创建 GitHub Release 或发布 PyPI。请使用下方指定分支的克隆命令。

![历史解析路径回放](docs/images/diagnosis.png)
*实际本机 Web 渲染：脱敏后的百度历史调查。系统解析器身份已替换为文档地址，不代表当前网络状态。*

## 解决什么问题

|场景|能够依据证据回答的范围|
|---|---|
|特定域名解析失败|本次是 NXDOMAIN、NODATA、SERVFAIL、REFUSED，还是传输超时|
|不同解析器结果不一致|哪些已测路径存在差异；公共解析器超时不等于目标域名故障|
|DNSSEC 阻断解析|支持范围内的 DS/DNSKEY、签名、否定证明检查，或明确 INDETERMINATE|
|DNS 正常但网站打不开|区分 TCP、TLS、HTTP 及正文完成情况，不把响应头当完整网页成功|
|多个异常同时出现|保留主诊断/并列观测和关联未知边界，不凭并存构造因果链|

## 核心能力与工程特色

- **一个 Agent、五个工具**：query_dns、compare_resolvers、query_authoritative、check_tcp、check_http，动态选择，不固定全部调用。
- **多路径 DNS**：A/AAAA/CNAME/NS/SOA、递归对照、选中权威直查、有界委派追踪、EDNS/EDE 与有限本地 DNSSEC。
- **A/Q/E/V 账本**：分别记录工具尝试、实际 DNS 请求、测量和本地验证。错误参数计入尝试，复合工具子测量有明确归属。
- **证据约束报告**：程序生成 Finding 与范围明确的结论，原始事实、未经验证的模型候选、直接依据和依赖材料分开保留。
- **路径级归纳**：按解析器、机制、来源、位置和时间窗口聚合兼容观测，保留每项查询，不冒充根因聚类。
- **条件式只读排障**：CHECK / POSSIBLE_FIX / VERIFY 分支；不自动修改配置。授权、预算和 fixture/live 隔离不由模型放宽。
- **本机 Web**：进度、取消、历史记录、证据、排障详情、时间线、JSON 和独立离线 HTML。

### 工作原理

用户 → 唯一 DeepSeek Agent → 五工具 → 授权/预算控制的 ToolBackend → A/Q/E 与本地 V → 确定性 Finding/报告 → Agent 继续或停止 → CLI/JSON/Web。

DNSSEC、诊断引擎和报告器是普通 Python 模块，不是额外 Agent 或工具。引用有效、JSON 合法不等于语义一定正确。[架构](docs/architecture.md) · [支持范围](docs/limitations.md)。

## 快速开始

需要 Git、Python 3.11+（CI 覆盖 3.11/3.12）、必要网络授权和现代浏览器。Agent 调查需自行配置 DeepSeek API Key，调用可能计费。

```bash
git clone --branch chore/open-source-release-prep --single-branch --depth 1 https://github.com/heyunz59/dns-investigator.git
cd dns-investigator
python -m venv .venv
```

Windows PowerShell：

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[web]"
Copy-Item .env.example .env
.\.venv\Scripts\Activate.ps1
```

Linux/macOS：

```bash
.venv/bin/python -m pip install -e ".[web]"
cp .env.example .env
source .venv/bin/activate
```

PowerShell 禁止激活时，可直接使用 .\.venv\Scripts\python.exe -m 运行，不必更改系统策略。在本地 .env 填 DEEPSEEK_API_KEY，不要发送或提交真实密钥。默认 deepseek-flash、https://api.deepseek.com、thinking disabled，实际模型可用性取决于账号。仅 CLI 可使用 `python -m pip install -e .`。

### Web 使用

```bash
python -m dns_investigator.web
# 或 dns-investigator-web
```

打开 http://127.0.0.1:8765 ，填写域名或 HTTP(S) URL，可添加问题描述。完成后查看结论、证据和条件式建议，按需导出 JSON/HTML。仅设计为本机回环服务，不支持直接公网多用户部署。[配置说明](docs/configuration.md)。

### CLI 使用

```bash
dns-investigator "example.com 解析失败，请调查 DNS"
dns-investigator "查询 example.com 的 A 记录"
dns-investigator --target example.com --format json
```

默认调用 DeepSeek，并可能进行真实授权网络测量。--target 指定目标；--format json 非交互，stdout 严格一个 JSON 对象，进度写 stderr。退出码：0 completed、3 limited、1 执行失败、2 输入/配置无效。completed 不是准确率。--verbose 展开文字报告，不能与 JSON 组合。

### 无密钥、无公网演示

```bash
python -m dns_investigator.main --target example.com --tools-only --fixture data/fixtures/C1.json --format json
```

使用合成 DNS/TCP/HTTP 事实，不调用模型。fixture 缺失不回退真实网络。**--tools-only 不带 --fixture 仍可能访问真实网络**；它是固定顺序的工具独立测试，不是 Agent 验收。Agent+fixture 仍需模型密钥。

无需密钥查看受控报告：运行 `python -m scripts.prepare_web_demos` 后，在本机 Web 历史中打开明确标记为示例的报告。

## 有来源的实际案例

[脱敏百度历史样本](data/regressions/baidu-investigation.json) 包含 19E、17Q、6A、0V。七次超时归为两组递归路径观测（五次和两次），正常 DNS/TCP 及 HTTP 301 后被安全策略拒绝的重定向均保留。它不证明最终页面加载成功，也不证明域名整体不可用。data_provenance 保存原始/脱敏哈希，二者不宣称字节相同。[方法与来源](docs/evaluation.md)。

![受控 DNSSEC 示例](docs/images/dnssec.png)
*真实 Web 渲染的受控签名 DNS 材料：DS/DNSKEY 不匹配。不是公网域名诊断。*

![调查时间线](docs/images/timeline.png)
*同一脱敏历史样本的实际调用时间线；没有新增工具调用。*

## 测试与验证

整理前候选在 Windows/Linux 通过 **604 项测试**。本轮保留全部测试函数，将必要数据从历史输出迁至稳定 fixture；[当前验证回执](docs/release/verification.json) 单独记录整理后的运行与 CI。覆盖受控报文、DNSSEC/NSEC3、安全授权、并发归属/统计、Agent、报告、Web 和安装后的 CLI。

```bash
python -m pip install -e ".[web,dev]"
python -m pytest -q
python scripts/check_repository.py
```

fixture、真实本机协议集成、脚本模型、付费模型、独立语义审核是不同验证类别。尚无独立故障根因准确率指标。[评测](docs/evaluation.md) · [测试清单](docs/release/test-inventory.md)。

## 安全与限制

仅探测已授权目标。HTTP/TCP 独立授权，保留证书校验和 Host/SNI。超时不证明服务器宕机；CDN、缓存、TTL 差异不能直接判为故障。NSEC3 限支持的零迭代、空 salt、非 Opt-Out 证明；不支持或材料不足保持未知。历史授权不等于当前授权；浏览器代理、DoH、缓存可能与工具不同。

脱敏后日志仍可能有网络信息，不要直接公开原始记录。本项目不提供自动修复、公网 Web 部署、完整 DNSSEC 覆盖或唯一根因保证。[安全政策](SECURITY.md) · [已知边界](docs/limitations.md)。

## 文档、贡献与许可证

[架构](docs/architecture.md) · [配置](docs/configuration.md) · [安全边界](docs/security.md) · [评测](docs/evaluation.md) · [开发](docs/development.md) · [变更](CHANGELOG.md) · [历史归档](docs/archive/README.md)

请按 [CONTRIBUTING.md](CONTRIBUTING.md) 提供可复现输入和回归结果。原创代码与文档经所有者批准采用 MIT；[LICENSE](LICENSE) 和 [第三方声明](THIRD_PARTY_NOTICES.md) 区分上游资源。该分支不自动创建正式发布。
