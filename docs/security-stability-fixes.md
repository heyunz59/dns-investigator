# 2026-11-01 安全性、诊断正确性与 Agent 稳定性修复

基线 `512141ed7b21d2b50387d5148d709011daaaf295`，保留原有196项测试、五工具、并发归属、A/Q/E预算、CNAME跟进和历史实验。新增普通安全/摘要模块，没有新增Agent或工具。工作分支 `fix/security-dns-agent-20261101`；本轮要求不自动推送，故未创建远程PR、未合并，远程Actions结果仍未验证。

## 提交与源码

|阶段|本地提交|内容|
|---|---|---|
|HTTP安全|1a7da47|每跳授权、校验IP后固定连接、Host/SNI及证书验证|
|权威与时间|f2421de|发现状态、阶段进度、时间比较资格|
|HTTP边界补测|8fb638f、d4e14da|Host/SNI覆盖拒绝、跳转拒绝保留证据、真实本机TLS；后者修正前者新增测试暴露的错误码/跳转信息问题|
|Agent|4de824c|决策草稿与正式报告分工、紧凑上下文、失败回退标识|
|对照与交付|本文件所在后续提交|独立实验、验证记录和公开审计，不再变更业务源码|

真实模型最终业务源码为 `4de824c`；实验保存全部模块SHA256，发布汇总已逐项验证与该提交及基线Git blob一致（明确区分LF与Windows CRLF字节）。后续评测/文档提交不被冒充为重新运行过的业务版本。

## HTTP 安全边界

位置：`http_safety.py` 的 HTTPPolicy/AuthorizedBackend/PinnedTransport，`tools.py` 的 check_http，`config.py` 的受信任授权配置。

默认按origin授权（scheme、host、port），标准同主机HTTP:80→HTTPS:443升级例外；跨域、换端口、凭据、错误URL均先拒绝。解析一次检查完整IP集合，再向数值IP建立连接，HTTP客户端不会再独立解析原hostname；每一跳建立新连接。保持原Host、SNI、CERT_REQUIRED与主机名验证，禁止覆盖Host/SNI。无自动HTTP重试、无跨请求池复用；已验证多地址有限回退，总deadline限制整个过程。

环回、私有、链路本地、元数据、非全球/保留、IPv4-mapped IPv6及过渡地址默认拒绝；任意一个候选不合规则整组拒绝。受信任 `HTTP_ALLOWED_ORIGINS` 与 `HTTP_ALLOWED_NETWORKS` 各自授权origin和CIDR，默认空；模型不能通过工具参数扩大配置。系统私有DNS仍可用于DNS工具，本轮没有将其一概禁用。

受控旧/新跳转复现：允许的 https://allowed.example/ 返回302至 http://127.0.0.1/，旧版MockTransport记录2次dispatch并最终200；新版只dispatch初始URL，保留302与被拒绝的跳转，error=HTTP_REDIRECT_TARGET_NOT_AUTHORIZED。这是HTTP调度反例，不冒充真实访问了内部服务。安全测试另用注入连接接口核对实际只连接已验证数值IP；真实本机TLS服务在显式测试授权下验证正常跳转、实际Host/SNI和错误证书主机名拒绝。

`tests/test_http_security.py` 23项通过：127、169.254.169.254、10、::1、未授权公共域/端口、凭据、混合IP、地址变换/rebinding、每跳重新校验、6请求上限、合法跨域配置、TLS不降级、错误主机名。临时CA/证书由cryptography在测试临时目录生成，私钥不进入仓库。实现依据：[HTTPX公开transport接口](https://www.python-httpx.org/advanced/transports/)、[HTTPcore公开network backend接口](https://www.encode.io/httpcore/network-backends/)、[cryptography X.509](https://cryptography.io/en/latest/x509/tutorial/)。

## 权威发现的真实阶段

位置：`authority.py`、`dns_wire.py`、`tools.py`、`reporting.py`。`query_attempt_ids`说明真实发出过哪些Q；未执行的预算拒绝仍只有A问题，不制造Q/E。TIMEOUT是有效测量E，dns_rcode=null，不代表收到了权威报文。

以下为无模型、真实回环DNS报文对照（每例外层A=1）；原始数据在 [baseline-offline.json](../results/published/security-stability/baseline-offline.json) 与 [current-offline.json](../results/published/security-stability/current-offline.json)。

|场景|旧状态|新状态 / completed|新Q/E|
|---|---|---|---|
|SOA超时|ZONE_UNKNOWN|SOA_DISCOVERY_TIMEOUT / false|1/1|
|SOA成功、NS超时|RECURSIVE_ASSISTED|NS_DISCOVERY_TIMEOUT / false|2/2|
|NS空|RECURSIVE_ASSISTED|NO_USABLE_NS / false|2/2|
|NS REFUSED / SERVFAIL|RECURSIVE_ASSISTED|NS_DISCOVERY_FAILED / false|各2/2|
|NS存在、地址未取得|RECURSIVE_ASSISTED|NS_ADDRESS_RESOLUTION_FAILED / false|6/6|
|目标应答非AA|RECURSIVE_ASSISTED|NO_AUTHORITATIVE_RESPONSE / false|8/8|
|两台中一台超时|RECURSIVE_ASSISTED|PARTIAL_AUTHORITATIVE_DISCOVERY / false|8/8|
|两台均超时|RECURSIVE_ASSISTED|NO_AUTHORITATIVE_RESPONSE / false|8/8|
|选中两台均有目标/补充SOA有效AA回答|RECURSIVE_ASSISTED|AUTHORITATIVE_QUERY_COMPLETED / true|8/8|
|SOA后Q预算耗尽|NS_DISCOVERY_FAILED|NS_DISCOVERY_FAILED / false|1/1|

报告保存 zone_found、ns_found、NS总数/选中数、地址数、实际直查数、收到报文数、有效AA回答数和逐台目标/SOA状态。完成仅指预算内选中子集完成，不表示所有权威服务器都正常，亦不代表根因确认。取消或总超时保留最后阶段和已取得证据。新增测试覆盖3种预算中断、事件控制取消；旧并发工具归属测试仍通过。

## 时间依据

位置：`dns_compare.py`、`dns_diagnosis.py`。只有有效带时区时间且间隔≤300秒才是TIME_COMPARABLE；缺失为TIME_UNKNOWN，非法或无时区为TIME_INVALID，超过窗口为TIME_WINDOW_DIFFERS。未知/跨窗记录差异可展示，不参与同期故障定位。旧测量不补造时间。

固定NXDOMAIN/NOERROR回放：10秒内两版均可比较；两条均缺时间时，旧版生成RECURSIVE_RESPONSE_DISAGREEMENT，新版取消该同期Finding，仅保留NXDOMAIN观测及DNS_TEMPORAL_DIFFERENCE。仅一条缺时间时旧pair.comparable=true，但旧分组未生成同期Finding；新版明确pair不可比较，不夸大旧版在每条路径都误报。非法、无时区、跨窗、等价时区、未知时间地址不同以及链式跨窗均有测试；9项时间测试通过。

## 复杂总结失败的实际原因及修复

历史4份真实失败完整消息与反馈另存 [failure-analysis.json](../results/published/security-stability/failure-analysis.json)，不是新增模型实验。已取得有效E，但模型重复填写程序事实、比较、Finding、执行问题等大量字段；实际反馈包括A父调用与子错误码、实际类型/默认类型的绑定不符，以及事实范围不匹配。部分历史程序对默认qtype的核对也有版本问题，不能把所有失败归因于模型。本次基线NS超时第3次同样两次重试“事实范围不匹配实际证据”，最终失败。

AgentDraft只负责6个决策字段。程序从A/E构造正式事实/执行问题/比较/最终摘要；`extra=forbid`防止模型塞入伪造程序字段。仍验证request_kind、E存在、无证据不得answered、假设证据关系、Finding引用；不是删除验证器来增加completed。E引用错误反馈包含具体字段、错误ID和可用ID。原始所有最终草稿（包括schema拒绝）与重试反馈都保留。

每次工具提供紧凑事实、Finding、全部执行失败、权威状态、别名授权和预算，避免三份原始DNS分区重复塞入上下文。记录超过16条时明确省略数量，不解释为不存在；原始E的完整报文不删。`agent_execution_status`和`report_availability/report_origin/fallback_reason`分开。脚本模型持续非法E999时，3次草稿后仍failed，但已有E1事实与程序报告可读，既不编造模型总结也不伪装Agent成功。

## 真实 DeepSeek 新旧重复对照

新目录 [real-model-comparison](../results/published/security-stability/real-model-comparison/summary.json) 保存14份脱敏JSON、每次配置/源码哈希/结果/错误/使用量/重试；原始JSON/JSONL在忽略目录 `results/runs/security-stability-{baseline-512141e,current-4de824c}/`。两版各7次：权威记录/SOA Serial差异3、NS发现超时3、正常A查询1。相同问题、deepseek-flash、thinking disabled、temperature0、8A/24Q、模型45秒超时、回环DNS每请求0.3秒。两个进程同机并行执行，时延/缓存/服务负载不能视为严格受控。

|实际指标|旧512141e|新4de824c|
|---|---|---|
|通过最终输出校验|6/7|7/7|
|其中权威记录/SOA差异|3/3|3/3|
|其中NS超时有限输出|2/3|3/3|
|正常单项A|1/1；1A/1Q/1E|1/1；1A/1Q/1E|
|模型失败/回退|1（7E仍保留）|0|
|外层A总数（含拒绝/部分失败）|31|40|
|实际Q / 有效E总数|60 / 60|51 / 51|
|最终输出提交 / 重交|9 / 2|8 / 1|
|平均整次耗时|20.902秒|12.551秒|
|有usage日志数|6/7|7/7|
|已记录输入/输出tokens|304082 / 22348（不完整）|211009 / 15555|

两个版本3次serial都取得至少2条A、2条SOA权威测量；新版少了旧版的重复SOA测量，但多次尝试显式指定测试回环resolver被正式安全策略拒绝，全部计入A。新serial首次因“被削弱的假设必须引用反面证据”重交一次后完成，规则保留。新A总数反而上升，不能声称调用合理性全面改善。模型服务版本未钉死，样本仅3次，不能据此推断长期成功率或根因准确率。

usage来自SDK累计计数，旧失败无usage，不猜补；汇总仅报已记录tokens/请求，不把SDK cost或不完整usage换算成真实账单。诊断范围/候选支持关系/错误根因断言的完整语义评分均为PENDING_HUMAN_REVIEW；程序Finding结构检查不是独立人工评分，也不是完整准确率。此次没有新增公网目标测量。

## 命令、实际结果与复现

从项目根目录，用 `.venv/Scripts/python.exe` 执行：

```text
-m pytest -q                                   # 修改前196通过，最终249 passed in 9.74s；无skip
-m pytest tests/test_http_security.py -q       # 23通过（含实际本机TLS握手）
scripts/verify_report_acceptance.py            # 9条通过；脚本模型/本机HTTP/历史回放
evaluation/analyze_summary_failures.py         # 4份历史失败分析，无新增模型请求
evaluation/security_stability_offline.py <新文件.json> --source-ref <业务版本>
evaluation/security_stability_runs.py <新的忽略目录> --arm <baseline或current> --source-ref <业务版本> --repeats 3
evaluation/summarize_security_stability.py results/runs <新公开目录>
scripts/check_public.py                        # 全引用/工作区规则审计；见公开审计快照
```

基线业务包从git blob导出到忽略目录，通过PYTHONPATH独立进程加载，未checkout/reset现有工作区；当前包直接加载4de824c。评测脚本、受控DNS注入和问题两臂相同，答案/评分不进入提示。复现必须正确切换被测源码；不能把 --source-ref 当作自动切换版本的参数。新的输出路径已存在会拒绝覆盖。原196项保留，仅因模型schema变化调整脚本最终输出字段、本机HTTP测试显式授权测试CIDR；旧安全/证据断言没有移除。

本轮公开规则扫描及文件清单见同目录 `public-audit.json` 与 `changed-files.txt`。本地路径、真实API key、未脱敏run和临时TLS私钥未纳入提交；规则扫描不保证排除全部隐私问题。

## 仍未完成与边界

- 未经本轮明确要求不自动推送，因此新提交远程Actions、Linux新依赖安装/测试未验证；本机Windows离线全部通过。
- 独立人工语义复核未完成；Agent仍可提出不合理候选/建议、重复拒绝的请求。确定性报告能限制事实范围，不能证明任意自然语言的因果关系。
- 安全测试针对明确边界与反例，不等于形式化SSRF证明；受信任配置需最小授权。HTTP禁用环境代理，不同于浏览器路径。
- 权威发现依赖递归DNS，默认仅2台、最多配置3台，每台选一个可用候选地址；未实现完整迭代解析、全NS/IP遍历和DNSSEC。
- 300秒仅为保守比较窗口，不保证DNS状态在窗口内完全稳定；时区明确也不保证源机器时钟同步。
- 无公网根因或多网络位置验收。此次可证明具体安全绕过被拦截、权威/时间资格不再误写，以及小样本复杂总结可交付性改善；不能宣称模型诊断整体准确率已达标。
