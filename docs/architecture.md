# 实现与证据边界

## 最终核验补修（2026-11-01）

架构仍为单Agent、五工具、双预算与显式A/Q/E归属。http_safety.py的授权/连接实现本轮未重写；HTTP证据新增body_state、body_complete、body_limit_bytes。观察到完整结束为true；读取错误为false；到达64KiB上限或尚未读取为null，不能把HTTP200或达到上限当作完整响应。旧日志缺字段按unknown_legacy展示。

authority.py用任务隔离的ATTEMPT_OBSERVER，在dns_wire实际分配Q时记录当前目标操作的query_attempt_ids；即使随后取消也能保留已发起查询数。并行任务不会写入同一observer；UDP/TCP回退仍是多个Q、同一个目标操作。中断保存INTERRUPTED与原阶段/原因。报告始终显示发现/选中/地址/已查询/收到响应/AA数量，完成仅限选中子集。

别名收敛与超时对照也必须满足带时区时间资格；未知时间的成功E仍展示，但不作为超时的同期对照。Finding起止按实际时刻选择原测量时间，不能按ISO字符串排序导致时区边界反转。原始时间不改写。

compact_v2补query_scope、不可重试请求/子路径、复合权威工具已有覆盖、AA/negative_scope。超过16条记录时摘要包含全集计数、唯一值集合SHA256、TTL范围及可解析SOA Serial，完整E不删。模型仍可能选择错误参数；拒绝继续计A，不伪造E或宣称自然语言已被完全验证。[实际核验及未通过项](final-verification.md)。

## 2026-11-01：HTTP 连接安全、权威阶段、时间资格与日志 v6

仍是单 PydanticAI Agent + 五个正式工具，build_agent 注册机制与动态选择不变。DNS Diagnosis Engine、HTTPPolicy、PinnedTransport 和 agent_summary 都是普通模块，不新增 Agent 或 Tool。并发 A/Q/E 归属继续通过显式调用 ID，预算与 fixture/live 隔离保留。

HTTP 路径为 check_http → 每跳 HTTPPolicy（scheme/host/port/凭据/origin）→ PinnedTransport → AuthorizedBackend 解析一次并检查完整地址集合 → 数值 IP 连接。原 URL hostname 留给 Host/SNI/证书验证，拒绝单独覆盖 Host/SNI。连接池不跨请求复用、关闭 HTTP/2 和自动重试；最多6次 HTTP 请求、16个候选地址，整体15秒覆盖解析、连接、跳转和读取。混合公网/内网地址集默认全部拒绝；允许内网需受信任 CIDR，跨 origin 另需显式授权。拒绝后的跳转不发送请求，已取得的302/错误仍保存。依据公开接口实现：[HTTPX transports](https://www.python-httpx.org/advanced/transports/)、[HTTPcore network backends](https://www.encode.io/httpcore/network-backends/)。

权威发现按 SOA → NS → NS地址 → 目标直查 → 补充SOA 保存阶段进度。有效权威回答需完整响应、AA及可解释结果；超时测量仍是E，不能把它当成取得DNS报文。completed=true只指本次有上限的选中NS及所需目标/SOA检查完成，不表示全部NS、全域或根因已验证。取消、总超时、预算拒绝保存最后阶段、有效E和执行问题。

compare_details 的每对结果记录 time_status：TIME_COMPARABLE / TIME_WINDOW_DIFFERS / TIME_UNKNOWN / TIME_INVALID。仅具有时区的有效测量时间且间隔≤300秒才可参与同期差异定位；窗口按起点划分，不靠链式相近把跨度大于300秒的证据并为一组。时间未知/跨窗仍可展示观测差异，但只生成无定位断言的 DNS_TEMPORAL_DIFFERENCE。不以文件时间补造测量时间。

AgentDraft 只要求 request_kind、outcome、hypotheses、analysis_summary、limitations、next_directions；extra=forbid。程序从真实E生成正式 observations/measured_facts/findings/结论和A执行问题，保留原 InvestigationResult 的可读兼容字段。模型 E 引用仍验证存在，回答完成仍须测量，假设的证据关系仍验证，再经受限报告器处理。每次工具返回紧凑事实与Finding、全部失败、权威进度、授权别名及剩余预算；最多展示16条记录时明确 omitted_count，完整响应仅保存在原始E，不删除。

schema_version=6 增加 decision_draft_v1、raw_model_drafts、validation_errors、output_attempt_count/output_resubmissions。agent_execution_status 与 report_availability/report_origin/fallback_reason 分开；重试有硬上限，模型失败仍保留程序事实与报告且 status=failed。hypotheses/自然语言候选及建议仍需语义复核。旧日志缺少这些字段时保持未知，不能补算为成功。[实际验证与边界](security-stability-fixes.md)。

## 2026-11-01：DNS 范围定位与日志 v5（历史阶段；当前以上文 v6 为准）

单 Agent 与五个正式 Tool 保持不变；A/Q/E、ContextVar 调用归属、并发、双层预算及 HTTP/TLS/IPv6 逻辑保留。新增模块 alias_scope.py 是普通授权规则，不是工具或 Agent。只有 query_dns 可跟进同模式有效 DNS 证据连接到原始目标的 CNAME，其他工具仍限原目标。跟进 E 保存 target_authorization 链及父 E；完整末端已有同类型记录时拒绝重复跟进。深度/目标数上限均8，既有 A/Q/时间/重复预算继续生效。网页跳转、模型文本、无关 Additional 不授权；观测链路不表示 DNSSEC 验证。

DNSClient → transport_status / dns_rcode / result_kind → compare_details（路径、逐对资格、排除原因、TTL/耗时观察）→ diagnose（查询范围与时间窗口聚合）→ 程序事实表 / Findings / 受约束范围摘要 / 建议。Agent 每次得到最新 Finding 和 allowed_dns_targets，自主决定继续或停止。规则不自动发查询。所有 root_cause_confirmed 固定 false；不声称已实现直接根因验证规则。

比较窗口最多300秒；来源、目标、类型不同或否定回答适用名不同不做内容冲突比较；非 AA 权威候选不当作已确认权威。未知来源/时间保留限制；没有把历史 TIMEOUT 适配为收到的报文。失败 A/Q 与有效 E 分离，局部失败留在结构中，成功子集继续比较。TIMEOUT 仍是 E 测量，但 dns_rcode=null。旧 rcode=TIMEOUT 只通过非修改适配函数读取。TTL/耗时不生成故障告警。

日志 v5 增加 diagnosis_policy=scoped_dns_v2、report_policy=scoped_evidence_bound_v2。模型草稿保持独立，模型事实声明若不匹配则重试；最终失败由程序保留事实、Finding 和摘要，report_fallback_reason 说明原因，状态仍 failed。hypotheses 数量只作观察，不决定 completed；completed 也不代表根因确认或语义准确。旧 schema 的新增字段均有默认值，旧报告不自动改写。[实验与边界](dns-accuracy-upgrade.md)。

## v0.3 原始架构（历史描述，以上文日志 v5 为准）

用户输入 → 唯一 DeepSeek/PydanticAI Agent → 五个正式工具 → ToolBackend → DNSClient / 现有 TCP、HTTP → E 测量 → 确定性 Diagnosis Engine → Finding 返回给 Agent → 模型选择下一项工具或输出有限结果。

五个工具在 build_agent 内正式注册：query_dns、compare_resolvers、query_authoritative、check_tcp、check_http。没有固定执行全部工具的调查脚本；--tools-only 及 verify_dns_v3.py 是显式的工具验收入口，不作为自主 Agent 的证明。

- dns_wire.py：显式 UDP/TCP 通信，每次报文交换独立 Q 编号。响应 RCODE、AA/RD/RA/TC、三个分区、TTL、CNAME、SOA Serial 均序列化；NODATA 为 NOERROR 下的结果类别。直接处理 DNS 报文，避免高级解析器异常丢失 NXDOMAIN 的 Authority/SOA。
- dns_compare.py：纯数据比较，差异不等于故障。TTL 不会误当作 CNAME 目标变化。
- authority.py：最近 SOA 所属区发现、NS 与其地址解析、有限公共权威直查，RD=0、AA 审核。发现依赖递归路径，未做根区起点迭代和 DNSSEC 验证。
- dns_diagnosis.py：只处理有效 E 证据；排除截断和非 AA 的权威对比，输出受限 Finding。程序重新生成最终 findings，模型不能注入伪 Finding。

日志格式 schema_version=3：attempts 是外层 A 工具尝试；dns_attempts 是实际 UDP/TCP Q 请求，parent_tool_call_id 指向 A；evidence 是有效 E 测量，每次截断响应、TCP 回退、超时都可追踪。复合工具不再创建伪造的聚合 E 证据。fixture 子响应也是独立 E，但不计真实网络 Q 请求；旧版日志和 fixture 仍可读。

DNS 请求总数、复合工具总时间、单次 DNS 超时及权威台数分别受限。DNS 底层预算耗尽后隐藏 DNS 工具，保留模型总结机会。工具取消/超时会保留已取得的子证据并返回给模型。权威自动发现的地址只接受 global IP；显式递归服务器只允许公共或系统已配置地址，系统私有 DNS 可正常使用。配置文件中用户主动设置的 compare_resolvers 地址是受信配置，模型不能覆盖该列表。

结构与规则不能证明全部自然语言语义正确，模型仍可能过度解释或引用不存在的编号；这种输出须重试或安全失败，不能称为确定的根因。详见 [v0.3 实际验证](dns-v3.md)。

v0.2 更新以 [可靠性修复说明](reliability-v2.md)为准：attempts 与有效 evidence 分离，框架参数拒绝也记录；输出状态区分 completed/limited/failed。下文中原有工具日志描述指有效测量，不代表全部调用尝试；不能再用 E 编号数量计算调用正确率分母。

CLI 解析域名或网址，缺目标时补充输入，非法目标在模型请求前拒绝。裸域名默认 HTTPS 并记录；原始路径保留。URL 查询值与片段在模型输入和日志中脱敏。相同 URL 的 HTTP 工具在本机恢复原始查询值，避免改变用户请求的含义；密钥不传入提示词。

PydanticAI Agent 自主选择 query_dns、check_tcp、check_http，可依据结果继续调用。应用层只做参数校验和调用预算约束。--tools-only 是独立工具冒烟检查，固定顺序不能作为 Agent 智能性的证据。fixtures 只含原始事实，不含预写原因。评分文件与 Agent 运行隔离。

ToolBackend 为每次测量分配 E 编号和 T 调用标识，记录时间、耗时、输入、错误及来源。JSONL 在每次工具结束后追加，即使模型服务随后故障也可保留证据；最终 JSON 保存结果、模型配置、版本、可见工具消息与耗时。SDK 错误仅记录类别，避免认证信息或请求详情外泄。输出验证器检查所有引用是否存在；这只能防止无效引用，不能证明文字结论必然正确，仍需案例人工审核。

DNS 使用系统配置解析器，可显式选择备用 IP，区分响应码和无记录。TCP 使用异步 IPv4/IPv6 套接字。HTTP 使用 httpx，验证证书，保留 Host/SNI，关闭环境代理，最多 5 次重定向，最多读取 64 KiB 原始响应字节；整体异步 deadline 覆盖连接、重定向和读取。每次响应记录可可靠获取的对端地址，缺失时为空。DNS、TCP 和 HTTP 不保证同一 IP；重定向可以到不同域名，需按日志解释，不能声称验证同一后端。

测量位置仅记 program-host，不记录本机用户名、主机名或本机绝对路径。原始 DNS 配置与用户输入可能含敏感信息，运行日志默认忽略。公开样本只保留已检查、脱敏的材料。程序不能复现浏览器缓存、hosts、代理、DoH 或历史网络状态。HTTP 页面正文从不进入模型上下文。

框架与官方文档核对：
- [PydanticAI DeepSeek 集成](https://pydantic.dev/docs/ai/models/deepseek/)
- [DeepSeek 工具调用及非思考配置](https://api-docs.deepseek.com/guides/tool_calls/)

默认 deepseek-flash，thinking.type=disabled；账号额度、实际模型可用性必须通过真实调用验证，不能用文档或脚本模型代替。
