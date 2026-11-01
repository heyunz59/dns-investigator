# 最终核验工作记录（2026-11-01）

起始业务/交付版本 d26d6b7，远程修复分支一致，main=512141e。工作区只有用户原有未跟踪 docs/manual-reviews/，保留不动。新工作分支 fix/final-verification-20261101；本轮不推送、不合并、不发布。当前完整基线：249 passed in 8.67s（Windows，无skip）。

## 要求—实现—证据—缺口—处理清单

|要求|当前实现（起始版本）|已有验证|初审分类/处理|
|---|---|---|---|
|HTTP逐跳origin/地址授权、固定连接、Host/SNI/证书|HTTPPolicy/AuthorizedBackend/PinnedTransport|23项安全测试含本机TLS及错误证书|已实现，保留；补多地址回退/实际标准升级/端口变更的外部行为验证|
|正文完成与上限/读取失败分开|保存status/error/bytes，报告finished_within_check_limits|正文超时、正文上限旧测试|有信息缺口，先复现后加明确读取状态|
|安全拒绝不当成网络故障|独立HTTP拒绝码、A/E分开|拒绝地址零连接、302保留|补正式摘要/建议验证，不重做网络安全模块|
|权威阶段与预算/部分失败|明确discovery_status、progress、A/Q/E|阶段/预算/取消测试|基础机制保留；补直查期间取消的实际计数、NS总数>选中数和最终报告范围|
|时间资格约束内容差异|time_status与300秒分组|9项时间测试|已实现；补别名无时区收敛、未知时间超时对照的上层边界|
|五工具/并发/别名/fixture隔离|原架构与ID归属机制|现有249项中的相关回归|保留，不新增工具或流水线|
|AgentDraft/严格引用/失败回退|六字段草稿、程序报告与来源状态|模型脚本失败与真实14次记录|保留；审查14份原始记录，不能把7/7当准确率|
|可避免的无效调用|A31→40，紧凑上下文及硬预算|逐次attempts完整|先区分测试身份映射、未授权目标、重复覆盖与合理追加；只修已确认缺口|
|摘要必要决策信息|事实/Findings/失败/授权目标/预算；记录16条上限|紧凑上下文保留失败测试|补完整记录聚合、不可重试参数及复合工具覆盖提示验证|
|实验版本/用量/语义复核|模块哈希、不同来源、缺usage不猜补|公开14次运行及summary|独立复核哈希/输入/口径，AI辅助语义审查标记；补测范围按修改确定|
|完整DNSSEC/迭代/公网根因/人工评分|当前不具备或未做|不以本机报文/JSON代替|本轮范围外或未知，不扩展功能|

以上是修改前清单，不是验收通过声明。下文在反例与最终结果取得后补齐；旧结果不改写。

## 已复现并修复的边界

同一组独立反例在d26d6b7隔离业务包上为 **8 failed / 2 passed**（pytest通过 `-o pythonpath=results/runs/final-verification-baseline-source/src`明确加载旧业务包），修改后10项通过。保存 [before-controlled-v2.json](../results/published/final-verification/before-controlled-v2.json)，不覆盖旧记录。首次before-counterexamples.json的HTTP服务使用localhost系统解析，IPv6候选先连接而IPv4服务未被到达；该初版HTTP结果是测试设施限制，不当作正文处理缺陷。v2用仅测试的127.0.0.1解析器和明确CIDR授权，执行实际本机HTTP通信；TLS/生产访问控制未放宽。

- 正文：原来小正文与达到64KiB都只有finished_within_check_limits；新增body_state/body_complete/body_limit_bytes，区分complete、limit_reached、read_error、not_read。达到上限不保证读取完整，即使状态码200；旧日志没有字段则unknown_legacy，不反向推断完整。
- 安全拒绝：原有连接阻断继续有效；补正式摘要/建议明确“策略拒绝、未连接被拒绝目标，不代表网络故障”。未新增SSRF绕过结论。
- 别名：两条无时区时间原来可ALIAS_FOLLOWUP_COMPLETED；统一使用带时区资格后保留ALIAS_RESOLUTION_INCOMPLETE，两个原始E仍保留。
- 超时对照：两条时间未知的TIMEOUT/NOERROR原来令assessment_level=scope_localized；现在仅超时E进入该Finding，成功E仍在事实表，缺乏同期时间不用于定位。
- 权威中断：受控UDP服务器确实收到第二台目标查询，取消/整体超时后原进度仍记1；新增任务隔离的Q分配观察器，按明确parent/query ID记录已尝试的目标操作。现在Q=7、E=6，目标查询=2、有效AA=1；中断阶段与原因保留，不制造第7条E。
- 权威范围展示：完成和未完成报告都列发现NS、选中NS、地址、目标查询、收到响应、有效AA；发现3台选中2台时仅声称本轮选中子集完成。Observer与并行其他工具的Q/E仍分属各自父调用。

第一阶段完整回归：**261 passed in 9.13s**，无skip；原249项没有删除或弱化。后续Agent摘要/实验审查结果另记，不能把这一阶段作为最终源码验收。

## 旧模型调用与摘要复核

逐条检查原14份JSON的输入、A/Q/E、正式事实/范围摘要、候选语句、建议及草稿，原文件未改写。当前臂40个A中，12个INVALID_INPUT来自serial三次各4个对测试环回解析器的A/SOA请求，4个INVALID_INPUT来自两次对未授权NS名称的查询；2个REDUNDANT_QUERY是同轮系统NS与比较重复。另7个PARTIAL_DNS_EXECUTION_ERROR中包含已有覆盖的SOA重开调查，以及有价值的公共NS对照遇到系统路径重复上限，不能将所有部分失败都判为无用。其余调用保留为已测或待人工判断目的，所有尝试仍在分母。

原设施把逻辑公共解析器路由到127后，E.resolver也暴露为127，诱导模型将物理端点当工具参数。本轮可选logical_identities模式分开配置身份与实际响应者：模型事实用逻辑resolver，Q.server/port、responding_resolver和controlled_network_endpoint仍保留真实回环端点；默认旧模式保留，旧快照不变。独立测试证明显式127参数仍被生产校验拒绝，未放宽权限。

摘要补充query_scope、具体不可重试请求/子路径和复合工具已有覆盖。INVALID_INPUT保留原错误码，另有稳定reason区分目标与解析器授权；不会多造E。16条记录展示上限保留，但另提供全集计数/唯一值摘要哈希/TTL范围/SOA Serial；未显示不解释为不存在。AA、negative_scope及resolution_complete进入事实摘要，完整原始E不删除。工具说明明确query_authoritative已补SOA，不强制顺序或禁止并行。

旧serial记录还有报告问题：A1已完成选中权威子集，A2重复SOA发现失败，建议却泛称“本次权威发现未完成”。现在明确失败调用A2和仍保留的完成调用A1；不让重复失败掩盖有效调查。单项正常查询不再默认建议收集故障设备信息。达到正文上限时body_complete为null（未确认完整），而非断言一定不完整；读取失败为false，观察到完整结束为true。

新增摘要/上下文反例修改前 **5 failed / 1 passed**；修改后通过。第二阶段完整269项通过，但一次运行耗时977.13秒异常，后续记录单独核查耗时，不据此声称性能改善。

原14份模型记录不是全部语义通过：正式测量行与E组合能对应，状态/来源大体受限；但多个候选语句仍把缓存、复制滞后、权威不可达或“而非域名侧”写得过强，虽status=无法确定且支持引用已清空，文字本身仍须复核。NS场景把多种原因合并为宽泛候选、serial首条建议掩盖已完成A1、正常A建议提故障设备也不适合原问题。上述由开发助手进行的审查明确是AI辅助语义复核，不计为独立人工准确率，不用关键词替换伪装解决任意因果语义。
