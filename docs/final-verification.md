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

## 最终核验结论

|项目|本轮最终判断|
|---|---|
|HTTP授权、IP绑定、Host/SNI/证书|保留现有实现；原23项及新增标准升级/授权端口/多地址回退/地址上限/总deadline检查通过，无新可利用绕过复现|
|正文读取与安全拒绝展示|修复；200后读取失败、64KiB上限、真实完成均有独立本机报文验证，安全拒绝不写成站点失败|
|权威阶段与完成范围|修复中断计数及最终展示；两台收到目标报文但一台回答时Q7/E6/查询2/AA1，发现3选中2明确限定子集|
|时间/别名/上层摘要|修复未知时间超时定位及无时区别名收敛；保留所有E。跨时区起止按真实时刻排序，不补造旧时间|
|五工具、动态选择、并发、A/Q/E、fixture隔离|保留，原249项及新回归通过；未引入第二Agent/第六Tool或固定调查流水线|
|AgentDraft、非法引用、回退|保留严格校验；无效E仍失败并保留报告。新两臂均无回退，不能由此推断今后不会失败|
|模型必要决策摘要|补全集聚合/范围/不可重试提示；原始响应和不利证据完整保留|
|调用合理性|**未证明改善**；新同设施对照A30→38，INVALID_INPUT2→6，未授权NS查询仍出现|
|完整语义正确/唯一根因|**未验收**；程序事实范围可核对，但自然语言候选仍可能过强。独立人工评分未完成|
|公网、多位置、最终新提交Linux/远程CI|本轮未执行；d26已有CI不替代新代码验证；不推送、不合并|

另外的独立反例：ISO字符串顺序与真实时刻不同，会令Finding范围开始晚于结束。92be49a反例失败；4be929d按有时区实际时刻选择原始起止，未知/非法时间不伪装范围。见time-bounds-before/after.json。这个错误没有改变原比较资格，但会误导展示，因此修正而不改写原测量。

## 新增真实模型补测及版本对应

固定验收项先写入 evaluation/final_verification_criteria.json，未传入Agent。只运行一批，两臂各7次：serial3、NS超时3、正常A1；全部失败/拒绝/草稿保留。模型 deepseek-flash、thinking disabled、temperature0、8A/24Q、model_timeout45、DNS每请求0.3秒，顺序执行两臂。源代码逐模块SHA256与Git blob/Windows CRLF表示核对通过。

|指标|d26d6b7，同逻辑身份设施|92be49a，同逻辑身份设施|
|---|---|---|
|最终模型输出通过校验|7/7|7/7|
|关键测量机械覆盖|7/7|7/7|
|正式事实范围与实际E对应|7/7|7/7|
|输出重交 / 回退|0 / 0|0 / 0|
|A全部尝试|30|38|
|Q实际请求尝试 / E测量|62 / 62|69 / 69|
|INVALID_INPUT|2|6|
|部分DNS执行错误|8|2|
|平均耗时|11.353秒|12.286秒|
|实际SDK记录输入 / 输出tokens|148492 / 12457|232778 / 13857|
|usage已知次数|7/7|7/7|

不是“模型更准确”的结果：两个版本均稳定取得结构化输出，新版调用、耗时和tokens更多；减少部分执行错误也不等于提高调用价值。新版六个INVALID_INPUT来自三次NS场景各两个未授权NS名称，仍被安全拒绝且计A，不产生Q/E。serial的同轮重复SOA调查减少，但改为一些RD=1的显式服务器复测，是否有价值缺少明确目的；不能一概标为正确或无用。未通过调用合理性改善的验收，不再追加样本挑选有利结果。

原40A属于旧物理身份设施；本次基线30A已经采用修正的逻辑身份设施，不能将40→38当成代码改善。两批模型服务时段/缓存/负载和实际服务端版本无法锁定，三次重复不足以推断长期成功率。SDK tokens按实际记录，费用没有换算成真实账单；缺失usage保持未知，本批没有缺失。

旧14份AI辅助复核在historical-AI-review.json，新14份在real-model-comparison/*/manifest.json的review字段；AI-semantic-findings.json另按源文件和假设ID列出具体语义问题及支持测量，包括旧版“A/SOA多解析器一致”扩大SOA测量范围、未测父委派却使用委派一致措辞等。完整草稿/正式结果在对应JSON，源文件不改写。可核对的核心结论是选中路径的记录/SOA差异或NS发现未完成。仍需人工处理的包括“差异说明缓存/不同步”“而非域名侧故障”、权威不可用等过强候选，以及注册/权威等宽泛合并。完整语义评分和错误根因断言数量仍为未知，不以机械7/7填成准确率或0错误。

付费当前臂源码是92be49a。最后业务源码4be929d仅修Finding跨时区起止；对旧14+新14共28份保存测量，在两版独立加载后重算Finding，逐份SHA256相同（finding-replay-*.json）。这是没有新增网络/模型请求的回放；不称4be929d已重新付费跑完14次。最终4be929d另跑本机/离线反例和完整测试。after-final-source.json属于92be49a中间阶段，以内部source_ref为准；最终受控材料为after-final-4be929d.json。

## 实际命令和材料

项目根目录执行，下列python均指 `.venv/Scripts/python.exe`：

```text
python -m pytest -q --durations=5
# 最终4be929d：271 passed in 9.29s，无skip；最慢单项2.04秒
python scripts/verify_report_acceptance.py
# 92be49a：9条通过，results/runs/report-acceptance-cd66b576b1f748978cc6922ef8637d5a/
python -m evaluation.final_counterexamples <新的输出.json>
# 本机实际HTTP/UDP + fixture/固定证据；不调用模型，不测公网
python evaluation/security_stability_runs.py <新目录> --arm <名称> --source-ref <实际加载版本> --repeats 3 --logical-identities
# 消耗实际API额度；--source-ref不自动切换代码，基线通过独立PYTHONPATH加载
python -m evaluation.final_verification_review
# 本轮目录专用、拒绝覆盖；AI辅助复核，不是独立人工评分
python -m evaluation.replay_final_findings <新文件.json> --source-ref <实际加载版本>
# 仅重算保存测量的Finding，不是模型运行
python scripts/check_public.py
# 全引用与当前公开文件规则；最终审计快照public-audit.json
```

相同源码曾有269项全部通过但耗时977.13秒；下一次带耗时记录的同码运行269项9.16秒，最后271项9.29秒。异常慢跑未复现、原因未查明，不能据此保证运行时延。首次本机HTTP测试设施的IPv6解析问题也保留说明，未当作被测代码漏洞。Windows本机验证不冒充新Linux验证；没有重测公网元数据或未授权内网服务。

最终源码/交付阶段：6e9c965（HTTP完成/时间收敛/权威中断）、92be49a（摘要/范围/受控身份）、4be929d（Finding跨时区范围）；本文件后续交付提交只增加评测/文档/审计。完整更改路径见[文件清单](../results/published/final-verification/changed-files.txt)；真实密钥、忽略目录原始JSON/JSONL、临时TLS私钥、用户未跟踪manual-reviews未提交。公开扫描仅是模式检查，不是隐私形式化证明。

计数边界：Q表示进入底层UDP/TCP通信的请求尝试，不保证目标实际收到；预算/重复限制在Q创建前拒绝。中断反例另以服务端收到事件确认两次目标报文；不会由E数量或返回顺序反推Q。并发归属和计数测试保留。

## 是否可进入课程演示

可以停止扩展功能，进入**有边界的课程演示和材料整理**。可演示固定单项查询、受控权威差异、NS发现超时、信息不足/回退和证据追溯，完整展示拒绝与限制。不能把模型候选作为已确认原因、把completed当正确率，或宣称无效调用已减少。若验收要求“调用合理性已改善”或“所有候选语义正确”，当前仍不通过这些要求；不以继续增加工具掩盖。

少量复测命令：`python -m pytest -q`；`python -m evaluation.final_counterexamples results/runs/新的demo文件.json`（不调用模型）；`python -m dns_investigator.main "查询 example.com 的 A 记录" --fixture data/fixtures/Q1.json`（真实DeepSeek、模拟测量，消耗额度）。长期公网根因、多网络位置、完整迭代/DNSSEC、独立人工语义评分仍不在本次已验证能力内。
