# DNS Investigator v0.5 诊断与行动建议专项技术报告

## 代码与范围

基线 `aed194ac53b9f9af8f2637c8b4d2efd9fd772317`。最终业务源码 `5e86226d36fdc7b426b3f06b3dbe844d6d1c51c7`，分支 `feature/v05-diagnostic-conclusion`。未合并 main。发行包仍为 0.4.0.dev0，本轮 v0.5 指报告能力里程碑，未发布发行版。

修改 schemas.py、reporting.py、main.py 和 agent.py 的报告策略标记；新增 diagnostic_reasoner.py、remediation.py。未改变 DNSSEC 密码学/否定证明/可信锚、trace、DNS wire、TCP/HTTP 安全和执行预算。五个工具及 DeepSeek 动态选择机制保持原样。完整逐模块差异核对在 regression-results.json。

执行流程：已有 Agent 调查结束 → 原有测量事实/Finding/协议与验证结果/假设关系审查 → 纯规则 reasoner → 主诊断和独立次诊断 → 条件行动与验证步骤 → 来源/范围校验 → CLI 优先展示高层结论，再显示审计详情。生成报告不重新探测、不调用第二个模型、不执行配置修改。

## 新结构与兼容

`DiagnosticConclusion`：diagnosis_status、三态 fault_detected（null=unknown）、primary_issue/summary、fault_layer/location、affected_scope/comparison_scope、cause/cause_status/alternative_causes/reason、E/V/Finding/A 引用、source_modes、remediation_steps/verification_steps/limitations。scope 保留具体目标、类型、解析器、端口、时间、来源、别名路径。不会扩成未测组合。

`RemediationStep`：id/priority/title、CHECK/POSSIBLE_FIX/VERIFY、description/target/reason、Finding/E/V 引用、instructions、expected_outcomes、verification_method、prerequisites、safety_notes、executed=False。不生成任意 shell，不依赖自由文本生成命令；可执行性体现在明确的人工检查、条件性变更和复测方式。执行与变更权限由用户另行控制。

`InvestigationResult` 增加 diagnostic_conclusion（默认 null）、secondary_diagnoses/remediation_plan/candidate_analysis（默认空）及 diagnosis_ordering。所有旧必需字段保留，旧日志加载不反向生成历史新结论。旧 conclusion 和 diagnostic_assessment 保留详细事实/定位职责；调查时加上高层摘要，单查询维持简洁。旧 recommendations 是兼容的调查补充检查，正式条件性修复来源为 remediation_plan，不作为另一套根因结论。模型执行失败保持 failed 和 application_fallback，已有测量生成程序诊断。

完整可序列化 schema 见 [schemas.json](schemas.json)。日志仍使用兼容 v7 外壳，report_policy 改为 diagnostic_conclusion_v05。

## 原因强度与规则边界

- CONFIRMED_PROTOCOL_ISSUE：仅已有本地 BOGUS、completed 验证，且 V 闭包有实际 E、locally_validated 来源、相同调用归属与匹配 QNAME/QTYPE 时使用。区分 DS_DIGEST_MISMATCH、签名未验证、时间异常观测和否定证明失败。确认的是本地支持策略内的协议结果，不确认管理员忘记操作、污染或唯一现场根因。Finding.root_cause_confirmed 仍为 False。
- FAULT_LOCALIZED：递归/选中权威超时或实质状态差异、未完成别名路径、TCP REFUSED/TIMEOUT/NETWORK_ERROR、HTTP 错误响应/请求错误、明确证书验证失败。端点预期未知时，HTTP 503 只确认该响应，不确认应用本应返回什么。SOA/地址集合差异不直接升级故障。
- INDETERMINATE、预算/取消/能力限制与安全拒绝保持 unknown，不当作 BOGUS/服务不可达。独立 trace 未完成会列停止原因与最后成功区域；仅明确的非权威/循环结果且有实际关联 E 才定位协议路径，不推断全部 NS 故障。
- 正常 CDN 差异、有效 SECURE 或正常 INSECURE 不制造客户端或配置故障。正常协议链中的转介与经过验证的无 DS 材料不能污染整体状态。只有单项正常查询时无修复计划。
- 所有未知候选/运维原因保持候选。LIKELY_CAUSE 已有稳定枚举，但当前无足够机械规则可靠给出高度因果支持，故不强行使用。已有 AgentDraft 假设经原有具体命题/范围关系审查后，保留顺序作为 candidate_analysis，仍为待人工复核模型候选；analysis_summary 不作测量依据。
- 多异常优先展示已验证协议异常，其他稳定排序；secondary_diagnoses 保留独立问题，排序不宣称主次因果。不做概率准确率估计。

DNSSEC DS 关联建议先只读核对父 DS/子 DNSKEY 和轮换，再由有权限管理员在确认具体配置问题后修正，最后重验完整信任链与递归。TLS 不关闭验证，指定后端仍需 Host/SNI；TCP 不禁用 IPv6/全部防火墙。模拟来源贯穿结论、范围与建议，真实操作先重新 live 解析，不探测模拟 IP。每个行动都有验证方式，CLI 优先显示主诊断的至多三项行动。

## 实际新旧报告对照

最终代码实际产生 [final-release/index.json](final-release/index.json) 十例：

| 受控场景 | 新高层状态 | 具体提升与原始新旧输出 |
|---|---|---|
| 单递归超时 | FAULT_LOCALIZED | [dns-timeout.json](final-release/dns-timeout.json)：具体超时解析器与成功对照分开，服务/网络/策略仍候选 |
| 递归/权威差异 | FAULT_LOCALIZED | [dns-mismatch.json](final-release/dns-mismatch.json)：限实际 AA 响应与已测组合，不称污染 |
| DS/DNSKEY 关联失败 | CONFIRMED_PROTOCOL_ISSUE | [dnssec-ds_mismatch.json](final-release/dnssec-ds_mismatch.json)：具体阶段、E/V 闭包、条件修复与复验 |
| RRSIG 失败 | CONFIRMED_PROTOCOL_ISSUE | [dnssec-tampered.json](final-release/dnssec-tampered.json)：签名失败与配置操作原因分离 |
| 正常委派追踪 | NO_FAULT_OBSERVED | [trace-normal.json](final-release/trace-normal.json)：中间转介不误当证据不足 |
| 非权威回答 | FAULT_LOCALIZED | [trace-non_aa.json](final-release/trace-non_aa.json)：只定位已测委派环节 |
| 追踪超时 | FAULT_LOCALIZED | [trace-timeout.json](final-release/trace-timeout.json)：所选服务器与未完成追踪分别保留 |
| HTTP 503 | FAULT_LOCALIZED | [http-503.json](final-release/http-503.json)：实际本机服务返回503，不用DNS正常推断端点设计 |
| 本次无明确异常 | NO_FAULT_OBSERVED | [dns-normal.json](final-release/dns-normal.json)：不推断用户客户端问题，不要求修改解析记录 |
| 正常未签名委派 | NO_FAULT_OBSERVED | [dnssec-insecure.json](final-release/dnssec-insecure.json)：不因正常缺DS制造配置错误 |

每个 JSON 同时保留 before/after 完整实际报告与共同 E/A/Q/V。before 使用 Git 基线原 reporting.py 实际执行（兼容 schema 使用当前版本），不是隔离全套旧程序或虚构文案；这轮重新采集的同一批测量供两版使用，事实表逐项断言一致。DNS 为受控回环 UDP、实际签名和本地密码学验证；HTTP 为真实本机 socket 服务与测试专用明确授权，非公网现场或模型实验。`final/`、`final-f13c/` 和 `final-source/` 保留中间业务提交的对照；`capture-initial-failure.json` 保留采集脚本读取可选属性时的初始失败，不将其改写为成功。四例文本对照另见 [comparisons.md](comparisons.md)。

## 验证与未完成项

基线实际 410 passed in29.27s；最终 5e86226 **447 passed in28.87s，新增37项，0 failed/0 skipped**。完整保留 NSEC3、并发证据、TCP/HTTP安全、五工具、预算、fixture及历史回归。新测试验证范围、原因等级、E/V归属、修复关联、模拟边界、实际签名 DNS、真实旧日志加载、脚本模型失败保留证据。pip check 通过。远程 CI 已实际成功：[Actions 41407533244](https://github.com/heyunz59/dns-investigator/actions/runs/41407533244)，验收快照 dcb39cb9；完整 job/step 和测试摘要见 ci-status.json。后续仅追加此回执，不改业务源码；不能用测试通过率代替语义验收。

未调用真实 DeepSeek，没有新增公网调查；FunctionModel 只验证框架失败回退，不冒充真实模型复测。独立人工语义复核 **PENDING**。当前规则覆盖有限，不能自动识别所有 Lame Delegation、客户端环境原因、接口业务意图或运维责任；LIKELY_CAUSE 不作无依据提升。历史 T01/T06/T10 与独立 DNSSEC 验证器的分歧仍保留，未扩展完整 DNSSEC。结构引用校验不能证明所有自然语言因果关系正确。建议未执行，未验证任何真实用户配置已经修好。
