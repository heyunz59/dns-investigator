# DNS 判断准确性与范围定位专项升级（2026-11-01）

本轮仅本地开发、提交与验证，未推送、合并或发布。起点与远程 main 均为 f0787c063ca11a95d9255c1e68b8b95697b9b90b；起始工作区只有用户的未跟踪 docs/manual-reviews/。这些人工材料及原始 runs 没有修改、提交。起始测试 136 passed in 8.90s。五工具、单 Agent、DeepSeek 非思考方案不变。

## 已实现及文件

- dns_wire.py：新增 transport_status/dns_rcode，TIMEOUT 有 E 但没有收到 RCODE；保留 result_kind、执行状态和原始记录。新超时 rcode=null，历史 rcode=TIMEOUT 通过 dns_outcome 非修改适配；未重新推断旧日志 NODATA。
- dns_compare.py：compare_details 返回实际路径、E/A/Q、比较资格、排除原因及原始 TTL/耗时；compare 保留代码列表接口。目标、类型、来源、否定回答适用名、AA 和最多300秒时间窗口受约束。未知时间/来源明确有限。逐对比较保留可用子集，失败项独立保留；不比较超时的记录、地址或 TTL。正常微小耗时/TTL差不生成功能故障告警。
- dns_diagnosis.py、schemas.py：按查询/来源/时间窗口聚合，不按两两数量输出重复告警。scope、observed_facts、localization 保留参与结果、例外路径与证据；超时的 affected_evidence_ids 只包含超时路径，不把正常响应者说成故障。RECURSIVE_QUERY_TIMEOUT、RECURSIVE_RESPONSE_DISAGREEMENT、RECURSIVE_AUTH_RESPONSE_MISMATCH、AUTHORITATIVE_RESPONSE_DISAGREEMENT、ALIAS_RESOLUTION_INCOMPLETE，以及原有 NXDOMAIN/NODATA/SERVFAIL/REFUSED；地址集合差异单列 RECORD_SET_DIFFERENCE。权威超时单列 AUTHORITATIVE_QUERY_TIMEOUT。root_cause_confirmed 固定 false，没有直接根因确认规则。
- reporting.py：保留程序事实、HTTP 状态/读取错误/跳转/最终 URL、TCP 端口及证书错误。新增 diagnostic_assessment、assessment_level、dns_comparison；摘要区分观测、路径范围及待验证原因，结论保留可读事实。正常查询不制造异常；未分类空 NOERROR 不宣称取得记录。内部发现的非授权名称仅建议外部专项检查，不暗示五工具已能独立查询它。
- 复合工具的部分执行失败/预算拒绝另存 A.dns_execution_issues，与已执行失败 Q 去重；fixture 或请求发出前的拒绝不造 Q/E。正式报告保留失败路径和可比较子集。三个 DNS 工具的执行问题都保留实际记录类型，工具返回 execution_issue_summary；外层 A 错误码不与某子路径错误码互换。错误码/目标/类型的校验保持严格。
- agent.py：工具返回最新 Finding 和 allowed_dns_targets，继续动态选择，不固定流水线。取消假设数量完成门槛；保留身份、category、testable_claim、measurement_scope、支持/反面引用、missing_information、evidence_review_notes 和最终去重。模型范围或 A/E 引用不合格仍重试；总结最终失败时，状态保持 failed，程序报告保留全部有效事实与 Finding、退回原因及原模型草稿。
- alias_scope.py、tools.py：仅 query_dns 可扩展至有效同来源 DNS 证据中与原目标连通的 CNAME 链。E2 保存 target_authorization 引用 E1；深度/目标数最多8，保留 A/Q 总预算、重复及时间限制。无关 Answer/Additional、网页重定向和模型文本不授权。已有同类型完整末端记录会拒绝无理由跟进；fixture 不回退网络，fixture/live 不能相互授权。不是 DNSSEC 或任意域名扫描；其他工具仍限原目标。
- accounting.py、evaluation/：拒绝和重复继续算 A，不算有效执行；评测假设数只作观察。日志 v5、scoped_dns_v2 与旧版本口径分开。旧对照数字和原始评分不修改。
- tests/、README、PRD 版本说明、architecture、validation 和本文件同步更新。新增 evaluation/accuracy_*、controlled_dns.py、summarize_accuracy.py，用于分离固定事实、评分标准、受控网络、模型调用和结果汇总。

## 修改前反例与独立标准

规则修改前保存 evaluation/accuracy_cases.py、accuracy_expectations.json 和 results/published/dns-accuracy-f0787c0/before.json。事实只有原始测量，标准答案不进入 Agent。共13个固定场景，另加一份历史 live-agent 回放。各场景共享边界：范围仅限所列名称/类型/路径/来源/时刻；不确认污染、服务器宕机、DNSSEC 或唯一根因。具体定位、未知和下一步如下。

| 输入 | 应观测/定位 | 必须保留的未知与下一步 |
|---|---|---|
| TIMEOUT / NOERROR | 超时路径的查询可用性；没有该路径记录内容 | 服务或网络未区分；同名同类型有限复测或路径对照 |
| NXDOMAIN / 有记录 NOERROR | 同范围完整 DNS 响应状态差异 | 缓存/策略/时间未区分；按需取 AA 权威证据 |
| SERVFAIL / NOERROR | 实际 DNS 响应状态差异 | 不证明域名不存在或 DNSSEC 原因；权威对照不等于 DNSSEC 验证 |
| 不同正常 IP | 记录集合差异 | CDN、调度与时间可能正常；无其他线索不自动加查 |
| TTL 60 / 58 | 原始 TTL 观察 | 不证明缓存或配置异常，也不推断原始权威 TTL |
| CNAME+NS 转介 | 转介/别名待跟进，非 NODATA | 仅可沿连通且有授权的别名查末端 |
| 仅 CNAME | ALIAS_RESOLUTION_INCOMPLETE | 不编造末端地址或否定回答 |
| AA=false 候选 | 收到候选回答，未确认权威身份 | 不做已确认递归/权威冲突；需 AA |
| 两台权威 SOA Serial 不同 | 同区、同类型 AA 回答差异 | 不确认同步故障；有限复测记录与 Serial |
| 一条超时、两条有效且不同 | 保留超时，并比较有效子集 | 不把超时变成第三种内容回答 |
| 无测量 | 信息不足 | 不生成虚假观测或范围定位，先取得授权测量 |
| 正常解析 | 已测范围没有状态异常 | 不制造异常 Finding；不能据此归因客户端 |
| 递归 NXDOMAIN / AA 正常 | 仅这些递归/权威路径存在回答差异 | 不直接归因为缓存污染；有目的地重复或对照 |

## 同证据的新旧对照

before.json 为修改前原始快照；after.json、final-after.json、release-replay.json、delivery-replay.json 保留过程快照。收尾时用隔离的 f0787c0 源码另存 **baseline-replay.json**，补正早期回放脚本给历史日志报告使用固定 probe.example 目标的上下文问题（原证据/诊断不变，不拿该脚本建议问题归罪于旧产品）；**accepted-source-replay.json 为最终业务源码 4632d74 的回放**，两者按历史日志实际目标比较。文件名不是人工验收结论。全部明确 replay，不是新 live 或模型运行；未覆盖原快照。summary.json 给出分母、代码和引用，13/13 只表示预设机械规则满足，不是语义准确率。

| 固定证据 | 旧规则 | 当前规则 |
|---|---|---|
| 超时/成功 | 同时产生 DNS_TIMEOUT 和响应内容冲突 | 仅超时/可用性范围，不比较空记录或 TTL |
| 超时、NXDOMAIN、成功 | 3条递归冲突，其中2条源于超时 | 1条真实响应差异；另保留超时及 NXDOMAIN |
| 历史 dns-v3/live-agent.json，17条 E | 6条超时 + 6条由超时引出的递归/权威冲突 | 5个查询范围的超时，0条内容冲突，17条 E 全保留 |
| CDN式不同IP | 比较层有地址差异，Finding 仅 inconclusive | 明示 RECORD_SET_DIFFERENCE，仍不判故障 |
| 正常 TTL 60/58 | 比较层 TTL_DIFFERENCE | 保留原始 TTL 观察，不当故障线索 |

在13个固定场景及1份历史回放中，“含超时证据的内容冲突 Finding”实际从 **9降为0**。这是可核对的具体误判消除，不代表所有内容冲突都被语义正确分类。预设 NXDOMAIN、SERVFAIL、递归/权威差异、权威差异、别名未知仍检出；本组未见这些预设规则的漏报，但不证明未覆盖故障没有漏报。重复统计按 code+查询范围计算，不能单凭 Finding 数变少证明准确性。

## 受控网络与真实模型分开

受控 DNS 通过实际 UDP 回环报文构造三类：系统路径超时/公共路径正常；递归 NXDOMAIN/AA 权威正常；两台 AA 的 RRset 和 Serial 不同。无模型时 A/Q/E 分别为 1/3/3、2/11/11、2/11/11，全部按预期保留事实和区别。测试只在 evaluation 注入端点，不放宽正式私有权威地址/端口权限；不模拟完整缓存、委派、DNSSEC。

真实 DeepSeek 使用相同 deepseek-flash、temperature=0、thinking=disabled，工具预算8、Q预算24、模型单次45秒、回环 DNS 单次0.3秒，问题和注入场景相同。每阶段每例仅1次，**不是旧 LLM/Agent A/B 的重跑**。测试机和本机服务相同，运行时段不同；不要求旧 IP、TTL 或耗时重复。

| 场景 | 原 f0787c0：状态；A/Q/E；秒 | 升级源码 0f9cd72：状态；A/Q/E；秒 |
|---|---|---|
| 超时对照 | completed；3/11/11；13.390 | completed；2/3/3；12.844 |
| 递归/权威差异 | completed；4/11/11；13.579 | completed；2/11/11；18.641 |
| 权威记录/Serial差异 | failed；6/17/17；40.765 | failed；5/14/14；53.031 |
| 单项 A | completed；1/1/1；3.844 | completed；1/1/1；4.906 |

以上升级批次在收尾修正之前。10ccb5e 另做超时案例真实模型验证：completed，3/11/11，15.187秒，只有 RECURSIVE_QUERY_TIMEOUT，无内容冲突。最终业务源码 **4632d74** 又做真实 DeepSeek + 部分失败 fixture：**completed，A/Q/E=2/0/2，12.968秒**，两条有效响应保留差异，失败子路径引用 A1，缺失权威事实引用 A2，没有伪造 E 或访问公网。该场景修正前6e8f379实际运行 failed，2/0/2，33.734秒，记录保留在 partial-before-typed；修正后为 partial-current。typed 摘要与实际类型对齐后未再用子错误码冒充外层 A 错误码。这只是一个模型个例，不能证明所有引用语义均正确。

4632d74 的三类受控报文与固定证据回放已执行；没有在这个最终源码重新付费跑旧四例，也没有做新的公网目标测量。不能把0f9cd72或10ccb5e的模型运行说成最终提交的完整验收。

old、intermediate（d0857cd）、final（0f9cd72，是实验阶段名，不表示最新最终提交）、release（10ccb5e）及两次部分失败复测共 **15次**真实模型执行全部保留。目录为 controlled-old/intermediate/final/release、partial-before-typed、partial-current，最终受控报文为 controlled-current。不同阶段不可合并成重复试验来算准确率。每份 manifest 有业务源码 SHA256；summary 将其与对应 Git blob 或其确切 CRLF 形式校验，不把换行转换冒充代码差异。最终本地交付提交仅在4632d74后增加评测与文档，业务源码哈希一致。

权威场景新旧均有模型执行问题引用不匹配，重试后失败。升级结果仍保留14条 measured_facts、3条 Findings、范围摘要与 report_fallback_reason，原模型草稿保留；没有将失败标为完成。部分模型尝试用实验回环地址显式复查，被正式地址权限拒绝；这些 A 计入分母，不计执行或 Q，不能解释为 DNS 故障。失败运行没有 SDK 完整 usage，记为未知，不能当作0成本。已取得的 usage 逐例保留，SDK估算不等于账单。

0f9cd72四例合计 A/Q/E 从14/40/40变为10/29/29，但总时间从71.578秒增至89.422秒（均值17.895→22.356秒）。收尾超时验证又出现3/11/11，说明工具选择有波动。**已证明的提升主要是固定证据比较与报告约束；未证明自主决策普遍更优、更快或更省钱。** 回放不新增网络调用；规则自身 CPU 额外开销未单独测量。

## 验证命令与复测

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m pytest tests/test_dns_accuracy.py tests/test_alias_scope.py tests/test_controlled_accuracy.py -q
.\.venv\Scripts\python.exe scripts/verify_report_acceptance.py
.\.venv\Scripts\python.exe scripts/check_public.py
.\.venv\Scripts\python.exe -m evaluation.capture_accuracy results/runs/my-new-replay.json
.\.venv\Scripts\python.exe -m evaluation.accuracy_model_run results/runs/my-new-wire --wire-only --scenarios timeout mismatch serial
```

capture_accuracy 拒绝覆盖已有快照。wire-only 是工具实验固定检查顺序，不证明 Agent 决策。去掉 wire-only 会调用真实 DeepSeek，必须另选新目录；程序不向模型提供预期答案。

accuracy_model_run 同样拒绝覆盖已有阶段 manifest 或 wire 记录；已用保留内容的临时目录核验，未调用模型/网络。完整相对文件清单见 dns-accuracy-changes.txt。

公网用户复测示例（本轮未新跑公网）：

```powershell
.\.venv\Scripts\python.exe -m dns_investigator.main "查询 example.com 的 A 记录"
.\.venv\Scripts\python.exe -m dns_investigator.main "example.com 解析失败，请按证据调查 DNS 路径差异"
```

第一条通常仅需 query_dns，报告实际地址/TTL；第二条由模型自主决定，不要求全部工具。正常、超时、部分失败都不直接确认唯一根因。

完整最终离线结果 **180 passed in 8.54s**；旧9项报告验收脚本仍通过（新日志另存）。scripts/check_public.py 已 PASS，收尾新文件另按相同规则检查；这仍是密钥/路径规则扫描，需人工复核自由文本。未验证远程 GitHub Actions。本轮未新增公网 DNS/TCP/HTTP 测量。原始日志留在忽略目录，公开候选为单独脱敏副本，未经自动发布。

## 仍不能确认的故障

不具备完整迭代、DNSSEC 验证、缓存内部观测、配置修改、长期采样或跨故障现场验证。单次超时不能分清服务与链路；内容差异不能直接分清调度、缓存、策略或攻击；Serial 差异不能直接确认同步故障。CNAME 跟进只支持有证据授权的 DNS 查询，不自动授权别名的权威/HTTP/TCP扫描。结构校验、受约束模板与 root_cause_confirmed=false 仍不能保证所有假设文字、证据关系和建议语义正确；独立人工复核未完成。
