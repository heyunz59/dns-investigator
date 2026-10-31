# v0.2 可靠性修复

v0.3 继承下述尝试/证据/有限结果机制，并新增独立 Q 网络请求与确定性 Finding；当前架构和预算见 [v0.3 说明](dns-v3.md)。本文件的三个工具与 schema_version=2 描述是历史口径，不代表当前工具数量。

起点 29d66f9，main；开始时本地无未提交改动，fetch 后远程没有更新。原始离线测试 36 项通过。未 reset、覆盖历史或强制推送。

## 输出与诊断状态

程序保守识别 request_kind=query/investigation，并要求模型输出匹配。可通过自然语言明确“只查询 A 记录”或“调查打不开原因”；含故障词的请求按调查处理，混合/复杂意图识别仍有边界。

outcome=answered 要求实际有效测量、非空观察和结论证据引用；调查还须至少两个不同假设，每个假设有支持/反面证据或缺失信息，获得支持/被削弱状态须有相应引用。单项查询不强制两个假设。引用仅可指向有效测量 E 编号，错误调用与用户陈述不自动获得 E 编号。A 组提前提供的 fixture 原始事实仍作为合法证据使用。

outcome=insufficient_information 允许有限结束，记录 status=limited、execution_status=ended、requirements_met=false。没有有效测量时，不接受 answered；即使模型标为信息不足，程序也会把无证据的自由文本结论替换为固定的“没有取得有效测量证据，无法确认故障原因”，禁止附带伪造观察或诊断假设。模型无法完成时返回程序生成的 execution_failed 有限结果，result_origin=application_fallback，保留独立证据，不冒充模型总结。

**结构校验仍无法判断所有语义真假或保证两个假设确实合理**，也不能证明引用的证据真正支持结论。含义过强、误读 HTTP 超时阶段等仍需人工复核；不能把 completed 当成确定性根因已确认。日志中的 requirements_met 表示本地结构与证据门槛，而非独立人工验收。

## 尝试、测量与错误

Agent 在 PydanticAI CallToolsNode 执行前记录所有三个网络工具的调用尝试，早于框架参数校验；工具函数通过 provider_call_id 接上原尝试，不重复增加计数。每次尝试有 A 编号，实际测量成功返回后才分配 E 编号。JSONL 是事件流，attempt_started/attempt_finished 通过 attempt_id 关联；最终 JSON 的 attempts 每次尝试恰有一行，评测不能简单数 JSONL 事件行数。

| code | 意义 | 可重试 |
|---|---|---|
| INVALID_INPUT | 参数非法、超范围、TCP 地址缺少已有 DNS 证据 | 否；修正参数构成新请求 |
| FRAMEWORK_ARGUMENT_REJECTED | 框架在工具函数前拒绝参数或工具不可用 | 否；修正后再提交 |
| FIXTURE_NOT_COVERED | 测试数据没有提供此项事实；不是无记录、NXDOMAIN 或真实网络失败 | 否 |
| NON_RETRYABLE_DUPLICATE | 已失败且不可重试的相同请求，被阻止重复执行 | 否 |
| INTERNAL_EXECUTION_ERROR | 工具内部错误，没有有效测量 | 否 |
| BUDGET_EXHAUSTED | 硬性预算拒绝，未执行测量 | 否 |
| CANCELLED / NOT_EXECUTED | 取消或结束前未执行 | 否 |

网络 TIMEOUT、NXDOMAIN、SERVFAIL、REFUSED、HTTP 503 等在 data 中保留，属于有效测量。工具内部错误仅返回固定说明，不暴露异常详情。fixture 缺失不回退 live，空 fixture 也保持 fixture 模式；其请求指纹忽略 timeout，换超时值不能绕过重复限制。

默认 10 次网络尝试，累计到 8 次后隐藏网络工具，让模型有机会提交结构化总结。批量调用可越过软阈值，但仅前 10 个尝试可执行，额外请求拒绝且仍记分母。框架另有模型请求上限与总时间预算；即使模型无视停止提示，执行仍有界。硬预算约束执行次数，不会抹去模型已经发出的额外调用尝试。

## 评测口径

工具正确率的分母为全部网络工具调用尝试，包括框架参数拒绝、输入拒绝、内部失败、缺失数据、重复、预算拒绝和未执行请求；final_result 等结构化输出排除。自动建议只做参数/执行/案例规则筛查，不能完全判断调用必要性。第一次有意义但缺 fixture 的请求不自动判错，重复不可重试请求判错；详见 call-review.jsonl。

必要测量只由 execution_status=ok 的 E 证据满足；尝试过同名工具不算完成。C3 单独要求默认解析器和 1.1.1.1 的有效 A 查询。A 组实际零网络尝试时工具正确率为 N/A；旧版缺少 attempts 的 B 组为 INCOMPLETE。旧实验原文与图表保持不变，其旧工具正确率不能据此追认为完整数据。

正常 C1–C6c 现在覆盖默认/备用解析器、A/AAAA、IPv4/IPv6 TCP、HTTP/HTTPS 原始响应。MISSING 专门只提供 A 事实，检查 AAAA 缺失与停止行为。Q1 只提供任务所需 A 数据。fixture 不含预写根因；cases 的标准不进入 Agent 提示词。

每次新实验保存独立目录、源码哈希、提交、模型配置、fixture 快照、全部成功/有限/失败回答。重复默认 3 次；A 与 B 相同模型、模式、温度，按重复交替顺序。A 提前知道全量事实，B 按需获取，信息集合存在差别，不能将差异完全归因于推理能力。自动筛查报告明确待人工复核，不等同完整语义评分，也不预设 Agent 更好。
