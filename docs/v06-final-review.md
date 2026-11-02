# v0.6 封版定向修复（2026-11-02）

基线为 `feat/v06-product-polish` / `75c16f7e0b512e2277c0b57c325cde6cf60f1979`。修复分支 `fix/v06-final-review`；不合并 main。原有未跟踪人工审查资料未改动、未自动提交。运行时仅修改 `web_view.py`、`report_replay.py`，未改动 Agent、工具、协议判断、安全策略、预算、页面资产或旧实验。

## P1：混合故障首页

原展示层只要发现 timeout_groups 就覆盖短摘要，忽略正式报告 `diagnostic_summary.title=None` 的限制。现在只在正式报告允许整体用超时概括时采用路径级短标题；否则保留正式主诊断及确认等级。并列时展示“多个异常观测，关联尚未确认，无法确认唯一主因”，合并展示各观测的位置与摘要，不声称已证明原因相互独立。唯一主诊断的说明另列次要观测，未重排正式诊断或完整建议。

|受控输入|修改前首页|修复后首页/依据|
|---|---|---|
|DNSSEC BOGUS + TIMEOUT|已测 DNS 解析路径超时|DNSSEC DS/DNSKEY 关联验证失败；保留已确认等级、example.test.、V7/E7/E8；另列查询超时，关联未定|
|HTTP 503 + TIMEOUT|部分 DNS 解析路径超时|多个异常观测，关联尚未确认；同时展示 HTTP 503 和递归超时，各自 CHECK 优先|
|TCP REFUSED + TIMEOUT|部分 DNS 解析路径超时|多个异常观测，关联尚未确认；同时展示连接拒绝和递归超时，各自 CHECK 优先|
|两个解析器超时，有成功对照|部分 DNS 解析路径超时|保持；明确不代表目标域名整体不可用|
|只有两个解析器超时，无成功对照|已测 DNS 解析路径超时|保持；明确缺少成功对照，整体可用性未知|
|DNSSEC INDETERMINATE + TIMEOUT|统一超时摘要，遗漏未完成验证|保留正式超时主诊断，补充 DNSSEC 未完成观测；DNSSEC 保持 INSUFFICIENT_EVIDENCE，未升级 BOGUS|

颜色沿用正式确认等级：已定位异常可为 bad，并不等于“确认 DNSSEC BOGUS”。测试同时核查文字、确认等级、直接依据、路径和前三项行动，未以颜色代替语义验收。HTML/JS/CSS 没有改动，正常单一故障的页面布局和样式不变，差异仅在受影响的摘要内容。

## P2：离线历史上下文

原回放只读顶层 request_context，并创建会读取当前系统 DNS 的实时 ToolBackend。现在使用仅含历史账本副本的报告适配对象，不构造实时后端；既不读取本机系统解析器/授权，也没有可执行网络或模型的方法。

上下文优先级为 `result.request_context`，仅该字段缺失才回退到顶层。显式空值、非法类型或目标/端口不符均保持未知，不从冲突的低优先级记录猜测。校验关注层、意图来源、歧义标记及目标范围；这只能确认历史字段格式和范围，不能鉴定上传日志的真实性。

只将原始调用参数能说明的路径保留为参数资料。复合查询缺少原始系统/显式路径区分时不推断 resolver=None。建议统一标记 authorization_status=requires_revalidation、can_execute_now=false、supported_by_current_tools=false；已知工具名另外记 available_tool_capability。能力说明和参数构造均不等于当前授权。管理员条件变更仍保留其原方法类别，绝不转成自动执行。

`original_result` 保留正式旧结果；E/A/Q/V、原始 Finding、根级执行状态及源文件不变。已有新格式报告不重新诊断；元数据不足的旧报告保守保留原展示。不完整上下文不再导致首页目标读取报错。

## 可复核证据

- 修改前完整测试：**584 passed in 41.48s**。
- 新测试 `tests/test_v06_final_review.py`：20 项，覆盖六种混合/纯超时、Web/CLI/JSON/HTML、一致上下文/冲突优先级/缺失/非法上下文、TCP 关注恢复、不同环境同结果、禁止后端初始化/模型/网络、建议授权与原账本完整性。
- 旧有并发归属、CNAME/转介、DNSSEC/NSEC3、TCP/HTTP 安全、A/Q/E/V、取消和导出测试均保留，未降低旧断言。
- `results/published/v06-final-review/20261102/before.json`：修改前实际 ViewModel/回放快照和冻结输入。混合场景是构造证据或既有受控 DNSSEC 材料，live 标签为原始输入字段，**不代表新增公网测量**。
- `python -m evaluation.v06_final_review <新的输出目录>`：9 组实际本机浏览器 DOM 和离线 HTML 检查；保存比较、CLI、截图、输入副本和源码哈希。不复写既有输出目录。
- 百度原日志仍为 19E/17Q/6A/0V，七次超时归为两组：192.168.5.1 五次、1.1.1.1 两次；正常对照、HTTP 301/重定向拒绝均保留。
- 本轮新增公网测量 **0**，DeepSeek 调用 **0**，未进行独立人工语义评分。测试通过或 completed 不等于诊断准确率。

最终完整回归、安装验证、公开检查与远程 CI 回执另见本目录关联的验证记录。无完整迭代/DNSSEC 新能力，无授权范围扩张，不自动修复。建议在本轮 CI 和定向验收通过后冻结 v0.6 报告模块；未知旧上下文及未观测的因果关系继续保持未知。
