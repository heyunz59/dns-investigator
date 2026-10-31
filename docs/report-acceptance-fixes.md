# 5223c06 报告层验收修复

起点为 5223c060dce2b436be7490185d7ac5eb29dd1867，工作区原有未跟踪 docs/manual-reviews/。读取验收意见和配套 JSON，保留原文件、原业务测量日志及旧评分；不修改工具层，不增加工具、UI 或 Agent。

## 修复一：.invalid 背景与测量分离

原问题：零测量的 limited 结果仍建议“本次公网 NXDOMAIN”，且覆盖 fixture 警示。

现在 .invalid 建议只陈述公网命名用途及规范预期，明确这是背景而非本次观测；本次应答仅由实际事实行描述。无证据、超时、fixture、私有解析返回地址、不匹配目标都不会凭后缀生成“测到了公网 NXDOMAIN”。fixture 即使没有产生 E 测量也保留来源提示，不被后缀分支覆盖。hosts/私有覆盖可能不同的边界保留。

## 修复二：按工具完整摘要

HTTP 同时保存/展示 status_code 与 error/request_state，200 响应头不再掩盖正文超时。measured_facts 和用户可见 observations/conclusion 均保留 redirects、final_url、bytes_read、明确错误类别及证书 verify_code。无错误时标 finished_within_check_limits，仅表示限额内检查结束，不承诺读取完整正文。TCP 摘要包含端口及安全错误详情。

反例验证：真实本机服务返回 HTTP 200 头后不发送正文，工具 TIMEOUT，摘要同时出现 200、TIMEOUT、incomplete、读取字节 0。另检查跳转成功、跳转失败、两次 302 最终 /get、证书校验失败（CERTIFICATE_VERIFY_FAILED / verify_code 10）和非默认 TCP 端口。

## 修复三：假设身份与具体证据关系

category 只分类，不再用于改写 statement 或计算不同原因数。保留“递归解析器本身发生故障”和“权威服务器无响应导致递归失败”等同类不同身份，以及原缺失信息。最终按具体 statement、measurement_scope、testable_claim 去重，检查空身份、编号唯一性、E 引用及转换后的调查结构；不再根据类别数量将 answered 改为 limited。只有没有有效测量或最终确实不足两个不同调查假设时，answered 才按结构门槛降级。

支持/反面关系不再仅由大类决定，也不一律删除反面证据。新增可选 testable_claim 与 measurement_scope，把具体可观测命题绑定到已测目标、来源和必要的解析器/类型/端口。例如“本次该解析器的该类型查询失败”，可被同一明确范围的 NOERROR 削弱；不同类型、不同解析器或未指定范围不能作这种机械反证。泛化的“解析器自身故障”“权威故障”等因果解释不会因此被自动确认。

旧假设未提供具体观测命题/范围时，仍保留原因身份和缺失信息，但不凭大类授予证据关系；evidence_review_notes 逐条说明未采纳的关系，模型原始引用仍在草稿。支持症状不等于唯一原因，模型错误标注命题与文本仍可能逃过机械检查，独立人工语义审核未完成。

## 最终代码验证

- 修改前原测试：120 passed in 7.60s。
- 新增 16 个反例；最终完整测试：136 passed in 7.88s。命令 `.venv\Scripts\python.exe -m pytest -q`。
- 命令 `.venv\Scripts\python.exe scripts/verify_report_acceptance.py`：最终报告代码另存 9 个验证条目，包括完整 investigate + 脚本模型的零测量 .invalid、受控 HTTP 正文超时、五份历史已发布结果回放、旧跳转回放、同类别两个原因输入。源码 SHA256、运行方式和基准提交见独立 metadata.json。
- 新目录 results/published/report-acceptance-0fb8ba950e694abb8bb05f201958222b/。运行没有调用付费模型，没有访问公网目标。历史日志回放不冒充新模型运行或重新公网调查。
- 五份旧结果已经丢失的具体假设身份无法从类别模板恢复；回放会去重已有重复项，不补造原原因。构造的两个具体假设反例用于证明最终代码保留这些身份。

本轮工具层保持不变，原并行归属、CNAME/转介、调用统计、IPv6、TLS 与不可重试回归均执行。测试数量和 completed/limited 仍不是语义验收准确率；本轮未做独立人工因果判断确认，也不宣称确定性模板能解决全部解释问题。

过程记录 report-acceptance-4ea744f8a0f247ada3d03ebd6f8bbeef/ 对应较早的报告代码哈希，也保留归档；最终按工具选择目标和同身份去重合并细节调整后，重新执行的9条验证是上述0fb8ba95目录，未将中间记录称为最终源码验证。

过程目录29cec54也保留，不代表最终代码。相同身份去重合并支持/反面引用及缺失信息，具体身份不同的同类原因不合并。
