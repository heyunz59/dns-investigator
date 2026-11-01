# fcd1d52 验收补修与 GitHub 交付（2026-11-01）

基线 fcd1d52；起始完整离线测试 180 passed in 8.84s。用户提供的验收 JSON 保持在未跟踪的 docs/manual-reviews/，没有改写或提交人工材料。先独立复现，新增测试在旧实现上 4 failed / 9 passed，之后修复。

## 别名后续回答与原始响应分开

原 E1 返回 ALIAS_INCOMPLETE，后续 E2 已取得 target.other A，原报告仍称末端未知。现在通过 target_authorization 的明确链路及有效 E 验证关联：同来源、同解析器/角色、同类型、最多300秒且后续不早于祖先、深度最多8。原始 E1/报文不改写，新增 ALIAS_FOLLOWUP_COMPLETED Finding 引用 E1、E2（多跳保留全部中间 E）。摘要明确后续目标和实际结果，不再无意义建议重复跟进。

后续 NXDOMAIN/NODATA 只针对其实际末端名称，不断言原始名称不存在。不同来源、类型、解析器、角色，缺时间、过期、无链路证明或后续超时均不能自动收敛；摘要限定原始路径，不否定另一路径已有的事实。同范围另一次尚未完成的样本仍保留。不是 DNSSEC 或完整迭代解析，也没有把子目标权威证据改成原目标直接权威回答。

## 权威发现失败不再被成功子测量掩盖

旧复现只执行成功 SOA（Q1/E1），NS 发现被 Q 预算拒绝，但 A1 无错误、正式报告只显示正常 SOA。复合工具现在同时收集 discovery 与 responses 的失败，保留 query_stage，明确 NS_DISCOVERY_FAILED，A1 报告 PARTIAL_DNS_EXECUTION_ERROR。

正式 execution_issues、comparison、摘要、建议及 attempt_finished 事件均保留这一失败。预算拒绝仍是 A 关联的未执行子检查，不增加 Q/E；已执行传输失败与 Q 记录合并，避免重复展示。成功 SOA 仍保存，但不再被描述为该调用已完成目标权威查询；建议仅在新的有预算调查中按需重开，不突破本轮预算。

## 实际验证

- 完整 `.venv\Scripts\python.exe -m pytest -q`：**196 passed in 8.76s**，原并发、A/Q/E、CNAME 分类、IPv6、TLS/HTTP 回归保留。
- 新增16项回归：正/负末端回答、多跳、部分样本收敛、来源/类型/路径/时间及证明约束、发现预算拒绝与实际 Q 执行错误去重；其中预算复现使用本机真实受控 DNS 报文，传输错误测试另有明确注入。
- `python -m evaluation.fcd_acceptance 新文件.json` 可独立复测，拒绝覆盖已有文件；before/after 位于 results/published/fcd-acceptance/。after 对应业务源码 2bc9a58 和各文件 SHA256，后续交付提交只增加文档/复现结果。
- 别名案例：保留2条 E，报告从“无末端事实”改为“同路径后续 target.other A=NOERROR，E1/E2”。
- 权威预算案例：A/Q/E 均保持 **1/1/1**，新增 A1 的 NS 发现错误；没有伪造第二条 Q/E。

本轮没有调用付费模型或测量公网目标。受控/离线验证不冒充真实模型验收或完整语义准确率，历史模型记录保持原样。推送前执行公开文件规则扫描；规则扫描不是独立人工隐私审核。用户已授权将原本地升级和本次验收补修推送至 heyunz59/dns-investigator，使用正常快进推送，不强制覆盖远程历史。远程 CI 需看本次提交对应的实际运行。
