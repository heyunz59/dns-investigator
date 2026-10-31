# 九个实际案例集中修复

本页描述 5223c06 当时实现，其中报告层缺陷已由[后续验收修复](report-acceptance-fixes.md)更正；不能将本页历史测试状态当成最终语义验收。

起点 4ebb005，原有 108 项测试通过。工作区原有未跟踪 docs/manual-reviews/，包含九案例汇总及分项复核；原文件和 results/runs 中的旧日志保持不变，没有将未脱敏原始日志纳入提交。

## 输出与事实来源

新增 reporting.py，日志 schema_version=4。measured_facts 是程序从有效 E 测量生成的逐行事实，含目标、解析器、类型、时间、来源、应答及记录/TTL。公开结果的 observations/conclusion 由这些事实生成，模型不能把部分查询组合扩成笛卡尔积；未列出的解析器×类型组合明确未测。模型提交的结构化事实若超出对应 E 字段，会被拒绝。原模型自由文字保存在 model_draft 和可见模型消息中，标为未验证草稿，不作为正式结论展示。这是主动收窄自由事实合成能力，不是靠一句关键词替换或补查来掩盖错误。

execution_issues 单独引用 A 编号，必须与真实调用的工具、目标、类型、错误码相匹配。FIXTURE_NOT_COVERED 不能借用 A 查询 E1 证明 AAAA 缺失，也不会产生伪测量 E。最终字段由调用记录生成；执行问题与 DNS/HTTP 有效测量中的失败应答是两种来源。工具返回 fact_summary 帮助模型看到当前已测范围。

最终日志 result_origin=model_with_evidence_bound_report，区分模型候选选择与程序生成的正式事实；原模型草稿保留 model_draft。复测过程快照仍保留当时字段，不回填伪造新版本结果。

假设增加单一 category。支持关系按测量种类限制：成功的 DNS/TCP/HTTP 不能支持客户端问题、端点设计意图、注册问题或证书过期；只有明确证书错误类别能关联证书候选解释。通用成功样本不作为宽泛原因的反证。候选假设保持待验证/无法确定，使用程序约束的单一问题表述，不允许先在假设确认、再在结论称未知。未分类解释不进入正式报告；不足两个有效类别时允许 limited，不编造注册故障凑数。

这套策略刻意牺牲部分自由归因和建议多样性：目前不能自动确认唯一根因，也不能证明模型类别选择、原始数据或全部语义正确。支持证据仅指观测到相关症状，不等于确认候选原因。独立人工复核仍需进行。

## 场景与建议

- .invalid 根据 [RFC 2606](https://www.rfc-editor.org/rfc/rfc2606.html#section-2) 的公网保留测试用途处理，移除注册/续费/恢复区文件建议；明确 hosts 与私有 DNS 覆盖仍可能不同。只匹配 .invalid 后缀，不适用于普通域名。
- fixture/synthetic 来源进入每条观察和结论；建议先重新 live 解析，再用真实地址检查，不能把 192.0.2.10 直接当公网目标。fixture 不回退 live。
- 正式建议由程序收敛为不修改配置的对照，curl.exe -v -L 跟随跳转并保留证书校验。指定后端仅作为外部 curl.exe --resolve 专项检查，保留原 HTTPS URL/Host/SNI；现有 HTTP 工具未增加绑定后端能力。不建议先禁用 IPv6 或关闭证书验证。
- 单项查询清除故障假设，隐藏 DNS_INCONCLUSIVE，CLI 简洁显示事实和执行问题；仅报告本次应答 TTL，不推断它必然不同于权威原始 TTL。

## 实际网络问题

network_errors.py 遍历异常 cause、context 与 args 中包装的异常，防循环并限制深度。只保存异常类型、整数 errno/winerror/verify_code 及固定说明，不保存可能含密钥、网址或个人数据的异常字符串。分类为明确证书验证失败、一般 TLS、连接失败、超时、未知。不是按 expired/badssl 域名猜测。HTTP 兼容旧 error 字段，同时新增 error_detail；证书验证保持开启。

IPv6 在本机 Windows ProactorEventLoop 受控复现：旧二元地址 sock_connect 立即 OSError errno=22/winerror=10022；数值 getaddrinfo(AI_NUMERICHOST) 产生 IPv6 四元地址后，同一回环服务 CONNECTED。该转换不访问 DNS，不计 DNS 请求。OSError 详情现在进入 TCP 日志。受控测试未跳过；额外公网对照中 IPv6 TCP CONNECTED，HTTPS 200，经另一个 IPv6 地址，仍按独立连接解释，不外推所有 IPv6 路径都正常。

## 调用、交互与兼容

工具参数 schema 明示 DNS/TCP 0<timeout<=5、HTTP 0<timeout<=15。框架拒绝仍进入外层尝试分母，不作为已执行重试。直接后端越界也返回明确上限说明。

同轮模型同时提出系统 query_dns 与相同域名/类型 compare_resolvers 时，前者返回 REDUNDANT_QUERY，保留尝试记录且不重复发包；模型仍自主决定工具。此去重只覆盖同轮 pending/running 比较，不能保证消除所有跨轮重复采样，DNS 双层预算与原重复上限继续生效。

CLI 记录 target_source=question_extraction / explicit_target / interactive_supplement，补充目标只记录最少事件。输入提示和非法端口拦截保留。无目标等待时间不冒充模型耗时。

旧 schema 1–3 可原样读取/导出，不追溯猜测执行问题来源，不重写旧评分。accounting 对旧记录标 legacy_unavailable，新记录标 typed_sources；历史字段继续保留，评测新增来源口径。导出保留公共 1.1.1.1/8.8.8.8，以不同稳定别名脱敏其他解析器，避免把不同解析路径合并成一个匿名身份。

## 本轮验证

原始复现日志：案例3 30cc79620887452f985e33a388dc1cb6；案例4 b6bb68eb0b6b4fa58425ebfcac5a2105；案例7 a95d5a099ef04cfcbc190efa5f6954c1；案例9 2e047310a4ac4eee9c21621242e1353c。按实际日志核对，公共解析器只有 A 的事实不能变成四类型全覆盖。

新增测试覆盖非笛卡尔查询矩阵、错误来源篡改、客户端/设计意图/证书候选的不当支持、上下文与参数包装的 TLS 异常、安全错误信息、真实 IPv6 回环、OSError 代码、重复调用拒绝、超时上限、补充目标来源、单项展示。旧并发证据、CNAME 转介、预算、不可重试测试继续执行。

真实模型复测目录：results/published/manual-fixes-ea2cbd11156f4c729d6f991a1f802d5e/，源快照与配置在 metadata.json。四次 live+真实模型：案例3 limited，案例4 completed，案例7 completed，单项查询 completed；一次 fixture+真实模型：案例9 limited。所有原始结果另存，未重跑全量付费实验。

- 案例4 本次取得 ConnectError→ConnectError→SSLCertVerificationError，verify_code=10；独立 TCP CONNECTED。新证据比旧 ConnectError 更具体，但不能把它回填旧日志。
- 案例9 只有一个模拟 A 的 E1；AAAA 缺失引用 A2/AAAA/FIXTURE_NOT_COVERED，真实状态未知。
- 同环境额外检查中 IPv6 TCP 2606:4700:10::6814:179a CONNECTED，HTTPS 200 对端是另一个 IPv6 地址。不是同一连接，不宣称网络整体无故障。
- 单项查询仅一次工具调用，正式报告不生成故障假设与 DNS_INCONCLUSIVE。

这些状态不是准确率，semantic_review 均为 PENDING_HUMAN_REVIEW。复测源码哈希见 metadata；其后的保守反面证据清理、辅助函数提取、来源标记与单项措辞简化仅用最终离线测试验证，未再次消耗 API 重跑。完整测试最终为 120 passed in 9.13s，公开文件检查通过。
