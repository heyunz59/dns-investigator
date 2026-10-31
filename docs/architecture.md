# 实现与证据边界

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
