# 实现与证据边界

## v0.3 当前架构（优先于以下历史描述）

用户输入 → 唯一 DeepSeek/PydanticAI Agent → 五个正式工具 → ToolBackend → DNSClient / 现有 TCP、HTTP → E 测量 → 确定性 Diagnosis Engine → Finding 返回给 Agent → 模型选择下一项工具或输出有限结果。

五个工具在 build_agent 内正式注册：query_dns、compare_resolvers、query_authoritative、check_tcp、check_http。没有固定执行全部工具的调查脚本；--tools-only 及 verify_dns_v3.py 是显式的工具验收入口，不作为自主 Agent 的证明。

- dns_wire.py：显式 UDP/TCP 通信，每次报文交换独立 Q 编号。响应 RCODE、AA/RD/RA/TC、三个分区、TTL、CNAME、SOA Serial 均序列化；NODATA 为 NOERROR 下的结果类别。直接处理 DNS 报文，避免高级解析器异常丢失 NXDOMAIN 的 Authority/SOA。
- dns_compare.py：纯数据比较，差异不等于故障。TTL 不会误当作 CNAME 目标变化。
- authority.py：最近 SOA 所属区发现、NS 与其地址解析、有限公共权威直查，RD=0、AA 审核。发现依赖递归路径，未做根区起点迭代和 DNSSEC 验证。
- dns_diagnosis.py：只处理有效 E 证据；排除截断和非 AA 的权威对比，输出受限 Finding。程序重新生成最终 findings，模型不能注入伪 Finding。

日志格式 schema_version=3：attempts 是外层 A 工具尝试；dns_attempts 是实际 UDP/TCP Q 请求，parent_tool_call_id 指向 A；evidence 是有效 E 测量，每次截断响应、TCP 回退、超时都可追踪。复合工具不再创建伪造的聚合 E 证据。fixture 子响应也是独立 E，但不计真实网络 Q 请求；旧版日志和 fixture 仍可读。

DNS 请求总数、复合工具总时间、单次 DNS 超时及权威台数分别受限。DNS 底层预算耗尽后隐藏 DNS 工具，保留模型总结机会。工具取消/超时会保留已取得的子证据并返回给模型。权威自动发现的地址只接受 global IP；显式递归服务器只允许公共或系统已配置地址，系统私有 DNS 可正常使用。配置文件中用户主动设置的 compare_resolvers 地址是受信配置，模型不能覆盖该列表。

结构与规则不能证明全部自然语言语义正确，模型仍可能过度解释或引用不存在的编号；这种输出须重试或安全失败，不能称为确定的根因。详见 [v0.3 实际验证](dns-v3.md)。

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
