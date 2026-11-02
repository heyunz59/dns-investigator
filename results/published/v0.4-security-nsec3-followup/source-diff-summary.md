# 源码影响与回归依据

比较范围：`2bacd75e..0faab010`。实际逐行差异请结合 GitHub commit diff；没有重写 ToolBackend/HTTP Transport，也未新增 Agent/Tool。

| 文件/函数 | 改动目的 | 影响及验证 |
|---|---|---|
| network_policy.numeric/public/networks/tcp_address | 共享数值地址分类，独立 TCP 许可 | IPv4-mapped 规范化、特殊段硬拒绝；TCP matrix 与测试 |
| http_safety.HTTPPolicy.address | 复用同一 numeric/public 分类 | 保留独立 origins/CIDR 和 Transport；HTTP 安全回归 |
| config.Config.__post_init__/load | 末尾兼容追加 tcp_allowed_networks | 默认空、严格 CIDR、invalid fail-fast；旧 positional 保留 |
| tools.ToolBackend.__init__/_validate/_tcp_evidence_usable/_tcp_address/check_tcp/call | 目标范围、当前测量、端口与网络许可同时检查 | 直调及 socket 前再次检查；A 失败无伪造 Q/E；保留连接异常与数值 IPv6 |
| agent.investigate | 加载受信任 TCP 配置 | 单 Agent/五工具注册、动态调用不改 |
| main.run_tools_only | 无 Key 也加载 Config 与安全策略 | CLI 受控配置测试；保留目标来源/端口校验 |
| dnssec_proof.nsec3_candidate/denial | 区分忽略候选/合法候选/能力受限 | 未知 hash/flags、owner/Next、iteration/salt/Opt-Out、多 RData/跨区边界 |
| dnssec_validation.Session.proof | V 记录候选分类来源 | 仅 crypto-verified 候选；不改变签名/锚/覆盖/预算 |

`source-verification.json` 确认 `check_http` 方法 AST 与基线相同；dns_wire、trace、dnssec collector、alias_scope、reporting、accounting、schemas 完全未变。HTTPPolicy 分类复用的行为由原 HTTP 安全测试确认。原来的主机绑定、SNI、证书验证、每跳授权、DNS pinning 没有放宽。

原有 TCP loopback 测试增加测试专用显式 CIDR/当前 DNS Evidence/动态端口，继续断言原来的连接成功、拒绝与 OSError。`evaluation/protocol_lab.py` 只给受控文档网段显式测试许可，不授权实际网络。`tests/test_tcp_policy.py` 增加 34 项安全路径测试；`tests/test_nsec3_followup.py` 增加 14 项候选/证明边界。没有删除旧失败记录或修改 Unbound 期望来抹平分歧。

新增 `evaluation/tcp_security_capture.py`、`tcp_nsec3_followup.py` 捕获修复前后；`finalize_tcp_nsec3_followup.py` 只汇总既有测量，不访问网络或调用模型。初始 TCP CSV 与原始 DNS 记录不被汇总改写。最终 410 项完整测试、wheel 字节核对、依赖检查及独立 Unbound 证据见本目录。
