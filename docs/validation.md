# 验证记录

日期：2026-10-31。模型默认 deepseek-flash，非思考模式，temperature=0。程序运行于 Python 3.12.14；依赖完整快照见 requirements-lock.txt。

## 已实现并验证

- 36 项离线测试通过：七种 fixture、无效输入、CLI 缺目标交互与非法 URL 拦截、DNS NXDOMAIN/无记录/SERVFAIL/REFUSED/超时、真实本机 TCP 连接与拒绝、真实本机 HTTP 重定向/503/正文上限/总超时、TLS 错误分类、证据编号、并发调用预算与模型失败日志。最后一次本地执行：36 passed in 5.96s。
- 真实 DeepSeek 已完成 live 调查闭环：运行 ID `5de515705979471e9d8f559ea3a4ea63`，9 次工具测量，包括 A/AAAA、两地址 TCP、HTTPS、重复检查和第二解析器；JSON 与 JSONL 实际落盘。
- 真实 DeepSeek 单项查询：运行 ID `0c8255c61bca456895dabd0c5a967e8d`，仅调用 DNS；额外 AAAA 查询未命中 fixture 并如实返回工具错误，模型未虚构记录。
- 真实独立工具检查：DNS 返回地址，一个 IPv4 TCP 超时，HTTPS 经另一个地址收到 200。结果不能合并成“同一后端 TCP 超时却 HTTP 成功”。公开副本移除了本机 DNS 配置。

## 实际发现与修复

初次真实模型运行返回了 Decimal 类型费用字段，导致最终 JSON 序列化失败；已有 JSONL 工具证据保留。修复费用字段序列化后重跑，完整日志成功保存。未将写入失败的运行计作成功验收。

试运行评测发现 DNS fixture 对未明确指定的 record_type/resolver 匹配过宽，可能把 A 数据返回给 AAAA 或另一解析器。已改为 A/默认解析器的明确缺省匹配并添加两项回归测试。试运行记录保留在本地，不能用于正式对比图。正式实验重新运行。

## 真实模型的局限与失败素材

Live 回答错误声称工具不支持 IPv6 TCP/HTTP 探测，实际上 TCP 支持 IPv6，HTTP 保留域名并按客户端解析；该回答是模型对工具能力的误述。它还对排除 DNS 失败表达过强，当前查询成功不能排除其他时刻、浏览器或客户端路径差异。证据编号有效不代表语义必然正确。

DNS 单项查询虽只使用 DNS 工具，但额外查询了 AAAA，超出了用户所问 A 记录的最小需要。fixture 没有该事实，返回工具侧错误；不能将此错误理解为没有 AAAA 记录。

## 仍需验证或补充

- 正式 A/B 已执行 7 个场景 × 1 次 × 2 组，共 14 次，使用修复后的 fixture 匹配；原始回答和逐项复核见 results/published/evaluation-20261031/。A 为 6/7，B 为 4/7；这只是 Codex 规则辅助复核的初步结果，待独立人工审核，不能当作稳定的效果提升证据。
- GitHub Actions 首次云端执行通过：[运行记录](https://github.com/heyunz59/dns-investigator/actions/runs/41164947160)。
- 多网络位置、实际 IPv6 连通性、真实无效 TLS 站点、长期重复采样尚未验证；TLS 错误分类已用可控测试验证。
- 截图为实际日志在浏览器中的只读视图，非原始终端截图，图中保留真实模型的不理想表述并标明开发者复核。
