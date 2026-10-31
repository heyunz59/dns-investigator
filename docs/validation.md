# 验证记录

## v0.2 可靠性修复（2026-10-31）

从 main/29d66f9 开始，工作区干净且与 origin/main 一致。先执行原有测试：36 passed in 5.66s。新增无证据确定性诊断拒绝、有限结果、基线事实保留、两个假设、框架参数拒绝计数、缺失数据不回退/不重试、软预算总结、硬预算批处理、内部失败、事件去重、必要测量、历史统计不补猜和规则筛查测试；最后完整离线执行为 **54 passed in 6.92s**。

真实 DeepSeek live 运行 `879e9cd494b24f5ba3f212821085baeb` 已 completed：5 次网络调用尝试，5 条有效测量，A/AAAA、两个 IPv4 TCP 和 HTTPS；保留不同 IP 结果的判断边界。公开副本 `results/published/live-agent-reliability-v2.json` 已移除本机解析器信息。它是实际模型验证，与脚本模型测试区分。

最后补充的事件去重和 CLI 状态区分后，又执行一次真实 live：`3adb76a6ea7f415f9eae3eaf7a94aa4e`，5 次尝试、5 条测量，模型明确返回 insufficient_information，日志为 limited / ended，不将“未复现、无法确认根因”误标为诊断完成。原始 JSONL 恰有 5 个 attempt_started、5 个 attempt_finished、5 个 evidence 事件。脱敏副本 `results/published/live-agent-reliability-v2-final.json` 保留。

正式新实验 `20261031T035848Z-c29b66`：8 场景 × 3 次 × 2 组 = 48 次实际运行，全部完成记录，未因调用失败或额度问题缩减重复。A=10 completed/14 limited/0 failed；B=9 completed/13 limited/2 failed。C3 三次 B 均取得模型结果，无 UsageLimitExceeded；Q1 三次 B 均只有 A 查询。MISSING 三次 B 都明确返回 FIXTURE_NOT_COVERED，没有重复执行缺失请求，但一次总结误引用 A2 后被校验拒绝。C2 另一次总结误引用 A4 也失败；保留证据和程序生成的有限失败结果，不伪造模型总结。

自动规则筛查 A=24/24、B=22/24；B 全部网络尝试 83 次，规则建议合理 78 次。评分、逐调用明细、每条检查、原始回答、源码哈希和 fixture 快照见 [独立实验目录](../results/published/evaluation-reliability-20261031T035848Z/README.md)。这是结构/执行/关键词筛查，**待独立人工复核，不能当作完整语义任务成功率**。旧实验及失败材料保持原样；旧工具正确率分母不完整，不与新结果直接横比。

结构校验仍不能证明假设语义合理、引用确实支持结论或建议一定适当。自动筛查也不能捕捉全部过强因果表述。未完成事项：独立人工逐例评分、多网络位置/长期重复采样；不以离线 mock 或 fixture 通过冒充 live 验收。

以下为 v0.1 历史验证记录，保留原始结论与局限；其中旧工具正确率不是完整调用统计。

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
