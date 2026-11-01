# 验证记录

## 安全、权威阶段、时间边界与 Agent 总结修复（2026-11-01）

基线512141e，修改前完整196项通过。工作分支 fix/security-dns-agent-20261101，原始 docs/manual-reviews/ 未跟踪内容及旧实验未改写。最终业务源码4de824c：完整 **249 passed in 9.74s**，无跳过；报告验收脚本 **9条通过**（results/runs/report-acceptance-49ea513fa33b49179ec1f3cbf3130214/）。保留旧并发、CNAME、A/Q/E、TLS、IPv6及重试测试。安全子集23项含真正本机TLS握手、证书主机名失败、Host/SNI；受控DNS验证阶段进度、预算和取消。受控报文不冒充公网根因验证。

新旧业务源码逐模块哈希与Git blob或Windows CRLF表示核对通过。独立14场景受控DNS、5组时间回放、HTTP mock跳转对照保存到 results/published/security-stability/{baseline,current}-offline.json；旧版NS超时标RECURSIVE_ASSISTED，新版为NS_DISCOVERY_TIMEOUT且无权威直查；两条缺时间的NXDOMAIN/NOERROR不再产生同期冲突Finding。原始响应不删除。公开检查为规则扫描，不替代人工隐私审查。

真实DeepSeek + 受控回环DNS，新旧各7次（权威记录/SOA差异3、NS超时3、正常A查询1），同 deepseek-flash、thinking disabled、temperature0、8A/24Q预算。校验输出旧6/7、新7/7；serial两版均3/3；旧NS超时2/3、新3/3；旧失败保留了7E程序报告。新版也有一次输出重交，原验证规则仍生效。新A总数40高于旧31，Q/E各51低于旧60，不宣称工具选择效率全面提升。诊断语义、定位正确性和错误根因断言均待独立人工复核，不从completed或Finding命中推导准确率。

完整14份脱敏模型JSON、逐次明细、源码和配置在 results/published/security-stability/real-model-comparison/；原始JSON/JSONL另存被忽略目录，不覆盖。最终源码后仅添加评测/文档/审计材料，没有把中间源码运行称为最终业务版本验证。未新增公网目标调查，本轮未推送，远程Actions未验证。[完整对照与边界](security-stability-fixes.md)。

## fcd1d52 验收补修（2026-11-01）

修改前180项通过；新增反例先复现4失败/9通过。修复别名成功跟进后 Finding/摘要未收敛，以及权威 discovery 的预算/执行错误漏记后，完整 **196 passed in 8.76s**。相同复现中 E1/E2 均保留；权威预算拒绝 A/Q/E 仍为1/1/1，并明确 A1 的 NS 发现失败。本轮未执行付费模型或公网测量。before/after及源码哈希另存 results/published/fcd-acceptance/，原始人工材料与旧日志不改写。[修复和验证说明](fcd-acceptance-fixes.md)。

## DNS 判断与范围定位专项升级（2026-11-01）

起点 f0787c0，工作区仅 docs/manual-reviews/ 未跟踪。修改前 **136 passed in 8.90s**。新增比较范围、超时非内容冲突、有效子集、Finding 聚合、单候选完成、总结失败保留报告、CNAME 授权/来源/预算、受控 DNS 真报文、复合失败保存/去重与实际类型引用测试；原并发、CNAME负回答、A/Q/E、TLS、HTTP、IPv6回归保留。最终 `.venv\Scripts\python.exe -m pytest -q`：**180 passed in 8.54s**，未跳过 IPv6；旧报告验收脚本继续 **9条验证通过**，另存 results/runs/report-acceptance-017a6b7b14654057bb4c1ecbbe5b6926/。scripts/check_public.py PASS；新增文件收尾按相同规则补查，规则扫描不能保证排除全部隐私问题。

提交前再用同规则批量扫描全部 Git 引用及当前文件：**PASS，24个历史提交、382个唯一 blob、267个当前文件**，见新实验目录的 public-audit-latest.json（审计时快照，不冒充独立人工隐私审核）。原测试仅因明确需求更新 Finding 代码、TIMEOUT 原始 RCODE=null 及取消假设数门槛的断言；未删除并发/预算等回归或把失败简单改为接受。

13个固定场景+1份历史 replay：含超时的内容冲突 Finding 9→0，历史17条 E 全保留；13/13只表示预设机械检查满足，不是整体语义准确率。3类受控回环 DNS 实验通过。真实 DeepSeek 共15次，分源码阶段保留，权威差异及部分失败模型总结曾失败。最终业务源码4632d74额外付费验证部分失败 fixture：completed，2 A / 0 Q / 2 E，12.968秒；旧四例未在最终源码全部付费重跑。没有新增公网目标测量或远程 Actions 验证。详细计数、源码、失败、耗时、未验证能力见 [专项交付记录](dns-accuracy-upgrade.md) 和 results/published/dns-accuracy-f0787c0/summary.json。

## 5223c06 报告层验收修复

原120项通过；修复后 **136 passed in 7.88s**。新增 .invalid 反例（零测量/超时/模拟/私有覆盖）、HTTP 200 后正文超时、跳转成功/失败、证书错误摘要、TCP 端口、同类不同原因、范围明确的反证、最终去重和非法引用测试。最终源码再执行脚本模型、本机 HTTP 服务及历史回放，共9条独立记录；没有付费模型调用或公网复测，源码哈希见 results/published/report-acceptance-0fb8ba950e694abb8bb05f201958222b/metadata.json。用户验收意见和配套原复现保持未改动。[逐项修复说明](report-acceptance-fixes.md)。

## 九案例集中修复（2026-10-31）

基于 4ebb005，修改前 **108 passed in 7.65s**。新增事实矩阵、typed A 执行问题、候选关系、TLS 异常包装、IPv6 回环与错误码、重复与超时拒绝、目标来源与单项展示测试；完整运行 **120 passed in 7.64s**，原并发/CNAME/预算回归保留。

五次真实 DeepSeek 复测及额外工具对照另存于 results/published/manual-fixes-ea2cbd11156f4c729d6f991a1f802d5e/：live 的 .invalid limited、badssl completed、example IPv6 调查 completed、单项查询 completed；fixture 缺失案例 limited。badssl 本次捕获明确证书验证异常和 verify_code=10。受控 Windows IPv6 旧地址形式 errno22/winerror10022，新形式 CONNECTED；公网独立 IPv6 TCP 也 CONNECTED。source/config/hash、实际回答、失败/拒绝均保留，状态不当作人工准确率。

docs/manual-reviews/ 原始用户材料及旧 runs 保持原样，原始材料未自动提交。输出事实由程序逐测量生成、模型草稿另存未验证区域，候选原因均保持未确认；独立人工语义确认、完整因果定位和所有跨轮去重尚不能保证。[逐项修复与边界](manual-review-fixes.md)。

## v0.3 并发与 CNAME 修复（2026-10-31）

基于 40d75ab，原有 87 项通过；新增回归先在旧代码复现 12 failed / 3 passed，再实施修复。最终 **108 passed in 8.03s**，命令 `.venv\Scripts\python.exe -m pytest -q`。并发测试采用 Event 控制完成顺序，核对调用/证据/内容及 JSON、JSONL，未禁用并发。报文测试联合检查解析与 Finding，覆盖 CNAME 转介、末端 NODATA/NXDOMAIN、未知别名、正常回答和截断。

真实 DeepSeek + 受控 fixture 两次：一例 limited（独立 DNS E1、HTTP 503 E2），一例 completed（CNAME+NS 被描述为转介）；无公网目标测量，不作为独立人工语义正确率。新目录 results/published/v3-targeted-7599982d892d46e19fe4999f157cd3b0/ 保留事实与回答，旧实验未更改。详情及协议出处见 [针对性修复记录](v0.3-targeted-fixes.md)。

## v0.3 DNS 深度诊断（2026-10-31）

起点 43f831a，原有 54 项离线测试通过。扩展五记录类型、完整 DNS 报文、多递归比较、权威发现与 RD/AA、确定性 Finding 和双层预算后，完整执行：**87 passed in 7.37s**。命令 `.venv\Scripts\python.exe -m pytest -q`。其中真实本机 DNS 集成测试覆盖 UDP 请求、TC 截断后 TCP 回退及 RD=0，另有并发预算和取消检查。脚本模型路径测试仅验证框架，不当作真实 DeepSeek 验收。

真实独立网络工具：2 次外层调用、16 次 DNS 请求、16 条测量，2 条 AA 权威回答；8 NOERROR 和 8 TIMEOUT 均保留。真实模型 live completed，3 次外层调用、16 次 DNS 请求。脱敏副本在 results/published/dns-v3/。

真实模型 D1–D10 首轮各 1 次：5 completed / 4 limited / 1 failed。D10 只调用 query_dns 一次。D2 因模型引用不存在的 E6 而失败，未标成功；补上复合 fixture 每个响应的 evidence_id 映射后，独立复测 completed（2f0b23498c6c4fa8bceb9a3ab4702766），旧失败保留。此为初步验证，不是人工语义准确率。新数据、规则指标与边界见 [v0.3 交付说明](dns-v3.md)。

未完成：独立人工语义评分、严格公平的规则系统/Agent 对照、多网络位置、完整迭代追踪和 DNSSEC（后两项不在本轮范围）。本轮未推送远程。

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
