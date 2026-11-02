# TCP 安全与 NSEC3 候选兼容性复核

基线 `2bacd75eb0639feca682af623b9000d59d611889`；独立分支 `fix/tcp-nsec3-followup`。TCP 业务提交 `20bd1ac`，候选分类提交 `844fa49`，最终业务提交 **`0faab0104817919dd8bdd3632e73136ca809c38b`**。最后一个业务提交之后仅增加测试、评测脚本与交付文档，没有变更运行源码。未合并 main。最终发布提交及实际 CI 另见 `ci-status.json` 和交付回复，避免把源码提交与材料提交混为一谈。

## TCP：修复缺口与验证

旧实现把 DNS Evidence 中出现的地址视为可连接目标，缺少独立的 IP 网络访问许可；DNS 返回私有地址不应自动授权内网探测。现在每次正式连接同时检查：目标/别名范围及当前有效 DNS A/AAAA Evidence、端口、数值 IP 网络策略。Additional/NS 地址、陈旧证据、外来注入记录和 fixture 不能授权 live 连接。IPv4-mapped IPv6 规范化后再分类和连接，拒绝 scoped IP。

`TCP_ALLOWED_NETWORKS` 默认空，仅显式用户配置可允许限定私网；与 HTTP CIDR、DNS 解析器许可独立。元数据、链路本地、组播、未指定、6to4/Teredo/NAT64 等高风险地址不能通过宽 CIDR 绕过。`_validate()` 和 socket 前均检查，保留 Windows IPv6 数值地址转换。拒绝产生 A，不产生伪造 E/Q，重复不可重试请求仍受已有 guard 限制。Agent 与无 API Key 的 tools-only 路径都加载该策略。

`tcp-security-details.json` 是实际调用原版/修复版 ToolBackend 的捕获结果。`tcp-security-matrix-initial.csv` 保留初始捕获；`tcp-security-matrix.csv` 补充真实 IP 分类，未改测量计数。52 行含修复前/后各 26 例。旧版私网等可进入连接路径；修复后预期拒绝的案例 socket 与 connect 均为 0。测试注入解析证据、拦截连接，**没有实际连接内网/元数据地址**。允许公共/显式私网、连接拒绝/超时分别记录，不能将策略拒绝算作网络故障。

单元测试另覆盖陈旧/跨目标/错误类型/不存在 Evidence、不同 IPv6 写法、独立 CIDR、直接调用、fixture、Agent 报告、tools-only 配置；已有真实本机 IPv4/IPv6 loopback 测试通过，只在测试中显式授权地址与动态端口。没有放宽生产默认行为。

## NSEC3：过滤不等于通过

根因是候选 Hash/Flags/形状和资源限制混在一起，未知候选可令已经充分的合法证明直接 INDETERMINATE。现在先区分 eligible、ignored、policy_limited；签名验证仍必需，CE/NC/wildcard 与覆盖判断没有降低。候选决定写入 V，支持追溯。

[RFC 5155 §8.1–8.2](https://www.rfc-editor.org/rfc/rfc5155.html#section-8.1)要求忽略未知 Hash Algorithm、非 0/1 Flags；剩余可用证明仍须满足 §8.3–8.4。X13/X15/X17（完整证明）从 INDETERMINATE 变为 SECURE，X14/X16/X18（证明不足）变为 BOGUS，与独立 Unbound 一致。T11 同样恢复 SECURE。仅有未知候选 X25 不得自动 SECURE。

Next Hash 长度错误不再令完整合法证明 BOGUS：X19 SECURE；X20/X21 剩余证明不足仍 BOGUS。有效但不覆盖的 X22、坏签名 X23 仍 BOGUS。原 T01/T05/T06 保持 **BOGUS/SECURE/BOGUS**；T01/T06 与 Unbound 的历史差异没有删除。

T10 的额外记录同时有畸形 owner 和 iterations=1；先排除不可用 owner 后，合法 iterations=0 证明完整，项目 SECURE，而 Unbound BOGUS。RFC5155 §8.2 允许（MAY）因参数不一致拒绝整份响应，故不能仅为状态一致把该 SECURE 改成 BOGUS。有效 owner 的非零迭代 X24 仍 INDETERMINATE，未执行额外高成本哈希。[RFC 9276 §3.1](https://www.rfc-editor.org/rfc/rfc9276.html#section-3.1)也保留验证器对高迭代的资源策略空间。此处是明确的工具支持范围，不宣称实现完整解析器行为。

X26 跨区布局在中间版 `844fa49` 出现 SECURE/Unbound BOGUS；原始 `nsec3-after` 留存。最终版将已认证的跨区布局明确标为 policy_limited，返回 INDETERMINATE，避免把此布局当完整支持。X27 多 RData 与 X28 Opt-Out 也保持能力受限。混合异常布局的普遍正确性尚未证明，不能从这批实验推出所有未知记录组合都兼容。

## 实际测试与材料解释

- 修改前完整测试：362 passed / 25.66s（本轮实际运行，未复用历史数字）。
- TCP 阶段完整测试：390 passed / 25.83s；最终：**410 passed / 25.36s，0 failed，0 skipped**，Windows Python 3.12.14。
- `python -m pip check` 通过；wheel 构建通过，全部打包模块及资产与最终源码逐字节一致，见 `source-verification.json`。
- 完整 pytest 覆盖 HTTP pinning、Host/SNI/TLS、重定向/rebinding、普通 DNS、CNAME/转介、并发 Evidence、fixture、不重试错误、trace、DNSSEC、五工具、报告与 A/Q/E/V；没有改删原 HTTP 测试断言。
- Unbound 1.26.2 为独立二进制/libunbound 实际执行，受控本机 DNS UDP：before、intermediate、final 各 28 场景。新上下文无缓存，保留 wire、配置、E/Q/V、签名与验证时间。不是公网调查或模型测试。
- 本轮 DeepSeek 调用 0；无模型诊断准确率结论。工具注册/调用动态能力由原 Agent 回归覆盖。

远程 Ubuntu / Python3.12 已实际执行 [GitHub Actions 41389247851](https://github.com/heyunz59/dns-investigator/actions/runs/41389247851)，对应交付快照 `e85fe84304c63b89ff5bd50e5bb4b14f5d271cbb`：**410 passed in21.46s**，公开扫描 PASS，完整 workflow success。`ci-status.json` 保留实际 job/step 状态及日志摘要；`conclusion.json.final_commit` 指此固定验收快照，后续提交仅追加 CI 回执与汇总脚本的元数据保留逻辑，不改业务源码。`wire-integrity.json` 对三阶段原始报文的 3572 个 query/response 哈希核验通过。

`nsec3-followup-matrix.csv` 对照 before/final。`candidate_decisions` 来自最终 V；`proof_sufficient` 是本次规则/协议分析，仍待人工独立复核，不是 Unbound 相等率评分。

旧审计观察器有两处元数据局限，未改写原始文件：before 每案例 environment 记录当前 checkout，而实际 import 为隔离归档 `20bd1ac`；由 `loaded-source-check.json` 的实际 import SHA 证明。final 的实际源码 SHA 见 `final-loaded-source-check.json`。X27 before 的原 equivalence=false 源自 RRset 内 RDATA 顺序比较；汇总脚本从原 wire 比较规范化、排序后的 RRset，所有 before/final 目标响应语义一致。原 false 字段仍保留，汇总同时列出修正结果。各阶段重新生成签名密钥/时间，不能把跨阶段 wire 字节不同误称为输入相同；每阶段项目与 Unbound 输入等价已核实。

## 未解决边界与验收状态

TCP 授权不证明目的服务安全、可达或为用户现场路径；IP 分类会受 Python ipaddress 版本影响，显式许可只适合可信范围。当前 DNS 证据采用有限时效窗，并非完整缓存/链 TTL 验证器。

T01/T06 严格证明覆盖分歧仍待后续协议裁定；T10 为可选响应级参数策略差异；X24/X26/X27/X28 能力受限与 Unbound 不同。未实现完整 NSEC3 Opt-Out/多参数/复杂跨区证明。固定场景未观测到新增错误 SECURE，不代表对所有签名布局完成安全证明。协议人工独立审计状态 **PENDING**。CI 通过只说明其实际执行的检查通过。
