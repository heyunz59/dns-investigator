# DNS Investigator v0.3 交付记录

起点：main / 43f831a，工作区干净。未创建新仓库，未推送远程，旧实验与失败案例未覆盖。模型继续 deepseek-flash、非思考模式。

## 新能力与适用场景

| 场景 | v0.3 新能力 | 验证 |
|---|---|---|
| 默认 NXDOMAIN，公共正常 | 多递归结果对照及 RESOLVER_DISAGREEMENT，建议权威证据 | D2 fixture、真实模型（含失败原文） |
| 默认超时，公共正常 | DNS_TIMEOUT 与路径差异，不确认服务器宕机 | D3 |
| 递归与权威记录状态不同 | AA 权威证据与 RECURSIVE_AUTH_MISMATCH | D4、权威发现测试 |
| 两台权威 SOA Serial 不同 | AUTH_SERVER_DISAGREEMENT，保留传播/配置未知 | D5、受控权威报文测试 |
| NOERROR 没有所需记录 | NODATA_OBSERVED，不混同 NXDOMAIN，也不直接称子域 NS/SOA 配置错误 | D6、负回答 SOA 测试 |
| 公共 DNS 不可达 | 单项超时保留其他解析器响应 | D7、live 原始记录 |
| CDN 地址不同 | 只记录地址集合差异，不生成污染根因 | D8、规则单元测试 |
| 权威服务器无法联系 | 保留 TIMEOUT 与发现局限，不能推断域名不存在 | D9 |
| 只查 A | 单工具路径，保留 v0.2 的选择性 | D10、原有查询测试 |

## 规则与证据

规则代码：NXDOMAIN_OBSERVED、NODATA_OBSERVED、DNS_TIMEOUT、DNS_SERVFAIL、DNS_REFUSED、RESOLVER_DISAGREEMENT、RECURSIVE_AUTH_MISMATCH、AUTH_SERVER_DISAGREEMENT、DNS_INCONCLUSIVE。每条有阶段、状态、E 引用、解释、局限与下一步。CDN 地址差异不生成递归状态故障；SOA Serial 不同不证明配置错误。只对相同 qname/qtype 比较，权威差异需 AA，不把转介当最终权威回答。

A（工具尝试）、Q（实际 DNS 报文请求）、E（测量）分开计数。默认最多 32 次实际 DNS 请求，UDP TC 后 TCP 重试另占一次。默认工具总预算 20 秒，单次最多 5 秒，权威默认 2 台。同目标、类型、服务器、角色、传输最多重复 2 次。Q 请求在 await 前原子预留，防止并发绕过预算。fixture 不访问 live，不包含正确根因或评分规则。

query_dns 的旧字段 records/record_type/rcode/cname_chain 保留；新字段含 qname/qtype/resolver/resolver_role、flags、answer/authority/additional、transport、result_kind、duration_ms、execution_status/error。CNAME 链只描述实际响应中的链，不凭空补齐；循环标记与 canonical_name 供进一步调查。

## 测试与实际执行

开始前：原有 54 项测试通过。原解析器 mock 测试迁移到实际使用的 DNS 报文层，保留原 RCODE/NODATA/超时断言，没有删除其验收意义。

新增测试包括五记录类型、负回答 SOA、CNAME 循环、转介、CDN/TTL、AA 限制、最近子区发现、多权威 Serial、并发硬预算、取消、私有目标限制、五工具实际注册与选择性调用。两个本机集成测试实际发送 UDP/TCP DNS 报文，包含真实 TC→TCP 回退和 RD=0；不等同公网权威服务验收。

命令：`.venv\Scripts\python.exe -m pytest -q`。本轮结果见 validation.md。

独立公网工具检查：2 次外层工具调用，16 次实际 DNS 请求、16 条有效测量，12 条递归测量和 4 条权威直查；其中 2 条 AA 回答、8 条 NOERROR 和 8 条 TIMEOUT。超时与成功均保留。脱敏记录在 results/published/dns-v3/live-tools.json。

真实 DeepSeek live：completed，3 次外层调用、16 次 DNS 请求；原始结果脱敏保存于 results/published/dns-v3/live-agent.json。这是实际模型和真实 DNS，不是 fixture 验收。

真实 DeepSeek D1–D10 首轮：每案例 1 次，共 10 次；5 completed、4 limited、1 failed，原文全部保留在 results/published/dns-v3/model-fixture-pilot/。D10 一次 query_dns，无其他工具。D2 模型反复引用不存在的 E6，被校验拒绝；发现复合 fixture 返回的响应缺少直接 E 映射后补齐。原失败不删除；后续复测单独保存。

D2 补充复测实际 completed，原文在 results/published/dns-v3/d2-retest.json；它是第 11 次额外模型运行，不回填首轮统计，不证明所有未来引用都会正确。完整修改文件清单见 v0.3-files.txt。

该复测仍包含一次无 fixture 覆盖的 check_http 尝试，已记录在分母，说明模型可能选择价值有限的辅助检查；completed 不等于工具选择最优。公开文件模式检查通过，未推送远程。

evaluation/dns_v3.py 保存执行状态、DNS 类别、Finding、关键测量数、耗时、外层调用与底层实际请求数。规则基线是在相同已观测证据上运行确定性引擎，不声称能证明 LLM 带来因果提升。工具合理性、错误根因断言数量和完整语义类别正确性均明确 PENDING_HUMAN_REVIEW；不能把执行完成率或规则输出当作诊断准确率。

## 边界与未完成项

- 递归辅助发现依赖当前解析路径；不是完整委派迭代追踪。最多向上检查 8 层 SOA，未发现时返回未知；不使用“最后两级域名”猜 zone。
- 权威每台仅使用一个可用公共地址，地址先尝试 A，必要时 AAAA；未穷举所有地址/视角。不支持模型传入任意权威地址或端口，系统合法私有递归 DNS 仍允许。
- 实际响应标志、记录及 Finding 可追溯；结构与规则不能保证全部自然语言因果判断正确，不宣称已排除所有污染、注册异常或客户端因素。没有完整 DNSSEC 验证、监控或自动修改配置。
- D1–D10 模型运行是一次初步验证，未做多轮独立人工语义评分。规则与模型的严格公平对照、更多公网位置与长期一致性尚未完成。
- 运行原始日志只在被忽略目录中保留；公开候选副本已脱敏。本轮不推送 GitHub。
