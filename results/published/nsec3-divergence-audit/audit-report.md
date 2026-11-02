# NSEC3 分歧调查（修复前结论）

调查HEAD 9ac06c0ed01d30bf3e611a62a2806cb59af6a29d，业务与133b49a一致；独立分支audit/nsec3-divergence。用户manual-reviews、旧实验保持原样。初始356项完整测试通过。没有DeepSeek调用，没有公网DNS；Unbound来源仍为原官方1.26.2便携DLL。版本、源码和DLL哈希、锚、时钟、签名窗口见environment.json。

## 结论与确定性

原始BOGUS/SECURE分歧3/3复现；目标完整RRset/签名材料等价。原始合法记录不够证明NXDOMAIN，畸形记录不是无关附件，而是Unbound普通区间比较成功所需的候选。D（参考实现处理路径差异）是原始分歧机制；不能把原始项目BOGUS直接判false BOGUS。与此同时T05证明了独立的B（项目过度拒绝）：已有充分、认证的合法证明时，额外坏owner让项目整个失败。这项应作最小修复，但不使T01/T06变SECURE。

## 原始证明逐条计算

Q=probe.example.test. IN A；签名区域example.test.；closest-encloser=example.test.；next-closer=probe.example.test.；wildcard=*.example.test.。
Hash分别为：{"example.test.": "JBAS736CHUNG3BB701JKJDHQKQLHVUG7", "probe.example.test.": "9VBMDRN5GAIGLEM11UAC4DILR4CPMA1R", "*.example.test.": "6CAN7N9ISON37DM8PIL7TS42F3KFOO3N"}。
合法apex记录JBAS…→9VBM…：精确证明closest-encloser；覆盖wildcard，但next恰好等于查询hash，严格区间不覆盖next-closer。畸形owner为32个!、next为20字节FF；字符非法、不能作为base32hex hash；其原始文本排序却覆盖查询与wildcard。两条RRSIG均用子区已认证DNSKEY实际验证通过。签名通过不能赋予畸形owner证明效力。
去坏记录仅剩apex，next-closer证明缺失（T02）；仅坏记录无closest-encloser（T03）。两条参数均SHA1/0次迭代/空salt/flags0，没有参数冲突。合法apex必要、非法候选不可用于有效证明；有效记录集合为空/不足时不能SECURE。独立解码合法性、区间与签名细节在proof-analysis.json及wire中。

## 输入、公平性及运行过程

每次同一Signed实例向两端提供同一生成器结果，原始场景未改。UDP观察器保存实际发送的请求/响应字节，不只保存解析字典。目标响应规范化RRset（包含签名、TTL）逐条等价；ID/请求选项/排列可能不同，不能声称整个wire逐字节相同。Unbound另有根NS等查询，数量逐例保存，不能混入项目Q。每次新进程/新上下文，无旧缓存；同一实验锚，外部验证时刻是整数秒，项目实际时间有小于一秒偏差，签名窗口±3600秒且非边界，见environment。算法策略原样（项目更窄），原始算法15及DS2均在双方支持范围。
原始配置verbosity0没有调试跟踪；API secure/bogus来自libunbound，不仅是AD位。后续副本只增加最终answer_packet无损hex，不改验证选项，见t07-corrected-v2及修复后记录。未取得的内部选择/OS进程退出码标UNKNOWN，不虚构0；Python完整实验命令退出成功。新原始wire索引含SHA256。重启消除了历史缓存解释；T02/T03否定“其他材料已足够”解释。不能断言每条多余RRset都被Unbound验证。

## 最小差异实验（完整首轮）

|ID|项目|Unbound|改动|
|---|---|---|---|
|T01|BOGUS|SECURE|unchanged original|
|T02|BOGUS|BOGUS|remove malformed|
|T03|BOGUS|BOGUS|malformed only|
|T04|SECURE|SECURE|valid ring|
|T05|BOGUS|SECURE|valid ring + extra malformed|
|T06|BOGUS|SECURE|same as T01 incomplete + malformed|
|T07|SECURE|SECURE|replace malformed by valid noncovering owner|
|T08|BOGUS|BOGUS|signed exact Q hash contradicts NXDOMAIN|
|T09|BOGUS|BOGUS|valid semantics but invalid signatures|
|T10|INDETERMINATE|BOGUS|extra iterations=1 parameter|
|T11|INDETERMINATE|SECURE|extra unknown algorithm/flags|
|T12|BOGUS|BOGUS|no denial records|

T07首轮设施错误：owner=next=零hash形成环绕覆盖，并非非覆盖，SECURE不是该轮错误放行证据；保留首轮CSV，不重写。另存t07-corrected-v2：owner零、next末位1，双方BOGUS；为了保证不覆盖同时改变owner与next，非单字段实验。T06故意重复T01以表达不完整有效集合＋坏候选。T08有精确qname hash/类型，NXDOMAIN语义矛盾；T09密码学错误；T05/T06/T08/T09均保存，不按结果删行。T10项目策略受限，T11未知算法/flag当前导致INDETERMINATE，是另一个可用性边界，不在本轮偷偷放宽全局策略。

## 规范与政策分开

[RFC5155](https://www.rfc-editor.org/rfc/rfc5155.html) §3.3及[RFC4648](https://www.rfc-editor.org/rfc/rfc4648.html)§3.3/§7规定base32hex解释；非法标签不能直接当合法hash。§8.3/8.4要求closest-encloser/next-closer和wildcard证明；签名和角色都要成立。§8.1未知hash算法与§8.2未知flags的忽略要求，不能与项目的迭代/salt/Opt-Out白名单混为一谈。§8.5/8.6分别约束NODATA/DS，不可套用本次NXDOMAIN。RFC7129是Informational背景，不能当新增MUST。
MUST：验证所需签名及否定证明、按规定忽略未知算法/保留flags候选；SHOULD和MAY须按具体条款应用，未找到“任何额外畸形owner都必须使整体BOGUS”的强制条款。对一般含无关坏数据的全响应处理存在实现选择；不能把严格字符合法性扩大成全池否决规则。项目iterations0/空salt等是本地策略，不是RFC一概要求。Unbound普通路径行为是实现事实，不是RFC授权接受非法owner。该非法owner在原始场景的标准有效性并非模糊：无法提供合法next-closer证明；但不据此宣称已经完成对Unbound整体实现的漏洞裁决。

## 最小修复建议与风险

仅让不合法owner候选不进入可用集合；继续对其余已验签合法材料求完整证明。没有充分证明仍失败，不根据是否有坏记录直接成功，不调整评分器、不删除T01、不全体降级UNKNOWN。必须验证T05由BOGUS→SECURE，T01/T02/T03/T06/T07/T08/T09/T12仍拒绝；原始与新增对照另存。签名筛选、锚、A/Q/E/V、预算、Agent均不改。未知flags/参数策略及部分DNAME边界仍单列，不能借本轮扩大支持范围。

此报告是开发助手可复现审计，不是独立人工盲审。最初T07和两次观测包装器启动错误保留目录；不能冒充协议失败。生产逻辑在本报告提交后才允许另一个修复提交。

## 修复与最终复核（独立于原始观察）

报告提交78ca1eb之后，最小修复e1ecd9e仅修改owner长度/字符不合法时的候选过滤（return False→continue），其他证明条件、签名、政策、预算不改。完整362 passed in25.71s（原356＋6回归）。after-isolated含修复后三次原始复现和完整12场景，全部保存wire、目标材料等价。T05从BOGUS变SECURE；T01/T06仍BOGUS，与Unbound的原始SECURE分歧保留；T02/T03/T07/T08/T09/T12仍BOGUS，没有新增错误放行。完整原37场景重新Unbound对照保存full-reference-isolated.json，项目状态与133b49a逐例无变化。

首轮T07循环区间错误另存pilot CSV；正式CSV并列before/after，before T07明确使用t07-corrected-v2。没有修改原始all-runs、旧业务评分或删除原始分歧。after-fix目录和full-reference-after.json因两个独立进程争用127.0.0.x:53而可能污染，全部排除验收且保留；真正验收为串行after-isolated和full-reference-isolated。包装器早期import/编码错误也保留，均非DNS结论。after-isolated/environment中business_source_commit沿用133b49a是记录器元数据错误：实际git_commit为e1ecd9e，业务哈希也对应修复；保留原字段并在此纠正，未来记录器已按Git最近业务提交获取。

reference-debug额外只改verbosity=4/logfile，不改变验证政策；日志958–976附近明确显示两个原始NSEC3签名通过、closest-encloser为example.test.、最终NAME ERROR验证成功。info渲染将!显示为?，真实wire仍为!。单个区间候选选择PC仍未插桩，不能把源码推导伪装成观测。额外返回的answer_wire_hex可无损解码检查最终RCODE/AD/EDNS；不是只看AD判断。原始三次始终verbosity0、空缓存。完整命令及退出信息在verifier-logs/commands.json；未观测的子进程退出码保持UNKNOWN。

## 规范等级补充

MUST：RFC5155 8.1忽略未知hash，8.2忽略未知保留flags；8.3/8.4必须具备对应完整证明，不能使用单纯签名成功替代名称/区间语义。SHOULD：3节建议NSEC3 TTL与SOA negative TTL一致，是缓存建议，不决定本次证明覆盖；7.4对未知算法区的加载/响应建议与验证器行为不同。MAY：6节允许Opt-Out与非Opt-Out混合，不能把所有非零flag一律当协议非法；本项目未承诺其验证语义。RFC9276更新参数运行建议，不能拿历史10.3的高迭代许可当当前安全推荐。参数0/空salt、资源限制是本地政策；Unbound先参数一致性检查和覆盖快路径是实现行为。未找到“任一额外坏owner必须使整个响应失败”的MUST。一般混合畸形/冲突材料超出本次可证明子集的解释，仍标UNRESOLVED_PROTOCOL_INTERPRETATION。

T11未知hash/flags的本地全局INDETERMINATE仍是已知政策/可用性不足，与“RFC规定必须全响应未知”不同；本轮没有借修复字符过滤去放宽未知算法或Opt-Out。原始false_bogus计数是对参考状态的机械分歧，不是协议裁决；本调查将原始D与独立T05的B分开。
