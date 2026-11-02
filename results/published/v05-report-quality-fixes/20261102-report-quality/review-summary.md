# v0.5 报告质量针对性修复（本地交付）

基线 `2fd02450c72249965cd3af555a3a9916083ebfcd`，分支 `fix/v05-report-quality`，业务源码提交 `5ce9e20e2d6cd09670e60145836a0d2013e595f5`。开始时仅 docs/manual-reviews/ 为用户未跟踪材料，未读取、改动或提交它；已核对远程参考分支仍为此基线。没有 reset/stash，没有其他任务并行写本工作区。未推送、合并或发布；远程 CI=NOT_RUN。

## 反例与修复

修改前先实际保存 [before.json](before.json) 的13份报告：10个历史受控案例回放和3个 constructed report input（同一TCP REFUSED/HTTP503事实配三种上下文）。随后从不可变 Git 归档隔离加载基线源码，扩充并保存33例 [expanded-baseline/before.json](expanded-baseline/before.json)，验证实际 import 的 reasoner 哈希与基线一致。不是仅拿 README 或手写旧输出作为基线。supplemental-baseline/ 的30例中间材料保留，未覆盖旧记录。

1. **DNSSEC位置**：旧 DS 不匹配将整条 E/V 闭包列为故障位置。现在先检查最终 BOGUS/completed、调用归属、问题范围和完整闭包，再从最终验证端点选实际阻断 V；不是按编号挑第一个失败候选。例中直接依据为 **V7、E7、E8**，位置为 **example.test. 父侧 DS 与子侧 DNSKEY 关联验证**，根至父区为 dependency_*，完整 E/V 不删除。RRSIG/证明按实际 scope 定位；未确定或旧记录缺直接元数据时明确阶段/未知，不把依赖当故障。trace 按 current_zone 的实际步骤分离停止子区与父侧引导依据。
2. **任务相关性**：已有规范化目标、URL、端口和显式关注层进入受控 request_context；常见否定/引用不当成正向关注，多层/不明确时未知。原文只用于提取，不成为证据或授权。目标、URL路径/query及端口不匹配的异常单列；TCP正常但HTTP503时优先说明关注路径未复现，不为正常TCP建议配置修复。明确HTTP请求的TLS失败也能相关。确认等级未提升。
3. **并列契约**：没有唯一领先者时 diagnosis_selection_mode=parallel、diagnostic_conclusion=null，secondary_diagnoses 包含全部并列项。没有虚构综合故障；日志、JSON、CLI、建议和模型失败回退均处理空primary。优先级只用于回答问题，不暗示HTTP/TCP之间或SERVFAIL/EDE/本地BOGUS之间存在已确认因果。
4. **分支排障**：CHECK.branches 的每项包含未来 condition、interpretation、next_action、change_prerequisites。递归超时有持续/恢复/全部超时/改收SERVFAIL四分支；DS、权威/委派、三类TCP、明确证书错误、401/403/404/429/500/502/503/504及正文未完成分别按结构化字段分派。不搜索 cause 文本。方法明确是当前工具候选、外部只读、管理员检查/条件变更、用户补充或模拟复核；当前工具仍须新调查中的目标、地址、端口与预算校验。未采集 Retry-After 不编造值，重试最多一次；fixture/synthetic 不直接进入 live 探测。没有执行配置修改。
5. **术语**：TIMEOUT 是未在时限内收到响应/建立连接；SERVFAIL/REFUSED 是实际DNS响应；TCP REFUSED是连接被拒绝；HTTP可能有状态码但正文未完成。原始状态码不变，Finding只改按状态生成的解释，不用全局替换。INVALID_INPUT/安全拒绝保留A与阻止目标，不当作远端故障。
6. **CLI**：默认只展示摘要、具体位置、确认等级/未知、最多三项操作、验证方式、直接E/V、次要/并列问题、执行/回退提示和日志路径。--verbose 才追加完整结果。--format json stdout仅一个JSON对象，进度到stderr；与--verbose冲突返回单一错误JSON/退出2。--help、无效参数/目标、缺配置、运行失败也有可解析约定；JSON及真实非TTY缺目标不等待输入。--tools-only默认横幅与工具JSON保持旧行为；搭配--format json则输出带mode/evidence/attempts/dns_attempts的单一对象，不调用模型。旧退出码0/3/1/2保留。

## 哪些原机制已经足够

1 Agent+5Tools、网络授权、CNAME授权、RD=0追踪、DNSSEC锚/密码学/状态、NSEC3、预算/并发归属、原测量内容与原始模型草稿均复用。工具、网络与协议验证源码未改，逐模块哈希见 regression-results.json。dns_diagnosis.py 只改 Finding 解释；33例比较其除 explanation 外的结构均相同。没有新增底层协议元数据或重新探测。

修改 schemas.py、diagnostic_reasoner.py、remediation.py、reporting.py、main.py、agent.py 的必要上下文接线、dns_diagnosis.py 的术语；新增 request_context.py。对应 tests/test_report_quality.py、evaluation/report_quality.py、finalize_report_quality.py 和文档/回放材料。旧记录新增字段默认未知/空，不补造过去的意图、时间或直接V。

## 验证材料与真实结果

- 实际基线：**447 passed in28.52s**；最终业务：**508 passed in41.53s，新增61项，0 failed/0 skipped**。`python -m pytest -q`；`python -m pip check` PASS。
- [location-before-after.json](location-before-after.json)：33例的旧位置、新直接位置与依赖分离。
- [diagnosis-priority-matrix.csv](diagnosis-priority-matrix.csv)：TCP/HTTP/模糊关注的相同证据哈希、选择理由、相关性及并列结果。
- [remediation-matrix.json](remediation-matrix.json)：完整方法、分支及变更前提，executed=false。
- [report-comparisons.md](report-comparisons.md) 和 [reports-after.json](reports-after.json)：实际新旧输出、来源类别、输入/原始材料哈希。原始13份反例、隔离基线30/33例均保留。
- [regression-results.json](regression-results.json)：版本、平台、运行方式与未改模块哈希；[conclusion.json](conclusion.json) 用 PASS/FAIL/NOT_RUN/UNKNOWN 并附依据。Git提交无法自嵌其完整SHA，最终交付提交由最终答复及本目录最后提交解析；源码SHA已固定。

历史受控测量回放不是新网络实验；constructed report input不是实际网络测量；FunctionModel只验证接线与失败回退，不冒充DeepSeek。完整pytest另包含原有真实回环DNS/TCP/HTTP及密码学测试的实际执行，与33例报告回放分开。没有新增公网请求或付费模型测试。开发助手复核属于 **AI辅助规则复核**，独立人工语义验收 **NOT_RUN**；不能把508项通过当诊断准确率。公开文件扫描是模式检查，不是完整隐私认证。

## 兼容与边界

允许调整的两项旧测试：交互提示现在显式模拟TTY，并新增真实非交互错误测试；无关注的TCP/HTTP双异常不再要求HTTP按字母排序优先，改验primary为空、两项故障和各自证据/分支保留。其余安全/协议/预算/引用等级断言未删除或放宽。

相关性不是完整自然语言理解；复杂否定、时间陈述、引用边界仍可能不够，需要用户人工复测。没有用分数伪装因果概率。未提供的时间/来源关联不补造，TCP的域名关联依赖本调查原有授权/测量归属，不凭用户文本扩大地址访问。日志缺少精细结构时仍可能只定位到阶段；expected_sni 是原URL/最终URL派生的期望，不是抓包证明。未支持的DNSSEC/历史T01/T06/T10差异均保留，未改变验证语义。建议未执行，未证明任何用户现场配置已经修复。

当前适合**停止扩展，进入用户人工复测与展示验收**：重点检查明确关注、多个独立异常、旧材料缺字段以及默认摘要是否足够易懂。若人工复核发现语义错误，继续针对反例修复，不增加工具、自动修复器或额外模型调用。
