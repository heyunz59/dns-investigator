# 对照实验与评分

2026-11-01 安全/稳定性专项：`security_stability_offline.py`保存14个受控DNS阶段场景、5组时间回放和HTTP mock调度；`security_stability_runs.py`在真实DeepSeek下默认每个关键场景重复3次，另1次单项对照，不是公网实验。每次使用新目录，不覆盖。`--source-ref`只记版本、不自动切换代码；基线包需独立PYTHONPATH进程加载，summarize_security_stability.py逐模块校验源码哈希后导出脱敏日志/实际分母。SDK tokens只累计已记录usage，旧失败缺失不猜补。新旧7次结果及限制见[修复记录](../docs/security-stability-fixes.md)。日志v6保留所有原始草稿/校验反馈，Agent失败与程序报告可用分开；不同版本不能把旧日志缺字段当作成功补齐。所有语义、范围定位和错误根因断言均待独立人工复核。

v0.3 DNS 专项入口：`python evaluation/dns_v3.py`（10 个场景，每个实际模型运行 1 次，fixture 工具数据），随后 `python evaluation/dns_v3_metrics.py results/runs/生成目录`。保存的状态、调用次数、Q 实际 DNS 请求数、E 测量数、规则 Finding、类型和耗时均来自实际记录。metrics.json 的规则命中与结构覆盖不等于语义准确率，工具合理性、错误根因断言与语义诊断仍待独立人工评分。规则基线只分析同一份已观测证据，不额外获取事实，不宣称可证明模型提升。旧版 A/B 实验保持原样。

v0.2：默认 8 案例 × 3 次 × 2 组，48 次真实模型运行。独立目录名含时间与随机后缀，保存源码哈希和原始数据快照。旧版 below 的 7 案例说明仅为历史背景；最新流程及计数口径见 [可靠性说明](../docs/reliability-v2.md)。`review.csv` 每完成一次运行即保存，不等整批结束。`call-review.jsonl` 的自动建议需独立人工审核。

新结果可先运行 `python evaluation/publish_review.py results/evaluation-raw/实验目录 results/published/新的实验目录`，再运行 `python evaluation/summarize.py results/published/新的实验目录/review.csv --output results/published/新的实验目录`。publish_review 的结构/执行/关键词筛查不能证明全部语义正确，生成的 reviewer 明确为 automatic_rules_pending_human_review；审核人应逐条核对原始回答。目标目录已存在时拒绝覆盖。

attempt_accounting 缺失或非 complete 的旧 B 组正确率输出 INCOMPLETE；不能再用 evidence 的条数补猜总尝试数。A 零调用维持 N/A。运行完成、结构通过、案例任务成功是不同概念，例如 C1 明确未复现且证据充分可以满足案例，但唯一根因仍未知。

从项目根目录运行 `python evaluation/run_eval.py --repeats 3`。这将产生 7 案例 × 3 次 × 2 组模型运行，会消耗实际 API 额度。需要最小验证时先用 `--repeats 1`。没有密钥时退出，不生成模拟成绩。

A 组直接获得对应 fixture 的全部原始事实，不能调用工具。B 组只通过工具按需获取事实。两组使用同一配置、相同问题、temperature=0、非思考模式，重复间交替先后顺序。A 组可能知道 B 组没有查询的事实；原始日志完整保留这一区别，不能将差异完全归因于推理水平。

人工评分规则在 cases.json；不传给 Agent。review.csv 每行对应一次实际运行：逐条核对该案例全部 criteria，全部满足且 completed 时 success=1，否则为 0。失败执行也计入分母，不能删除。B 组检查 required_tools 是否遗漏、参数与目标是否正确、调用是否对调查有帮助；correct_calls 填合理调用数。C3 必须有默认/备用两次 DNS；C2 禁止虚构地址连接；Q1 不应有 TCP/HTTP。额外调用是否合理由审核人记录依据。任务完成与工具正确率分别计分；缺失必要调用应使任务失败，不通过缩少调用数提高成绩。

填写 reviewer 和 notes 后运行 `python evaluation/summarize.py results/evaluation-raw/review.csv`，生成实际 CSV 和对比图。零调用的工具正确率为 N/A。总耗时包含模型、工具、重试与框架开销；tool_ms 是工具测量耗时之和，并行时不能简单从总耗时扣除后称作纯模型耗时。

额外交互测试 C6a（无目标时补充）和 C6b（非法 URL 拒绝）由 tests 和 CLI 验证；它们不假装是可由模型评测的完整调查。C6c 是部分工具失败案例。

所有运行与评分表默认在被忽略的 results/evaluation-raw/。公开前逐个检查域名、网址路径、输入与输出，复制可公开样本到 results/published/。不得预填成功率；未执行不算失败，也不算成功。截图必须来自实际运行；尚未获得的截图不能以示意图冒充。

本次已实际执行的初步实验在 `results/published/evaluation-20261031/`，每组每案例 1 次。评分由 Codex 根据保存的真实回答逐项复核，并辅以执行状态、必要工具与参数的程序检查，**未经过独立人工盲评**。review.csv 与 call-review.csv 可逐项修改并重算；不要将该初步评分描述为人工评测。正式人工审核时建议核对全量回答，并补到 3 次重复。
# DNS 判断专项评测（2026-11-01）

使用 accuracy_cases.py 的固定事实，标准答案独立存于 accuracy_expectations.json，不提供给 Agent。capture_accuracy.py 是固定证据回放；controlled_dns.py 是仅测试用回环依赖注入，正式私有地址权限不放宽；accuracy_model_run.py 是真实 DeepSeek + 受控 DNS，不是公网验证，也不是 fixture 测试。summarize_accuracy.py 输出分母、A/Q/E、时间、失败、源码哈希和待人工复核标记。

新评测日志 v5；review_rules 的假设数量只作观察，不参与成功门槛。dns_v3_metrics 按日志版本选历史/当前代码名，不能把不同口径数字直接混算。历史 cases.json 的“至少两个”评分文字保留为旧口径，不作为新程序完成门槛。新实验和历史报告均保留，不修改旧评分。
