# 对照实验与评分

从项目根目录运行 `python evaluation/run_eval.py --repeats 3`。这将产生 7 案例 × 3 次 × 2 组模型运行，会消耗实际 API 额度。需要最小验证时先用 `--repeats 1`。没有密钥时退出，不生成模拟成绩。

A 组直接获得对应 fixture 的全部原始事实，不能调用工具。B 组只通过工具按需获取事实。两组使用同一配置、相同问题、temperature=0、非思考模式，重复间交替先后顺序。A 组可能知道 B 组没有查询的事实；原始日志完整保留这一区别，不能将差异完全归因于推理水平。

人工评分规则在 cases.json；不传给 Agent。review.csv 每行对应一次实际运行：逐条核对该案例全部 criteria，全部满足且 completed 时 success=1，否则为 0。失败执行也计入分母，不能删除。B 组检查 required_tools 是否遗漏、参数与目标是否正确、调用是否对调查有帮助；correct_calls 填合理调用数。C3 必须有默认/备用两次 DNS；C2 禁止虚构地址连接；Q1 不应有 TCP/HTTP。额外调用是否合理由审核人记录依据。任务完成与工具正确率分别计分；缺失必要调用应使任务失败，不通过缩少调用数提高成绩。

填写 reviewer 和 notes 后运行 `python evaluation/summarize.py results/evaluation-raw/review.csv`，生成实际 CSV 和对比图。零调用的工具正确率为 N/A。总耗时包含模型、工具、重试与框架开销；tool_ms 是工具测量耗时之和，并行时不能简单从总耗时扣除后称作纯模型耗时。

额外交互测试 C6a（无目标时补充）和 C6b（非法 URL 拒绝）由 tests 和 CLI 验证；它们不假装是可由模型评测的完整调查。C6c 是部分工具失败案例。

所有运行与评分表默认在被忽略的 results/evaluation-raw/。公开前逐个检查域名、网址路径、输入与输出，复制可公开样本到 results/published/。不得预填成功率；未执行不算失败，也不算成功。截图必须来自实际运行；尚未获得的截图不能以示意图冒充。
