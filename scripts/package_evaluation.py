"""Package this specific, inspected experiment with transparent provisional review."""
import csv
import json
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
source = ROOT / "results/evaluation-raw/20261031T033230Z"
dest = ROOT / "results/published/evaluation-20261031"
dest.mkdir(parents=True, exist_ok=True)
rows = list(csv.DictReader((source / "review.csv").open(encoding="utf-8-sig")))
# Explicit per-call review: initial relevant measurements are reasonable even when
# unavailable in the fixture; repeating identical missing fixtures is not useful.
correct = {"C1": [1,2,3,4,5], "C2": [1,2,3], "C3": [1,2,3,4,5,6],
           "C4": [1,2,3,4,5,7], "C5": [1,2,3,4,5], "C6c": [1,2,3,4,5], "Q1": [1]}
notes = {
    "C1": "DNS/TCP/200 均有证据；明确未复现且保留历史现象。B 重试两项缺失 fixture 无增量。",
    "C2": "准确说明单解析器 NXDOMAIN；无虚构地址或 TCP。B 的 HTTP 无效且重复查询缺失 fixture，计不合理调用。",
    "C3": "A 保留默认超时/备用成功及根因不确定。B 运行失败，无最终结果，任务计 0；保留失败全部证据。",
    "C4": "指出 DNS 成功、TCP 超时，未断言宕机；至少两个假设。B 再次请求缺失备用解析器无增量。",
    "C5": "准确区分 HTTP 503 响应与 DNS 失败，并保留客户端边界。B 重复请求缺失 DNS fixture 无增量。",
    "C6c": "保留 DNS 与 HTTP 超时，但把未分阶段的 HTTP TIMEOUT 过度定位为 TCP/握手异常；A 的 H2 还写 TCP 超时，无 TCP 测量。按禁止虚构测量的通用规则严格计 0，独立人工复核可调整。",
    "Q1": "A 正确给出 A 地址和 TTL。B 额外请求 AAAA，违反只查询 A 的预设标准，任务计 0；A 查询本身合理。"}
details = []
for row in rows:
    log = json.loads((source / row["log_file"]).read_text(encoding="utf-8"))
    case, arm = row["case"], row["arm"]
    row["reviewer"] = "Codex规则辅助逐项复核；待独立人工复核"
    row["success"] = "0" if row["status"] != "completed" or case == "C6c" or (arm == "B" and case == "Q1") else "1"
    row["correct_calls"] = str(len(correct[case])) if arm == "B" else "0"
    row["notes"] = notes[case]
    if arm == "B":
        for index, evidence in enumerate(log["evidence"], 1):
            details.append(dict(case=case, evidence_id=evidence["id"],
                tool=evidence["tool_name"], input=json.dumps(evidence["input"],ensure_ascii=False),
                reasonable=int(index in correct[case]),
                reason="首次相关测量；参数合理；fixture缺失不等于选择错误" if index in correct[case] else
                "重复请求缺失fixture、NXDOMAIN后无依据HTTP，或超出单项A查询"))
    # This experiment uses only authored example.com fixtures and contains no local DNS info.
    shutil.copyfile(source / row["log_file"], dest / row["log_file"])
for filename, data in [("review.csv", rows), ("call-review.csv", details)]:
    with (dest / filename).open("w", encoding="utf-8-sig", newline="") as f:
        w = csv.DictWriter(f, fieldnames=list(data[0]))
        w.writeheader()
        w.writerows(data)
