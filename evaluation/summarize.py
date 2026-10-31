"""Generate actual metrics only from completely reviewed runs."""
import argparse
import csv
from pathlib import Path
import statistics
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt


def summarize(source, output):
    rows = list(csv.DictReader(source.open(encoding="utf-8-sig")))
    if not rows or any(r["success"] not in {"0", "1"} or not r["reviewer"].strip() for r in rows):
        raise ValueError("所有真实执行记录都须人工审核，success 填 0/1，reviewer 不得为空")
    result = []
    for arm in ("A", "B"):
        group = [r for r in rows if r["arm"] == arm]
        if not group:
            raise ValueError("必须同时有 A/B 两组")
        total = sum(int(r["total_calls"]) for r in group)
        if arm == "B" and any(not r["correct_calls"].isdigit() or not 0 <= int(r["correct_calls"]) <= int(r["total_calls"]) for r in group):
            raise ValueError("B 组须逐调用审核 correct_calls，且不得超过总调用数")
        result.append(dict(arm=arm, executions=len(group),
            success_rate=sum(int(r["success"]) for r in group)/len(group),
            tool_accuracy=sum(int(r["correct_calls"]) for r in group)/total if total else "N/A",
            mean_seconds=statistics.mean(float(r["elapsed_seconds"]) for r in group)))
    output.mkdir(parents=True, exist_ok=True)
    with (output / "evaluation.csv").open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=list(result[0]))
        w.writeheader()
        w.writerows(result)
    fig, ax = plt.subplots(figsize=(6, 4))
    ax.bar(["A: facts supplied", "B: agent + tools"], [r["success_rate"] for r in result])
    reviewers = {r["reviewer"] for r in rows}
    review_label = "Codex review; human review pending" if any("Codex" in r for r in reviewers) else "Reviewed results"
    ax.set(ylim=(0, 1), ylabel="Task success rate", title=f"Same-model comparison\n{review_label}")
    fig.tight_layout()
    fig.savefig(output / "comparison.png", dpi=160)
    plt.close(fig)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("review", type=Path)
    p.add_argument("--output", type=Path, default=Path("results/published"))
    a = p.parse_args()
    summarize(a.review, a.output)
