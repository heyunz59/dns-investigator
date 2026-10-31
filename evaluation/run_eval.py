"""Same-model A/B experiment. Answers and manual review remain local until reviewed."""
import argparse
import asyncio
import csv
import json
from pathlib import Path
from datetime import datetime, timezone
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from dns_investigator.agent import investigate
from dns_investigator.config import Config
from dns_investigator.target import parse_target


async def run(repeats):
    config = Config.load()
    if not config.api_key:
        print("BLOCKED: 未配置 DEEPSEEK_API_KEY；未执行模型对照实验，未生成成功率或对比图。")
        return 2
    cases = json.loads((ROOT / "evaluation/cases.json").read_text(encoding="utf-8"))
    out = ROOT / "results/evaluation-raw" / datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out.mkdir(parents=True, exist_ok=True)
    reviews = []
    for repeat in range(1, repeats + 1):
        for case in cases:
            fixture = ROOT / f"data/fixtures/{case['id']}.json"
            entries = json.loads(fixture.read_text(encoding="utf-8"))
            facts = [dict(id=f"E{i+1}", tool_call_id=f"F{i+1}", tool_name=e["tool"],
                          input=e["match"], data=e["data"], source_mode="fixture",
                          measurement_location="synthetic", execution_status="ok") for i, e in enumerate(entries)]
            # Alternate order between repetitions; both arms use identical model and settings.
            for arm in (["A", "B"] if repeat % 2 else ["B", "A"]):
                log, path = await investigate(case["question"], parse_target(case["target"]), config,
                    fixture=fixture if arm == "B" else None,
                    baseline_facts=facts if arm == "A" else None, log_dir=out)
                calls = log["evidence"] if arm == "B" else []
                required = set(case["required_tools"])
                review = dict(case=case["id"], repeat=repeat, arm=arm, run_id=log["run_id"],
                    status=log["status"], elapsed_seconds=log["elapsed_seconds"],
                    tool_ms=sum(c["duration_ms"] for c in calls), total_calls=len(calls),
                    missing_required_tools=";".join(sorted(required - {c["tool_name"] for c in calls})) if arm == "B" else "N/A",
                    success="", correct_calls="", reviewer="", notes="", log_file=path.name)
                reviews.append(review)
                # Append each answer's metadata immediately, including failed runs.
                manifest = out / "manifest.jsonl"
                with manifest.open("a", encoding="utf-8") as f:
                    f.write(json.dumps(review, ensure_ascii=False) + "\n")
                print(case["id"], repeat, arm, log["status"], path.name, flush=True)
    with (out / "review.csv").open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=list(reviews[0]))
        writer.writeheader()
        writer.writerows(reviews)
    print("按 cases.json 的规则审核真实回答，填写 review.csv，再运行 summarize.py。不要将未审核日志公开。")
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--repeats", type=int, default=3)
    args = p.parse_args()
    if not 1 <= args.repeats <= 10:
        p.error("repeats 必须为 1–10")
    raise SystemExit(asyncio.run(run(args.repeats)))
