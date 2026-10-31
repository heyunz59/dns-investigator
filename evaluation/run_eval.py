"""Same-model experiment; scoring criteria never enter Agent context."""
import argparse
import asyncio
import csv
import hashlib
import json
import subprocess
import sys
import uuid
from pathlib import Path
from datetime import datetime, timezone

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from dns_investigator.agent import investigate
from dns_investigator.config import Config
from dns_investigator.target import parse_target
from dns_investigator.accounting import statistics, call_reviews


async def run(repeats):
    config = Config.load()
    if not config.api_key:
        print("BLOCKED: 未配置 DEEPSEEK_API_KEY；未执行真实模型实验。")
        return 2
    cases = json.loads((ROOT / "evaluation/cases.json").read_text(encoding="utf-8"))
    out = ROOT / "results/evaluation-raw" / (datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ") + "-" + uuid.uuid4().hex[:6])
    out.mkdir(parents=True, exist_ok=False)
    metadata = dict(repeats_requested=repeats, cases=len(cases), expected_executions=repeats*len(cases)*2,
                    model=config.model, thinking="disabled", temperature=0, max_tool_calls=config.max_tool_calls,
                    model_timeout=config.model_timeout, schema_version=3,
                    dns_query_budget=config.dns_query_budget,dns_tool_timeout=config.dns_tool_timeout,
                    commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                    source_hashes={str(p.relative_to(ROOT)): hashlib.sha256(p.read_bytes()).hexdigest()
                                   for p in (ROOT / "src/dns_investigator").glob("*.py")})
    (out / "experiment.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    (out / "cases.json").write_text(json.dumps(cases, ensure_ascii=False, indent=2), encoding="utf-8")
    snapshot = out / "fixtures"
    snapshot.mkdir()
    for case in cases:
        (snapshot / f"{case['id']}.json").write_bytes((ROOT / f"data/fixtures/{case['id']}.json").read_bytes())
    print("EXPERIMENT", out.name, flush=True)
    reviews = []
    for repeat in range(1, repeats + 1):
        for case in cases:
            fixture = snapshot / f"{case['id']}.json"
            entries = json.loads(fixture.read_text(encoding="utf-8"))
            facts = [dict(id=f"E{i+1}", tool_call_id=f"F{i+1}", tool_name=e["tool"],
                          input=e["match"], data=e["data"], source_mode="fixture",
                          measurement_location="synthetic", execution_status="ok") for i, e in enumerate(entries)]
            for arm in (["A", "B"] if repeat % 2 else ["B", "A"]):
                log, path = await investigate(case["question"], parse_target(case["target"]), config,
                    fixture=fixture if arm == "B" else None,
                    baseline_facts=facts if arm == "A" else None, log_dir=out)
                stats = statistics(log, case)
                suggestions = call_reviews(log, case) if arm == "B" else []
                review = dict(case=case["id"], repeat=repeat, arm=arm, run_id=log["run_id"],
                    status=log["status"], requirements_met=log["requirements_met"],
                    elapsed_seconds=log["elapsed_seconds"], tool_ms=stats["tool_ms"],
                    total_calls=stats["total_calls"], dns_network_attempts=stats["dns_network_attempts"],
                    measurements=stats["measurements"],attempt_accounting=stats["attempt_accounting"],
                    missing_required_tools=json.dumps(stats["missing_required_measurements"], ensure_ascii=False) if arm == "B" else "N/A",
                    success="", correct_calls="", reviewer="", notes="", log_file=path.name)
                reviews.append(review)
                with (out / "manifest.jsonl").open("a", encoding="utf-8") as f:
                    f.write(json.dumps(review, ensure_ascii=False) + "\n")
                with (out / "call-review.jsonl").open("a", encoding="utf-8") as f:
                    for suggestion in suggestions:
                        f.write(json.dumps(dict(run_id=log["run_id"],case=case["id"],repeat=repeat,
                            reviewer="automatic_rules_pending_human_review", **suggestion),ensure_ascii=False)+"\n")
                with (out / "review.csv").open("w", newline="", encoding="utf-8-sig") as f:
                    writer = csv.DictWriter(f, fieldnames=list(reviews[0]))
                    writer.writeheader()
                    writer.writerows(reviews)
                print(case["id"], repeat, arm, log["status"], path.name, flush=True)
    return 0


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--repeats", type=int, default=3)
    args = p.parse_args()
    if not 1 <= args.repeats <= 10:
        p.error("repeats 必须为 1–10")
    raise SystemExit(asyncio.run(run(args.repeats)))
