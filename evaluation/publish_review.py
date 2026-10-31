"""Export an explicitly selected fixture experiment and transparent automated screen."""
import argparse
import csv
import json
from pathlib import Path
import shutil
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from review_rules import screen


def publish(source, destination):
    # Never overwrite an existing published experiment.
    destination.mkdir(parents=True, exist_ok=False)
    cases = {c["id"]: c for c in json.loads((source / "cases.json").read_text(encoding="utf-8"))}
    rows = [json.loads(line) for line in (source / "manifest.jsonl").read_text(encoding="utf-8").splitlines()]
    checks = []
    for row in rows:
        log = json.loads((source / row["log_file"]).read_text(encoding="utf-8"))
        if any(e.get("source_mode") != "fixture" for e in log.get("evidence", [])):
            raise ValueError("仅允许已选定并审查的 fixture 实验；live 日志须另行脱敏")
        rating = screen(log, cases[row["case"]])
        row.update(success=rating["success"], correct_calls=rating["correct_calls"],
                   reviewer="automatic_rules_pending_human_review", notes=rating["note"])
        checks.append(dict(run_id=row["run_id"],case=row["case"],repeat=row["repeat"],arm=row["arm"],**rating))
        shutil.copyfile(source / row["log_file"], destination / row["log_file"])
    for name in ["cases.json", "experiment.json", "call-review.jsonl"]:
        shutil.copyfile(source / name, destination / name)
    shutil.copytree(source / "fixtures", destination / "fixtures")
    (destination / "rule-checks.json").write_text(json.dumps(checks,ensure_ascii=False,indent=2),encoding="utf-8")
    with (destination / "review.csv").open("w",encoding="utf-8-sig",newline="") as f:
        w = csv.DictWriter(f,fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("source", type=Path)
    p.add_argument("destination", type=Path)
    args = p.parse_args()
    publish(args.source,args.destination)
