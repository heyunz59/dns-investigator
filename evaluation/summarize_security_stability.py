"""Publish sanitized copies and descriptive counts, never a semantic accuracy score."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))
from scripts.export_run import export


def read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def verify_source(metadata):
    verified = {}
    for name, expected in metadata["source_hashes"].items():
        blob = subprocess.check_output([
            "git", "show", f"{metadata['source_ref']}:src/dns_investigator/{name}"
        ])
        # Windows worktrees use CRLF; Git stores LF. Match exact captured bytes
        # against one of those explicit representations, never normalize a hash.
        variants = {"git_blob": blob, "windows_crlf": blob.replace(b"\r\n", b"\n").replace(b"\n", b"\r\n")}
        matched = next((kind for kind, data in variants.items()
                        if hashlib.sha256(data).hexdigest() == expected), None)
        if matched is None:
            raise ValueError(f"Captured source differs from commit: {name}")
        verified[name] = matched
    return verified


def summarize(source, destination):
    destination.mkdir(parents=True, exist_ok=False)
    all_rows = []
    summaries = {}
    for arm, ref in (("baseline", "512141e"), ("current", "4de824c")):
        raw = source / f"security-stability-{arm}-{ref}"
        metadata = read(raw / "experiment.json")
        verified = verify_source(metadata)
        export(raw / "experiment.json", destination / arm / "experiment.json")
        export(raw / "manifest.json", destination / arm / "manifest.json")
        rows = read(raw / "manifest.json")
        for row in rows:
            log = read(raw / row["run_file"])
            export(raw / row["run_file"], destination / arm / row["run_file"])
            auth = [e for e in log["evidence"]
                    if e["data"].get("resolver_role") == "authoritative"]
            retries = [p.get("content") for m in log["visible_messages"] for p in m["parts"]
                       if p.get("tool_name") == "final_result" and p.get("outcome") == "retried"]
            row["authoritative_measurements_by_type"] = dict(Counter(e["data"].get("qtype") for e in auth))
            row["rejected_or_partial_attempts"] = dict(Counter(
                a["error"]["code"] for a in log["attempts"] if a.get("error")))
            row["output_retry_feedback"] = retries
            row["formal_measured_facts_count"] = len(log["result"].get("measured_facts", []))
            row["independent_semantic_review"] = "PENDING"
            all_rows.append(row)
        summaries[arm] = dict(
            source_ref=metadata["source_ref"], source_hash_verification=verified,
            runs=len(rows), validated_outputs=sum(r["validated_agent_output"] for r in rows),
            fallback_runs=sum(r["fallback"] for r in rows),
            per_scenario={s: dict(runs=sum(r["scenario"] == s for r in rows),
                validated=sum(r["scenario"] == s and r["validated_agent_output"] for r in rows))
                for s in ("serial", "ns_timeout", "normal")},
            totals={k: sum(r[k] for r in rows) for k in ("A", "Q", "E", "output_attempts", "output_resubmissions")},
            mean_elapsed_seconds=round(statistics.mean(r["elapsed_seconds"] for r in rows), 3),
            usage_recorded_runs=sum(r.get("usage") is not None for r in rows),
            usage_note="Old failed log has no usage; token totals are partial, not a billing estimate.",
            recorded_token_totals={k: sum((r.get("usage") or {}).get(k, 0) for r in rows)
                                   for k in ("input_tokens", "output_tokens", "cache_read_tokens", "requests")},
        )
    result = dict(
        mode="real_DeepSeek_API_and_controlled_loopback_DNS_not_public_DNS",
        review="descriptive_automatic_counts_pending_independent_human_semantic_review",
        model="deepseek-flash", thinking="disabled", temperature=0,
        limitations=[
            "Only 3 repeats per critical scenario and 1 control; model service version/load/cache not pinned.",
            "Arms ran in separate concurrent processes on the same host; timing is not a controlled performance benchmark.",
            "Controlled server addresses in tool feedback elicited private-resolver requests that production policy rejected; all count in A.",
            "Agent output validation and deterministic findings do not establish root-cause or localization accuracy.",
            "Baseline serial already validated 3/3; no improvement in serial success rate is established.",
            "No new public-target network experiment or remote CI run.",
        ], arms=summaries, runs=all_rows,
    )
    # Apply the same exporter to embedded resolver/configuration text too.
    temp = destination / "summary.json"
    temp.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    export(temp, temp)
    return summaries


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path)
    args = parser.parse_args()
    result = summarize(args.source, args.destination)
    for arm, data in result.items():
        print(arm, data["validated_outputs"], "/", data["runs"], data["totals"], data["mean_elapsed_seconds"])
