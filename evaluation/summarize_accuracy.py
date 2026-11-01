"""Explicit mechanical replay metrics + executed-run manifests; no semantic accuracy claim."""
import hashlib
import importlib.util
import json
from collections import Counter
from pathlib import Path
import subprocess
import sys

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
spec=importlib.util.spec_from_file_location("export_run",ROOT/"scripts/export_run.py")
export_module=importlib.util.module_from_spec(spec);spec.loader.exec_module(export_module)

CONTENT={"RESOLVER_DISAGREEMENT","RECURSIVE_AUTH_MISMATCH","AUTH_SERVER_DISAGREEMENT",
    "RECURSIVE_RESPONSE_DISAGREEMENT","RECURSIVE_AUTH_RESPONSE_MISMATCH","AUTHORITATIVE_RESPONSE_DISAGREEMENT"}


def replay_metrics(payload):
    rows=[]
    for name,c in payload["cases"].items():
        by_id={e["id"]:e for e in c["evidence"]}
        false_conflicts=sum(f["code"] in CONTENT and any(by_id[i]["data"].get("result_kind",by_id[i]["data"].get("rcode"))=="TIMEOUT" for i in f["evidence_ids"]) for f in c["findings"])
        keys=[]
        for f in c["findings"]:
            scope=tuple(sorted({(by_id[i]["data"].get("qname"),by_id[i]["data"].get("qtype")) for i in f["evidence_ids"]}))
            keys.append((f["code"],scope))
        rows.append(dict(case=name,E=len(c["evidence"]),finding_count=len(c["findings"]),
            timeout_in_content_conflict_findings=false_conflicts,
            repeated_code_query_scope_count=sum(n-1 for n in Counter(keys).values()),
            codes=dict(Counter(f["code"] for f in c["findings"]))))
    return rows


def summarize():
    out=ROOT/"results/published/dns-accuracy-f0787c0"
    before=json.loads((out/"baseline-replay.json").read_text(encoding="utf-8"))
    after=json.loads((out/"release-replay.json").read_text(encoding="utf-8"))
    expectation=json.loads((ROOT/"evaluation/accuracy_expectations.json").read_text(encoding="utf-8"))
    checks=[]
    for case,expected in expectation["cases"].items():
        codes={f["code"] for f in after["cases"][case]["findings"]}
        checks.append(dict(case=case,required_present=set(expected.get("required",[]))<=codes,
            forbidden_absent=not bool(set(expected.get("forbidden",[]))&codes)))
    executions=[]
    refs={"old":"f0787c0","new":"d0857cd","final":"0f9cd72","release":"10ccb5e"}
    for arm,label in [("old","old"),("new","intermediate"),("final","final"),("release","release")]:
        source=ROOT/f"results/runs/dns-accuracy-20261101-{arm}"
        destination=out/f"controlled-{label}";destination.mkdir(exist_ok=True)
        for file in source.glob("*.json"):
            export_module.export(file,destination/file.name)
        manifest=json.loads((source/f"{arm}-manifest.json").read_text(encoding="utf-8"))
        for row in manifest:
            verification={}
            for name,digest in row["source_hashes"].items():
                content=subprocess.check_output(["git","show",f'{refs[arm]}:src/dns_investigator/{name}'])
                variants={"git_blob":content,"git_blob_with_CRLF":content.replace(b"\r\n",b"\n").replace(b"\n",b"\r\n")}
                matches=[kind for kind,data in variants.items() if hashlib.sha256(data).hexdigest()==digest]
                assert matches,(arm,name)
                verification[name]=matches[0]
            row["source_commit"]=refs[arm]
            row["source_verification"]=verification
        executions+=manifest
    payload=dict(review="AI_assisted_automatic_rules_pending_independent_human_review",
        baseline_commit="f0787c063ca11a95d9255c1e68b8b95697b9b90b",final_production_source_commit="10ccb5e",
        final_source_hashes=after["source_hashes"],
        replay_before=replay_metrics(before),replay_after=replay_metrics(after),fixed_acceptance_checks=checks,
        model_executions=executions,model_trials_per_case_per_arm=1,
        source_phases=refs,release_paid_model_scope=["timeout"],
        historical_live_source_unchanged=before["historical_source_sha256"]==after["historical_source_sha256"],
        limits=["Replay evaluates fixed evidence, not autonomous tool selection.",
                "Loopback DNS is constructed wire traffic, not a complete recursive server or public network test.",
                "Original and intermediate attempts/failures preserved. Final serial may fail; inspect actual status.",
                "Root assertion correctness, localization semantics, next-step value require human review; counters are not overall accuracy.",
                "Tools cannot explicitly revisit untrusted private loopback IPs; some model attempts hit test-environment permission restrictions. No production guard was relaxed.",
                "No new public DNS/TCP/HTTP measurements or remote GitHub Actions verification in this upgrade."])
    (out/"summary.json").write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding="utf-8")
    print("Replay cases:",len(checks),"mechanical requirements met:",sum(c["required_present"] and c["forbidden_absent"] for c in checks))
    for arm in ("old","new","final","release"):
        subset=[e for e in executions if e["arm"]==arm]
        print(arm,len(subset),"A/Q/E",*(sum(e[k] for e in subset) for k in ("A","Q","E")),"seconds",round(sum(e["elapsed_seconds"] for e in subset),3))


if __name__=="__main__":summarize()
