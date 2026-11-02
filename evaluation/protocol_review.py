"""Mechanical review of developer regression data; no semantic accuracy score."""
import argparse
import hashlib
import json
from collections import Counter
from pathlib import Path


def load(path):return json.loads(Path(path).read_text(encoding="utf-8"))


def review(reference,agent,output):
    if output.exists():raise FileExistsError("Preserve previous reviews")
    reference_data=load(reference);rows=[]
    boundaries={"nsec3_policy","opt_out","algorithm16","key_timeout","cohosted_unproven","nsec3_invalid_owner","nsec3_dname"}
    for r in reference_data["runs"]:
        ref=r["reference"]
        status=None if ref.get("error") else "SECURE" if ref["secure"] else "BOGUS" if ref["bogus"] else "INSECURE"
        project=r["project"];core=r["scenario"] not in boundaries
        e={e["id"]:e for e in r["evidence"]};v={v["id"]:v for v in r["validation_results"]}
        link_errors=[]
        for item in v.values():
            if set(item["evidence_ids"])-e.keys() or set(item["validation_result_ids"])-v.keys():link_errors.append(item["id"])
            if any(e[i]["parent_tool_call_id"]!=item["parent_tool_call_id"] for i in item["evidence_ids"] if i in e):link_errors.append(item["id"])
        rows.append(dict(case=r["scenario"],declared_core=core,project=project["dnssec_status"],reference=status,
            reference_error=ref.get("error"),agreement=(project["dnssec_status"]==status) if status else None,
            false_secure=(project["dnssec_status"]=="SECURE" and status not in {None,"SECURE"}),
            false_bogus=(project["dnssec_status"]=="BOGUS" and status not in {None,"BOGUS"}),
            A=len(r["attempts"]),Q=len(r["dns_attempts"]),E=len(e),V=len(v),
            compute=project.get("compute"),reference_packets=len(r["external_reference_packets"]),link_errors=link_errors))
    manifest=load(agent/"manifest.json");agent_rows=[]
    source=load(agent/"experiment.json")
    for r in manifest:
        log=load(agent/r["file"])
        agent_rows.append({**r,"output_attempts":log.get("output_attempt_count"),"output_resubmissions":log.get("output_resubmissions"),
            "validation_errors":log.get("validation_errors"),"unnecessary_calls":"PENDING_HUMAN_REVIEW",
            "error_root_cause_assertions":"PENDING_HUMAN_REVIEW"})
    all_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path("src/dns_investigator").glob("*.py")}
    summary=dict(review="developer_automated_checks_pending_independent_human_review",holdout=False,
        regression_development_set=True,semantic_accuracy="not_established",source_ref=reference_data["source_ref"],
        reference_comparison_warning="false_secure/false_bogus are mechanical reference-disagreement candidates, not independently adjudicated errors; all boundary rows remain visible",
        source_hashes_match_current=reference_data["source_hashes"]==all_hashes==source["source_hashes"],
        protocol=dict(cases=len(rows),core_cases=sum(r["declared_core"] for r in rows),
            core_reference_agreements=sum(r["declared_core"] and r["agreement"] is True for r in rows),
            false_secure=sum(r["false_secure"] for r in rows),false_bogus=sum(r["false_bogus"] for r in rows),
            project_statuses=dict(Counter(r["project"] for r in rows)),rows=rows),
        agent=dict(cases=len(agent_rows),statuses=dict(Counter(r["status"] for r in agent_rows)),
            execution_completed=sum(r["agent_status"]=="completed" for r in agent_rows),
            A=sum(r["A"] for r in agent_rows),Q=sum(r["Q"] for r in agent_rows),E=sum(r["E"] for r in agent_rows),V=sum(r["V"] for r in agent_rows),
            input_tokens=sum((r["usage"] or {}).get("input_tokens",0) for r in agent_rows),
            output_tokens=sum((r["usage"] or {}).get("output_tokens",0) for r in agent_rows),
            requests=sum((r["usage"] or {}).get("requests",0) for r in agent_rows),
            seconds=sum(r["elapsed_seconds"] for r in agent_rows),rows=agent_rows))
    output.write_text(json.dumps(summary,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps({"hashes_match":summary["source_hashes_match_current"],
        "protocol":{k:v for k,v in summary["protocol"].items() if k!="rows"},
        "agent":{k:v for k,v in summary["agent"].items() if k!="rows"}},indent=2))


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("reference",type=Path);p.add_argument("agent",type=Path);p.add_argument("output",type=Path)
    a=p.parse_args();review(a.reference,a.agent,a.output)
