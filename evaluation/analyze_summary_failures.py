"""Read saved failures, never rewrite experiments or pass scoring to the Agent."""
import json
from pathlib import Path


def analyze(out):
    if out.exists():raise FileExistsError("Preserve previous analysis")
    rows=[]
    for path in Path("results/published/dns-accuracy-f0787c0").glob("*/*.json"):
        log=json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(log,dict) or log.get("status")!="failed" or "visible_messages" not in log:continue
        returns=[p.get("content") for m in log["visible_messages"] for p in m["parts"]
                 if p.get("part_kind")=="tool-return" and p.get("tool_name")=="final_result"]
        draft=log.get("model_draft") or {}
        actual={a["attempt_id"]:a for a in log["attempts"]}
        mismatches=[]
        for issue in draft.get("execution_issues",[]):
            a=actual.get(issue["attempt_id"])
            if not a:mismatches.append(dict(attempt_id=issue["attempt_id"],reason="unknown_attempt"));continue
            mismatches.append(dict(attempt_id=issue["attempt_id"],declared_tool=issue.get("tool_name"),actual_tool=a["tool_name"],
                declared_code=issue.get("error_code"),actual_outer_code=(a.get("error") or {}).get("code"),
                declared_type=issue.get("record_type"),requested_type=a.get("input",{}).get("record_type","A")))
        rows.append(dict(source_file=path.as_posix(),run_id=log["run_id"],error=log.get("error"),
            evidence_count=len(log["evidence"]),attempt_count=len(log["attempts"]),validation_feedback=returns,
            declared_program_owned_fields=sorted(set(draft)&{"execution_issues","measured_facts","observations","findings","dns_comparison"}),
            execution_issue_details=mismatches,visible_message_characters=len(json.dumps(log["visible_messages"],ensure_ascii=False)),
            limitation="Saved validation feedback establishes rejection cause; not every field has independent semantic review."))
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(dict(mode="historical_failure_analysis_no_model",runs=rows,
        conclusion="Stored feedback identifies repeated A-issue/measurement-field rejections, including child-versus-outer codes and earlier composite type expectations. Full report schema burdens the model with program-owned fields; does not establish a model capability limit.",
        review="AI_assisted_pending_human_review"),ensure_ascii=False,indent=2),encoding="utf-8")
    print("saved failures analyzed:",len(rows))


if __name__=="__main__":analyze(Path("results/published/security-stability/failure-analysis.json"))
