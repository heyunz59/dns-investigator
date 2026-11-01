"""Observed execution metrics only; semantic claims remain pending human review."""
import json
import sys
from pathlib import Path


def calculate(directory):
    rows=json.loads((directory/"summary.json").read_text(encoding="utf-8"))
    expected={"D1":"DNS_INCONCLUSIVE","D2":"RESOLVER_DISAGREEMENT","D3":"DNS_TIMEOUT",
        "D4":"RECURSIVE_AUTH_MISMATCH","D5":"AUTH_SERVER_DISAGREEMENT","D6":"NODATA_OBSERVED",
        "D7":"DNS_TIMEOUT","D8":"DNS_INCONCLUSIVE","D9":"DNS_TIMEOUT","D10":"DNS_INCONCLUSIVE"}
    for row in rows:
        log=json.loads((directory/row["run_file"]).read_text(encoding="utf-8"))
        current={**expected,"D2":"RECURSIVE_RESPONSE_DISAGREEMENT","D3":"RECURSIVE_QUERY_TIMEOUT",
            "D4":"RECURSIVE_AUTH_RESPONSE_MISMATCH","D5":"AUTHORITATIVE_RESPONSE_DISAGREEMENT",
            "D7":"RECURSIVE_QUERY_TIMEOUT","D8":"RECORD_SET_DIFFERENCE","D9":"AUTHORITATIVE_QUERY_TIMEOUT"}
        row["rule_policy"]="scoped_dns_v2" if log.get("schema_version",0)>=5 else "legacy_v3"
        row["expected_rule_finding_present"]=(current if log.get("schema_version",0)>=5 else expected)[row["case"]] in row["finding_codes"]
        row["mechanically_valid_tool_calls"]=sum(a["status"] in {"measured","unavailable","execution_error"} for a in log["attempts"])
        row["non_dns_tool_calls"]=sum(a["tool_name"] in {"check_tcp","check_http"} for a in log["attempts"])
        row["key_measurement_coverage"]={"observed_dns_measurements":row["measurements"],
            "roles":sorted({e["data"].get("resolver_role","recursive") for e in log["evidence"]}),
            "authoritative_aa_responses":sum(bool(e["data"].get("flags",{}).get("AA")) for e in log["evidence"])}
        row["semantic_diagnosis_accuracy"]="PENDING_HUMAN_REVIEW"
    (directory/"metrics.json").write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding="utf-8")


if __name__=="__main__":calculate(Path(sys.argv[1]))
