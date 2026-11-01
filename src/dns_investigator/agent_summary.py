"""Compact model context. Full packets and measurements remain in the evidence ledger."""
from .reporting import facts,issues
from .dns_diagnosis import diagnose
from .alias_scope import alias_paths


def current_state(backend,response):
    measured=[]
    for fact in facts(backend.calls):
        row={k:v for k,v in fact.items() if v is not None}
        if len(row.get("records",[]))>16:
            row["records_omitted_count"]=len(row["records"])-16;row["records"]=row["records"][:16]
        measured.append(row)
    findings=[{k:f[k] for k in ("code","status","scope","evidence_ids","explanation","limitations","next_checks")} for f in diagnose(backend.calls)]
    partial=[dict(attempt_id=a["attempt_id"],queries=a["dns_execution_issues"]) for a in backend.attempts if a.get("dns_execution_issues")]
    return dict(id=response.get("id"),tool_call_id=response.get("tool_call_id",response.get("attempt_id")),
        error=response.get("error"),new_evidence_ids=[e["id"] for e in backend.owned_evidence(response.get("tool_call_id",response.get("attempt_id")))],
        fact_summary=measured,current_findings=findings,execution_issue_summary=[i.model_dump() for i in issues(backend.attempts)],
        partial_dns_issues=partial,authority_investigations=[dict(attempt_id=a["attempt_id"],**a["authority_state"]) for a in backend.attempts if a.get("authority_state")],
        allowed_dns_targets=list(alias_paths(backend).values()),finish_now=backend.finish_now,
        budget=dict(tool_attempts_remaining=max(0,backend.max_calls-len(backend.attempts)),dns_requests_remaining=max(0,backend.dns.limit-len(backend.dns.attempts))),
        context_policy="compact_v1; complete raw DNS/HTTP evidence retained in JSON/JSONL; omitted records are not absent")
