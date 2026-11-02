"""Compact model context. Full packets and measurements remain in the evidence ledger."""
from .reporting import facts,issues
from .dns_diagnosis import diagnose
from .alias_scope import alias_paths
import hashlib
import json


def record_aggregate(records,typ):
    values=sorted({str(r.get("value","")).lower().rstrip(".") for r in records})
    ttls=[r["ttl"] for r in records if isinstance(r.get("ttl"),(int,float))]
    serials=[]
    if typ=="SOA":
        for value in values:
            try:serials.append(int(value.split()[2]))
            except (ValueError,IndexError):pass  # Legacy/malformed text remains in raw E.
    return dict(total_count=len(records),unique_values=len(values),
        value_set_sha256=hashlib.sha256(json.dumps(values,ensure_ascii=False).encode()).hexdigest(),
        ttl_min=min(ttls) if ttls else None,ttl_max=max(ttls) if ttls else None,
        soa_serials=list(dict.fromkeys(serials)))


def current_state(backend,response):
    measured=[]
    for fact in facts(backend.calls):
        row={k:v for k,v in fact.items() if v is not None}
        if len(row.get("records",[]))>16:
            row["record_aggregate"]=record_aggregate(row["records"],row.get("record_type"))
            row["records_omitted_count"]=len(row["records"])-16;row["records"]=row["records"][:16]
        measured.append(row)
    findings=[{k:f[k] for k in ("code","status","scope","evidence_ids","explanation","limitations","next_checks","provenance","finding_status","validation_result_ids") if k in f} for f in diagnose(backend.calls)]
    partial=[dict(attempt_id=a["attempt_id"],queries=a["dns_execution_issues"]) for a in backend.attempts if a.get("dns_execution_issues")]
    scope=alias_paths(backend)
    blocked=[dict(tool_name=name,arguments=arguments) for name,arguments in (json.loads(x) for x in sorted(backend.blocked))]
    return dict(id=response.get("id"),tool_call_id=response.get("tool_call_id",response.get("attempt_id")),
        error=response.get("error"),new_evidence_ids=[e["id"] for e in backend.owned_evidence(response.get("tool_call_id",response.get("attempt_id")))],
        fact_summary=measured,current_findings=findings,execution_issue_summary=[i.model_dump() for i in issues(backend.attempts)],
        partial_dns_issues=partial,authority_investigations=[dict(attempt_id=a["attempt_id"],**a["authority_state"]) for a in backend.attempts if a.get("authority_state")],
        allowed_dns_targets=list(scope.values()),finish_now=backend.finish_now,
        query_scope=dict(independent_tool_targets=[backend.target.domain],query_dns_targets=list(scope),
            system_resolver_argument=None,configured_public_resolvers=[r for r in backend.resolvers if r is not None],
            resolver_policy="系统路径用 resolver=None；其他显式地址仍须通过现有公共/系统地址策略。权威候选请用 query_authoritative，内部 NS 名称不自动授权为独立目标。"),
        non_retryable_requests=blocked,
        non_retryable_dns_paths=[dict(attempt_id=a["attempt_id"],qname=q.get("qname"),qtype=q.get("qtype"),resolver=q.get("resolver"),error=q.get("error"))
            for a in backend.attempts for q in a.get("dns_execution_issues",[]) if (q.get("error") or {}).get("retryable") is False],
        tool_coverage=dict(query_authoritative="单次已包含区域SOA/NS、NS地址、选中NS的目标类型及补充SOA；先复用这些E，再决定是否确需重采样。"),
        budget=dict(tool_attempts_remaining=max(0,backend.max_calls-len(backend.attempts)),dns_requests_remaining=max(0,backend.dns.limit-len(backend.dns.attempts))),
        context_policy="compact_v2; complete raw DNS/HTTP evidence retained in JSON/JSONL; omitted records are not absent; aggregate describes the full record set, not only the 16 visible records")
