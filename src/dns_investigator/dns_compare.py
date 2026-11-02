"""Scoped pair comparisons; failures do not erase comparable responding subsets."""
from datetime import datetime
from itertools import combinations
from .dns_wire import comparable_response,dns_outcome

MAX_COMPARISON_SECONDS=300


def evidence_rows(evidence):
    return [{**e["data"],"evidence_id":e["id"],"source_mode":e.get("source_mode","unknown"),
             "measured_at":e.get("started_at"),"parent_tool_call_id":e.get("tool_call_id"),
             "query_attempt_id":e.get("query_attempt_id"),"target_authorization":e.get("target_authorization")} for e in evidence if e.get("data",{}).get("qname")]


def normal(value):
    return value.lower().rstrip(".") if isinstance(value,str) else value


def measured_time(row):
    value=row.get("measured_at")
    if value is None:return None
    try:
        parsed=datetime.fromisoformat(value)
        return parsed if parsed.tzinfo is not None and parsed.utcoffset() is not None else None
    except (TypeError,ValueError):return None


def time_relation(a,b):
    if not a.get("measured_at") or not b.get("measured_at"):return "TIME_UNKNOWN"
    left,right=measured_time(a),measured_time(b)
    if left is None or right is None:return "TIME_INVALID"
    return "TIME_COMPARABLE" if abs((left-right).total_seconds())<=MAX_COMPARISON_SECONDS else "TIME_WINDOW_DIFFERS"


def path(row):
    return dict(evidence_id=row.get("evidence_id"),attempt_id=row.get("parent_tool_call_id"),
        query_attempt_id=row.get("query_attempt_id"),target=normal(row.get("qname")),record_type=row.get("qtype"),
        query_stage=row.get("query_stage"),
        resolver=row.get("resolver"),role=row.get("resolver_role","recursive"),
        source_mode=row.get("source_mode","unknown"),measured_at=row.get("measured_at"),
        execution_status=row.get("execution_status","ok"),error=row.get("error"),**dns_outcome(row))


def scope_reason(a,b):
    if (normal(a.get("qname")),a.get("qtype"))!=(normal(b.get("qname")),b.get("qtype")):
        return "QUERY_SCOPE_DIFFERS"
    if a.get("source_mode","unknown")!=b.get("source_mode","unknown"):
        return "SOURCE_MODE_DIFFERS"
    for row in (a,b):
        if row.get("resolver_role")=="authoritative" and not row.get("flags",{}).get("AA"):
            return "AUTHORITY_NOT_CONFIRMED"
    return None


def compare_details(rows):
    pairs=[];codes=[];observations=[]
    for i,j in combinations(range(len(rows)),2):
        a,b=rows[i],rows[j];sa,sb=dns_outcome(a),dns_outcome(b)
        item=dict(path_indices=[i,j],evidence_ids=[r["evidence_id"] for r in (a,b) if r.get("evidence_id")],
                  codes=[],comparable=False,time_status=time_relation(a,b),reason=scope_reason(a,b))
        pairs.append(item)
        if item["reason"]:continue
        if any(r.get("execution_status","ok")!="ok" for r in (a,b)):
            item["reason"]="EXECUTION_FAILED";continue
        if {sa["transport_status"],sb["transport_status"]}=={"timeout","responded"}:
            item.update(codes=["QUERY_AVAILABILITY_DIFFERENCE"],reason="NO_CONTENT_FROM_TIMEOUT" if item["time_status"]=="TIME_COMPARABLE" else item["time_status"])
            codes+=item["codes"];continue
        if not comparable_response(a) or not comparable_response(b):
            item["reason"]="INCOMPLETE_OR_NO_RESPONSE";continue
        if any(s["result_kind"] in {"NODATA","NXDOMAIN"} for s in (sa,sb)):
            terminal=[normal(r.get("negative_name") or r.get("canonical_name") or r.get("qname")) for r in (a,b)]
            if terminal[0]!=terminal[1]:
                item["reason"]="NEGATIVE_SCOPE_DIFFERS";continue
        item["comparable"]=item["time_status"]=="TIME_COMPARABLE"
        if not item["comparable"]:item["reason"]=item["time_status"]
        if sa["dns_rcode"]!=sb["dns_rcode"]:item["codes"].append("RCODE_DISAGREEMENT")
        if bool(a.get("records"))!=bool(b.get("records")):item["codes"].append("RECORD_PRESENCE_DISAGREEMENT")
        values=lambda r:tuple(sorted(x["value"].lower().rstrip(".") for x in r.get("records",[])))
        if values(a)!=values(b):item["codes"].append("ADDRESS_SET_DIFFERENCE")
        chain=lambda r:tuple((normal(x.get("name")),normal(x.get("target"))) if isinstance(x,dict) else normal(x) for x in r.get("cname_chain",[]))
        if chain(a)!=chain(b):item["codes"].append("CNAME_DIFFERENCE")
        if a.get("soa_serials")!=b.get("soa_serials") and a.get("qtype")=="SOA":item["codes"].append("SOA_SERIAL_DIFFERENCE")
        if item["codes"] and not item["comparable"]:item["codes"].append("NONCONTEMPORANEOUS_DIFFERENCE")
        observations.append(dict(path_indices=[i,j],evidence_ids=item["evidence_ids"],
            ttl_values=[[x.get("ttl") for x in r.get("records",[])] for r in (a,b)],
            duration_ms=[r.get("duration_ms") for r in (a,b)],interpretation="TTL 与耗时为单次观测，不证明缓存、配置或性能异常。"))
        codes+=item["codes"]
    if not codes:
        codes=["NO_SIGNIFICANT_DIFFERENCE" if any(p["comparable"] for p in pairs) else "COMPARISON_INCONCLUSIVE"]
    return dict(scope=dict(max_time_gap_seconds=MAX_COMPARISON_SECONDS),paths=[path(r) for r in rows],pairs=pairs,
        differences=list(dict.fromkeys(codes)),observations=observations,
        limitations=["时间/来源缺失的旧记录不能证明同时或同源；响应差异不等于唯一根因。",
                      "记录差异可能来自 CDN、GeoDNS、负载均衡、缓存、策略和查询时间；超时没有提供记录或 TTL 事实。"])


def compare(rows):
    """Compatibility facade; full paths and exclusions in compare_details."""
    return compare_details(rows)["differences"]
