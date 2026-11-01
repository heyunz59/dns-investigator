"""Scoped pair comparisons; failures do not erase comparable responding subsets."""
from datetime import datetime
from itertools import combinations
from .dns_wire import comparable_response,dns_outcome

MAX_COMPARISON_SECONDS=300


def evidence_rows(evidence):
    return [{**e["data"],"evidence_id":e["id"],"source_mode":e.get("source_mode","unknown"),
             "measured_at":e.get("started_at"),"parent_tool_call_id":e.get("tool_call_id"),
             "query_attempt_id":e.get("query_attempt_id")} for e in evidence if e.get("data",{}).get("qname")]


def normal(value):
    return value.lower().rstrip(".") if isinstance(value,str) else value


def path(row):
    return dict(evidence_id=row.get("evidence_id"),attempt_id=row.get("parent_tool_call_id"),
        query_attempt_id=row.get("query_attempt_id"),target=normal(row.get("qname")),record_type=row.get("qtype"),
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
    times=[r.get("measured_at") for r in (a,b)]
    if all(times):
        try:
            if abs((datetime.fromisoformat(times[0])-datetime.fromisoformat(times[1])).total_seconds())>MAX_COMPARISON_SECONDS:
                return "TIME_WINDOW_DIFFERS"
        except (ValueError,TypeError):return "TIME_NOT_COMPARABLE"
    return None


def compare_details(rows):
    pairs=[];codes=[];observations=[]
    for i,j in combinations(range(len(rows)),2):
        a,b=rows[i],rows[j];sa,sb=dns_outcome(a),dns_outcome(b)
        item=dict(path_indices=[i,j],evidence_ids=[r["evidence_id"] for r in (a,b) if r.get("evidence_id")],
                  codes=[],comparable=False,reason=scope_reason(a,b))
        pairs.append(item)
        if item["reason"]:continue
        if any(r.get("execution_status","ok")!="ok" for r in (a,b)):
            item["reason"]="EXECUTION_FAILED";continue
        if {sa["transport_status"],sb["transport_status"]}=={"timeout","responded"}:
            item.update(codes=["QUERY_AVAILABILITY_DIFFERENCE"],reason="NO_CONTENT_FROM_TIMEOUT")
            codes+=item["codes"];continue
        if not comparable_response(a) or not comparable_response(b):
            item["reason"]="INCOMPLETE_OR_NO_RESPONSE";continue
        if any(s["result_kind"] in {"NODATA","NXDOMAIN"} for s in (sa,sb)):
            terminal=[normal(r.get("negative_name") or r.get("canonical_name") or r.get("qname")) for r in (a,b)]
            if terminal[0]!=terminal[1]:
                item["reason"]="NEGATIVE_SCOPE_DIFFERS";continue
        item["comparable"]=True
        if sa["dns_rcode"]!=sb["dns_rcode"]:item["codes"].append("RCODE_DISAGREEMENT")
        if bool(a.get("records"))!=bool(b.get("records")):item["codes"].append("RECORD_PRESENCE_DISAGREEMENT")
        values=lambda r:tuple(sorted(x["value"].lower().rstrip(".") for x in r.get("records",[])))
        if values(a)!=values(b):item["codes"].append("ADDRESS_SET_DIFFERENCE")
        chain=lambda r:tuple((normal(x.get("name")),normal(x.get("target"))) if isinstance(x,dict) else normal(x) for x in r.get("cname_chain",[]))
        if chain(a)!=chain(b):item["codes"].append("CNAME_DIFFERENCE")
        if a.get("soa_serials")!=b.get("soa_serials") and a.get("qtype")=="SOA":item["codes"].append("SOA_SERIAL_DIFFERENCE")
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
