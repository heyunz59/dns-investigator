"""Deterministic evidence findings, without model calls or asserted root causes."""
from itertools import combinations
from .dns_compare import compare


def diagnose(evidence):
    findings=[]
    rows=[(e,e["data"]) for e in evidence if e.get("execution_status")=="ok" and
          e.get("data",{}).get("qname") and not e["data"].get("flags",{}).get("TC")]
    def add(code,stage,ids,explanation):
        findings.append(dict(code=code,stage=stage,status="observed",evidence_ids=ids,
            explanation=explanation,limitations=["单次观测不证明唯一根因；缓存、CDN、策略、路径与时间差仍需核实。"],
            next_checks=["比较同名同类型的递归及 AA 权威回答，保留未知与时间差。 "]))
    for e,r in rows:
        code={"NXDOMAIN":"NXDOMAIN_OBSERVED","TIMEOUT":"DNS_TIMEOUT","SERVFAIL":"DNS_SERVFAIL","REFUSED":"DNS_REFUSED"}.get(r.get("rcode"))
        if r.get("rcode")=="NOERROR" and not r.get("records") and r.get("result_kind") != "REFERRAL":
            code="NODATA_OBSERVED"
        if code:
            add(code,r.get("resolver_role","recursive"),[e["id"]],f"{r.get('qname')} {r.get('qtype')} 本次返回 {r.get('result_kind',r.get('rcode'))}；不推断注册状态或服务器宕机。")
    for (ea,a),(eb,b) in combinations(rows,2):
        if (a.get("qname"),a.get("qtype")) != (b.get("qname"),b.get("qtype")):
            continue
        roles={a.get("resolver_role","recursive"),b.get("resolver_role","recursive")}
        if "authoritative" in roles and any(r.get("resolver_role")=="authoritative" and not r.get("flags",{}).get("AA") for r in (a,b)):
            continue
        significant=any(c in compare([a,b]) for c in ("RCODE_DISAGREEMENT","RECORD_PRESENCE_DISAGREEMENT"))
        serial=a.get("soa_serials") != b.get("soa_serials") and a.get("qtype")=="SOA"
        address={r["value"] for r in a.get("records",[])} != {r["value"] for r in b.get("records",[])}
        if roles=={"recursive"} and a.get("resolver") != b.get("resolver") and significant:
            add("RESOLVER_DISAGREEMENT","recursive",[ea["id"],eb["id"]],"不同递归解析路径返回不同响应状态；建议获取权威证据。")
        elif roles=={"recursive","authoritative"} and (significant or address):
            add("RECURSIVE_AUTH_MISMATCH","recursive-authoritative",[ea["id"],eb["id"]],"递归与 AA 权威回答有差异；缓存及正常调度仍可能解释差异。")
        elif roles=={"authoritative"} and a.get("resolver") != b.get("resolver") and (significant or serial or address):
            add("AUTH_SERVER_DISAGREEMENT","authoritative",[ea["id"],eb["id"]],"不同 AA 权威回答或 SOA Serial 存在差异；不直接确认同步故障。")
    if not findings:
        findings.append(dict(code="DNS_INCONCLUSIVE",stage="dns",status="insufficient_information",
            evidence_ids=[e["id"] for e,r in rows],explanation="未发现足以定位故障的 DNS 状态差异。",
            limitations=["正常查询不能排除历史或客户端差异。"],next_checks=["按问题需要补充证据；不要强制执行全部工具。 "]))
    return findings
