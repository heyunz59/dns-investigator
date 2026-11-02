"""Deterministic scoped observations and localization; no confirmed causal verdicts."""
from collections import defaultdict
from datetime import datetime
from .dns_compare import compare_details,evidence_rows,normal,measured_time,time_relation
from .dns_wire import dns_outcome,comparable_response
from .alias_scope import completed_followups


def _windows(rows):
    groups=defaultdict(list)
    for row in rows:
        groups[(normal(row["qname"]),row.get("qtype"),row.get("source_mode","unknown"))].append(row)
    for group in groups.values():
        # Bound the whole window, not a transitive chain of pairwise time gaps.
        def stamp(r):
            parsed=measured_time(r)
            return parsed.timestamp() if parsed else None
        known=sorted((r for r in group if stamp(r) is not None),key=stamp)
        while known:
            first=stamp(known[0]);part=[r for r in known if stamp(r)-first<=300]
            known=known[len(part):];yield part
        missing=[r for r in group if stamp(r) is None]
        if missing:yield missing


def diagnose(evidence):
    findings=[]
    rows=evidence_rows([e for e in evidence if e.get("execution_status")=="ok"])
    all_by_id={r["evidence_id"]:r for r in rows}
    completed=completed_followups(rows)
    for group in _windows(rows):
        first=group[0];by_id={r["evidence_id"]:r for r in group}
        def add(code,stage,selected,explanation,affected=None):
            selected=list(dict.fromkeys(selected));facts=[all_by_id[eid] for eid in selected]
            paths=[dict(resolver=r.get("resolver"),role=r.get("resolver_role","recursive"),evidence_id=r["evidence_id"]) for r in facts]
            affected=selected if affected is None else affected
            timed=sorted((r for r in facts if measured_time(r) is not None),key=measured_time)
            scope=dict(target=normal(first["qname"]),record_type=first.get("qtype"),source_mode=first.get("source_mode"),
                dns_followup_only=any(r.get("target_authorization") for r in facts),paths=paths,
                time_start=timed[0]["measured_at"] if timed else None,
                time_end=timed[-1]["measured_at"] if timed else None)
            observed=[dict(evidence_id=r["evidence_id"],qname=r["qname"],qtype=r.get("qtype"),measured_at=r.get("measured_at"),source_mode=r.get("source_mode"),resolver=r.get("resolver"),role=r.get("resolver_role","recursive"),
                authoritative_answer=r.get("flags",{}).get("AA",False),negative_name=r.get("negative_name"),
                records=r.get("records",[]),soa_serials=r.get("soa_serials",[]),**dns_outcome(r)) for r in facts]
            checks=next_checks(code,scope,observed)
            findings.append(dict(code=code,stage=stage,status="observed",scope=scope,evidence_ids=selected,
                observed_facts=observed,localization=dict(affected_evidence_ids=affected,
                    other_paths=[dict(evidence_id=r["evidence_id"],resolver=r.get("resolver"),**dns_outcome(r)) for r in group if r["evidence_id"] not in affected],
                    interpretation="只定位列出的查询与路径；异常不自动归因于整台解析器或整个域名。"),
                root_cause_confirmed=False,explanation=explanation,
                limitations=["单次观测不能区分缓存、策略、调度、网络路径或服务因素；未确认唯一根因。",
                             "缺失时间/来源的旧日志保留未知；未执行 DNSSEC 验证或完整迭代解析。"],next_checks=checks))
        unary=defaultdict(list)
        for r in group:
            state=dns_outcome(r);kind=state["result_kind"];role=r.get("resolver_role","recursive")
            if state["transport_status"]=="timeout":
                unary[("RECURSIVE_QUERY_TIMEOUT" if role=="recursive" else "AUTHORITATIVE_QUERY_TIMEOUT",role)].append(r["evidence_id"])
            elif kind in {"REFERRAL","ALIAS_INCOMPLETE","INDETERMINATE"} and r.get("cname_chain"):
                unary[("ALIAS_FOLLOWUP_COMPLETED" if r["evidence_id"] in completed else "ALIAS_RESOLUTION_INCOMPLETE",role)].append(r["evidence_id"])
            elif comparable_response(r):
                code={"NXDOMAIN":"NXDOMAIN_OBSERVED","NODATA":"NODATA_OBSERVED","SERVFAIL":"DNS_SERVFAIL","REFUSED":"DNS_REFUSED"}.get(kind)
                if code:unary[(code,role)].append(r["evidence_id"])
        for (code,role),ids in unary.items():
            described="；".join(f"{by_id[i].get('resolver')} 对 {by_id[i].get('negative_name') or first['qname']} 返回 {dns_outcome(by_id[i])['result_kind']}（{i}）" for i in ids)
            selected=ids[:]
            if code=="ALIAS_FOLLOWUP_COMPLETED":
                selected += [eid for origin in ids for proof in completed[origin] for eid in proof]
                add(code,role,selected,"原始响应的别名解析未完成；后续同来源、同解析路径、同类型的已授权查询已取得完整末端回答。原始响应不改写，否定回答仅适用于实际末端名称。",ids)
                continue
            if code.endswith("QUERY_TIMEOUT"):
                selected += [r["evidence_id"] for r in group if dns_outcome(r)["transport_status"]=="responded"
                    and any(time_relation(by_id[i],r)=="TIME_COMPARABLE" for i in ids)]
            add(code,role,selected,f"查询 {first['qname']} {first.get('qtype')}：{described}。不推断注册状态或服务器宕机。",ids)
        buckets=defaultdict(set)
        comparison=compare_details(group)
        for pair in comparison["pairs"]:
            if not pair["comparable"]:continue
            a,b=[group[i] for i in pair["path_indices"]]
            if a.get("resolver")==b.get("resolver") and a.get("resolver_role","recursive")==b.get("resolver_role","recursive"):continue
            roles={r.get("resolver_role","recursive") for r in (a,b)}
            codes=set(pair["codes"])
            status=bool(codes & {"RCODE_DISAGREEMENT","RECORD_PRESENCE_DISAGREEMENT"})
            content=bool(codes & {"ADDRESS_SET_DIFFERENCE","CNAME_DIFFERENCE","SOA_SERIAL_DIFFERENCE"})
            if not(status or content):continue
            if roles=={"recursive"}:
                code="RECURSIVE_RESPONSE_DISAGREEMENT" if status else "RECORD_SET_DIFFERENCE"
            elif roles=={"recursive","authoritative"}:code="RECURSIVE_AUTH_RESPONSE_MISMATCH"
            elif roles=={"authoritative"}:code="AUTHORITATIVE_RESPONSE_DISAGREEMENT"
            else:continue
            buckets[code].update(pair["evidence_ids"])
        for code,ids in buckets.items():
            ordered=[r["evidence_id"] for r in group if r["evidence_id"] in ids]
            add(code,"dns-comparison",ordered,
                f"{first['qname']} {first.get('qtype')} 的完整可比较响应存在状态或记录集合差异；详见各路径结果。地址及 SOA Serial 差异只是观察，正常调度和时间变化仍可能解释。")
    temporal=defaultdict(set)
    for pair in compare_details(rows)["pairs"]:
        if "NONCONTEMPORANEOUS_DIFFERENCE" in pair["codes"]:
            a=rows[pair["path_indices"][0]]
            temporal[(normal(a["qname"]),a.get("qtype"),a.get("source_mode"))].update(pair["evidence_ids"])
    for (name,typ,source),ids in temporal.items():
        findings.append(dict(code="DNS_TEMPORAL_DIFFERENCE",stage="dns-comparison",status="insufficient_time_basis",
            scope=dict(target=name,record_type=typ,source_mode=source),evidence_ids=[r["evidence_id"] for r in rows if r["evidence_id"] in ids],
            observed_facts=[dict(evidence_id=r["evidence_id"],qname=r["qname"],qtype=r.get("qtype"),resolver=r.get("resolver"),measured_at=r.get("measured_at"),records=r.get("records",[]),**dns_outcome(r)) for r in rows if r["evidence_id"] in ids],
            localization={},root_cause_confirmed=False,explanation="跨时间或时间未知的响应/记录差异，不具备可靠同期定位条件。",
            limitations=["缺失、非法或无时区时间不补造；不能由文件生成时间推断查询时间。"],
            next_checks=[f"query_dns：按需对 {name} {typ} 在有真实测量时间的新调查中取得路径对照，避免将历史差异认作同期冲突。 "]))
    for row in rows:
        for ede in row.get("ede",[]):
            findings.append(dict(code="EDE_REPORTED",stage="dns-edns",status="observed",provenance="server_reported",
                finding_status="observed",severity="information",validation_result_ids=[],
                scope=dict(target=row["qname"],record_type=row["qtype"],resolver=row.get("resolver"),source_mode=row.get("source_mode")),
                evidence_ids=[row["evidence_id"]],observed_facts=[dict(evidence_id=row["evidence_id"],ede=ede)],localization={},root_cause_confirmed=False,
                explanation=f"REPORTED_BY_SERVER：{row.get('resolver')} 自报 EDE {ede.get('code')} {ede.get('name','MALFORMED')}，不是本程序DNSSEC验证。",
                limitations=["EDE可以伴随NOERROR；AD/DO或EDE不等于本地验证；Extra Text不可信。"],next_checks=[]))
    if not findings:
        complete=bool(rows) and all(comparable_response(r) and dns_outcome(r)["result_kind"]=="NOERROR" for r in rows)
        findings.append(dict(code="DNS_INCONCLUSIVE",stage="dns",status="no_anomaly_observed" if complete else "insufficient_information",
            scope={},evidence_ids=[r["evidence_id"] for r in rows],observed_facts=[],localization={},root_cause_confirmed=False,
            explanation="本次已测 DNS 查询未发现状态异常。" if complete else "没有足够的完整可比较 DNS 回答来定位故障。",
            limitations=["正常查询不能排除历史或客户端差异；未知不等于正常。"],next_checks=[] if complete else ["query_dns：对授权目标和所需记录取得响应；失败时保留未知。 "]))
    return findings


def next_checks(code,scope,observed):
    name,typ=scope["target"],scope["record_type"]
    paths=", ".join(str(x["resolver"]) for x in observed)
    if code=="ALIAS_FOLLOWUP_COMPLETED":return []
    if scope.get("dns_followup_only") and code!="ALIAS_RESOLUTION_INCOMPLETE":
        return [f"query_dns：可对已授权别名 {name} {typ} 有限查询；当前 compare_resolvers/query_authoritative 不接受扩展别名。别名权威对照属于外部专项检查，尚未执行，不能归属为原域名直接权威证据。"]
    if code.endswith("QUERY_TIMEOUT"):
        return [f"query_dns：预算允许时对 {name} {typ} 的超时路径有限复测（涉及 {paths}）；若恢复则削弱持续不可用解释，若仍超时仍不能区分服务与网络。"]
    if code=="ALIAS_RESOLUTION_INCOMPLETE":
        return [f"query_dns：仅沿 {name} {typ} 已观测且获授权的 CNAME 目标跟进；末端正/负回答可缩小范围，缺失时保留未知。"]
    if code in {"RECURSIVE_RESPONSE_DISAGREEMENT","NXDOMAIN_OBSERVED","NODATA_OBSERVED","DNS_SERVFAIL","DNS_REFUSED"}:
        return [f"query_authoritative：按需检查 {name} {typ}，仅使用 AA 回答；一致时削弱递归独有差异解释，不一致时仍需区分缓存、策略和时间。"]
    if code in {"RECURSIVE_AUTH_RESPONSE_MISMATCH","AUTHORITATIVE_RESPONSE_DISAGREEMENT"}:
        return [f"query_authoritative / query_dns：预算允许时复测 {name} {typ} 的已列路径（{paths}），比较记录和 SOA；持续差异缩小到这些查询路径，不能单凭 Serial 确认同步故障。"]
    return [f"本次 {name} {typ} 的地址集合差异可来自 CDN/调度；无额外故障线索时停止，不为正常差异自动追加检查。"]
