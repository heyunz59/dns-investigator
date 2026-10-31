"""Evidence-bound output. Free model drafts are retained separately for review."""
import json
import re
from pydantic_ai import ModelRetry
from .schemas import Observation,ExecutionIssue


def facts(evidence):
    rows=[]
    for e in evidence:
        d=e["data"];args=e.get("input",{})
        target=(d.get("ip",args.get("ip","unknown")) if e["tool_name"]=="check_tcp" else
                args.get("url",d.get("final_url","unknown")) if e["tool_name"]=="check_http" else d.get("qname",args.get("domain","unknown")))
        rows.append(dict(evidence_id=e["id"],target=target,
            resolver=d.get("resolver",args.get("resolver")),record_type=d.get("qtype",args.get("record_type")),
            measured_at=e.get("started_at"),source_mode=e["source_mode"],tool=e["tool_name"],
            result=next((d[k] for k in ("result_kind","rcode","status_code","status","error") if d.get(k) is not None),"UNKNOWN"),
            records=d.get("records",[]),error=d.get("error"),error_detail=d.get("error_detail"),peer_ip=d.get("peer_ip")))
        if e["tool_name"]=="check_http":
            rows[-1].update(status_code=d.get("status_code"),final_url=d.get("final_url"),redirects=d.get("redirects",[]),
                bytes_read=d.get("bytes_read"),request_state="incomplete" if d.get("error") else "finished_within_check_limits")
        elif e["tool_name"]=="check_tcp":rows[-1]["port"]=d.get("port",args.get("port"))
    return rows


def issues(attempts):
    return [ExecutionIssue(attempt_id=a["attempt_id"],tool_name=a["tool_name"],
        target=str(a.get("input",{}).get("domain",a.get("input",{}).get("url",a.get("input",{}).get("ip","unknown")))),
        record_type=a.get("input",{}).get("record_type","A") if a["tool_name"]=="query_dns" else None,
        error_code=a["error"]["code"],description=a["error"].get("message","")) for a in attempts if a.get("error")]


def validate_issue_refs(result,attempts):
    known={i.attempt_id:i for i in issues(attempts)}
    for issue in result.execution_issues:
        actual=known.get(issue.attempt_id)
        if actual is None or any(getattr(issue,k)!=getattr(actual,k) for k in ("tool_name","target","record_type","error_code")):
            raise ModelRetry("执行问题引用必须匹配实际 A 调用的工具、目标、类型与错误码。")


def validate_fact_claims(result,evidence):
    known={f["evidence_id"]:f for f in facts(evidence)}
    for claim in result.measured_facts:
        if claim.get("evidence_id") not in known or any(known[claim["evidence_id"]].get(k)!=v for k,v in claim.items()):
            raise ModelRetry("测量范围不匹配实际证据：不得扩大解析器、类型、目标或来源。")


def evidence_bound_report(result,backend):
    """Authoritative facts + constrained candidate relationships, no prose fact synthesis."""
    measured=facts(backend.calls)
    result.measured_facts=measured
    result.execution_issues=issues(backend.attempts)
    def describe(f):
        scope=f"{f['target']}"+(f" {f['record_type']} / 解析器 {f['resolver']}" if f["record_type"] else f" {f['tool']}")
        if f["tool"]=="check_http":
            details=f"HTTP 状态码={f['status_code']}；请求状态={f['request_state']}；错误={f['error']}；读取字节={f['bytes_read']}；最终 URL={f['final_url']}；跳转={json.dumps(f['redirects'],ensure_ascii=False)}"
            if f["error_detail"]:
                details+=f"；底层错误类别={f['error_detail'].get('code')}；证书错误={json.dumps(f['error_detail'].get('certificate'),ensure_ascii=False)}"
        elif f["tool"]=="check_tcp":
            details=f"端口={f['port']}；错误详情={json.dumps(f['error_detail'],ensure_ascii=False)}"
        else:details=json.dumps(f["records"],ensure_ascii=False) if f["records"] else ""
        return f"{scope}：{f['result']} {details}；来源 {f['source_mode']}；时间 {f['measured_at']}（{f['evidence_id']}）"
    result.observations=[Observation(evidence_id=f["evidence_id"],observation=describe(f)) for f in measured]
    # No parser attempts or model prose are allowed to add measured combinations.
    result.conclusion="；".join(describe(f) for f in measured) if measured else "没有取得有效测量证据，无法确认故障原因。"
    result.conclusion_evidence_ids=[f["evidence_id"] for f in measured]
    if measured and result.request_kind!="query":result.conclusion += "。以上仅为已测组合，未列出的解析器×类型组合未测；不据此确认唯一根因。"
    allowed={f["evidence_id"]:f for f in measured}
    kept=[]
    identities={}
    def relation_status(h):
        if h.supporting_evidence_ids and h.contradicting_evidence_ids:return "无法确定"
        return "待验证" if h.supporting_evidence_ids else "被削弱" if h.contradicting_evidence_ids else "无法确定"
    for h in result.hypotheses:
        def admissible(eid,support):
            if eid not in allowed:raise ModelRetry("假设引用了不存在的测量证据。")
            f=allowed[eid];scope=h.measurement_scope
            # Category is not a causal identity. Only an explicit observation claim
            # with an exact measured scope may establish a mechanical relationship.
            required={"target","source_mode"}
            if h.testable_claim=="dns_query_failure":required|={"resolver","record_type"}
            if h.testable_claim=="tcp_connection_failure":required|={"port"}
            if not required.issubset(scope) or any(scope[k] is None for k in required) or any(f.get(k)!=v for k,v in scope.items()):return False
            if h.testable_claim=="dns_query_failure":
                return f["record_type"] is not None and ((f["result"] in {"NXDOMAIN","NODATA","SERVFAIL","REFUSED","TIMEOUT"}) if support else f["result"]=="NOERROR")
            if h.testable_claim=="certificate_verification_failure":
                return f["error_detail"] is not None and f["error_detail"].get("code")=="CERTIFICATE_VERIFY_FAILED" and support
            if h.testable_claim=="http_error_response":return f["tool"]=="check_http" and isinstance(f["status_code"],int) and ((f["status_code"]>=400) if support else f["status_code"]<400)
            if h.testable_claim=="tcp_connection_failure":return f["tool"]=="check_tcp" and ((f["result"] in {"TIMEOUT","REFUSED","NETWORK_ERROR"}) if support else f["result"]=="CONNECTED")
            return False  # client state, endpoint intent and registration not measured by these tools
        proposed_support=h.supporting_evidence_ids[:];proposed_counter=h.contradicting_evidence_ids[:]
        h.supporting_evidence_ids=[x for x in proposed_support if admissible(x,True)]
        h.contradicting_evidence_ids=[x for x in proposed_counter if admissible(x,False)]
        h.evidence_review_notes=[f"{eid} 的{direction}关系缺少匹配的具体观测命题/范围或结果类型；未据此确认或否定该原因。"
            for direction,proposed,kept_refs in [("支持",proposed_support,h.supporting_evidence_ids),("反面",proposed_counter,h.contradicting_evidence_ids)]
            for eid in proposed if eid not in kept_refs]
        # Candidate explanations remain candidates, even when a symptom is observed.
        h.status=relation_status(h)
        h.statement=re.sub(r"^(?:已确认|已经确认|已证实)[：:\s]*","",h.statement).strip()
        if not h.statement:raise ModelRetry("假设身份不能为空。")
        if not h.missing_information and not h.contradicting_evidence_ids:
            h.missing_information=["仍需直接验证该候选解释，症状不等于已确认原因。"]
        identity=(re.sub(r"\s+","",h.statement).casefold(),json.dumps(h.measurement_scope,sort_keys=True),h.testable_claim)
        if identity not in identities:
            kept.append(h);identities[identity]=h
        else:
            original=identities[identity]
            for field in ("supporting_evidence_ids","contradicting_evidence_ids","missing_information","evidence_review_notes"):
                setattr(original,field,list(dict.fromkeys(getattr(original,field)+getattr(h,field))))
            original.status=relation_status(original)
    result.hypotheses=kept
    invalid=backend.target.domain=="invalid" or backend.target.domain.endswith(".invalid")
    synthetic=backend.fixture is not None or any(f["source_mode"]!="live" for f in measured)
    if result.request_kind=="query":result.hypotheses=[]
    if invalid:result.hypotheses=[h for h in result.hypotheses if h.category!="registration"]
    if len({h.id for h in result.hypotheses})!=len(result.hypotheses):raise ModelRetry("最终假设编号必须唯一。")
    if result.outcome=="answered" and (not measured or (result.request_kind=="investigation" and len(result.hypotheses)<2)):
        result.outcome="insufficient_information"
    recommendations=["优先收集故障设备的具体错误、发生时间，再进行不修改配置的对照检查。"]
    if synthetic:recommendations=["本次包含 fixture/synthetic 事实。转入真实检查前先重新 live 解析，再使用真实返回地址；不要探测模拟 IP。"]
    if invalid:recommendations.append(".invalid 按规范为公网保留测试用途，预期不在公共 DNS 中正常解析；这是背景知识，不是本次观测。实际结果以测量表为准，hosts 或私有 DNS 覆盖仍可能不同。请核对服务应使用的真实域名。")
    elif result.request_kind!="query" and not synthetic:
        recommendations += [f"外部对照可用 curl.exe -v -L '{backend.target.url}'，保留证书校验；IPv4/IPv6 可分别用 -4/-6 对照，不修改系统配置。",
            "现有 HTTP 工具不能绑定指定后端。外部专项检查可用 curl.exe --resolve 域名:端口:IP 配合原始 HTTPS URL，保留 Host/SNI 和证书校验。"]
    result.recommendations=recommendations
    if result.request_kind=="query":
        result.findings=[f for f in result.findings if f.code!="DNS_INCONCLUSIVE"]
        result.limitations=["仅报告列出的本次查询及应答 TTL，未测组合未知；没有权威对照时不判断原始 TTL。"]
    else:result.limitations=["仅代表列出的测量位置、时刻、来源和组合；程序路径成功不证明用户客户端有问题。", "独立 TCP 和 HTTP 是不同连接，可能使用不同后端；结果差异须先核查工具和现场。", "候选解释与事实分开，结构和类型限制仍不能保证全部语义正确。"]
    return result
