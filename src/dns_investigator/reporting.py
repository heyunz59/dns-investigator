"""Evidence-bound output. Free model drafts are retained separately for review."""
import json
from pydantic_ai import ModelRetry
from .schemas import Observation,ExecutionIssue


def facts(evidence):
    rows=[]
    for e in evidence:
        d=e["data"];args=e.get("input",{})
        rows.append(dict(evidence_id=e["id"],target=d.get("qname",args.get("domain",args.get("url",args.get("ip","unknown")))),
            resolver=d.get("resolver",args.get("resolver")),record_type=d.get("qtype",args.get("record_type")),
            measured_at=e.get("started_at"),source_mode=e["source_mode"],tool=e["tool_name"],
            result=next((d[k] for k in ("result_kind","rcode","status_code","status","error") if d.get(k) is not None),"UNKNOWN"),
            records=d.get("records",[]),error=d.get("error"),error_detail=d.get("error_detail"),peer_ip=d.get("peer_ip")))
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
        details=json.dumps(f["records"],ensure_ascii=False) if f["records"] else ""
        return f"{scope}：{f['result']} {details}；来源 {f['source_mode']}；时间 {f['measured_at']}（{f['evidence_id']}）"
    result.observations=[Observation(evidence_id=f["evidence_id"],observation=describe(f)) for f in measured]
    # No parser attempts or model prose are allowed to add measured combinations.
    result.conclusion="；".join(describe(f) for f in measured) if measured else "没有取得有效测量证据，无法确认故障原因。"
    result.conclusion_evidence_ids=[f["evidence_id"] for f in measured]
    if measured and result.request_kind!="query":result.conclusion += "。以上仅为已测组合，未列出的解析器×类型组合未测；不据此确认唯一根因。"
    allowed={f["evidence_id"]:f for f in measured}
    for h in result.hypotheses:
        def admissible(eid,support):
            f=allowed[eid]
            if h.category=="dns_resolution":
                return f["record_type"] is not None and ((f["result"] in {"NXDOMAIN","NODATA","SERVFAIL","REFUSED","TIMEOUT"}) if support else f["result"]=="NOERROR")
            if h.category=="certificate_validation":
                return f["error_detail"] is not None and f["error_detail"].get("code")=="CERTIFICATE_VERIFY_FAILED" and support
            if h.category=="http_response":return f["tool"]=="check_http" and isinstance(f["result"],int) and f["result"]>=400 and support
            if h.category=="transport":return f["tool"]=="check_tcp" and ((f["result"] in {"TIMEOUT","REFUSED","NETWORK_ERROR"}) if support else f["result"]=="CONNECTED")
            return False  # client state, endpoint intent and registration not measured by these tools
        h.supporting_evidence_ids=[x for x in h.supporting_evidence_ids if admissible(x,True)]
        h.contradicting_evidence_ids=[x for x in h.contradicting_evidence_ids if admissible(x,False)]
        # A successful sampled path cannot refute a general candidate covering
        # unmeasured clients/addresses/times. Keep it in measured_facts instead.
        h.contradicting_evidence_ids=[]
        # Candidate explanations remain candidates, even when a symptom is observed.
        h.status="待验证" if h.supporting_evidence_ids else "无法确定"
        h.statement={"dns_resolution":"DNS 解析路径是否有异常","transport":"指定地址的连接路径是否有异常", "http_response":"HTTP 错误响应的服务侧原因", "certificate_validation":"证书验证是否失败及其具体原因", "client_environment":"用户客户端环境是否与程序路径不同", "endpoint_intent":"该端点是否按设计返回错误状态", "registration":"域名注册或权威配置是否异常", "other":"其他尚未验证的解释"}[h.category]
        h.missing_information=["仍需直接验证该候选解释，症状不等于已确认原因。"]
    invalid=backend.target.domain=="invalid" or backend.target.domain.endswith(".invalid")
    synthetic=any(f["source_mode"]!="live" for f in measured)
    if result.request_kind=="query":result.hypotheses=[]
    result.hypotheses=[h for h in result.hypotheses if h.category!="other"]
    if invalid:result.hypotheses=[h for h in result.hypotheses if h.category!="registration"]
    if result.request_kind=="investigation" and result.outcome=="answered" and len({h.category for h in result.hypotheses})<2:
        result.outcome="insufficient_information"
    recommendations=["优先收集故障设备的具体错误、发生时间，再进行不修改配置的对照检查。"]
    if synthetic:recommendations=["本次包含 fixture/synthetic 事实。转入真实检查前先重新 live 解析，再使用真实返回地址；不要探测模拟 IP。"]
    if invalid:recommendations=[".invalid 为公网保留测试用途，本次公网 NXDOMAIN 符合此用途；如需访问实际服务，请核对真实域名。hosts 或私有 DNS 覆盖仍可能有不同结果。"]
    elif result.request_kind!="query" and not synthetic:
        recommendations += [f"外部对照可用 curl.exe -v -L '{backend.target.url}'，保留证书校验；IPv4/IPv6 可分别用 -4/-6 对照，不修改系统配置。",
            "现有 HTTP 工具不能绑定指定后端。外部专项检查可用 curl.exe --resolve 域名:端口:IP 配合原始 HTTPS URL，保留 Host/SNI 和证书校验。"]
    result.recommendations=recommendations
    if result.request_kind=="query":
        result.findings=[f for f in result.findings if f.code!="DNS_INCONCLUSIVE"]
        result.limitations=["仅报告列出的本次查询及应答 TTL，未测组合未知；没有权威对照时不判断原始 TTL。"]
    else:result.limitations=["仅代表列出的测量位置、时刻、来源和组合；程序路径成功不证明用户客户端有问题。", "独立 TCP 和 HTTP 是不同连接，可能使用不同后端；结果差异须先核查工具和现场。", "候选解释与事实分开，结构和类型限制仍不能保证全部语义正确。"]
    return result
