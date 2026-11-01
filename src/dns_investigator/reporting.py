"""Evidence-bound output. Free model drafts are retained separately for review."""
import json
import re
from pydantic_ai import ModelRetry
from .schemas import Observation,ExecutionIssue
from .dns_compare import compare_details,evidence_rows
from .dns_wire import dns_outcome
from .dns_diagnosis import diagnose
from .schemas import Finding
from .alias_scope import alias_paths


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
        elif e["tool_name"]=="query_dns":
            rows[-1].update(**dns_outcome(d),resolver_role=d.get("resolver_role","recursive"),
                negative_name=d.get("negative_name"),cname_chain=d.get("cname_chain",[]),
                canonical_name=d.get("canonical_name"),query_attempt_id=e.get("query_attempt_id"),attempt_id=e.get("tool_call_id"))
            rows[-1]["target_authorization"]=e.get("target_authorization")
    return rows


def issues(attempts):
    return [ExecutionIssue(attempt_id=a["attempt_id"],tool_name=a["tool_name"],
        target=str(a.get("input",{}).get("domain",a.get("input",{}).get("url",a.get("input",{}).get("ip","unknown")))),
        record_type=a.get("input",{}).get("record_type","A") if a["tool_name"] in {"query_dns","compare_resolvers","query_authoritative"} else None,
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
    result.findings=[Finding(**f) for f in diagnose(backend.calls)]
    allowed_targets=alias_paths(backend)
    for finding in result.findings:
        name=finding.scope.get("target")
        if name and name!=backend.target.domain and name not in allowed_targets:
            finding.next_checks=[f"外部专项检查：核实 {name} {finding.scope.get('record_type')}；该名称来自内部发现测量，当前五工具的独立目标授权未扩展到它。此建议尚未执行，不能描述为可直接调用现有工具。"]
    dns_rows=evidence_rows(backend.calls)
    failures=[dict(qname=q.get("qname"),qtype=q.get("qtype"),resolver=q.get("server"),
        source_mode="fixture" if backend.fixture is not None else "live",execution_status="error",
        parent_tool_call_id=q.get("parent_tool_call_id"),query_attempt_id=q.get("query_attempt_id"),
        error={"code":q["status"]}) for q in backend.dns.attempts if q["status"] not in {"measured","running"}]
    key=lambda r:(r.get("parent_tool_call_id"),r.get("qname"),r.get("qtype"),r.get("resolver"))
    recorded={key(r) for r in failures}
    failures += [r for a in backend.attempts for r in a.get("dns_execution_issues",[]) if key(r) not in recorded]
    result.dns_comparison=compare_details(dns_rows+failures)
    result.diagnostic_assessment,result.assessment_level=assessment(result,measured)
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
    result.conclusion=(result.diagnostic_assessment+" 已验证事实："+"；".join(describe(f) for f in measured)) if measured else "没有取得有效测量证据，无法确认故障原因。"
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
        h.evidence_review_notes=list(dict.fromkeys(h.evidence_review_notes+[f"{eid} 的{direction}关系缺少匹配的具体观测命题/范围或结果类型；未据此确认或否定该原因。"
            for direction,proposed,kept_refs in [("支持",proposed_support,h.supporting_evidence_ids),("反面",proposed_counter,h.contradicting_evidence_ids)]
            for eid in proposed if eid not in kept_refs]))
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
    if result.outcome=="answered" and not measured:
        result.outcome="insufficient_information"
    recommendations=["优先收集故障设备的具体错误、发生时间，再进行不修改配置的对照检查。"]
    if synthetic:recommendations=["本次包含 fixture/synthetic 事实。转入真实检查前先重新 live 解析，再使用真实返回地址；不要探测模拟 IP。"]
    if invalid:recommendations.append(".invalid 按规范为公网保留测试用途，预期不在公共 DNS 中正常解析；这是背景知识，不是本次观测。实际结果以测量表为准，hosts 或私有 DNS 覆盖仍可能不同。请核对服务应使用的真实域名。")
    elif result.request_kind!="query" and not synthetic and not dns_rows:
        recommendations += [f"外部对照可用 curl.exe -v -L '{backend.target.url}'，保留证书校验；IPv4/IPv6 可分别用 -4/-6 对照，不修改系统配置。",
            "现有 HTTP 工具不能绑定指定后端。外部专项检查可用 curl.exe --resolve 域名:端口:IP 配合原始 HTTPS URL，保留 Host/SNI 和证书校验。"]
    if result.request_kind!="query" and not invalid:
        priority={"RECURSIVE_RESPONSE_DISAGREEMENT":0,"RECURSIVE_AUTH_RESPONSE_MISMATCH":0,"AUTHORITATIVE_RESPONSE_DISAGREEMENT":0,
                  "RECURSIVE_QUERY_TIMEOUT":1,"AUTHORITATIVE_QUERY_TIMEOUT":1,"ALIAS_RESOLUTION_INCOMPLETE":2}
        checks=list(dict.fromkeys(c for f in sorted(result.findings,key=lambda f:priority.get(f.code,3)) for c in f.next_checks))[:3]
        if checks:recommendations=(recommendations if synthetic else [])+checks
        elif dns_rows:
            recommendations=(recommendations if synthetic else [])+["本次已测范围未发现 DNS 状态异常；若用户仍无法访问，先核对故障时间、客户端错误和测量环境，再决定是否检查 TCP/HTTP。"]
    result.recommendations=recommendations
    if result.request_kind=="query":
        result.findings=[f for f in result.findings if f.code!="DNS_INCONCLUSIVE"]
        result.limitations=["仅报告列出的本次查询及应答 TTL，未测组合未知；没有权威对照时不判断原始 TTL。"]
    else:result.limitations=["仅代表列出的测量位置、时刻、来源和组合；程序路径成功不证明用户客户端有问题。", "独立 TCP 和 HTTP 是不同连接，可能使用不同后端；结果差异须先核查工具和现场。", "候选解释与事实分开，结构和类型限制仍不能保证全部语义正确。"]
    return result


def assessment(result,measured):
    """Constrained fact/localization templates; model causal prose is never trusted."""
    if not measured:return "没有取得有效测量证据，无法确认故障原因。","insufficient_evidence"
    if result.request_kind=="query":return "单项查询的本次结果如下；不据此诊断其他路径或唯一根因。","query_measured"
    parts=[];localized=False
    for f in result.findings:
        scope=f.scope
        if not scope:continue
        target=f"{scope.get('target')} {scope.get('record_type')} [来源 {scope.get('source_mode')}]"
        refs="、".join(f.evidence_ids)
        if f.code.endswith("QUERY_TIMEOUT"):
            affected=set(f.localization.get("affected_evidence_ids",[]))
            timed=[str(r["resolver"]) for r in f.observed_facts if r["evidence_id"] in affected]
            responded=[f"{r['resolver']}={r['result_kind']}" for r in f.observed_facts if r["transport_status"]=="responded"]
            parts.append(f"{target}：{', '.join(timed)} 本次查询超时"+(f"，其他响应路径为 {', '.join(responded)}" if responded else "，尚无足够对照")+
                f"；线索限于这些查询路径的可用性，不能区分服务与网络问题，也没有取得超时路径的记录内容（{refs}）。")
            localized=localized or bool(responded)
        elif f.code in {"RECURSIVE_RESPONSE_DISAGREEMENT","RECURSIVE_AUTH_RESPONSE_MISMATCH","AUTHORITATIVE_RESPONSE_DISAGREEMENT"}:
            paths="、".join(f"{r['role']} {r['resolver']}={r['result_kind']}" for r in f.observed_facts)
            parts.append(f"{target}：{paths} 存在完整响应状态或记录差异；范围限于已列路径，缓存、策略、调度与时间原因尚未区分（{refs}）。")
            localized=True
        elif f.code=="RECORD_SET_DIFFERENCE":parts.append(f"{target} 的响应记录集合不同；这可来自正常 CDN/调度，当前不能据此判故障（{refs}）。")
        elif f.code=="ALIAS_RESOLUTION_INCOMPLETE":parts.append(f"{target} 已观测别名但末端解析未完成；没有最终地址或否定回答的证据（{refs}）。")
        elif f.code in {"NXDOMAIN_OBSERVED","NODATA_OBSERVED","DNS_SERVFAIL","DNS_REFUSED"}:
            parts.append(f.explanation+f"（{refs}）")
    if not parts:
        dns=[m for m in measured if m["tool"]=="query_dns"]
        http_errors=[m for m in measured if m["tool"]=="check_http" and (m["error"] or isinstance(m["result"],int) and m["result"]>=400)]
        if http_errors:parts=["已取得 HTTP 层响应或请求错误，详情见事实表；这不直接证明 DNS 故障或客户端问题。"]
        elif dns and all(r.get("result")=="NOERROR" and r.get("records") for r in dns):parts=["本次已测 DNS 查询取得记录，未发现该范围的解析状态异常；不能据此确认用户客户端原因。"]
        else:parts=["已有测量不足以定位 DNS 异常范围；未测路径保持未知。"]
    if result.execution_issues:
        parts.append("另有调用执行问题（"+"、".join(i.attempt_id+":"+i.error_code for i in result.execution_issues)+"）；这些不是 DNS 应答，不能当作 NXDOMAIN；有效测量子集仍保留。")
    return " ".join(parts),"scope_localized" if localized else "measured_without_root_cause"
