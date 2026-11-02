"""Post-investigation rules. No I/O, model invocation or operational root-cause inference."""
from .schemas import DiagnosticConclusion


def scope(f):
    return {k: f.get(k) for k in ('evidence_id','target','record_type','resolver','resolver_role',
        'port','measured_at','source_mode','result','canonical_name','cname_chain') if f.get(k) is not None}


def validation_closure(ids, rows, evidence):
    known={v['id']:v for v in rows};seen=set();es=set();pending=list(ids)
    while pending:
        vid=pending.pop()
        if vid in seen:continue
        v=known.get(vid)
        if v is None or v.get('provenance')!='locally_validated':return [],[]
        seen.add(vid);es.update(v.get('evidence_ids',[]));pending.extend(v.get('validation_result_ids',[]))
    if not seen or not es or not es.issubset(evidence):return [],[]
    return sorted(seen),sorted(es)


def reason(result):
    facts={f['evidence_id']:f for f in result.measured_facts};candidates=[]
    def add(code,layer,title,cause,ids,status='FAULT_LOCALIZED',alternatives=(),vids=(),aids=(),detected=True):
        ids=list(dict.fromkeys(ids))
        if any(e not in facts for e in ids):raise ValueError('Diagnostic evidence is missing')
        selected=[facts[e] for e in ids]
        d=DiagnosticConclusion(diagnosis_status=status,fault_detected=detected,primary_issue=code,
            summary=title,fault_layer=layer,fault_location='；'.join(
                f"{f['target']}"+(f" {f['record_type']} via {f['resolver']}" if f.get('record_type') else
                f" port {f.get('port')}" if f['tool']=='check_tcp' else '') for f in selected) or '未完成的调查范围',
            affected_scope=[scope(f) for f in selected],cause=cause,
            cause_status='VERIFIED_PROTOCOL' if status=='CONFIRMED_PROTOCOL_ISSUE' else
                'OBSERVED_MECHANISM' if status=='FAULT_LOCALIZED' else 'UNKNOWN',
            alternative_causes=list(alternatives),reason=cause,evidence_ids=ids,validation_ids=list(vids),
            relevant_attempt_ids=list(aids),finding_codes=[code] if code in {f.code for f in result.findings} else [],
            source_modes=sorted({f['source_mode'] for f in selected}),
            limitations=['范围仅为所列来源、时间及已测组合；协议异常不确认具体运维操作或用户故障的唯一原因。'])
        if any(m!='live' for m in d.source_modes):
            d.summary='[fixture/synthetic 模拟数据] '+d.summary
            d.limitations.append('不得作为当前真实公网故障；真实检查前须重新 live 解析，不能直接探测模拟地址。')
        candidates.append(d);return d

    validated_negative_ds=set();validated_protocol_attempts=set()
    for p in result.protocol_investigations:
        v=p.get('validation')
        if not v:continue
        vs,es=validation_closure(v.get('validation_result_ids',[]),result.validation_results,set(facts))
        state=v.get('dnssec_status');code=v.get('reason_code','UNKNOWN')
        if state in {'SECURE','INSECURE'} and vs and v.get('validation_execution')=='completed':
            validated_negative_ds.update(e for e in es if facts[e].get('record_type')=='DS')
            validated_protocol_attempts.add(p['attempt_id'])
        if state=='BOGUS' and vs and v.get('validation_execution')=='completed':
            names={'DS_DIGEST_MISMATCH':'父区域 DS 与已取得子区域 DNSKEY 无法建立关联',
                'NO_SIGNATURE_VALIDATED':'所列 RRset 的 RRSIG 未通过本地验证',
                'DENIAL_DOES_NOT_COVER_QUESTION':'已验证签名的否定证明未覆盖本次问题',
                'NEGATIVE_SOA_MISSING':'否定回答缺少所需 SOA 材料'}
            message=names.get(code,'所列 DNSSEC 验证环节未通过')
            d=add('DNSSEC_VALIDATION','DNSSEC',message,
                f"{message}；阶段={v.get('failure_stage')}，reason_code={code}，范围={v.get('validation_scope')}；限本地验证策略。",
                es,'CONFIRMED_PROTOCOL_ISSUE',('密钥轮换、发布配置或签名材料问题仍需管理员核对',),vs,[p['attempt_id']])
            d.limitations.append('本工具有有限协议支持；否定证明等与独立验证器的历史分歧仍须复核。')
            sigs=[x for x in result.validation_results if x['id'] in vs and x.get('rrsig_summary')]
            timed=[x for x in sigs if x['rrsig_summary'].get('expired_count') or x['rrsig_summary'].get('not_yet_valid_count')]
            if timed:d.cause+='；观察到过期/尚未生效签名，不能断言这是唯一验证失败原因。'
        elif state=='INDETERMINATE' or state=='BOGUS':
            add('DNSSEC_UNDETERMINED','DNSSEC','DNSSEC 验证尚不能确定',
                f"状态={state}，阶段={v.get('failure_stage')}，原因={code}；证据或当前能力不足，不能确认配置故障。",
                es,'INSUFFICIENT_EVIDENCE',vids=vs,aids=[p['attempt_id']],detected=None)
    codes={
        'RECURSIVE_QUERY_TIMEOUT':('Recursive DNS','所列递归查询路径本次未响应',('解析器服务状态','网络路径或访问策略')),
        'AUTHORITATIVE_QUERY_TIMEOUT':('Authoritative DNS','所列权威服务器本次查询超时',('该服务器或路径暂时不可用','访问策略')),
        'RECURSIVE_RESPONSE_DISAGREEMENT':('Recursive DNS','已测递归响应状态不一致',('缓存','解析策略','数据更新或时间变化')),
        'RECURSIVE_AUTH_RESPONSE_MISMATCH':('Authoritative DNS','递归与选中权威响应存在差异',('缓存','解析策略','权威更新或正常调度')),
        'AUTHORITATIVE_RESPONSE_DISAGREEMENT':('Authoritative DNS','选中权威响应存在差异',('正常调度','配置或更新传播')),
        'ALIAS_RESOLUTION_INCOMPLETE':('CNAME/Alias Resolution','当前别名路径尚未取得完整末端回答',('尚未查询末端','查询中断或路径限制')),
        'DNS_SERVFAIL':('Recursive DNS','所列 DNS 查询收到 SERVFAIL',('递归上游或验证失败','解析器策略')),
        'DNS_REFUSED':('Recursive DNS','所列 DNS 查询收到 REFUSED',('服务器访问策略','查询范围限制')),
    }
    for f in result.findings:
        if f.code not in codes:continue
        layer,title,alts=codes[f.code]
        # SOA serial / record-only differences are observations, not faults.
        selected=[facts[e] for e in f.evidence_ids if e in facts]
        if f.code in {'RECURSIVE_AUTH_RESPONSE_MISMATCH','AUTHORITATIVE_RESPONSE_DISAGREEMENT'}:
            if len({x['result'] for x in selected})<2:continue
            if any(x.get('resolver_role')=='authoritative' and not x.get('authoritative_answer') for x in selected):continue
        affected=f.localization.get('affected_evidence_ids') or f.evidence_ids
        d=add(f.code,layer,title,f.explanation,affected,alternatives=alts)
        d.unaffected_or_comparison_scope=[scope(x) for x in selected if x['evidence_id'] not in affected]
        d.evidence_ids=list(dict.fromkeys(d.evidence_ids+f.evidence_ids))
        d.limitations+=f.limitations
    for p in result.protocol_investigations:
        if p.get('mode')!='trace' or p.get('completed'):continue
        stop=p.get('stop_reason','UNKNOWN');aid=p['attempt_id']
        es=[f['evidence_id'] for f in facts.values() if f.get('attempt_id')==aid]
        # Budget/cancel/unsupported are execution limitations, not delegation faults.
        definite=bool(es) and stop in {'NON_AUTHORITATIVE_ANSWER','NON_PROGRESSING_REFERRAL_CYCLE'}
        add('DELEGATION_TRACE_STOPPED','Delegation','独立委派追踪未完成',
            f"最后成功区域={p.get('last_successful_zone')}；停止原因={stop}；不代表整个区域或全部 NS 不可用。",es,
            'FAULT_LOCALIZED' if definite else 'INSUFFICIENT_EVIDENCE',aids=[aid],detected=True if definite else None)
    for f in facts.values():
        eid=[f['evidence_id']]
        if f['tool']=='check_tcp' and f['result'] in {'REFUSED','TIMEOUT','NETWORK_ERROR'}:
            add('TCP_'+f['result'],'TCP/Network Transport',f"所列 IP/端口 TCP {f['result']}",
                f"本次独立 TCP 连接结果={f['result']}；详情={f.get('error_detail')}。不证明 HTTP 使用相同后端。",eid,
                alternatives=('服务监听','主机防火墙','网络访问策略或路径'))
        if f['tool']!='check_http' or f.get('security_refusal'):continue
        detail=f.get('error_detail') or {};error=f.get('error');status=f.get('status_code')
        if detail.get('code')=='CERTIFICATE_VERIFY_FAILED':
            add('TLS_CERTIFICATE_VERIFY_FAILED','TLS','TLS 证书验证失败',
                f"该连接的证书校验明确失败；错误详情={detail}。",eid,alternatives=('证书有效期、名称或信任链问题需按实际错误核对',))
        elif error:
            add('HTTP_REQUEST_'+str(error),'TLS' if error=='TLS_ERROR' else 'HTTP','HTTP 请求未完成',
                f"状态码={status}；请求错误={error}；正文状态={f.get('body_state')}；错误详情={detail}。不能由已收响应头断言完整成功。",eid)
        elif isinstance(status,int) and status>=400:
            add('HTTP_'+str(status),'HTTP',f"HTTP 返回 {status}",
                f"本次 {f['target']} 最终 {f.get('final_url')} 返回 {status}；不证明 DNS 故障或该响应是否符合端点设计。",eid,
                alternatives=('访问权限或请求条件','应用或上游服务行为'))
    # Stable, explicit ordering. Independent issues are retained, never called a unique cause.
    candidates.sort(key=lambda d:(0 if d.diagnosis_status=='CONFIRMED_PROTOCOL_ISSUE' else
        2 if d.diagnosis_status=='INSUFFICIENT_EVIDENCE' else 1,d.primary_issue,d.fault_location))
    if not candidates:
        incomplete=bool(result.execution_issues) or any(f.get('security_refusal') for f in facts.values())
        incomplete=incomplete or any(f['tool']=='query_dns' and (f.get('transport_status')!='responded' or
            f['result']!='NOERROR' and f['evidence_id'] not in validated_negative_ds and not
            (f['result']=='REFERRAL' and f.get('attempt_id') in validated_protocol_attempts)) for f in facts.values())
        incomplete=incomplete or any(f['tool']=='check_http' and f.get('request_state') not in {'complete','finished_within_check_limits'} for f in facts.values())
        normal=bool(facts) and not incomplete
        add('MEASURED_NORMAL' if normal else 'INSUFFICIENT_EVIDENCE','Unknown',
            '本次已测范围未发现明确异常。' if normal else '没有足够有效测量完成故障定位。',
            '仅为本次已测路径的状态，不确认客户端原因。' if facts else '没有取得有效测量证据，无法确认故障原因。',
            list(facts),'NO_FAULT_OBSERVED' if normal else 'INSUFFICIENT_EVIDENCE',detected=False if normal else None)
    primary,*secondary=candidates
    primary.relevant_attempt_ids=list(dict.fromkeys(primary.relevant_attempt_ids+[i.attempt_id for i in result.execution_issues]))
    if result.execution_issues:
        primary.limitations.append('另有未完成/被拒绝调用：'+', '.join(f'{i.attempt_id}:{i.error_code}' for i in result.execution_issues)+'；不是目标故障测量。')
    if secondary:primary.limitations.append('还存在独立异常或未完成范围；排序仅用于展示，不确认主次因果关系。')
    return primary,secondary


def validate_diagnostics(result,attempts):
    es={f['evidence_id'] for f in result.measured_facts};vs={v['id'] for v in result.validation_results}
    codes={f.code for f in result.findings};aids={a['attempt_id'] for a in attempts}
    for d in [result.diagnostic_conclusion]+result.secondary_diagnoses:
        if d is None:continue
        if set(d.evidence_ids)-es or set(d.validation_ids)-vs or set(d.finding_codes)-codes or set(d.relevant_attempt_ids)-aids:
            raise ValueError('Invalid diagnostic source reference')
        if d.diagnosis_status=='CONFIRMED_PROTOCOL_ISSUE' and (not d.evidence_ids or not d.validation_ids):
            raise ValueError('Confirmed protocol issue needs E/V')
        for step in d.remediation_steps+d.verification_steps:
            if not set(step.evidence_ids).issubset(d.evidence_ids) or not set(step.validation_ids).issubset(d.validation_ids):
                raise ValueError('Remediation source exceeds diagnosis')
