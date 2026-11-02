"""Post-investigation rules. No I/O, model invocation or operational root-cause inference."""
from .schemas import DiagnosticConclusion
from urllib.parse import urlsplit


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
        ids=sorted(set(ids))
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
        d.direct_evidence_ids=ids[:];d.direct_validation_ids=list(vids)
        d.location=[dict(qname=f['target'] if f.get('record_type') else None,qtype=f.get('record_type'),resolver=f.get('resolver'),role=f.get('resolver_role'),
            ip=f['target'] if f['tool']=='check_tcp' else f.get('peer_ip'),port=f.get('port'),
            url=f['target'] if f['tool']=='check_http' else None,final_url=f.get('final_url'),
            measured_at=f.get('measured_at'),source_mode=f.get('source_mode')) for f in selected]
        for position,f in zip(d.location,selected):
            if f['tool']=='check_http':
                try:
                    original=urlsplit(f['target']);final=urlsplit(f.get('final_url') or f['target'])
                    position.update(original_host=original.hostname,final_host=final.hostname,
                        port=final.port or (443 if final.scheme=='https' else 80),expected_sni=final.hostname if final.scheme=='https' else None)
                except ValueError:position['url_metadata_status']='unknown_legacy_url'
        d.fault_component=layer
        if any(m!='live' for m in d.source_modes):
            d.summary='[fixture/synthetic 模拟数据] '+d.summary
            d.limitations.append('不得作为当前真实公网故障；真实检查前须重新 live 解析，不能直接探测模拟地址。')
        candidates.append(d);return d

    validated_negative_ds=set();validated_protocol_attempts=set()
    for p in result.protocol_investigations:
        terminal=facts.get(p.get('terminal_evidence_id'))
        if (p.get('mode')=='trace' and p.get('completed') and terminal and
            terminal.get('attempt_id')==p['attempt_id'] and terminal.get('authoritative_answer') and
            terminal['result']=='NOERROR'):
            validated_protocol_attempts.add(p['attempt_id'])
        v=p.get('validation')
        if not v:continue
        vs,es=validation_closure(v.get('validation_result_ids',[]),result.validation_results,set(facts))
        known_v={row['id']:row for row in result.validation_results}
        validation_scope=v.get('validation_scope') or {}
        if (any(known_v[vid].get('parent_tool_call_id')!=p['attempt_id'] for vid in vs) or
            str(validation_scope.get('qname','')).lower().rstrip('.')!=str(p.get('target','')).lower().rstrip('.') or
            validation_scope.get('qtype')!=p.get('record_type')):
            vs,es=[],[]
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
            # Start at the final validator's blocking endpoints, never at an
            # arbitrary failed candidate elsewhere in the transitive closure.
            blocking=[known_v[x] for x in v.get('validation_result_ids',[]) if x in known_v and
                known_v[x].get('reason_code')==code and known_v[x].get('local_result')!='SIGNATURE_CHECK_PASSED']
            direct_v=sorted(x['id'] for x in blocking)
            direct_e=sorted({e for x in blocking for e in x.get('evidence_ids',[])})
            d.direct_validation_ids=direct_v;d.direct_evidence_ids=direct_e
            d.dependency_validation_ids=sorted(set(vs)-set(direct_v));d.dependency_evidence_ids=sorted(set(es)-set(direct_e))
            d.failure_stage=v.get('failure_stage');d.reason_code=code;d.fault_component=blocking[0]['kind'] if len({x['kind'] for x in blocking})==1 else 'dnssec-validation'
            d.affected_scope=[scope(facts[e]) for e in direct_e]
            d.location=[dict(x.get('scope',{}),validation_id=x['id'],component=x['kind']) for x in blocking]
            if code=='DS_DIGEST_MISMATCH' and blocking:
                d.fault_location='；'.join(sorted({x.get('scope',{}).get('zone','区域未知')+' 父侧 DS 与子侧 DNSKEY 关联验证' for x in blocking}))
            elif blocking:
                d.fault_location='；'.join(sorted({str(x.get('scope',{}))+' / '+str(d.failure_stage) for x in blocking}))
            else:
                d.fault_location='DNSSEC '+str(d.failure_stage)+'；旧材料未标识直接阻断 RRset/区域'
                d.limitations.append('有完整本地验证结果，但缺少直接阻断点元数据；保留宽范围，不把依赖链当故障位置。')
            d.limitations.append('本工具有有限协议支持；否定证明等与独立验证器的历史分歧仍须复核。')
            sigs=[x for x in result.validation_results if x['id'] in vs and x.get('rrsig_summary')]
            timed=[x for x in sigs if x['rrsig_summary'].get('expired_count') or x['rrsig_summary'].get('not_yet_valid_count')]
            if timed:d.cause+='；观察到过期/尚未生效签名，不能断言这是唯一验证失败原因。'
        elif state=='INDETERMINATE' or state=='BOGUS':
            d=add('DNSSEC_UNDETERMINED','DNSSEC','DNSSEC 验证尚不能确定',
                f"状态={state}，阶段={v.get('failure_stage')}，原因={code}；证据或当前能力不足，不能确认配置故障。",
                es,'INSUFFICIENT_EVIDENCE',vids=vs,aids=[p['attempt_id']],detected=None)
            d.reason_code=code;d.failure_stage=v.get('failure_stage')
            d.direct_evidence_ids=[];d.direct_validation_ids=[]
            d.dependency_evidence_ids=es;d.dependency_validation_ids=vs;d.affected_scope=[]
            d.location=[dict(validation_scope=v.get('validation_scope'),failure_stage=d.failure_stage,reason_code=code)]
            d.fault_location=f'DNSSEC 未能确定：阶段={d.failure_stage}，原因={code}；未确认故障区域'
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
        if f.code in {'DNS_SERVFAIL','DNS_REFUSED'} and selected and all(x.get('resolver_role')=='authoritative' for x in selected):
            layer='Authoritative DNS'
        if f.code in {'RECURSIVE_AUTH_RESPONSE_MISMATCH','AUTHORITATIVE_RESPONSE_DISAGREEMENT'}:
            if len({x['result'] for x in selected})<2:continue
            if any(x.get('resolver_role')=='authoritative' and not x.get('authoritative_answer') for x in selected):continue
        affected=f.localization.get('affected_evidence_ids') or f.evidence_ids
        description=f.explanation
        if f.code.endswith('QUERY_TIMEOUT'):
            description='；'.join(f"{facts[e]['target']} {facts[e].get('record_type')} 经 {facts[e].get('resolver')} 查询未在时限内收到响应" for e in affected)+'；未确认服务器宕机。'
        d=add(f.code,layer,title,description,affected,alternatives=alts)
        d.reason_code=f.code
        d.unaffected_or_comparison_scope=[scope(x) for x in selected if x['evidence_id'] not in affected]
        d.evidence_ids=list(dict.fromkeys(d.evidence_ids+f.evidence_ids))
        d.limitations+=f.limitations
    for p in result.protocol_investigations:
        if p.get('mode')!='trace' or p.get('completed'):continue
        stop=p.get('stop_reason','UNKNOWN');aid=p['attempt_id']
        es=[f['evidence_id'] for f in facts.values() if f.get('attempt_id')==aid]
        # Budget/cancel/unsupported are execution limitations, not delegation faults.
        definite=bool(es) and stop in {'NON_AUTHORITATIVE_ANSWER','NON_PROGRESSING_REFERRAL_CYCLE'}
        d=add('DELEGATION_TRACE_STOPPED','Delegation','独立委派追踪未完成',
            f"最后成功区域={p.get('last_successful_zone')}；停止原因={stop}；不代表整个区域或全部 NS 不可用。",es,
            'FAULT_LOCALIZED' if definite else 'INSUFFICIENT_EVIDENCE',aids=[aid],detected=True if definite else None)
        d.reason_code=stop;d.failure_stage='delegation-trace'
        blocking_steps=[s for s in p.get('steps',[]) if s.get('stage')=='trace-query' and s.get('zone')==p.get('current_zone') and s.get('evidence_id') in es]
        d.direct_evidence_ids=sorted({s['evidence_id'] for s in blocking_steps})
        d.dependency_evidence_ids=sorted(set(es)-set(d.direct_evidence_ids))
        d.affected_scope=[scope(facts[e]) for e in d.direct_evidence_ids]
        d.location=[{k:s.get(k) for k in ('zone','qname','qtype','server','ns','stage','evidence_id')} for s in blocking_steps] or [dict(last_successful_zone=p.get('last_successful_zone'),last_delegated_zone=p.get('last_delegated_zone'),stop_reason=stop)]
        d.fault_location=f"追踪停止：{stop}；最后成功区域={p.get('last_successful_zone')}；最后委派区域={p.get('last_delegated_zone')}"
    for f in facts.values():
        eid=[f['evidence_id']]
        if f['tool']=='check_tcp' and f['result'] in {'REFUSED','TIMEOUT','NETWORK_ERROR'}:
            wording={'REFUSED':'本次连接被拒绝','TIMEOUT':'未在时限内建立连接','NETWORK_ERROR':'本次连接遇到底层执行/网络错误，原因未明'}[f['result']]
            d=add('TCP_'+f['result'],'TCP/Network Transport',f"TCP：{wording}",
                f"{wording}（{f['result']}）；详情={f.get('error_detail')}。不证明 HTTP 使用相同后端。",eid,
                alternatives=('服务监听','主机防火墙','网络访问策略或路径'))
            d.reason_code=f['result'];d.failure_stage='tcp-connect'
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
        if candidates and candidates[-1].evidence_ids==eid:
            d=candidates[-1];d.reason_code=detail.get('code') or str(error or status)
            d.status_code=status;d.error_details=detail
            d.failure_stage='tls-validation' if d.fault_layer=='TLS' else 'http-request'
    # Stable, explicit ordering. Independent issues are retained, never called a unique cause.
    candidates.sort(key=lambda d:(0 if d.diagnosis_status=='CONFIRMED_PROTOCOL_ISSUE' else
        2 if d.diagnosis_status=='INSUFFICIENT_EVIDENCE' else 1,d.primary_issue,d.fault_location))
    if not candidates:
        incomplete=bool(result.execution_issues) or any(f.get('security_refusal') for f in facts.values())
        incomplete=incomplete or any(f['tool']=='query_dns' and (f.get('transport_status')!='responded' or
            f['result']!='NOERROR' and f['evidence_id'] not in validated_negative_ds and not
            (f['result']=='REFERRAL' and f.get('attempt_id') in validated_protocol_attempts)) for f in facts.values())
        incomplete=incomplete or any(f['tool']=='check_http' and f.get('request_state') not in {'complete','finished_within_check_limits'} for f in facts.values())
        incomplete=incomplete or any(f.get('resolver_role')=='authoritative' and not f.get('authoritative_answer') and
            not (f['result']=='REFERRAL' and f.get('attempt_id') in validated_protocol_attempts) for f in facts.values())
        normal=bool(facts) and not incomplete
        add('MEASURED_NORMAL' if normal else 'INSUFFICIENT_EVIDENCE','Unknown',
            '本次已测范围未发现明确异常。' if normal else '没有足够有效测量完成故障定位。',
            '仅为本次已测路径的状态，不确认客户端原因。' if facts else '没有取得有效测量证据，无法确认故障原因。',
            list(facts),'NO_FAULT_OBSERVED' if normal else 'INSUFFICIENT_EVIDENCE',detected=False if normal else None)
    from .path_groups import aggregate
    candidates=aggregate(result,candidates,facts)
    primary,secondary=select_diagnoses(result,candidates,facts,add)
    for d in ([primary] if primary else [])+secondary:
        d.relevant_attempt_ids=list(dict.fromkeys(d.relevant_attempt_ids+[i.attempt_id for i in result.execution_issues]))
        if result.execution_issues:d.limitations.append('另有未完成/被拒绝调用：'+', '.join(f'{i.attempt_id}:{i.error_code}' for i in result.execution_issues)+'；不是目标故障测量。')
        if len(candidates)>1:d.limitations.append('其他独立异常的关联未验证；同时发生不证明因果关系。')
    return primary,secondary


def select_diagnoses(result,candidates,facts,add):
    ctx=result.request_context;focus=ctx.get('focus_layers',[]) if not ctx.get('ambiguous',True) else []
    def layer_matches(layer):return bool(focus) and (layer in focus or focus==['HTTP'] and layer=='TLS')
    def matches_scope(rows,layer):
        target=ctx.get('target')
        if not rows:return False
        def single(row):
            name=str(row.get('target','')).lower().rstrip('.')
            if layer=='TCP/Network Transport':
                return (not ctx.get('port') or row.get('port')==ctx['port']) and (not ctx.get('ip') or name==ctx['ip'])
            if layer in {'HTTP','TLS'} and ctx.get('url'):
                a,b=urlsplit(name),urlsplit(ctx['url'])
                def identity(p):return p.scheme,p.hostname,p.port or (443 if p.scheme=='https' else 80),p.path or '/',p.query
                return identity(a)==identity(b)
            return not target or name==str(target).lower().rstrip('.')
        return any(single(row) for row in rows)
    def protocol_matches(d):return any(p.get('target')==ctx.get('target') and p.get('attempt_id') in d.relevant_attempt_ids for p in result.protocol_investigations)
    if len(focus)==1 and not any(layer_matches(d.fault_layer) and (matches_scope(d.affected_scope,d.fault_layer) or protocol_matches(d)) for d in candidates):
        tools={'TCP/Network Transport':'check_tcp','HTTP':'check_http','Recursive DNS':'query_dns'}
        selected=[f for f in facts.values() if f['tool']==tools.get(focus[0]) and matches_scope([f],focus[0])]
        normal=bool(selected) and all(f['result']=='CONNECTED' if f['tool']=='check_tcp' else
            f['result']=='NOERROR' and f.get('transport_status')=='responded' and bool(f.get('records')) if f['tool']=='query_dns' else
            isinstance(f.get('status_code'),int) and f['status_code']<400 and not f.get('error') and not f.get('security_refusal') and f.get('request_state') in {'complete','finished_within_check_limits'} for f in selected)
        d=add('FOCUS_NOT_REPRODUCED' if normal else 'FOCUS_UNMEASURED',focus[0],
            '所关注的路径本次未复现异常。' if normal else '所关注的环节尚未取得足够测量。',
            '其他层异常单列，不确认用户所述问题原因。',[f['evidence_id'] for f in selected],
            'NO_FAULT_OBSERVED' if normal else 'INSUFFICIENT_EVIDENCE',detected=False if normal else None)
    for d in candidates:
        target=ctx.get('target');names=[str(x.get('target','')).lower().rstrip('.') for x in d.affected_scope]
        # DNSSEC's final question is context; direct DS/DNSKEY names can be ancestors.
        protocol_target=any(p.get('target')==target and p.get('attempt_id') in d.relevant_attempt_ids for p in result.protocol_investigations)
        matches=not target or protocol_target or matches_scope(d.affected_scope,d.fault_layer) or d.primary_issue=='FOCUS_UNMEASURED'
        d.intent_source=ctx.get('intent_source','unknown')
        d.relevance='explicit_focus' if layer_matches(d.fault_layer) and matches else 'other_measured_scope' if not matches else 'independent_observation'
        d.selection_reason=('明确关注层与本调查已测范围匹配；目标/端口按已有结构检查，未提供的时间/关联不补造；不改变确认等级。' if d.relevance=='explicit_focus' else
            '独立测量保留；缺少足够问题相关性或主次依据，不推断唯一主因。')
    explicit=[d for d in candidates if d.relevance=='explicit_focus']
    pool=explicit or [d for d in candidates if d.relevance!='other_measured_scope'] or candidates
    rank=lambda d:0 if d.diagnosis_status=='CONFIRMED_PROTOCOL_ISSUE' else 1 if d.diagnosis_status=='FAULT_LOCALIZED' else 2
    best=min(rank(d) for d in pool);leaders=[d for d in pool if rank(d)==best]
    ordered=sorted(candidates,key=lambda d:(d.primary_issue,d.fault_location))
    if len(leaders)!=1:
        result.diagnosis_selection_mode='parallel';return None,ordered
    primary=leaders[0];primary.selection_reason+=(' 本地协议确认优先。' if best==0 else '')
    result.diagnosis_selection_mode='primary';return primary,[d for d in ordered if d is not primary]


def validate_diagnostics(result,attempts):
    es={f['evidence_id'] for f in result.measured_facts};vs={v['id'] for v in result.validation_results}
    codes={f.code for f in result.findings};aids={a['attempt_id'] for a in attempts}
    group_ids=[g.diagnostic_group_id for g in result.diagnostic_groups]
    if len(group_ids)!=len(set(group_ids)):raise ValueError('Duplicate diagnostic group')
    from .path_groups import qualify,stamp,WINDOW_SECONDS
    facts={f['evidence_id']:f for f in result.measured_facts}
    for g in result.diagnostic_groups:
        rows=[facts[e] for e in g.direct_evidence_ids]
        if g.grouped_observation_count!=len(set(g.direct_evidence_ids)) or not all(qualify(f,result.measurement_provenance) and f.get('transport_status')=='timeout' and f.get('resolver_role')=='recursive' for f in rows):raise ValueError('Invalid grouped observation')
        if len({(f.get('resolver'),f.get('source_mode'),result.measurement_provenance[f['evidence_id']].get('measurement_location')) for f in rows})!=1 or max(stamp(f) for f in rows)-min(stamp(f) for f in rows)>WINDOW_SECONDS:raise ValueError('Incompatible group scope')
        expected={result.measurement_provenance[e].get('query_attempt_id') for e in g.direct_evidence_ids if result.measurement_provenance[e].get('query_attempt_recorded')}-{None}
        if set(g.query_attempt_ids)!=expected:raise ValueError('Grouped Q sources do not match E')
    for d in [result.diagnostic_conclusion]+result.secondary_diagnoses:
        if d is None:continue
        if not set(d.direct_evidence_ids+d.dependency_evidence_ids).issubset(d.evidence_ids) or not set(d.direct_validation_ids+d.dependency_validation_ids).issubset(d.validation_ids):
            raise ValueError('Direct/dependency sources exceed validated closure')
        if set(d.direct_evidence_ids)&set(d.dependency_evidence_ids) or set(d.direct_validation_ids)&set(d.dependency_validation_ids):raise ValueError('Direct/dependency sources overlap')
        if set(d.evidence_ids)-es or set(d.validation_ids)-vs or set(d.finding_codes)-codes or set(d.relevant_attempt_ids)-aids:
            raise ValueError('Invalid diagnostic source reference')
        if d.diagnosis_status=='CONFIRMED_PROTOCOL_ISSUE' and (not d.evidence_ids or not d.validation_ids):
            raise ValueError('Confirmed protocol issue needs E/V')
        measured={f['evidence_id']:f for f in result.measured_facts}
        for row in d.affected_scope+d.unaffected_or_comparison_scope:
            if row.get('evidence_id') not in d.evidence_ids or row!=scope(measured[row['evidence_id']]):
                raise ValueError('Diagnostic scope exceeds measurement')
        if d.diagnosis_status=='CONFIRMED_PROTOCOL_ISSUE':
            matching=False
            for p in result.protocol_investigations:
                v=p.get('validation') or {}
                linked,linked_e=validation_closure(v.get('validation_result_ids',[]),result.validation_results,es)
                if v.get('dnssec_status')=='BOGUS' and v.get('validation_execution')=='completed' and set(linked)==set(d.validation_ids) and set(linked_e)==set(d.evidence_ids):
                    known={r['id']:r for r in result.validation_results}
                    blocking=[known[x] for x in v.get('validation_result_ids',[]) if x in known and known[x].get('reason_code')==v.get('reason_code') and known[x].get('local_result')!='SIGNATURE_CHECK_PASSED']
                    if set(d.direct_validation_ids)!={x['id'] for x in blocking} or set(d.direct_evidence_ids)!={e for x in blocking for e in x.get('evidence_ids',[])}:raise ValueError('Direct sources do not match final blocking validation')
                    matching=True
            if not matching:raise ValueError('Confirmed diagnosis does not match local BOGUS result')
        for step in d.remediation_steps+d.verification_steps:
            if not set(step.evidence_ids).issubset(d.evidence_ids) or not set(step.validation_ids).issubset(d.validation_ids):
                raise ValueError('Remediation source exceeds diagnosis')
