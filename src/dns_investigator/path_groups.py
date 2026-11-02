"""Path-level observation groups; never merges causes or changes measurements/Findings."""
import hashlib
import ipaddress
import json
from datetime import datetime

WINDOW_SECONDS=300


def stamp(f):
    try:
        d=datetime.fromisoformat(f['measured_at'])
        return d.timestamp() if d.tzinfo is not None else None
    except (KeyError,ValueError,TypeError):return None


def qualify(f,provenance):
    p=provenance.get(f['evidence_id'],{})
    return (f.get('source_mode') in {'live','fixture','synthetic'} and p.get('measurement_location')
        and p.get('execution_status')=='ok' and stamp(f) is not None)


def successful(f):
    return (f.get('tool')=='query_dns' and f.get('transport_status')=='responded' and
        f.get('result')=='NOERROR' and f.get('records') and not (f.get('dns_flags') or {}).get('TC') and
        f.get('resolution_complete') is not False and
        (f.get('resolver_role')!='authoritative' or f.get('authoritative_answer') is True))


def comparable(a,b,provenance):
    return (qualify(a,provenance) and qualify(b,provenance) and
        a['target'].lower().rstrip('.')==b['target'].lower().rstrip('.') and
        a.get('record_type')==b.get('record_type') and a['source_mode']==b['source_mode'] and
        provenance[a['evidence_id']]['measurement_location']==provenance[b['evidence_id']]['measurement_location'] and
        abs(stamp(a)-stamp(b))<=WINDOW_SECONDS)


def aggregate(result,candidates,facts):
    from .diagnostic_reasoner import scope
    provenance=result.measurement_provenance;pool={};keep=[]
    for d in candidates:
        if d.primary_issue!='RECURSIVE_QUERY_TIMEOUT':keep.append(d);continue
        if not d.direct_evidence_ids or any(e not in facts or not qualify(facts[e],provenance) for e in d.direct_evidence_ids):
            keep.append(d);continue # legacy scope retained, never invent grouping metadata
        used=False
        for eid in d.direct_evidence_ids:
            f=facts.get(eid)
            if not f or f.get('transport_status')!='timeout' or f.get('resolver_role')!='recursive':continue
            used=True
            try:resolver=str(ipaddress.ip_address(f.get('resolver')))
            except ValueError:resolver=f.get('resolver')
            p=provenance.get(eid,{})
            key=(d.primary_issue,d.reason_code,resolver,'recursive',f.get('source_mode'),p.get('measurement_location'))
            if not qualify(f,provenance) or not resolver:key+=('unqualified',eid)
            pool.setdefault(key,{})[eid]=(f,d)
        if not used:keep.append(d)
    groups=[]
    for key,observations in sorted(pool.items(),key=lambda item:repr(item[0])):
        remaining=sorted(observations.values(),key=lambda pair:(stamp(pair[0]) or 0,pair[0]['evidence_id']))
        while remaining:
            start=stamp(remaining[0][0]);batch=[pair for pair in remaining if start is None or stamp(pair[0]) is not None and stamp(pair[0])-start<=WINDOW_SECONDS]
            remaining=remaining[len(batch):]
            rows=[f for f,_ in batch];ids=sorted(f['evidence_id'] for f in rows)
            d=batch[0][1].model_copy(deep=True);server=key[2]
            d.diagnostic_group_id='DG-'+hashlib.sha256(json.dumps([key,ids],sort_keys=True).encode()).hexdigest()[:12]
            d.grouped_observation_count=len(ids);d.direct_evidence_ids=ids
            controls=[f for f in facts.values() if successful(f) and any(comparable(a,f,provenance) for a in rows)]
            d.evidence_ids=sorted(set(ids+[f['evidence_id'] for f in controls]))
            d.affected_scope=[scope(f) for f in sorted(rows,key=lambda f:f['evidence_id'])]
            d.unaffected_or_comparison_scope=[scope(f) for f in controls]
            d.query_attempt_ids=sorted({provenance[e]['query_attempt_id'] for e in ids if provenance.get(e,{}).get('query_attempt_recorded')})
            d.location=[dict(resolver=server,role='recursive',measurement_location=key[5],source_mode=key[4],
                time_start=min((f['measured_at'] for f in rows),key=lambda x:datetime.fromisoformat(x).timestamp()) if start is not None else None,
                time_end=max((f['measured_at'] for f in rows),key=lambda x:datetime.fromisoformat(x).timestamp()) if start is not None else None)]
            location_display='本次程序主机' if key[5]=='program-host' else key[5] or '测量位置未知'
            d.fault_location=f"{location_display} → {server} 的本组 DNS 查询路径"
            d.summary=f"解析器 {server}：{len(ids)} 次递归查询超时"
            if key[4]!='live':d.summary='[fixture/synthetic 模拟数据] '+d.summary
            queries=list(dict.fromkeys(f"{f['target']} {f.get('record_type')}" for f in rows))
            d.cause=f"{server} 的 {len(ids)} 次查询未在时限内收到响应；已测组合：{'、'.join(queries)}。只归纳路径级现象，未确认共同或独立根因。"
            d.reason=d.cause
            d.grouped_findings=[dict(code=f.code,scope=f.scope,evidence_ids=[e for e in f.evidence_ids if e in ids])
                for f in result.findings if f.code==d.primary_issue and set(f.evidence_ids)&set(ids)]
            d.relevant_attempt_ids=sorted({provenance[e].get('attempt_id') for e in ids if provenance.get(e,{}).get('attempt_recorded')})
            d.limitations=list(dict.fromkeys(d.limitations+['跨名称/类型归并仅表示同一路径的超时现象，不证明这些观测具有唯一共同原因。']))
            if not qualify(rows[0],provenance):d.limitations.append('时间、位置或执行来源不完整，本条保留为单次观测，未与其他记录合并。')
            groups.append(d)
    result.diagnostic_groups=groups
    return keep+groups


def overview(result):
    groups=result.diagnostic_groups
    if not groups:return
    facts=result.measured_facts;by_id={f['evidence_id']:f for f in facts}
    failed={e for g in groups for e in g.direct_evidence_ids}
    controls=[f for f in facts if successful(f) and any(comparable(by_id[e],f,result.measurement_provenance) for e in failed)]
    tcp=[dict(evidence_id=f['evidence_id'],ip=f['target'],port=f.get('port'),status=f['result']) for f in facts if f['tool']=='check_tcp' and f['result']=='CONNECTED']
    http=[dict(evidence_id=f['evidence_id'],url=f['target'],final_url=f.get('final_url'),status_code=f.get('status_code'),
        request_state=f.get('request_state'),redirects=f.get('redirects'),security_refusal=f.get('security_refusal'))
        for f in facts if f['tool']=='check_http' and f.get('status_code') is not None]
    all_d=([result.diagnostic_conclusion] if result.diagnostic_conclusion else [])+result.secondary_diagnoses
    only_groups=all(d.diagnostic_group_id for d in all_d)
    title='部分递归 DNS 查询路径超时' if controls else '已测递归 DNS 查询路径超时，尚无可靠成功对照'
    text='；'.join(g.summary for g in groups)+'。'
    if controls:
        recursive=sorted({str(f['resolver']) for f in controls if f.get('resolver_role')=='recursive'})
        auth=sorted({str(f['resolver']) for f in controls if f.get('resolver_role')=='authoritative'})
        if recursive:text+='已测递归正常响应路径：'+ '、'.join(recursive)+'。'
        if auth:text+='已测选中权威服务器正常响应：'+'、'.join(auth)+'；不代表全部权威。'
        text+='这些对照限各自实际名称、类型、来源和时间，不足以认定目标域名整体 DNS 不可用。'
    else:text+='没有足够的同来源/位置/时间及同名同类型成功对照；不能认定域名整体故障或服务器宕机。'
    if tcp:text+='已测 TCP 连接成功：'+'、'.join(f"{r['ip']}:{r['port']}（{r['evidence_id']}）" for r in tcp)+'；不代表全部 HTTPS 正常。'
    for r in http:
        text+=f"HTTP {r['url']} 取得 {r['status_code']}（{r['evidence_id']}）。"
        if r['security_refusal']:text+='后续重定向被安全策略拒绝，未请求被拒绝目标，不是目标站点不可达，也未完成最终页面检测。'
        elif r['request_state']!='complete':text+='请求完成状态另列，不将状态码当完整页面成功。'
    result.diagnostic_summary=dict(title=title if only_groups else None,explanation=text,scope='measured_paths_only',
        timeout_groups=[dict(group_id=g.diagnostic_group_id,resolver=g.location[0]['resolver'],count=g.grouped_observation_count,
            evidence_ids=g.direct_evidence_ids,query_attempt_ids=g.query_attempt_ids,queries=g.affected_scope) for g in groups],
        successful_dns=[dict(evidence_id=f['evidence_id'],target=f['target'],record_type=f.get('record_type'),resolver=f.get('resolver'),role=f.get('resolver_role'),source_mode=f['source_mode'],measured_at=f.get('measured_at')) for f in controls],
        tcp_successes=tcp,http_responses=http,root_cause_confirmed=False)
