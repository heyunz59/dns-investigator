"""Pure presentation mappings. Never query, validate protocols, or raise certainty."""
from collections import Counter
from datetime import datetime

TOOLS = {'query_dns': '查询 DNS', 'compare_resolvers': '对比解析器', 'query_authoritative': '检查权威 DNS', 'check_tcp': '检测 TCP 连接', 'check_http': '检查 HTTP'}
STATES = {'running': '调查进行中', 'cancelling': '正在停止调查', 'cancelled': '已取消调查', 'completed': '调查完成', 'limited': '调查受限', 'failed': '调查失败', 'started': '执行未结束（历史记录）', 'historical_replay': '历史回放'}
EXECUTION = {'measured':'已记录', 'ok':'已执行', 'completed':'已完成', 'rejected':'未获准执行', 'failed':'执行失败', 'error':'执行错误', 'pending':'未完成', 'cancelled':'已取消'}
RESULTS = {'TIMEOUT':'查询超时', 'NOERROR':'正常响应', 'NXDOMAIN':'名称不存在', 'SERVFAIL':'DNS 服务失败', 'REFUSED':'DNS 拒绝查询', 'INDETERMINATE':'无法确定', 'BOGUS':'验证失败', 'SECURE':'验证通过', 'INSECURE':'未签名区域'}
REASONS = {'DS_DIGEST_MISMATCH':'父区域 DS 与子区域 DNSKEY 无法建立关联', 'DNSKEY_SIGNATURE_INVALID':'DNSKEY 签名验证失败', 'TRUST_ANCHOR_UPDATE_REQUIRED':'信任锚需要更新', 'RECURSIVE_QUERY_TIMEOUT':'已测递归查询路径超时'}
TITLES = {'TCP_REFUSED':'已测 TCP 连接被拒绝', 'HTTP_503':'已测 HTTP 服务返回 503', 'RECURSIVE_AUTH_RESPONSE_MISMATCH':'递归与选中权威响应存在差异', 'DS_DIGEST_MISMATCH':'DNSSEC DS/DNSKEY 关联验证失败', 'RECURSIVE_QUERY_TIMEOUT':'已测 DNS 查询路径超时'}

def dictionaries(value):
    return [x for x in value if isinstance(x, dict)] if isinstance(value, list) else []

def recorded_time(value):
    try: return datetime.fromisoformat(value.replace('Z', '+00:00')).timestamp()
    except (ValueError, TypeError, AttributeError): return None

def result_text(e):
    data = e.get('data') or e
    tool = e.get('tool_name') or e.get('tool')
    if tool == 'check_tcp':
        return {'CONNECTED':'连接成功（仅限已测 IP/端口）','REFUSED':'TCP 连接被拒绝','TIMEOUT':'TCP 连接超时'}.get(data.get('status'), 'TCP 结果未确定')
    if tool == 'check_http':
        status = data.get('status_code')
        refusal = data.get('security_refusal') or data.get('error') or {}
        blocked = data.get('request_state') == 'blocked_by_policy' or 'NOT_AUTHORIZED' in str(refusal) or 'BLOCKED' in str(refusal)
        return ('取得 HTTP '+str(status) if status else '未取得 HTTP 状态码') + ('；后续请求未获授权，未验证最终页面' if blocked else '；仅代表本次已测请求')
    value = data.get('result_kind') or data.get('result') or data.get('dns_rcode') or data.get('rcode') or data.get('status')
    return RESULTS.get(str(value), '结果未记录' if not value else str(value))

def enrich(view, log):
    r = view['result']; ds = view['diagnoses']; d = (ds or [{}])[0]
    evidence = dictionaries(view['evidence']); by_id = {e.get('id') or e.get('evidence_id'):e for e in evidence}
    incident = log.get('incident') or {}; target = incident.get('target') or {}
    target = target.get('url') or target.get('domain') if isinstance(target, dict) else target
    view.update(target=target or r.get('request_context', {}).get('target') or '目标未记录',
        measured_at=log.get('started_at') or next((e.get('started_at') or e.get('measured_at') for e in evidence if e.get('started_at') or e.get('measured_at')), None),
        replay=bool(log.get('report_replay')) or log.get('status') == 'historical_replay',
        state_label=STATES.get(view['state'], '状态未记录'), full_explanation=view['explanation'],
        short_title=view['title'], short_explanation='当前证据仅支持所列测量范围；具体配置原因及未测路径仍需核对。')
    overview = view['diagnostic_summary']
    if overview.get('timeout_groups'):
        view['short_title'] = '部分 DNS 解析路径超时' if overview.get('successful_dns') else '已测 DNS 解析路径超时'
        view['short_explanation'] = '异常集中在已测的部分解析器查询路径，具体原因尚未确认。' + ('其他已测查询存在正常响应，不能据此认定目标域名整体 DNS 不可用。' if overview.get('successful_dns') else '缺少足够成功对照，尚无法确定目标域名的整体可用性。')
        view['short_location'] = '、'.join(str(x.get('resolver','未记录解析器')) for x in overview['timeout_groups'])
    else:
        fallback_title = {'CONFIRMED_PROTOCOL_ISSUE':'已确认所列协议异常','FAULT_LOCALIZED':'已测范围出现异常，具体原因待核对','LIKELY_CAUSE':'存在候选原因，仍需进一步验证','NO_FAULT_OBSERVED':'本次未观察到明确故障','INSUFFICIENT_EVIDENCE':'证据不足，暂无法确定'}.get(d.get('diagnosis_status'),'证据不足，暂无法确定')
        view['short_title'] = '多个独立异常，无法确认唯一主因' if r.get('diagnosis_selection_mode') == 'parallel' else TITLES.get(d.get('primary_issue'), TITLES.get(d.get('reason_code'), fallback_title))
        status = d.get('diagnosis_status')
        if status == 'NO_FAULT_OBSERVED': view['short_explanation'] = '本次已测范围内未观察到明确故障；这不代表所有路径、记录类型或后续请求均正常。'
        elif status == 'CONFIRMED_PROTOCOL_ISSUE': view['short_explanation'] = '所列协议异常已有直接验证依据；具体配置操作原因仍需核对，不能据此推断所有访问路径均失败。'
        elif status == 'INSUFFICIENT_EVIDENCE' or not ds: view['short_explanation'] = '当前证据不足以确认故障或根因；请查看调查限制，并在授权范围内补充测量。'
        elif status == 'LIKELY_CAUSE': view['short_explanation'] = '现有观测支持候选原因，尚未完成确认；请先核对关键证据，再决定是否修改配置。'
    if view['state'] == 'cancelled':
        view.update(label='调查已取消', tone='uncertain', short_explanation='调查已停止，仅保留取消前取得的实际证据；取消不代表 DNS 故障。')
    view.setdefault('short_location', view['location'])
    measurements = []
    queries = dictionaries(view['dns_attempts'])
    if not queries:
        queries = [dict(evidence_id=e.get('id') or e.get('evidence_id')) for e in evidence if (e.get('tool_name') or e.get('tool')) == 'query_dns']
    for q in queries:
        e = by_id.get(q.get('evidence_id'), {}); data = e.get('data') or e
        value = data.get('result_kind') or data.get('result') or data.get('dns_rcode') or data.get('rcode')
        timeout = value == 'TIMEOUT' or data.get('transport_status') == 'timeout'
        complete = data.get('resolution_complete') is True
        # A recorded event is not a successful DNS answer.
        tone = 'uncertain' if timeout else 'good' if value == 'NOERROR' and complete else 'bad' if value in ('SERVFAIL','REFUSED') else 'neutral'
        raw_rcode = data.get('dns_rcode') or data.get('rcode')
        rcode = raw_rcode if raw_rcode in ('NOERROR','FORMERR','SERVFAIL','NXDOMAIN','NOTIMP','REFUSED','YXDOMAIN','YXRRSET','NXRRSET','NOTAUTH','NOTZONE','BADVERS','BADCOOKIE') and not timeout else '未收到响应' if timeout else '未记录'
        measurements.append(dict(resolver=q.get('server') or data.get('resolver') or e.get('resolver') or '未记录',
            name=q.get('qname') or data.get('qname') or data.get('target') or e.get('input',{}).get('domain') or '未记录',
            type=q.get('qtype') or data.get('record_type') or '未记录', role=q.get('resolver_role') or data.get('resolver_role') or 'unknown',
            source=e.get('source_mode') or 'unknown', location=e.get('measurement_location') or incident.get('measurement_location') or '未记录',
            time=q.get('finished_at') or data.get('measured_at') or e.get('started_at'),
            duration=q.get('duration_ms', data.get('duration_ms')), evidence_id=q.get('evidence_id'), query_id=q.get('query_attempt_id') or data.get('query_attempt_id'),
            parent_id=q.get('parent_tool_call_id') or e.get('tool_call_id'), rcode=rcode,
            execution=EXECUTION.get(q.get('status'), q.get('status') or '状态未记录'), result='查询超时' if timeout else result_text(e),
            tone=tone, complete=complete, raw=q))
    grouped = {}
    for m in measurements:
        key=(str(m['resolver']),str(m['role']),str(m['source']),str(m['location']))
        grouped.setdefault(key, []).append(m)
    groups=[]
    for key, ms in grouped.items():
        counts=Counter(m['result'] for m in ms)
        groups.append(dict(resolver=key[0],role=key[1],source=key[2],location=key[3],measurements=ms,
            summary='；'.join(f'{v} 次{k}' for k,v in counts.items()),
            tone='uncertain' if any(m['tone']=='uncertain' for m in ms) else 'good' if all(m['tone']=='good' for m in ms) else 'neutral'))
    view['resolver_groups']=groups
    view['paths']=[dict(resolver=g['resolver'],role=g['role'],source=g['source'],location=g['location'],summary=g['summary'],tone=g['tone'],
        queries=list(dict.fromkeys(m['name']+' '+m['type'] for m in g['measurements']))) for g in groups]
    view['evidence_cards']=[dict(id=e.get('id') or e.get('evidence_id') or 'ID 未记录',
        title=(TOOLS.get(e.get('tool_name') or e.get('tool'), '测量')+' · '+str((e.get('input') or {}).get('domain') or (e.get('data') or e).get('target') or '')+' · '+result_text(e)),raw=e) for e in evidence]
    direct=set(i for x in ds for i in x.get('direct_evidence_ids',[])+x.get('direct_validation_ids',[]))
    view['evidence_cards'].sort(key=lambda c:c['id'] not in direct)
    view['validation_cards']=[dict(id=v.get('id') or v.get('validation_id') or 'ID 未记录',title=RESULTS.get(v.get('status'),v.get('status') or '验证结果未记录'),raw=v) for v in dictionaries(view['validations'])]
    timeline=[]
    for a in dictionaries(view['attempts']):
        aid=a.get('attempt_id') or a.get('id'); related=[e for e in evidence if e.get('tool_call_id')==aid or e.get('parent_tool_call_id')==aid or (e.get('id') or e.get('evidence_id')) in a.get('evidence_ids',[])]
        refs=[aid]+[e.get('id') or e.get('evidence_id') for e in related]+[q.get('query_attempt_id') for q in queries if q.get('parent_tool_call_id')==aid]
        error=a.get('error')
        timeline.append(dict(time=a.get('started_at') or a.get('timestamp'), operation=TOOLS.get(a.get('tool_name'), a.get('tool_name') or '操作未记录'),
            target=a.get('input',{}).get('domain') or a.get('input',{}).get('url') or a.get('input',{}).get('ip') or '目标未记录',
            state=EXECUTION.get(a.get('status'),a.get('status') or '状态未记录'), duration=a.get('duration_ms'),
            summary='调用未执行或未完成；不据此判断远端故障。' if a.get('status') in ('rejected','failed','error','cancelled','pending') else '；'.join(dict.fromkeys(result_text(e) for e in related)) or '没有关联结果记录。',
            refs=[x for x in refs if x],error=error,raw=a))
    timeline.sort(key=lambda x:(recorded_time(x['time']) is None,recorded_time(x['time']) or 0))
    view['timeline']=timeline
    view['dnssec']=[dict(title=REASONS.get(x.get('reason_code'), 'DNSSEC 验证范围与依据'),location=x.get('fault_location'),stage=x.get('failure_stage') or '阶段未记录',
        certainty=x.get('diagnosis_status'),direct=x.get('direct_evidence_ids',[])+x.get('direct_validation_ids',[]),dependencies=x.get('dependency_evidence_ids',[])+x.get('dependency_validation_ids',[])) for x in ds if x.get('fault_layer')=='DNSSEC']
    return view
