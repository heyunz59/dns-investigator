"""Read-only checks and conditional changes; instructions are never executed."""
from .schemas import RemediationStep,RemediationBranch


def branches(d):
    """Future conditions, not additional observed facts. Dispatch on structured fields."""
    def branch(condition,interpretation,next_action,change=False):
        return RemediationBranch(condition='如果后续检查发现：'+condition,interpretation=interpretation,next_action=next_action,
            change_prerequisites=['管理权限、配置备份及已确认的具体配置问题；另行操作，不自动执行。'] if change else [])
    if d.diagnosis_status=='NO_FAULT_OBSERVED' or d.primary_issue=='FOCUS_UNMEASURED':
        return [branch('用户提供现场错误、时间、网络与访问方式','补充陈述不等于新测量；当前关注问题未复现或未测','先核对现场信息，再决定是否进行新的授权检查，不修改正常路径的配置。')]
    if d.reason_code=='DS_DIGEST_MISMATCH':
        return [branch('父侧 DS 与子侧 DNSKEY 的算法/digest 发布材料仍不匹配','关联异常复现，但轮换或配置操作原因未定','管理员核对轮换状态后条件性修正对应发布材料，再重验完整链。',True),
            branch('DS/DNSKEY 匹配但 RRSIG 验证失败','当前阻断环节已变化','检查签名者、DNSKEY、RRSIG 和验证时间，不直接修改 DS。'),
            branch('材料缺失或算法/策略不支持','仍无法确定','保持未知，按同一信任锚/时间与独立验证器只读复核。')]
    if d.primary_issue.endswith('QUERY_TIMEOUT'):
        return [branch('原解析路径仍超时、对照正常','范围集中于所列查询路径；服务与网络未区分','检查该解析器服务日志与受限网络可达性。'),
            branch('原路径恢复响应','可能间歇性；不能确认已永久修复','记录复测时间，核对故障时刻和日志。'),
            branch('所有已授权对照路径均超时','范围可能更广，未确认本机或运营商原因','核对测量工具及现场网络，不无界增加查询。'),
            branch('原路径收到 SERVFAIL','已收到 DNS 错误响应，不再是超时','转入响应错误及上游/验证材料的调查。')]
    if d.fault_layer=='DNSSEC':
        return [branch('相同信任锚、时间、材料下验证仍失败','仅复现所列验证阶段异常','按 reason_code 核对签名、有效期或否定证明；排除实现支持边界后再修正。',d.diagnosis_status=='CONFIRMED_PROTOCOL_ISSUE'),
            branch('独立验证器通过或本地能力受限','结论存在实现/策略差异','保留 E/V 与分歧，不盲目替换密钥或关闭 DNSSEC。')]
    if d.fault_layer in {'Authoritative DNS','Delegation','CNAME/Alias Resolution','Recursive DNS'}:
        return [branch('仅选中单个 NS 无响应或非 AA，其他路径正常','只定位该服务器/路径，不代表全区不可用','核对该 NS 服务、父侧委派和同名同类型查询。'),
            branch('地址未取得、发现未完成或预算中断','缺的是执行材料，不是已确认区域故障','在新的有预算且已授权调查中补足地址/发现或别名末端，不突破本轮预算。'),
            branch('多个选中 NS 均有明确异常','异常范围扩大至已测子集','管理员核对各 NS 的地址、服务和发布配置，不直接替换全部服务器。',True)]
    if d.fault_layer=='TCP/Network Transport':
        observed={'REFUSED':'连接拒绝','TIMEOUT':'连接超时','NETWORK_ERROR':'底层执行/网络错误'}.get(d.reason_code,'尚未复现')
        return [branch('同一 IP/端口仍为 '+observed,'复测仅确认连接结果，未确认服务未启动','对照服务监听、主机/网络访问日志，区分未监听、访问控制和路径。'),
            branch('确认监听或访问规则存在具体错误','取得可操作的管理配置证据','管理员仅修正对应服务/规则，再复测同一端口。',True),
            branch('复测成功或错误类别变化','路径状态随时间变化，原原因仍未确认','保留新错误码和时间；不禁用 IPv6 或关闭整个防火墙。')]
    if d.fault_layer=='TLS':
        code=(d.error_details.get('certificate') or {}).get('verify_code')
        check={10:'证书有效期与本地时钟',9:'证书生效时间与本地时钟',62:'原始主机名与证书 SAN',20:'发行链与信任根',21:'发行链与信任根'}.get(code,'实际错误类别、证书链、名称与时钟；未知不等于过期')
        return [branch('只读核对后确认 '+check+' 存在问题','错误码提供方向，不自动确定运维根因','有权限者修正已确认的证书/链/时间配置，保留 Host/SNI 和证书验证。',True),
            branch('证书材料正常或只有一般连接错误','尚未定位证书根因','核对相同域名与路径的 TLS 日志，不依据域名猜测过期，不用 IP 替换 URL。')]
    if d.fault_layer=='HTTP':
        hints={401:'认证条件',403:'授权/访问策略',404:'URL 路由与资源发布',429:'请求频率与服务限额',500:'应用错误日志',502:'网关和上游响应',503:'服务健康与维护状态',504:'网关/上游时限'}
        hint=hints.get(d.status_code,'连接、响应头及正文完成状态')
        if d.primary_issue.startswith('HTTP_REQUEST_'):
            return [branch('收到状态码但正文读取仍未完成','响应头存在不等于完整请求成功','核对正文/上游日志和传输中断；最多一次已授权对照重试。'),
                branch('完整完成或错误变化','原异常未持续复现','记录状态码、最终 URL、正文状态与时间；不据此认定用户现场已修复。')]
        return [branch('同一请求仍返回 '+str(d.status_code),'状态码是现象，不能证明具体原因','只读核对 '+hint+' 及端点设计；最多一次已授权对照重试，未采集 Retry-After 不编造等待值。'),
            branch('管理员确认具体 '+hint+' 配置错误','有条件的配置修复依据成立','仅修正对应设置，不因 HTTP 错误修改 DNS。',True),
            branch('响应符合设计或复测恢复','该响应不一定是故障或可能间歇性','保留请求条件和时间，再核对用户现场错误。')]
    return [branch('用户提供现场错误、时间、网络与访问方式','补充的是用户陈述，不是本机测量','在授权范围内选择能区分该症状的下一项检查，不随意修改 DNS。'),
        branch('仍无有效证据或被安全策略阻止','不能证明远端服务故障','先核对参数/授权/执行问题，不自动扩大目标范围。')]


def plan(diagnosis, query=False):
    d=diagnosis
    if query and d.diagnosis_status=='NO_FAULT_OBSERVED':return []
    if d.diagnosis_status=='NO_FAULT_OBSERVED' or d.primary_issue=='FOCUS_UNMEASURED':
        actions=['在故障设备记录具体错误、发生时间和当时网络；对照同一目标，先不修改配置。']
        fix=None
    elif d.fault_layer=='DNSSEC':
        if d.diagnosis_status!='CONFIRMED_PROTOCOL_ISSUE':
            actions=['核对所列验证未完成原因、预算和算法策略；用同一信任锚、时间与问题向独立验证器提供已有材料。']
            fix=None
        elif d.reason_code=='DS_DIGEST_MISMATCH':
            actions=['只读查询并核对父区域发布的 DS 与子区域正在使用的 DNSKEY（含 key tag、算法和 digest）。',
                     '核对密钥轮换时间、发布状态与管理权限，确认具体不匹配发生在哪个父子区域。']
            fix='只有确认父子 DS/DNSKEY 关联配置错误后，管理员才按正确密钥轮换流程修正对应记录；不直接删除 DS 或关闭 DNSSEC。'
        elif d.reason_code in {'NO_SIGNATURE_VALIDATED','RRSIG_MISSING'}:
            actions=['核对所列 RRset 的 RRSIG signer、key tag、算法、有效期与验证时钟，再与当前可信 DNSKEY 对照。']
            fix='只有确认签名或发布时间配置问题后，由管理员更新对应签名/发布流程，保留 DNSSEC 验证。'
        else:
            actions=['对照原 QNAME/QTYPE、失败阶段和 E/V 链，核对所列 SOA、NSEC/NSEC3、签名及覆盖范围；用独立验证器复核。']
            fix='只有确认区域材料存在具体问题且排除验证器支持边界后，由管理员修正相应发布材料，避免盲目修改整个区域。'
    elif d.fault_layer in {'Recursive DNS','Authoritative DNS','Delegation','CNAME/Alias Resolution'}:
        actions=['从相同测量位置复测所列目标、记录类型和解析路径，记录真实复测时间；与已测对照路径比较。']
        if d.fault_layer=='Delegation':actions+=['只读核对父区域 NS、委派地址与被选中子区域服务器的 AA 回答；单个 NS 失败不等于整个区域不可用。']
        elif d.fault_layer=='CNAME/Alias Resolution':actions+=['根据 affected_scope 中的 CNAME 路径与 canonical_name 核对缺失末端；外部名称需单独授权，未完成不等于别名配置错误。']
        elif 'TIMEOUT' in d.primary_issue:actions+=['核对该解析器/权威服务状态、网络可达性和查询访问策略，区分服务与路径因素。']
        else:actions+=['核对具体解析器缓存、查询策略与权威发布状态；地址或 SOA Serial 差异可能来自正常调度或更新。']
        fix='仅在对照确认具体缓存、服务或区域配置问题并具备管理权限后，修正对应配置；不要仅凭差异更换 DNS 或改记录。'
    elif d.fault_layer=='TCP/Network Transport':
        actions=['核对所列 IP/端口的服务监听及主机/网络放行规则；区分 REFUSED、TIMEOUT 和 NETWORK_ERROR。']
        fix='只有确认具体监听或访问规则错误后，由管理员修正对应服务/规则，不关闭全部防火墙或禁用 IPv6。'
    elif d.fault_layer=='TLS':
        actions=['核对实际证书错误码、证书有效期、目标名称、证书链与系统时间，保留原域名的 Host/SNI 和证书校验。']
        fix='仅在证实证书或信任链配置问题后更新对应证书/链；不得关闭证书验证或用 IP 替换 HTTPS 域名。'
    elif d.fault_layer=='HTTP':
        actions=['核对所列 URL、最终 URL、状态码、重定向与请求完成状态；结合服务日志和接口设计确认响应含义。']
        fix='仅在确认应用、权限或上游配置问题且有管理权限后修正对应设置；4xx/5xx 不要求修改 DNS。'
    else:
        actions=['先处理所列执行问题并收集故障设备的错误、时间和现场网络；只在新的有预算且已授权调查中补足缺失检查。']
        fix=None
    synthetic=any(s!='live' for s in d.source_modes)
    safety=['尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。']
    if synthetic:
        safety+=['fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。']
    verification=('从相同位置、记录复测时间，重新检查相同目标/类型/解析器；比较原异常是否消失及对照是否稳定。'
        if d.fault_layer in {'Recursive DNS','Authoritative DNS','Delegation','CNAME/Alias Resolution'} else
        '以同一信任锚、策略、时间范围和 QNAME/QTYPE 重验完整 DNSSEC 链与递归响应，保存新的 E/V；不能只看一次解析成功。'
        if d.fault_layer=='DNSSEC' else
        '以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。')
    steps=[]
    for typ,title,instructions in [('CHECK','优先核对与定位',actions)]+(
            [('POSSIBLE_FIX','条件成立后的修复',[fix])] if fix else [])+[
            ('VERIFY','复测并保留新证据',[verification])]:
        steps.append(RemediationStep(id=f'{d.primary_issue}-R{len(steps)+1}',priority=len(steps)+1,title=title,
            action_type=typ,description='；'.join(instructions),target=d.fault_location,reason=d.cause,
            related_finding_codes=d.finding_codes,evidence_ids=d.evidence_ids,validation_ids=d.validation_ids,
            instructions=instructions,expected_outcomes=['缩小到所列异常环节或明确仍缺失的证据；不预设故障已修复。'],
            verification_method=verification,prerequisites=['有效的目标授权；配置变更另需管理权限与原因确认。'],safety_notes=safety,
            method=dict(kind='simulation_review' if synthetic else 'administrator_read_only' if typ!='VERIFY' else 'external_read_only',
                supported_by_current_tools=False,parameters=d.location,description='人工只读核对或外部复核；不是自动工具调用。'),
            branches=branches(d) if typ=='CHECK' else []))
    for step in steps:
        if step.branches:step.expected_outcomes=[b.condition for b in step.branches]
        if d.diagnosis_status=='NO_FAULT_OBSERVED' or d.primary_issue=='FOCUS_UNMEASURED' or d.fault_layer=='Unknown':
            step.method=dict(kind='user_information',supported_by_current_tools=False,
                parameters={},description='补充故障设备、时间、网络与访问方式；用户陈述不作为测量。')
            continue
        if step.action_type=='POSSIBLE_FIX':
            step.method=dict(kind='administrator_conditional_change',supported_by_current_tools=False,
                parameters=d.location,description='仅在分支条件和管理权限成立后人工变更；本程序不执行。')
        elif not synthetic and d.affected_scope:
            f=d.affected_scope[0]
            if d.fault_layer=='Recursive DNS' and f.get('record_type'):
                step.method=dict(kind='current_tool',tool_name='query_dns',supported_by_current_tools=True,
                    parameters=dict(domain=f['target'],record_type=f['record_type'],resolver=f.get('resolver')),
                    description='后续新的授权调查中的候选检查；仍须目标、解析器、时效和预算校验，尚未执行。')
            elif d.fault_layer=='TCP/Network Transport':
                step.method=dict(kind='current_tool',tool_name='check_tcp',supported_by_current_tools=True,
                    parameters=dict(ip=f['target'],port=f.get('port')),
                    description='必须先取得新的 live DNS 地址证据并重新通过网络/端口授权，尚未执行。')
    return steps


def attach(result):
    from .diagnostic_reasoner import reason
    result.diagnostic_conclusion,result.secondary_diagnoses=reason(result)
    if result.report_fallback_reason:
        for d in ([result.diagnostic_conclusion] if result.diagnostic_conclusion else [])+result.secondary_diagnoses:
            d.limitations.append('程序回退报告，Agent 总结失败：'+result.report_fallback_reason)
    result.diagnosis_ordering='先匹配受控目标/明确关注层，再考虑确认等级；同级无充分主次依据时 primary=null 并列保留。稳定代码只用于展示平局。'
    result.remediation_plan=[]
    for i,d in enumerate([result.diagnostic_conclusion]+result.secondary_diagnoses):
        if d is None:continue
        steps=plan(d,result.request_kind=='query')
        for step in steps:step.id=f'D{i+1}-'+step.id
        d.remediation_steps=[s for s in steps if s.action_type!='VERIFY']
        d.verification_steps=[s for s in steps if s.action_type=='VERIFY']
        result.remediation_plan+=steps
    # Candidate wording is never promoted to a validated fact. Only reviewed scoped
    # relationships survive, and source limitations accompany the model's ranking.
    result.candidate_analysis=[dict(hypothesis_id=h.id,statement=h.statement,status='CANDIDATE',
        evidence_ids=h.supporting_evidence_ids,missing_information=h.missing_information,
        source='existing_agent_draft_unverified',review='PENDING_HUMAN_SEMANTIC_REVIEW')
        for h in result.hypotheses if h.supporting_evidence_ids]
    return result
