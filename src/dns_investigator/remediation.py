"""Read-only checks and conditional changes; instructions are never executed."""
from .schemas import RemediationStep


def plan(diagnosis, query=False):
    d=diagnosis
    if query and d.diagnosis_status=='NO_FAULT_OBSERVED':return []
    if d.primary_issue=='MEASURED_NORMAL':
        actions=['在故障设备记录具体错误、发生时间和当时网络；对照同一目标，先不修改配置。']
        fix=None
    elif d.fault_layer=='DNSSEC':
        if d.diagnosis_status!='CONFIRMED_PROTOCOL_ISSUE':
            actions=['核对所列验证未完成原因、预算和算法策略；用同一信任锚、时间与问题向独立验证器提供已有材料。']
            fix=None
        elif 'DS_DIGEST_MISMATCH' in d.cause:
            actions=['只读查询并核对父区域发布的 DS 与子区域正在使用的 DNSKEY（含 key tag、算法和 digest）。',
                     '核对密钥轮换时间、发布状态与管理权限，确认具体不匹配发生在哪个父子区域。']
            fix='只有确认父子 DS/DNSKEY 关联配置错误后，管理员才按正确密钥轮换流程修正对应记录；不直接删除 DS 或关闭 DNSSEC。'
        elif 'SIGNATURE' in d.cause or 'RRSIG' in d.cause:
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
            verification_method=verification,prerequisites=['有效的目标授权；配置变更另需管理权限与原因确认。'],safety_notes=safety))
    return steps


def attach(result):
    from .diagnostic_reasoner import reason
    result.diagnostic_conclusion,result.secondary_diagnoses=reason(result)
    if result.report_fallback_reason:
        result.diagnostic_conclusion.limitations.append('程序回退报告，Agent 总结失败：'+result.report_fallback_reason)
    result.diagnosis_ordering='本地已验证协议异常优先，其余按确定性与稳定代码排序；不表示独立异常间存在主次因果。'
    result.remediation_plan=[]
    for i,d in enumerate([result.diagnostic_conclusion]+result.secondary_diagnoses):
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
