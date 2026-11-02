"""Outcome/scope/causal-level tests, not natural-language accuracy scoring."""
from datetime import datetime,timezone
from pathlib import Path
import pytest
import dns.flags,dns.message,dns.rcode,dns.rrset
from dns_investigator.dns_wire import parse_response
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target
from dns_investigator.schemas import InvestigationResult,ExecutionIssue
from dns_investigator.reporting import evidence_bound_report
from dns_investigator.diagnostic_reasoner import validate_diagnostics,reason
from dns_investigator.remediation import attach


def draft(**kw):
    return InvestigationResult(observations=[],hypotheses=[],conclusion='draft',conclusion_evidence_ids=[],limitations=[],recommendations=[],**kw)


def backend():return ToolBackend(parse_target('probe.example'))


def add(b,data,tool='query_dns',mode='live'):
    e=dict(id=f'E{len(b.calls)+1}',tool_name=tool,source_mode=mode,started_at=datetime.now(timezone.utc).isoformat(),
        input=dict(domain=b.target.domain,record_type='A',url=b.target.url,ip='192.0.2.10',port=443),
        execution_status='ok',data=data)
    b.calls.append(e);return e


def dns(b,kind='NOERROR',resolver='1.1.1.1',role='recursive',value='192.0.2.10',mode='live'):
    q=__import__('dns.message',fromlist=['make_query']).make_query(b.target.domain,'A')
    m=__import__('dns.message',fromlist=['make_response']).make_response(q)
    if role=='authoritative':m.flags|=dns_flags.AA
    if kind=='NOERROR':m.answer.append(dns_rrset.from_text(b.target.domain+'.',60,'IN','A',value))
    elif kind!='TIMEOUT':m.set_rcode(dns_rcode.from_text(kind))
    data=parse_response(m,b.target.domain,'A',resolver,role)
    if kind=='TIMEOUT':data.update(rcode='TIMEOUT',result_kind='TIMEOUT',transport_status='timeout',dns_rcode=None,error={'code':'TIMEOUT'})
    return add(b,data,mode=mode)


# Avoid shadowing the dns helper with imported modules.
from dns import flags as dns_flags,rrset as dns_rrset,rcode as dns_rcode


@pytest.mark.parametrize('scenario,expected,layer',[
    ('timeout','FAULT_LOCALIZED','Recursive DNS'),('normal','NO_FAULT_OBSERVED','Unknown'),
    ('mismatch','FAULT_LOCALIZED','Authoritative DNS'),('auth_timeout','FAULT_LOCALIZED','Authoritative DNS'),
    ('alias','FAULT_LOCALIZED','CNAME/Alias Resolution'),('refused','FAULT_LOCALIZED','TCP/Network Transport'),
    ('tcp_timeout','FAULT_LOCALIZED','TCP/Network Transport'),('http_503','FAULT_LOCALIZED','HTTP'),
    ('certificate','FAULT_LOCALIZED','TLS'),('policy','INSUFFICIENT_EVIDENCE','Unknown'),
    ('cdn','NO_FAULT_OBSERVED','Unknown'),('empty','INSUFFICIENT_EVIDENCE','Unknown'),
    ('partial','INSUFFICIENT_EVIDENCE','Unknown'),('trace','INSUFFICIENT_EVIDENCE','Delegation'),
    ('multi','FAULT_LOCALIZED','HTTP'),('body_timeout','FAULT_LOCALIZED','HTTP')])
def test_scoped_mechanism(scenario,expected,layer):
    b=backend()
    if scenario in {'timeout','auth_timeout'}:
        dns(b,'TIMEOUT',role='authoritative' if scenario=='auth_timeout' else 'recursive');dns(b,resolver='8.8.8.8')
    elif scenario=='mismatch':dns(b,'NXDOMAIN');dns(b,role='authoritative',resolver='9.9.9.9')
    elif scenario in {'normal','cdn','partial','trace'}:
        dns(b)
        if scenario=='cdn':dns(b,resolver='8.8.8.8',value='192.0.2.20')
        if scenario=='partial':b.attempts=[dict(attempt_id='A1',tool_name='query_dns',input={'domain':b.target.domain,'record_type':'AAAA'},error={'code':'FIXTURE_NOT_COVERED'})]
        if scenario=='trace':b.attempts=[dict(attempt_id='A1',tool_name='query_authoritative',input={'domain':b.target.domain},protocol_state=dict(mode='trace',completed=False,stop_reason='DNS_BUDGET_EXHAUSTED',last_successful_zone='example'))]
    elif scenario=='alias':add(b,dict(qname=b.target.domain,qtype='A',resolver='1.1.1.1',rcode='NOERROR',result_kind='ALIAS_INCOMPLETE',records=[],cname_chain=[dict(name=b.target.domain,target='alias.example')],canonical_name='alias.example'))
    elif scenario in {'refused','tcp_timeout','multi'}:add(b,dict(ip='192.0.2.10',port=443,status='TIMEOUT' if scenario=='tcp_timeout' else 'REFUSED'),'check_tcp')
    if scenario in {'http_503','certificate','body_timeout','multi'}:
        add(b,dict(status_code=503 if scenario in {'http_503','multi'} else 200 if scenario=='body_timeout' else None,
            final_url=b.target.url,error='TIMEOUT' if scenario=='body_timeout' else 'TLS_ERROR' if scenario=='certificate' else None,
            error_detail={'code':'CERTIFICATE_VERIFY_FAILED','certificate':{'verify_code':10}} if scenario=='certificate' else None,
            body_complete=scenario not in {'body_timeout','certificate'}),'check_http')
    if scenario=='policy':b.attempts=[dict(attempt_id='A1',tool_name='check_tcp',input={'ip':'10.0.0.1'},error={'code':'INVALID_INPUT','reason':'TCP_TARGET_ADDRESS_NOT_AUTHORIZED'})]
    r=evidence_bound_report(draft(),b);d=r.diagnostic_conclusion
    if scenario=='multi':
        # No explicit task focus: retain both observations without a lexical primary.
        assert d is None and r.diagnosis_selection_mode=='parallel'
        assert {x.fault_layer for x in r.secondary_diagnoses}=={'HTTP','TCP/Network Transport'}
        assert all(x.diagnosis_status==expected for x in r.secondary_diagnoses)
        return
    assert d.diagnosis_status==expected and d.fault_layer==layer
    assert d.cause_status!='VERIFIED_PROTOCOL'
    assert set(d.evidence_ids).issubset({e['id'] for e in b.calls})
    if scenario=='multi':assert {x.fault_layer for x in [d]+r.secondary_diagnoses}=={'HTTP','TCP/Network Transport'}
    if scenario in {'policy','partial','trace','empty'}:assert d.fault_detected is None
    if scenario=='timeout':assert d.affected_scope[0]['resolver']=='1.1.1.1' and d.unaffected_or_comparison_scope[0]['resolver']=='8.8.8.8'
    if scenario=='alias':assert d.affected_scope[0]['canonical_name']=='alias.example'
    if scenario=='certificate':assert 'verify_code' in d.cause
    if scenario=='body_timeout':assert '200' in d.cause and 'TIMEOUT' in d.cause
    for step in r.remediation_plan:
        assert not step.executed and step.verification_method
        assert step.action_type!='POSSIBLE_FIX' or step.prerequisites


@pytest.mark.parametrize('scenario,status,reason_code',[
    ('ds_mismatch','CONFIRMED_PROTOCOL_ISSUE','DS_DIGEST_MISMATCH'),
    ('tampered','CONFIRMED_PROTOCOL_ISSUE','NO_SIGNATURE_VALIDATED'),
    ('expired','CONFIRMED_PROTOCOL_ISSUE','NO_SIGNATURE_VALIDATED'),
    ('secure','NO_FAULT_OBSERVED',None),('insecure','NO_FAULT_OBSERVED',None),
    ('algorithm16','INSUFFICIENT_EVIDENCE',None)])
async def test_real_signed_validator_drives_diagnosis(scenario,status,reason_code):
    from evaluation.signed_protocol_lab import signed_lab
    async with signed_lab(scenario) as lab:
        b=lab.backend();await b.call('query_authoritative',domain=b.target.domain,mode='dnssec',timeout=.2)
    r=evidence_bound_report(draft(),b);d=r.diagnostic_conclusion
    assert d.diagnosis_status==status
    if reason_code:
        assert reason_code in d.cause and d.validation_ids and d.evidence_ids
        known={v['id']:v for v in b.validation_results}
        assert all(known[v]['provenance']=='locally_validated' for v in d.validation_ids)
        assert d.cause_status=='VERIFIED_PROTOCOL'
        assert any(s.action_type=='POSSIBLE_FIX' for s in d.remediation_steps)


def test_forged_bogus_without_v_chain_not_confirmed():
    r=draft();r.protocol_investigations=[dict(attempt_id='A1',validation=dict(dnssec_status='BOGUS',validation_execution='completed',validation_result_ids=['V99']))]
    attach(r)
    assert r.diagnostic_conclusion.diagnosis_status=='INSUFFICIENT_EVIDENCE'


def test_ede_and_cdn_not_local_crypto_or_client_diagnosis():
    b=backend();e=dns(b);e['data']['ede']=[dict(code=6,name='DNSSEC Bogus')]
    d=evidence_bound_report(draft(),b).diagnostic_conclusion
    assert d.diagnosis_status=='NO_FAULT_OBSERVED' and d.validation_ids==[] and d.fault_layer!='Client Environment'


async def test_fixture_single_query_is_short_no_fix():
    b=ToolBackend(parse_target('example.com'),Path('data/fixtures/Q1.json'))
    await b.call('query_dns',domain=b.target.domain)
    r=evidence_bound_report(draft(request_kind='query'),b)
    assert r.diagnostic_conclusion.source_modes==['fixture'] and not r.remediation_plan and not r.hypotheses


def test_synthetic_anomaly_has_no_live_probe_advice():
    b=backend();add(b,dict(ip='192.0.2.10',port=443,status='REFUSED'),'check_tcp',mode='synthetic')
    r=evidence_bound_report(draft(),b)
    assert r.diagnostic_conclusion.summary.startswith('[fixture/synthetic')
    assert all(any('重新 live' in s for s in step.safety_notes) for step in r.remediation_plan)


def test_final_reference_validation_rejects_tamper():
    b=backend();dns(b);r=evidence_bound_report(draft(),b)
    r.diagnostic_conclusion.evidence_ids.append('A1')
    with pytest.raises(ValueError):validate_diagnostics(r,b.attempts)


async def test_failed_agent_keeps_report_and_failed_status(tmp_path):
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.messages import ModelResponse,ToolCallPart
    from dns_investigator.agent import investigate
    from dns_investigator.config import Config
    count=0
    def respond(messages,info):
        nonlocal count
        count+=1
        if count==1:return ModelResponse(parts=[ToolCallPart('query_dns',{'domain':'example.com'})])
        raise RuntimeError('test model summary failure')
    log,_=await investigate('查询 example.com A',parse_target('example.com'),Config('test'),
        Path('data/fixtures/Q1.json'),FunctionModel(respond),log_dir=tmp_path)
    assert log['status']=='failed' and log['report_origin']=='application_fallback'
    assert log['result']['diagnostic_conclusion']['evidence_ids']==['E1']
    assert log['result']['report_fallback_reason']


def test_real_historical_reports_load_without_inventing_new_diagnosis():
    import json
    paths=list(Path('results/published').glob('evaluation-reliability-*/*.json'))
    # Use checked-in v0.4 wire-experiment reports if the v0.2 directory has no top-level reports.
    paths+=list(Path('results/published/nsec3-divergence-audit').rglob('*project.json'))
    checked=0
    for p in paths:
        old=json.loads(p.read_text(encoding='utf-8'))
        if isinstance(old,dict) and isinstance(old.get('result'),dict):
            r=InvestigationResult.model_validate(old['result'])
            assert r.diagnostic_conclusion is None
            assert r.conclusion==old['result']['conclusion'];checked+=1
    assert checked>0


def test_policy_redirect_and_body_limit_remain_unknown():
    for body,refusal in [('not_read',{'code':'HTTP_ORIGIN_NOT_AUTHORIZED'}),('limit_reached',None)]:
        b=backend();add(b,dict(status_code=200,final_url=b.target.url,body_state=body,body_complete=False,
            security_refusal=refusal),'check_http')
        d=evidence_bound_report(draft(),b).diagnostic_conclusion
        assert d.fault_detected is None and d.diagnosis_status=='INSUFFICIENT_EVIDENCE'


def test_authoritative_refusal_not_recursive_failure():
    b=backend();dns(b,'REFUSED',role='authoritative')
    d=evidence_bound_report(draft(),b).diagnostic_conclusion
    assert d.fault_layer=='Authoritative DNS' and d.primary_issue=='DNS_REFUSED'


def test_non_aa_does_not_confirm_normal_authority():
    b=backend();e=dns(b,role='authoritative');e['data']['flags']['AA']=False
    d=evidence_bound_report(draft(),b).diagnostic_conclusion
    assert d.diagnosis_status=='INSUFFICIENT_EVIDENCE' and d.fault_detected is None


@pytest.mark.parametrize('scenario',['normal','non_aa','timeout'])
async def test_actual_delegation_trace_report(scenario):
    from evaluation.protocol_lab import protocol_lab
    async with protocol_lab(scenario) as lab:
        b=lab.backend();returned=await b.call('query_authoritative',domain=b.target.domain,mode='trace',timeout=.1)
    r=evidence_bound_report(draft(),b)
    if scenario=='normal':assert r.diagnostic_conclusion.diagnosis_status=='NO_FAULT_OBSERVED'
    else:
        trace=next(d for d in [r.diagnostic_conclusion]+r.secondary_diagnoses if d.fault_layer=='Delegation')
        assert returned['data']['stop_reason'] in trace.cause and trace.relevant_attempt_ids==['A1']
        assert trace.diagnosis_status!='CONFIRMED_PROTOCOL_ISSUE'
        assert trace.evidence_ids
