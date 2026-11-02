"""Report replay / constructed inputs / scripted model tests, not public-network acceptance."""
import copy,json,subprocess,sys
from pathlib import Path
from types import SimpleNamespace
import pytest
from evaluation.report_quality import report
from dns_investigator.schemas import InvestigationResult
from dns_investigator.diagnostic_reasoner import validate_diagnostics
from dns_investigator.request_context import context
from dns_investigator.target import parse_target

ROOT=Path('results/published/v05-report-quality-fixes/20261102-report-quality')
ROWS={r['case']:r for r in json.loads((ROOT/'before.json').read_text(encoding='utf-8'))['cases']}


def test_direct_ds_location_and_complete_dependencies():
    row=ROWS['dnssec-ds_mismatch'];r=report(row);d=r['diagnostic_conclusion']
    assert d['direct_validation_ids']==['V7'] and d['direct_evidence_ids']==['E7','E8']
    assert d['location']==[dict(zone='example.test.',validation_id='V7',component='ds_digest')]
    assert {x['record_type'] for x in d['affected_scope']}=={'DS','DNSKEY'}
    assert all(x['target'].rstrip('.')=='example.test' for x in d['affected_scope'])
    assert set(d['evidence_ids'])==set(d['direct_evidence_ids']+d['dependency_evidence_ids'])
    assert set(d['validation_ids'])==set(d['direct_validation_ids']+d['dependency_validation_ids'])
    assert set(d['evidence_ids'])==set(row['before']['diagnostic_conclusion']['evidence_ids'])
    assert d['reason_code']=='DS_DIGEST_MISMATCH' and d['failure_stage']=='child-ds-match'
    bad=InvestigationResult.model_validate(r);bad.diagnostic_conclusion.direct_evidence_ids=['E1']
    bad.diagnostic_conclusion.dependency_evidence_ids=list(set(d['evidence_ids'])-{'E1'})
    with pytest.raises(ValueError):validate_diagnostics(bad,row['attempts'])


@pytest.mark.parametrize('case',list(ROWS))
def test_same_evidence_replay_preserves_measurements_and_references(case):
    row=ROWS[case];r=report(row)
    assert r['measured_facts']==row['before']['measured_facts']
    assert r['validation_results']==row['before']['validation_results']
    validate_diagnostics(InvestigationResult.model_validate(r),row['attempts'])


@pytest.mark.parametrize('focus,expected',[('TCP','TCP_REFUSED'),('HTTP','HTTP_503'),('ambiguous',None)])
def test_question_relevance_explains_selection(focus,expected):
    r=report(ROWS['multi-'+focus]);all_d=([r['diagnostic_conclusion']] if r['diagnostic_conclusion'] else [])+r['secondary_diagnoses']
    assert {d['primary_issue'] for d in all_d}=={'TCP_REFUSED','HTTP_503'}
    if expected:
        d=r['diagnostic_conclusion'];assert d['primary_issue']==expected
        assert d['relevance']=='explicit_focus' and d['intent_source']=='explicit_user_statement'
        assert '匹配' in d['selection_reason'] and d['cause_status']=='OBSERVED_MECHANISM'
    else:assert r['diagnostic_conclusion'] is None and r['diagnosis_selection_mode']=='parallel'


def test_focused_tcp_normal_does_not_hide_http_failure():
    row=copy.deepcopy(ROWS['multi-TCP']);row['evidence'][0]['data']['status']='CONNECTED'
    r=report(row);d=r['diagnostic_conclusion']
    assert d['primary_issue']=='FOCUS_NOT_REPRODUCED' and d['fault_detected'] is False
    assert any(x['primary_issue']=='HTTP_503' for x in r['secondary_diagnoses'])
    assert not any(s['action_type']=='POSSIBLE_FIX' for s in d['remediation_steps'])
    assert d['remediation_steps'][0]['method']['kind']=='user_information'


@pytest.mark.parametrize('case,change',[('multi-HTTP','path'),('multi-TCP','port')])
def test_other_url_or_port_not_treated_as_requested_fault(case,change):
    row=copy.deepcopy(ROWS[case])
    if change=='path':row['request_context']['url']='https://probe.example/different-path'
    else:row['request_context']['port']=80
    r=report(row)
    assert r['diagnostic_conclusion']['primary_issue']=='FOCUS_UNMEASURED'
    assert any(d['fault_detected'] is True for d in r['secondary_diagnoses'])


def test_evidence_order_does_not_select_another_problem():
    for case in ['multi-TCP','multi-HTTP','multi-ambiguous','dnssec-ds_mismatch','dns-timeout']:
        row=copy.deepcopy(ROWS[case]);before=report(row);row['evidence'].reverse();after=report(row)
        def semantic(r):return [(d['primary_issue'],d['fault_location'],d['direct_evidence_ids'],d['direct_validation_ids']) for d in ([r['diagnostic_conclusion']] if r['diagnostic_conclusion'] else [])+r['secondary_diagnoses']]
        assert semantic(before)==semantic(after)


@pytest.mark.parametrize('text,focus',[
    ('只检查 TCP，不查 HTTP',['TCP/Network Transport']),('不要看TCP，只查HTTP',['HTTP']),
    ('不要只看 TCP',[]),('用户说“TCP坏了”，检查HTTP',['HTTP']),
    ('TCP 或 HTTP 有问题',[]),('not HTTP; TCP problem',['TCP/Network Transport'])])
def test_explicit_focus_negation_quotation_and_ambiguity(text,focus):
    c=context(text,parse_target('probe.example'),'investigation');assert c['focus_layers']==focus


def test_claim_of_pollution_is_not_evidence():
    row=copy.deepcopy(ROWS['dns-normal']);row['request_context']=context('怀疑 DNS 污染',parse_target(row['target']),'investigation')
    r=report(row);all_d=([r['diagnostic_conclusion']] if r['diagnostic_conclusion'] else [])+r['secondary_diagnoses']
    assert all(d['cause_status']!='VERIFIED_PROTOCOL' and d['fault_detected'] is not True for d in all_d)
    assert r['diagnostic_conclusion']['diagnosis_status']=='NO_FAULT_OBSERVED'


def test_candidate_failure_does_not_override_final_secure():
    row=copy.deepcopy(ROWS['dnssec-insecure'])
    row['validation_results'].append(dict(id='V999',kind='rrset_signature',local_result='SIGNATURE_CHECK_FAILED',reason_code='NO_SIGNATURE_VALIDATED',evidence_ids=['E1'],validation_result_ids=[],provenance='locally_validated',parent_tool_call_id='A1'))
    assert report(row)['diagnostic_conclusion']['diagnosis_status']=='NO_FAULT_OBSERVED'


def test_dns_timeout_is_not_a_returned_rcode():
    r=report(ROWS['dns-timeout'])
    assert all('返回 TIMEOUT' not in f['explanation'] for f in r['findings'])
    d=r['diagnostic_conclusion'];assert '未在时限内收到响应' in d['cause']
    check=d['remediation_steps'][0]
    assert len(check['branches'])==4
    assert all(b['condition'].startswith('如果后续') and b['interpretation'] and b['next_action'] for b in check['branches'])
    # Replayed system identity lacks the original resolver configuration in this
    # backend: do not claim the recorded numeric address is currently executable.
    assert check['method']['supported_by_current_tools'] is False
    assert check['method']['authorization_status']=='unknown' and check['executed'] is False


@pytest.mark.parametrize('status',[401,403,404,429,500,502,503,504])
def test_http_branches_are_specific_without_proving_root_cause(status):
    row=copy.deepcopy(ROWS['multi-HTTP']);row['evidence']=row['evidence'][1:];row['evidence'][0]['data']['status_code']=status
    d=report(row)['diagnostic_conclusion'];step=d['remediation_steps'][0]
    assert d['status_code']==status and d['cause_status']=='OBSERVED_MECHANISM'
    assert str(status) in step['branches'][0]['condition']
    assert step['method']['supported_by_current_tools'] is False # synthetic, no live probe
    assert all('配置' not in b['next_action'] or b['change_prerequisites'] or '修改' not in b['next_action'] for b in step['branches'])


@pytest.mark.parametrize('tcp',['REFUSED','TIMEOUT','NETWORK_ERROR'])
def test_tcp_branches_use_actual_status(tcp):
    row=copy.deepcopy(ROWS['multi-TCP']);row['evidence']=row['evidence'][:1];row['evidence'][0]['data']['status']=tcp
    d=report(row)['diagnostic_conclusion'];assert d['reason_code']==tcp
    assert d['remediation_steps'][0]['branches'][1]['change_prerequisites']
    assert d['location'][0]['ip']=='192.0.2.10' and d['location'][0]['port']==443


def test_ds_plan_uses_structured_reason_not_cause_prose():
    from dns_investigator.remediation import plan
    d=InvestigationResult.model_validate(report(ROWS['dnssec-ds_mismatch'])).diagnostic_conclusion
    d.cause='unrelated prose SIGNATURE'
    assert '父侧 DS' in plan(d)[0].branches[0].condition


@pytest.mark.parametrize('verify_code',[10,62,20,None])
def test_tls_branches_follow_error_metadata(verify_code):
    row=copy.deepcopy(ROWS['multi-HTTP']);row['evidence']=row['evidence'][1:]
    row['evidence'][0]['data'].update(status_code=None,error='TLS_ERROR',error_detail=dict(code='CERTIFICATE_VERIFY_FAILED',certificate=dict(verify_code=verify_code)))
    row['request_context']={}
    d=report(row)['diagnostic_conclusion'];branch=d['remediation_steps'][0]['branches'][0]
    assert d['fault_layer']=='TLS' and branch['change_prerequisites']
    assert d['location'][0]['qname'] is None and d['location'][0]['original_host']=='probe.example'
    assert d['location'][0]['expected_sni']=='probe.example'
    expected={10:'有效期',62:'SAN',20:'信任根',None:'未知不等于过期'}[verify_code]
    assert expected in branch['condition']
    assert 'Host/SNI' in branch['next_action']


def test_http_headers_200_with_body_timeout_is_incomplete():
    row=copy.deepcopy(ROWS['multi-HTTP']);row['evidence']=row['evidence'][1:]
    row['evidence'][0]['data'].update(status_code=200,error='TIMEOUT',body_state='read_error',body_complete=False)
    d=report(row)['diagnostic_conclusion']
    assert d['primary_issue']=='HTTP_REQUEST_TIMEOUT' and d['fault_detected'] is True
    assert '200' in d['cause'] and '未完成' in d['remediation_steps'][0]['branches'][0]['condition']


def test_trace_direct_scope_is_stopped_child_not_root():
    r=report(ROWS['trace-non_aa']);d=r['diagnostic_conclusion']
    assert d['direct_evidence_ids']==['E3'] and d['dependency_evidence_ids']==['E1','E2']
    assert all(x['zone']=='example.test.' for x in d['location'])
    assert d['reason_code']=='NON_AUTHORITATIVE_ANSWER'


def test_indeterminate_never_promoted_by_failed_candidate():
    row=copy.deepcopy(ROWS['dnssec-ds_mismatch'])
    for a in row['attempts']:
        if a.get('protocol_state',{}).get('validation'):
            a['protocol_state']['validation'].update(dnssec_status='INDETERMINATE',reason_code='POLICY_LIMIT',validation_execution='capability_limited')
    r=report(row)
    assert r['diagnostic_conclusion']['diagnosis_status']=='INSUFFICIENT_EVIDENCE'
    assert r['diagnostic_conclusion']['cause_status']=='UNKNOWN'
    assert r['diagnostic_conclusion']['reason_code']=='POLICY_LIMIT'
    assert not r['diagnostic_conclusion']['direct_validation_ids']


def test_empty_report_and_safety_issue_not_remote_failure():
    row=copy.deepcopy(ROWS['multi-TCP']);row['evidence']=[]
    row['attempts']=[dict(attempt_id='A1',tool_name='check_tcp',input={'ip':'10.0.0.1','port':443},error=dict(code='INVALID_INPUT',reason='TCP_TARGET_ADDRESS_NOT_AUTHORIZED'))]
    r=report(row);ds=([r['diagnostic_conclusion']] if r['diagnostic_conclusion'] else [])+r['secondary_diagnoses']
    assert all(d['fault_detected'] is not True for d in ds)
    assert r['execution_issues'][0]['target']=='10.0.0.1' and not r['measured_facts']


def test_legacy_defaults_do_not_invent_direct_sources():
    old=copy.deepcopy(ROWS['dnssec-ds_mismatch']['before']);r=InvestigationResult.model_validate(old)
    assert r.diagnostic_conclusion.direct_validation_ids==[] and r.request_context=={}


@pytest.mark.parametrize('args,code',[
    (['--format','json'],2),(['网站打不开','--format','json'],2),
    (['--target','https://u:p@example.com','--format','json'],2),
    (['--format','json','--verbose'],2),(['--format','json','--bad-flag'],2),
    (['--format','json','--help'],0),
    (['查询 example.com A','--tools-only','--fixture','data/fixtures/Q1.json','--format','json'],0)])
def test_real_cli_json_stdout_contract(args,code):
    p=subprocess.run([sys.executable,'-m','dns_investigator.main']+args,input='',text=True,encoding='utf-8',capture_output=True)
    assert p.returncode==code,(p.stdout,p.stderr)
    obj=json.loads(p.stdout);assert isinstance(obj,dict)
    if '--tools-only' in args:assert obj['mode']=='tools_only' and obj['evidence']


async def test_cli_model_failure_and_parallel_summary(monkeypatch,capsys,tmp_path):
    from dns_investigator import main as cli
    from dns_investigator.config import Config
    r=report(ROWS['multi-ambiguous']);r['report_fallback_reason']='scripted model failed'
    async def fake(*a,**kw):
        kw['progress'](dict(id='E1',tool_name='check_tcp',execution_status='ok'))
        return dict(status='failed',result=r),tmp_path/'test.json'
    monkeypatch.setattr(cli,'investigate',fake);monkeypatch.setattr(cli.Config,'load',lambda:Config('test'))
    args=SimpleNamespace(question='检查 probe.example',target=None,tools_only=False,fixture=None,format='json',verbose=False)
    assert await cli.run(args)==1
    captured=capsys.readouterr();assert json.loads(captured.out)['status']=='failed'
    assert 'E1' in captured.err
    args.format='text';assert await cli.run(args)==1
    text=capsys.readouterr().out
    assert '并列' in text and '程序回退' in text and 'TCP' in text and 'HTTP' in text
    assert '"measured_facts"' not in text and text.count('（尚未执行）')<=3


async def test_context_wiring_without_paid_model(tmp_path):
    from pydantic_ai.models.function import FunctionModel
    from dns_investigator.agent import investigate
    from dns_investigator.config import Config
    def fail(*a,**kw):raise RuntimeError('scripted summary failure')
    log,_=await investigate('只检查 example.com TCP',parse_target('example.com'),Config('test'),
        model=FunctionModel(fail),log_dir=tmp_path)
    assert log['status']=='failed' and log['request_context']['focus_layers']==['TCP/Network Transport']
    assert log['result']['request_context']==log['request_context']


async def test_actual_framework_parallel_failure_fallback(tmp_path):
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.messages import ModelResponse,ToolCallPart
    from dns_investigator.agent import investigate
    from dns_investigator.config import Config
    fixture=tmp_path/'f.json'
    fixture.write_text(json.dumps([
        dict(tool='query_dns',match=dict(domain='probe.example'),data=dict(qname='probe.example',qtype='A',resolver='system',rcode='NOERROR',records=[dict(value='192.0.2.10',ttl=60)])),
        dict(tool='check_tcp',match=dict(ip='192.0.2.10',port=443),data=dict(ip='192.0.2.10',port=443,status='REFUSED')),
        dict(tool='check_http',match=dict(url='https://probe.example/'),data=dict(status_code=503,error=None,body_complete=True,final_url='https://probe.example/'))]),encoding='utf-8')
    count=0
    def respond(*args):
        nonlocal count
        count+=1
        if count==1:return ModelResponse(parts=[ToolCallPart('query_dns',dict(domain='probe.example'))])
        if count==2:return ModelResponse(parts=[ToolCallPart('check_tcp',dict(ip='192.0.2.10',port=443)),ToolCallPart('check_http',dict(url='https://probe.example/'))])
        raise RuntimeError('scripted final failure')
    log,_=await investigate('调查 probe.example',parse_target('probe.example'),Config('test'),fixture,FunctionModel(respond),log_dir=tmp_path/'logs')
    assert log['status']=='failed' and len(log['evidence'])==3
    assert log['result']['diagnostic_conclusion'] is None and log['result']['diagnosis_selection_mode']=='parallel'
    assert {d['primary_issue'] for d in log['result']['secondary_diagnoses']}=={'HTTP_503','TCP_REFUSED'}
