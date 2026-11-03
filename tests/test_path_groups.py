"""Historical real-log replay and constructed counterexamples; never new public probes."""
import copy,json,re
from pathlib import Path
from datetime import datetime,timezone,timedelta
import pytest
from dns_investigator.report_replay import canonical
from dns_investigator.web import present,create_app
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target
from dns_investigator.schemas import InvestigationResult
from dns_investigator.reporting import evidence_bound_report
from dns_investigator.diagnostic_reasoner import validate_diagnostics
from fastapi.testclient import TestClient

FIX=Path('data/regressions/baidu-investigation.json')


def test_real_log_all_ledgers_preserved_and_two_path_groups(monkeypatch):
    async def forbidden(*a,**kw):raise AssertionError('no tool/model/network in replay')
    monkeypatch.setattr(ToolBackend,'call',forbidden)
    log=json.loads(FIX.read_text(encoding='utf-8-sig'));old=copy.deepcopy(log);rebuilt=canonical(log);r=rebuilt['result']
    assert log==old
    for k in ['evidence','attempts','dns_attempts','validation_results','status']:assert rebuilt[k]==old[k]
    assert len(log['evidence'])==19 and len(log['dns_attempts'])==17
    assert sum(e['data'].get('result_kind')=='TIMEOUT' for e in log['evidence'])==7
    g={x['location'][0]['resolver']:x for x in r['diagnostic_groups']}
    assert set(g)=={'192.0.2.53','1.1.1.1'}
    assert set(g['192.0.2.53']['direct_evidence_ids'])=={'E2','E5','E8','E10','E14'}
    assert set(g['1.1.1.1']['direct_evidence_ids'])=={'E4','E7'}
    assert [g[s]['grouped_observation_count'] for s in ['192.0.2.53','1.1.1.1']]==[5,2]
    assert set(g['192.0.2.53']['query_attempt_ids'])=={'Q1','Q6','Q8','Q10','Q14'}
    assert set(g['1.1.1.1']['query_attempt_ids'])=={'Q2','Q5'}
    assert len(r['secondary_diagnoses'])==2 and r['diagnostic_conclusion'] is None
    assert len(r['remediation_plan'])==6 and sum(s['action_type']=='CHECK' for s in r['remediation_plan'])==2
    assert r['findings']==old['result']['findings'] and rebuilt['findings']==old['findings']
    for step in r['remediation_plan']:
        assert len(step['diagnostic_group_ids'])==1 and step['query_attempt_ids'] and step['applicable_scope']
        assert not step['executed']
    overview=r['diagnostic_summary']
    assert {x['resolver'] for x in overview['successful_dns']}=={'8.8.8.8','202.112.144.246','153.3.238.93','220.181.33.31'}
    assert [x['record_type'] for x in overview['successful_dns'] if x['resolver']=='8.8.8.8']==['A']
    assert overview['tcp_successes'][0]['evidence_id']=='E18'
    assert overview['http_responses'][0]['status_code']==301
    assert overview['http_responses'][0]['security_refusal']['request_sent_to_rejected_target'] is False
    assert '200' not in overview['explanation'] and '未完成最终页面检测' in overview['explanation']
    assert len(r['measured_facts'])==19


def test_web_import_history_export_and_summary_match_formal_report(tmp_path):
    c=TestClient(create_app(tmp_path));token=re.search(r'name="local-token" content="([^"]+)"',c.get('/').text)[1]
    old=json.loads(FIX.read_text(encoding='utf-8-sig'));key=c.post('/api/import',json=old,headers={'x-local-token':token}).json()['id']
    view=c.get('/api/reports/'+key).json();export=c.get('/api/reports/'+key+'/export').json()
    assert view['title']=='部分递归 DNS 查询路径超时' and view['tone']=='uncertain'
    assert len(view['diagnostic_groups'])==2 and len(view['evidence'])==19
    assert '多个独立异常' not in view['title'] and '301' in view['explanation']
    assert len(export['evidence'])==19 and export['result']==view['result']
    assert export['original_result']==old['result']
    assert len(c.get('/api/history').json())==1
    assert json.loads((tmp_path/(key+'.json')).read_text(encoding='utf-8'))['result']==old['result']


def constructed(rows):
    """Rows: resolver/name/type/state/seconds/mode/location/role."""
    b=ToolBackend(parse_target('probe.example'));start=datetime(2026,11,2,tzinfo=timezone.utc)
    for i,row in enumerate(rows,1):
        server,name,typ,state,seconds,mode,location,role=row
        b.calls.append(dict(id=f'E{i}',tool_name='query_dns',tool_call_id='A1',query_attempt_id=f'Q{i}',
            source_mode=mode,measurement_location=location,started_at=(start+timedelta(seconds=seconds)).isoformat(),execution_status='ok',
            input=dict(domain=name,record_type=typ,resolver=server),data=dict(qname=name,qtype=typ,resolver=server,resolver_role=role,
                transport_status='timeout' if state=='TIMEOUT' else 'responded',dns_rcode=None if state=='TIMEOUT' else state,
                result_kind=state,rcode=None if state=='TIMEOUT' else state,records=[] if state!='NOERROR' else [dict(value='192.0.2.10',ttl=60)],
                flags=dict(AA=role=='authoritative'),resolution_complete=state!='TIMEOUT')))
        b.dns.attempts.append(dict(query_attempt_id=f'Q{i}',evidence_id=f'E{i}',parent_tool_call_id='A1',status='measured'))
    return b


def row(server='1.1.1.1',name='probe.example',typ='A',state='TIMEOUT',seconds=0,mode='synthetic',location='test-host',role='recursive'):
    return server,name,typ,state,seconds,mode,location,role


def report(b):
    return evidence_bound_report(InvestigationResult(observations=[],hypotheses=[],conclusion='draft',conclusion_evidence_ids=[],limitations=[],recommendations=[]),b)


@pytest.mark.parametrize('second',[
    row(seconds=10),row(typ='AAAA',seconds=10),row(name='ns.example',seconds=10)])
def test_same_path_repeated_types_and_names_preserved(second):
    b=constructed([row(),second]);before=copy.deepcopy(b.calls);r=report(b)
    assert len(r.diagnostic_groups)==1 and r.diagnostic_groups[0].grouped_observation_count==2
    assert len(r.diagnostic_groups[0].affected_scope)==2 and b.calls==before


@pytest.mark.parametrize('second',[
    row(server='8.8.8.8'),row(seconds=301),row(mode='live'),row(location='other-host')])
def test_incompatible_path_time_source_or_location_never_merge(second):
    r=report(constructed([row(),second]));assert len(r.diagnostic_groups)==2


def test_window_is_not_transitive():
    r=report(constructed([row(),row(seconds=250),row(seconds=500)]))
    assert sorted(g.grouped_observation_count for g in r.diagnostic_groups)==[1,2]


def test_success_and_timeout_same_resolver_do_not_cancel():
    r=report(constructed([row(),row(state='NOERROR',seconds=1)]))
    assert r.diagnostic_groups[0].direct_evidence_ids==['E1']
    assert r.diagnostic_summary['successful_dns'][0]['evidence_id']=='E2'


def test_all_timeouts_no_control_and_all_normal():
    r=report(constructed([row(),row(server='8.8.8.8')]))
    assert not r.diagnostic_summary['successful_dns'] and '尚无可靠成功对照' in r.diagnostic_summary['title']
    normal=report(constructed([row(state='NOERROR'),row(server='8.8.8.8',state='NOERROR')]))
    assert not normal.diagnostic_groups and normal.diagnostic_conclusion.diagnosis_status=='NO_FAULT_OBSERVED'


def test_other_mechanisms_and_authority_are_independent():
    b=constructed([row(),row(state='SERVFAIL'),row(role='authoritative',server='9.9.9.9'),row(role='authoritative',server='8.8.4.4',state='NOERROR')])
    b.calls.append(dict(id='E5',tool_name='check_tcp',source_mode='synthetic',measurement_location='test-host',execution_status='ok',input=dict(ip='192.0.2.10',port=443),data=dict(ip='192.0.2.10',port=443,status='REFUSED')))
    r=report(b);ds=([r.diagnostic_conclusion] if r.diagnostic_conclusion else [])+r.secondary_diagnoses
    assert {'RECURSIVE_QUERY_TIMEOUT','DNS_SERVFAIL','TCP_REFUSED','AUTHORITATIVE_QUERY_TIMEOUT'}.issubset({d.primary_issue for d in ds})
    assert r.diagnostic_summary['title'] is None and len(r.diagnostic_groups)==1


def test_dnssec_bogus_not_swallowed_by_timeout():
    p=Path('tests/fixtures/reports/dnssec-ds-mismatch.json');old=json.loads(p.read_text(encoding='utf-8'))
    from evaluation.report_quality import report as replay
    extra=constructed([row()]).calls[0];extra.update(id='E999',query_attempt_id='Q999')
    r=replay(dict(target=old['evidence'][0]['input']['domain'],evidence=old['evidence']+[extra],attempts=old['attempts'],dns_attempts=old['dns_attempts'],validation_results=old['validation_results']))
    assert r['diagnostic_conclusion']['diagnosis_status']=='CONFIRMED_PROTOCOL_ISSUE'
    assert r['diagnostic_conclusion']['direct_validation_ids']==['V7']
    assert r['diagnostic_groups'] and not r['diagnostic_summary']['title']


@pytest.mark.parametrize('missing',['started_at','measurement_location'])
def test_legacy_missing_metadata_keeps_observations_without_invented_group(missing):
    b=constructed([row(),row(name='ns.example')])
    for e in b.calls:e.pop(missing,None)
    r=report(b);assert not r.diagnostic_groups and len(r.measured_facts)==2


def test_wrong_group_q_reference_rejected():
    b=constructed([row(),row(seconds=1)]);r=report(b)
    r.diagnostic_groups[0].query_attempt_ids=['A1']
    with pytest.raises(ValueError,match='Grouped Q'):validate_diagnostics(r,b.attempts)


def test_replay_failure_report_keeps_failed_execution_and_all_evidence():
    log=json.loads(FIX.read_text(encoding='utf-8-sig'));log['status']='failed';log['agent_execution_status']='failed'
    log['result']['report_fallback_reason']='constructed summary-failure replay'
    rebuilt=canonical(log)
    assert rebuilt['status']=='failed' and len(rebuilt['evidence'])==19
    assert len(rebuilt['result']['diagnostic_groups'])==2
    assert all(any('程序回退' in s for s in g['limitations']) for g in rebuilt['result']['diagnostic_groups'])


def test_fixture_scope_and_permuted_evidence_are_explicit():
    b=constructed([row(mode='fixture'),row(mode='fixture',typ='AAAA',seconds=1)])
    r=report(b);d=r.diagnostic_groups[0]
    assert '[fixture/synthetic' in d.summary and d.source_modes==['fixture']
    before=(d.diagnostic_group_id,set(d.direct_evidence_ids),d.grouped_observation_count)
    b.calls.reverse();after=report(b).diagnostic_groups[0]
    assert before==(after.diagnostic_group_id,set(after.direct_evidence_ids),after.grouped_observation_count)


def test_cli_uses_same_scoped_overview_not_independent_root_causes(capsys):
    from dns_investigator.main import summary
    log=canonical(json.loads(FIX.read_text(encoding='utf-8-sig')));before=copy.deepcopy(log)
    summary(log['result']);text=capsys.readouterr().out
    assert '部分递归 DNS 查询路径超时' in text and '192.0.2.53' in text and '1.1.1.1' in text
    assert '并列异常/未完成范围' not in text and '301' in text and '重定向被安全策略拒绝' in text
    assert text.count('CHECK（尚未执行）')==2 and log==before
