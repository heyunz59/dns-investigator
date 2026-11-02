"""Mixed report and offline replay regression; no fresh public/model tests."""
import copy
import json
import re
from pathlib import Path
import pytest
from fastapi.testclient import TestClient
from evaluation.v06_review_cases import cases
from dns_investigator.web import present, create_app
from dns_investigator.report_replay import canonical
from dns_investigator.request_context import context
from dns_investigator.target import parse_target


def diagnoses(r):
    return ([r['diagnostic_conclusion']] if r.get('diagnostic_conclusion') else [])+r.get('secondary_diagnoses', [])


@pytest.mark.parametrize('name', ['dnssec_timeout','http_timeout','tcp_timeout','indeterminate_timeout','partial_timeouts','only_timeouts'])
def test_mixed_view_html_cli_json_preserve_formal_selection(name,tmp_path,capsys):
    log=cases()[name];before=copy.deepcopy(log);v=present(log);r=log['result']
    assert log==before and v['result']==r
    assert v['diagnoses']==diagnoses(r)
    assert any(p['tone']=='uncertain' and p['resolver']=='1.1.1.1' for p in v['paths'])
    checks=[next(s for s in d['remediation_steps'] if s['action_type']=='CHECK') for d in diagnoses(r)]
    if r['diagnosis_selection_mode']=='parallel':
        assert v['steps'][:len(checks)]==checks
    else:
        assert v['steps'][0] in r['diagnostic_conclusion']['remediation_steps']
    if name=='dnssec_timeout':
        assert v['short_title']=='DNSSEC DS/DNSKEY 关联验证失败'
        assert v['tone']=='bad' and v['label']=='已确认协议异常'
        assert '所列协议异常已有直接验证依据' in v['short_explanation']
        assert '另有观测' in v['short_explanation'] and '关联尚未确认' in v['short_explanation']
        assert v['short_location']==r['diagnostic_conclusion']['fault_location']
        assert 'example.test.' in v['short_location']
        assert set(v['dnssec'][0]['direct'])=={'V7','E7','E8'} and v['dnssec'][0]['dependencies']
    elif name in ('http_timeout','tcp_timeout'):
        assert v['short_title'].startswith('多个异常观测，关联尚未确认')
        assert v['label']=='多个异常观测' and v['tone']=='uncertain'
        for d in diagnoses(r):
            assert d['summary'] in v['short_explanation'] and d['fault_location'] in v['short_location']
        assert v['result']['diagnostic_conclusion'] is None
        assert any(p['tone']=='good' and p['resolver']=='8.8.8.8' for p in v['paths'])
    elif name=='partial_timeouts':
        assert v['short_title']=='部分 DNS 解析路径超时' and v['tone']=='uncertain'
        assert '不能据此认定目标域名整体 DNS 不可用' in v['short_explanation']
    elif name=='only_timeouts':
        assert v['short_title']=='已测 DNS 解析路径超时' and v['tone']=='uncertain'
        assert '缺少足够成功对照' in v['short_explanation']
    else:
        assert v['label']=='已定位异常范围，根因未确认' and v['tone']=='bad'
        assert v['short_title']=='已测 DNS 查询路径超时'
        assert v['dnssec'][0]['certainty']=='INSUFFICIENT_EVIDENCE'
        assert not v['dnssec'][0]['direct']
        assert all(d['diagnosis_status']!='CONFIRMED_PROTOCOL_ISSUE' for d in v['diagnoses'])
        assert '关联尚未确认' in v['short_explanation']
    from dns_investigator.main import summary
    summary(r);cli=capsys.readouterr().out
    for d in diagnoses(r):assert d['summary'] in cli and d['diagnosis_status'] in cli
    c=TestClient(create_app(tmp_path))
    token=re.search(r'name="local-token" content="([^"]+)"',c.get('/').text)[1]
    key=c.post('/api/import',json=log,headers={'x-local-token':token}).json()['id']
    api=c.get('/api/reports/'+key).json()
    exported=c.get('/api/reports/'+key+'/export').json()
    assert api['result']==r==exported['result']
    html=c.get('/api/reports/'+key+'/html').text
    assert '<h1>'+v['short_title']+'</h1>' in html
    assert v['short_explanation'] in html and v['short_location'] in html
    for s in v['steps'][:3]:assert s['description'] in html
    for p in v['paths']:assert p['resolver'] in html and p['summary'] in html
    assert json.loads((tmp_path/(key+'.json')).read_text(encoding='utf8'))==log


def legacy():return cases()['legacy_result_context']


def focus(layer):return context('只检查 '+layer,parse_target('probe.example'),'investigation')


@pytest.mark.parametrize('mode',['result_only','conflict','root_fallback'])
def test_valid_stored_context_selects_original_tcp_not_timeout(mode):
    log=legacy()
    if mode=='conflict':log['request_context']=focus('HTTP')
    if mode=='root_fallback':log['request_context']=log['result'].pop('request_context')
    original=copy.deepcopy(log);new=canonical(log)
    assert log==original and new['original_result']==original['result']
    assert new['result']['request_context']['focus_layers']==['TCP/Network Transport']
    assert new['result']['diagnostic_conclusion']['primary_issue']=='TCP_REFUSED'
    assert new['report_replay']['request_context_source']==('request_context' if mode=='root_fallback' else 'result.request_context')
    assert new['report_replay']['request_context_validation']=='validated_stored_fields'
    for key in ['evidence','attempts','dns_attempts','validation_results','status']:assert new[key]==log[key]
    assert new['result']['findings']==log['result']['findings']


@pytest.mark.parametrize('bad',[None,[], 'TCP',{}, {'focus_layers':'TCP'},
    dict(focus_layers=['TCP/Network Transport'],ambiguous=False,intent_source='import_click'),
    dict(focus_layers=['TCP/Network Transport'],ambiguous=False,intent_source='explicit_user_statement',target='other.test'),
    dict(focus_layers=['TCP/Network Transport'],ambiguous=False,intent_source='explicit_user_statement',port=True)])
def test_invalid_or_explicit_unknown_result_context_never_falls_back_to_root(bad):
    log=legacy();log['result']['request_context']=bad;log['request_context']=focus('HTTP')
    new=canonical(log)
    assert new['result']['request_context']=={} and new['result']['diagnostic_conclusion'] is None
    assert new['report_replay']['request_context_source']=='result.request_context'


def test_missing_context_is_unknown_and_incomplete_logs_remain_loadable():
    log=legacy();log['result'].pop('request_context')
    new=canonical(log)
    assert new['result']['request_context']=={} and new['result']['diagnostic_conclusion'] is None
    assert new['report_replay']['request_context_source']=='unknown'
    for old in ({}, {'status':'failed','result':{}}, {'result':{'request_context':[]},'evidence':[]}):
        assert canonical(old)==old and isinstance(present(old),dict)
    incomplete=legacy();incomplete.pop('incident')
    assert canonical(incomplete)==incomplete and present(incomplete)['result']==incomplete['result']


def test_replay_never_constructs_live_backend_and_is_environment_independent(monkeypatch):
    import dns.resolver,dns.asyncquery
    from dns_investigator.tools import ToolBackend
    from dns_investigator.config import Config
    from pydantic_ai import Agent
    import socket,httpx
    def forbidden(*args,**kwargs):raise AssertionError('replay must not read environment or execute I/O')
    log=legacy();original=copy.deepcopy(log)
    monkeypatch.setattr(ToolBackend,'__init__',forbidden)
    monkeypatch.setattr(ToolBackend,'call',forbidden)
    monkeypatch.setattr(Config,'load',forbidden)
    monkeypatch.setattr(Agent,'run',forbidden)
    monkeypatch.setattr(socket,'create_connection',forbidden)
    monkeypatch.setattr(httpx.AsyncClient,'request',forbidden)
    monkeypatch.setattr(dns.asyncquery,'udp',forbidden)
    monkeypatch.setattr(dns.asyncquery,'tcp',forbidden)
    touched=[]
    def resolver(*a,**kw):touched.append(True);raise AssertionError('current system DNS read')
    monkeypatch.setattr(dns.resolver,'Resolver',resolver)
    results=[]
    for dns_servers in ('1.1.1.1','192.168.50.1,8.8.8.8'):
        monkeypatch.setenv('DNS_RESOLVERS',dns_servers)
        results.append(canonical(log))
    assert results[0]==results[1] and not touched and log==original
    new=results[0]
    assert new['report_replay']['current_environment_used'] is False
    assert new['report_replay']['new_measurements']==new['report_replay']['new_model_calls']==0
    steps=new['result']['remediation_plan']
    nested=[s for d in diagnoses(new['result']) for s in d['remediation_steps']+d['verification_steps']]
    for s in steps+nested:
        m=s['method']
        assert not s['executed'] and not m['supported_by_current_tools'] and not m['can_execute_now']
        assert m['authorization_status']=='requires_revalidation' and m['kind']!='current_tool'
    # Compare-resolvers ledger lacks a recorded per-packet system-vs-explicit path.
    for s in steps:
        if s['diagnostic_group_ids'] and s['action_type']!='POSSIBLE_FIX':assert s['method']['parameters']=={}
    assert any(s['method']['available_tool_capability']=='check_tcp' for s in steps)


def test_original_baidu_file_and_all_ledgers_remain_identical():
    p=Path('data/regressions/baidu-investigation.json');raw=p.read_bytes();log=json.loads(raw)
    new=canonical(log)
    assert p.read_bytes()==raw and new['original_result']==log['result']
    assert len(new['result']['diagnostic_groups'])==2
    for k in ('evidence','attempts','dns_attempts','validation_results','findings','status'):assert new[k]==log[k]
    assert [g['grouped_observation_count'] for g in new['result']['diagnostic_groups']]==[2,5]
