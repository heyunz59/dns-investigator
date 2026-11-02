"""Web presentation contract and loopback boundary tests; no public probes."""
import copy
import json
import re
from pathlib import Path
from types import SimpleNamespace
import pytest
from fastapi.testclient import TestClient
from dns_investigator.web import create_app, present
from evaluation.report_quality import report

ROWS=json.loads(Path('results/published/v05-report-quality-fixes/20261102-report-quality/before.json').read_text(encoding='utf8'))['cases']

@pytest.mark.parametrize('row',ROWS,ids=lambda r:r['case'])
def test_existing_report_mapping(row):
    result=report(row)
    log=dict(result=result, **{k:row.get(k,[]) for k in ('evidence','attempts','dns_attempts','validation_results')})
    before=copy.deepcopy(log)
    vm=present(log)
    assert log==before
    assert vm['evidence']==row.get('evidence',[]) or vm['evidence']==result['measured_facts']
    assert vm['validations']==row.get('validation_results',[]) or vm['validations']==result['validation_results']
    assert 'nodes' not in vm
    if result.get('diagnostic_conclusion'):
        assert vm['location']==result['diagnostic_conclusion']['fault_location']
    if result.get('diagnosis_selection_mode')=='parallel':assert '唯一主因' in vm['title']
    assert all(s.get('executed') is False for s in vm['steps'])

@pytest.mark.parametrize('log',[{}, {'conclusion':'旧版报告'}, {'result':{}}, {'demo':True}, {'result':{'report_fallback_reason':'模型失败','measured_facts':[{'evidence_id':'E1'}]}}])
def test_incomplete_and_fallback(log):
    vm=present(log)
    assert vm['tone']=='uncertain'
    assert vm['location']=='未取得可确认的位置'
    assert vm['demo']==bool(log.get('demo'))

def setup(tmp_path):
    c=TestClient(create_app(tmp_path))
    token=re.search(r'name="local-token" content="([^"]+)"',c.get('/').text)[1]
    return c,{'x-local-token':token}

def test_import_history_export_xss_and_privacy(tmp_path):
    c,h=setup(tmp_path)
    raw={'result':{'conclusion':'<script>alert(1)</script>'},'api_key':'secret','authorization':'private','url':'https://user:pass@example.com/?key=value'}
    r=c.post('/api/import',json=raw,headers=h);assert r.status_code==200
    key=r.json()['id']
    assert c.get('/api/reports/'+key).json()['title']==raw['result']['conclusion']
    exported=c.get('/api/reports/'+key+'/export')
    assert exported.status_code==200
    assert 'secret' not in exported.text and 'private' not in exported.text and 'user:pass' not in exported.text and 'value' not in exported.text
    assert len(c.get('/api/history').json())==1
    assert 'attachment' in exported.headers['content-disposition']
    assert c.get('/api/reports/%2E%2E%2Fconfig').status_code==404
    assert c.post('/api/import',json=raw).status_code==403
    assert c.get('/',headers={'host':'attacker.example'}).status_code==400
    assert 'frame-ancestors' in c.get('/').headers['content-security-policy']

@pytest.mark.parametrize('body',[[], 'abc', {'result':[]}, None])
def test_bad_import(tmp_path,body):
    c,h=setup(tmp_path)
    assert c.post('/api/import',json=body,headers=h).status_code==400

def test_missing_key_and_target(tmp_path,monkeypatch):
    c,h=setup(tmp_path)
    monkeypatch.setattr('dns_investigator.web.Config.load',lambda:SimpleNamespace(api_key=''))
    assert c.post('/api/start',json={'target':'https://user:pass@example.com'},headers=h).status_code==400
    r=c.post('/api/start',json={'target':'example.com'},headers=h)
    assert r.status_code==400 and 'DEEPSEEK_API_KEY' in r.text

@pytest.mark.asyncio
async def test_real_entry_wiring(tmp_path,monkeypatch):
    import httpx
    calls=[]
    async def fake(text,target,config,**kw):
        calls.append((text,target,kw))
        kw['progress']({'id':'E1','tool_name':'query_dns','execution_status':'measured'})
        return {'status':'limited'},tmp_path/'abc.json'
    monkeypatch.setattr('dns_investigator.web.Config.load',lambda:SimpleNamespace(api_key='secret'))
    monkeypatch.setattr('dns_investigator.web.investigate',fake)
    app=create_app(tmp_path)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=('127.0.0.1',123)),base_url='http://localhost') as c:
        token=re.search(r'name="local-token" content="([^"]+)"',(await c.get('/')).text)[1]
        r=await c.post('/api/start',json={'target':'example.com','question':'DNS 查询失败'},headers={'x-local-token':token})
        import asyncio
        await asyncio.sleep(0.02)
        job=(await c.get('/api/jobs/'+r.json()['id'])).json()
        assert job['state']=='limited' and job['events'][0]['id']=='E1'
        assert calls[0][2]['target_source']=='explicit_target'
        assert 'fixture' not in calls[0][2]

@pytest.mark.parametrize('status,tone,label',[('INSUFFICIENT_EVIDENCE','uncertain','证据不足'),('NO_FAULT_OBSERVED','good','未观察到'),('FAULT_LOCALIZED','bad','根因未确认')])
def test_confirmation_never_upgraded(status,tone,label):
    log={'result':{'diagnostic_conclusion':{'diagnosis_status':status,'summary':'DNSSEC INDETERMINATE','fault_location':'未验证范围'}}}
    v=present(log)
    assert v['tone']==tone and label in v['label']
    assert 'BOGUS' not in json.dumps(v)
