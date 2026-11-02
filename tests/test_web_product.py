"""Product presentation, cancellation, offline export and ownership boundaries."""
import asyncio
import copy
import json
import re
from pathlib import Path
from types import SimpleNamespace
import httpx
import pytest
from fastapi.testclient import TestClient
from dns_investigator.web import create_app, present
from dns_investigator.web_view import recorded_time

BAIDU=Path('data/regressions/baidu-investigation.json')

def client(tmp_path):
    c=TestClient(create_app(tmp_path))
    h={'x-local-token':re.search(r'name="local-token" content="([^"]+)"',c.get('/').text)[1]}
    return c,h

def test_baidu_short_summary_and_scoped_comparisons():
    log=json.loads(BAIDU.read_text(encoding='utf8')); before=copy.deepcopy(log); v=present(log)
    assert log==before
    assert v['short_title']=='部分 DNS 解析路径超时'
    assert '整体 DNS 不可用' in v['short_explanation'] and '不能' in v['short_explanation']
    assert len(v['short_explanation'])<150
    groups={g['resolver']:g for g in v['resolver_groups']}
    assert groups['192.168.5.1']['summary']=='5 次查询超时'
    assert groups['1.1.1.1']['summary']=='2 次查询超时'
    assert groups['8.8.8.8']['summary']=='1 次正常响应'
    assert {m['type'] for m in groups['8.8.8.8']['measurements']}=={'A'}
    assert all(m['rcode']=='未收到响应' for m in groups['192.168.5.1']['measurements'])
    assert all(m['query_id'] and m['evidence_id'] and m['time'] for m in groups['192.168.5.1']['measurements'])
    assert len(v['timeline'])==len(log['attempts'])
    assert any('未执行' in e['summary'] for e in v['timeline'])
    assert '后续' in next(c['title'] for c in v['evidence_cards'] if c['id']=='E19')

def test_no_unmeasured_success_or_forged_rcode():
    log={'evidence':[{'id':'E1','tool_name':'query_dns','data':{'resolver':'r','qname':'x.test','record_type':'AAAA','result_kind':'TIMEOUT','rcode':'TIMEOUT','resolution_complete':False},'source_mode':'fixture'}]}
    v=present(log)
    assert v['paths'][0]['tone']=='uncertain'
    assert v['resolver_groups'][0]['measurements'][0]['rcode']=='未收到响应'
    assert len(v['paths'])==1 and v['paths'][0]['queries']==['x.test AAAA']
    assert not any(g['tone']=='good' for g in v['paths'])

def test_groups_keep_roles_sources_positions_and_record_types():
    evidence=[]
    for i,(role,source,loc) in enumerate([('recursive','live','host1'),('authoritative','live','host1'),('recursive','synthetic','host1'),('recursive','live','host2')]):
        evidence.append({'id':f'E{i}','tool_name':'query_dns','source_mode':source,'measurement_location':loc,'data':{'resolver':'1.1.1.1','qname':'a.test','record_type':'A','result_kind':'NOERROR','resolution_complete':True,'resolver_role':role}})
    v=present({'evidence':evidence})
    assert len(v['resolver_groups'])==4
    assert all(p['queries']==['a.test A'] for p in v['paths'])

def test_timeline_real_order_unknown_time_and_no_sixth_tool():
    v=present({'attempts':[{'attempt_id':'A2','tool_name':'check_tcp','started_at':'2026-11-02T10:00:01+00:00','status':'rejected','duration_ms':0},{'attempt_id':'A3','tool_name':'check_http','status':'failed'},{'attempt_id':'A1','tool_name':'query_dns','started_at':'2026-11-02T10:00:00+00:00','duration_ms':22}]})
    assert [t['refs'][0] for t in v['timeline']]==['A1','A2','A3']
    assert v['timeline'][0]['duration']==22 and v['timeline'][2]['time'] is None
    assert '远端故障' in v['timeline'][1]['summary']
    assert not any(t['operation']=='dnssec_validate' for t in v['timeline'])

def test_dnssec_direct_dependencies_and_html(tmp_path):
    c,h=client(tmp_path)
    rows=json.loads(Path('results/published/v05-report-quality-fixes/20261102-report-quality/before.json').read_text(encoding='utf8'))['cases']
    from evaluation.report_quality import report
    row=next(x for x in rows if x['case']=='dnssec-ds_mismatch')
    key=c.post('/api/import',headers=h,json={'result':report(row),'evidence':row['evidence'],'validation_results':row.get('validation_results',[]),'demo':True}).json()['id']
    v=c.get('/api/reports/'+key).json()
    assert set(v['dnssec'][0]['direct'])=={'V7','E7','E8'}
    assert v['dnssec'][0]['dependencies']
    page=c.get('/api/reports/'+key+'/html')
    assert page.status_code==200 and '直接依据' in page.text and '尚未执行' in page.text
    assert 'script-src &#39;none&#39;' not in page.text # static CSP is literal
    assert "script-src 'none'" in page.text and '<script' not in page.text

def test_html_untrusted_export_and_json_compatibility(tmp_path):
    c,h=client(tmp_path)
    raw={'incident':{'target':'<img src=x onerror=alert(1)>'},'proxy-authorization':'private-proxy','config':{'password':'private-pw'},'environment':{'TOKEN':'private-env'},'result':{'conclusion':'<script>alert(1)</script>'},'url':'https://user:pass@x.test/?token=private-query'}
    key=c.post('/api/import',headers=h,json=raw).json()['id']
    page=c.get('/api/reports/'+key+'/html').text
    assert '<img' not in page and '<script>' not in page and '&lt;script&gt;' in page
    assert all(x not in page for x in ['private-proxy','private-pw','private-env','user:pass','private-query'])
    exported=c.get('/api/reports/'+key+'/export').json()
    assert exported['result']==raw['result']
    assert 'environment' not in exported and 'config' not in exported

def test_history_filter_order_actual_time_not_import_time(tmp_path):
    c,h=client(tmp_path)
    for target,time in [('a.test','2025-01-01T00:00:00Z'),('b.test','2026-01-01T00:00:00Z'),('a.test',None)]:
        c.post('/api/import',headers=h,json={'incident':{'target':{'domain':target}},'started_at':time,'result':{}})
    rows=c.get('/api/history?domain=a.test&order=oldest').json()
    assert len(rows)==2 and rows[0]['time']=='测量时间未记录' and rows[1]['time'].startswith('2025')
    assert not c.get('/api/history?domain=../../.env').json()
    assert recorded_time(None) is None

@pytest.mark.asyncio
async def test_cancel_stops_backend_preserves_evidence_and_session_ownership(tmp_path,monkeypatch):
    stopped=asyncio.Event()
    async def fake(*args,**kwargs):
        kwargs['progress']({'id':'E1','tool_name':'query_dns','tool_call_id':'A1','data':{'result_kind':'TIMEOUT'}})
        try: await asyncio.Event().wait()
        finally: stopped.set()
    monkeypatch.setattr('dns_investigator.web.investigate',fake)
    monkeypatch.setattr('dns_investigator.web.Config.load',lambda:SimpleNamespace(api_key='test'))
    app=create_app(tmp_path)
    transport=httpx.ASGITransport(app=app,client=('127.0.0.1',123))
    async with httpx.AsyncClient(transport=transport,base_url='http://localhost') as a,httpx.AsyncClient(transport=transport,base_url='http://localhost') as b:
        token=re.search(r'name="local-token" content="([^"]+)"',(await a.get('/')).text)[1];h={'x-local-token':token}
        await b.get('/')
        key=(await a.post('/api/start',headers=h,json={'target':'example.com'})).json()['id']
        await asyncio.sleep(.01)
        assert (await b.get('/api/jobs/'+key)).status_code==404
        assert (await b.post('/api/jobs/'+key+'/cancel',headers=h)).status_code==404
        await a.get('/') # refresh retains cookie ownership
        assert (await a.get('/api/jobs/'+key)).json()['state']=='running'
        assert (await a.post('/api/jobs/'+key+'/cancel')).status_code==403
        await a.post('/api/jobs/'+key+'/cancel',headers=h)
        await asyncio.wait_for(stopped.wait(),1)
        await asyncio.sleep(.01)
        j=(await a.get('/api/jobs/'+key)).json();assert j['state']=='cancelled'
        saved=json.loads((tmp_path/(j['report_id']+'.json')).read_text(encoding='utf8'))
        assert saved['evidence'][0]['id']=='E1' and saved['status']=='cancelled'
        assert (await a.get('/api/reports/'+j['report_id'])).json()['tone']=='uncertain'
    restarted=create_app(tmp_path)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=restarted,client=('127.0.0.1',1)),base_url='http://localhost') as c:
        assert (await c.get('/api/jobs/'+key)).status_code==404

@pytest.mark.asyncio
async def test_real_agent_cancel_persists_ledger(tmp_path):
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.messages import ModelResponse, ToolCallPart
    from dns_investigator.agent import investigate
    from dns_investigator.config import Config
    from dns_investigator.target import parse_target
    waiting=asyncio.Event();calls=[]
    async def respond(messages,info):
        if not any(getattr(p,'part_kind','')=='tool-return' for m in messages for p in m.parts):
            calls.append('query_dns')
            return ModelResponse(parts=[ToolCallPart('query_dns',{'domain':'example.com','record_type':'A'})])
        waiting.set();await asyncio.Event().wait()
    task=asyncio.create_task(investigate('查询 example.com A',parse_target('example.com'),Config('test',model='scripted-test'),Path('data/fixtures/Q1.json'),FunctionModel(respond),log_dir=tmp_path))
    await asyncio.wait_for(waiting.wait(),5)
    task.cancel()
    log,path=await asyncio.wait_for(task,3)
    saved=json.loads(path.read_text(encoding='utf8'))
    assert log['status']=='cancelled' and saved['evidence'][0]['id']=='E1'
    assert calls==['query_dns'] and len(saved['attempts'])==1
    assert '用户取消' in str(saved['result']['limitations']) or '取消' in saved['result']['conclusion']

@pytest.mark.asyncio
async def test_remote_request_rejected(tmp_path):
    app=create_app(tmp_path)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app,client=('192.0.2.1',1)),base_url='http://localhost') as c:
        assert (await c.get('/')).status_code==403

def test_oversize_invalid_and_forged_nested_import(tmp_path):
    c,h=client(tmp_path)
    assert c.post('/api/import',headers=h,content=b' '*16000001).status_code==413
    assert c.post('/api/import',headers=h,json={'result':{'diagnostic_conclusion':[]}}).status_code in (200,400)
    assert c.post('/api/import',headers=h,json={'evidence':['<script>']}).status_code==400

def test_legacy_long_summary_uses_controlled_fallback_without_data_loss():
    text='未验证条件和完整原始解释。'*1000
    v=present({'result':{'conclusion':text}})
    assert v['short_title']=='证据不足，暂无法确定'
    assert len(v['short_explanation'])<100
    assert v['result']['conclusion']==text

def test_friendly_evidence_identity_and_internal_validation_references():
    v=present({'evidence':[{'id':'E7','tool_name':'query_dns','tool_call_id':'A1','input':{'domain':'x.test','record_type':'A','resolver':'1.1.1.1'},'data':{'result_kind':'TIMEOUT'}}], 'attempts':[{'attempt_id':'A1','tool_name':'query_authoritative'}], 'validation_results':[{'id':'V7','parent_tool_call_id':'A1','kind':'ds_digest','local_result':'SIGNATURE_CHECK_FAILED','reason_code':'DS_DIGEST_MISMATCH','scope':{'zone':'x.test.'}}]})
    assert '1.1.1.1 的 x.test A' in v['evidence_cards'][0]['title']
    assert 'DS' in v['validation_cards'][0]['title'] and '未记录' not in v['validation_cards'][0]['title']
    assert 'V7' in v['timeline'][0]['refs']
    assert len(v['timeline'])==1 and len(v['timeline'][0]['internal_validations'])==1
