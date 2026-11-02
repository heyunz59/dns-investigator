"""Final-review ledger replay and actual local browser/HTML checks, no probes."""
import contextlib
import hashlib
import io
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path
import uvicorn
from evaluation.v06_review_cases import cases, BEFORE
from dns_investigator.report_replay import canonical
from dns_investigator.web import create_app, present
from dns_investigator.main import summary


def save(path,data):path.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf8')


def run(out):
    out.mkdir(parents=True,exist_ok=False)
    logs=cases()
    logs['baidu']=json.loads(Path('data/regressions/baidu-investigation.json').read_text(encoding='utf8'))
    root_context=json.loads(json.dumps(logs['legacy_result_context']))
    root_context['request_context']=root_context['result'].pop('request_context')
    logs['legacy_root_context']=root_context
    baseline=json.loads(BEFORE.read_text(encoding='utf8'))['cases']
    comparisons={}
    # The stored source tag is retained, while the surrounding provenance explicitly
    # marks the mixed rows as constructed. These are not new live measurements.
    history=out/'imported';history.mkdir()
    for i,(name,log) in enumerate(logs.items()):
        save(history/(f'case{i}.json'),log)
        v=present(log);new=canonical(log)
        for key in ('evidence','attempts','dns_attempts','validation_results','status'):assert new[key]==log[key]
        text=io.StringIO()
        with contextlib.redirect_stdout(text):summary(v['result'])
        (out/(name+'-cli.txt')).write_text(text.getvalue(),encoding='utf8')
        comparisons[name]=dict(before_short_title=baseline.get(name,{}).get('view',{}).get('short_title'),
            after={k:v[k] for k in ('short_title','short_explanation','short_location','label','tone','paths','dnssec')},
            first_actions=v['steps'][:3],diagnosis_selection_mode=v['result'].get('diagnosis_selection_mode'),
            diagnoses=[{k:d.get(k) for k in ('primary_issue','diagnosis_status','direct_evidence_ids','direct_validation_ids','dependency_evidence_ids','dependency_validation_ids')} for d in v['diagnoses']],
            replay=new.get('report_replay'),ledgers_unchanged=True)
    app=create_app(history);sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=port,log_level='warning'))
    worker=threading.Thread(target=server.run,kwargs={'sockets':[sock]},daemon=True);worker.start()
    checks=[]
    try:
        for _ in range(100):
            if server.started:break
            time.sleep(.05)
        assert server.started
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            executable=next((str(x) for x in [Path('C:/Program Files/Google/Chrome/Application/chrome.exe'),Path('C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe')] if x.exists()),None)
            browser=p.chromium.launch(executable_path=executable,headless=True)
            page=browser.new_page(viewport=dict(width=1440,height=1200),device_scale_factor=1)
            errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
            page.goto(f'http://127.0.0.1:{port}')
            for i,(name,log) in enumerate(logs.items()):
                v=present(log)
                page.evaluate('(key)=>load(key)',f'case{i}')
                assert page.locator('#title').inner_text()==v['short_title']
                assert page.locator('#explanation').inner_text()==v['short_explanation']
                assert page.locator('#location').inner_text()==v['short_location']
                assert page.locator('#label').inner_text()=='● '+v['label']
                assert page.locator('#label').get_attribute('class')==v['tone']
                assert page.locator('#actions li').count()==min(3,len(v['steps']))
                for step,text in zip(v['steps'][:3],page.locator('#actions li').all_text_contents()):assert step['description'] in text
                assert page.locator('#paths .path-row').count()==len(v['paths'])
                page.screenshot(path=str(out/(name+'-web.png')))
                response=page.request.get(f'http://127.0.0.1:{port}/api/reports/case{i}/html')
                assert response.ok
                html=response.text();(out/(name+'.html')).write_text(html,encoding='utf8')
                offline=browser.new_page(viewport=dict(width=1440,height=1200))
                offline.goto((out/(name+'.html')).resolve().as_uri())
                assert offline.locator('h1').inner_text()==v['short_title']
                assert v['short_explanation'] in offline.locator('main > article').inner_text()
                if name in ('dnssec_timeout','http_timeout','baidu'):
                    offline.screenshot(path=str(out/(name+'-offline.png')))
                offline.close()
                checks.append(dict(case=name,dom_and_offline_html='PASS',browser_errors=list(errors)))
            assert not errors
            browser.close()
    finally:
        server.should_exit=True;worker.join(timeout=10);sock.close()
    save(out/'comparison.json',comparisons)
    save(out/'validation.json',dict(mode='constructed mixed ledger + historical baidu replay, actual local browser and offline HTML',
        source_head_before_commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        source_hashes={str(p).replace('\\','/'):hashlib.sha256(p.read_bytes()).hexdigest() for p in [Path('src/dns_investigator/web_view.py'),Path('src/dns_investigator/report_replay.py')]},
        cases=checks,new_public_measurements=0,new_model_calls=0,independent_human_semantic_review='NOT_RUN'))
    print(f'PASS: {len(checks)} actual Web DOM and offline HTML replays; no new public/model calls')


if __name__=='__main__':run(Path(sys.argv[1]))
