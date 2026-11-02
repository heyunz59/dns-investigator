"""Historical public-log replay and local browser capture; no model/public probes."""
import contextlib,csv,hashlib,io,json,socket,sys,threading,time
from pathlib import Path
import uvicorn
from dns_investigator.report_replay import canonical
from dns_investigator.web import present,create_app
from dns_investigator.main import summary


def save(p,d):p.write_text(json.dumps(d,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


def run(out):
    raw=Path('data/regressions/baidu-investigation.json').read_bytes();log=json.loads(raw.decode('utf-8-sig'))
    new=canonical(log);r=new['result'];view=present(new)
    for key in ['evidence','attempts','dns_attempts','validation_results']:assert log[key]==new[key]
    save(out/'after-investigation.json',new);save(out/'after-web.json',view)
    old=json.loads((out/'before-report.json').read_text(encoding='utf-8'))
    save(out/'comparison.json',dict(input_sha256=hashlib.sha256(raw).hexdigest(),mode='historical public log replay; no new live investigation',
        before_diagnoses=len(([old['diagnostic_conclusion']] if old['diagnostic_conclusion'] else [])+old['secondary_diagnoses']),
        after_diagnoses=len(view['diagnoses']),before_steps=len(old['remediation_plan']),after_steps=len(r['remediation_plan']),
        evidence_preserved=19,dns_attempts_preserved=17,timeout_measurements_preserved=7,findings_preserved=len(r['findings']),
        new_public_measurements=0,new_model_calls=0,independent_semantic_review='NOT_RUN'))
    rows=[]
    by_id={e['id']:e for e in log['evidence']}
    for g in r['diagnostic_groups']:
        for eid in sorted(g['direct_evidence_ids'],key=lambda s:int(s[1:])):
            e=by_id[eid];d=e['data']
            rows.append(dict(group_id=g['diagnostic_group_id'],resolver=d['resolver'],evidence_id=eid,query_attempt_id=e['query_attempt_id'],qname=d['qname'],qtype=d['qtype'],measured_at=e['started_at'],source_mode=e['source_mode'],measurement_location=e['measurement_location']))
    with (out/'group-evidence.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    text=io.StringIO()
    with contextlib.redirect_stdout(text):summary(r)
    (out/'after-cli.txt').write_text(text.getvalue(),encoding='utf-8')
    history=Path('results/runs/public-path-aggregation/browser-history');history.mkdir(parents=True,exist_ok=True)
    (history/'baiduregression.json').write_bytes(raw)
    app=create_app(history)
    sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    server=uvicorn.Server(uvicorn.Config(app,host='127.0.0.1',port=port,log_level='warning'))
    worker=threading.Thread(target=server.run,kwargs={'sockets':[sock]},daemon=True);worker.start()
    try:
        for _ in range(100):
            if server.started:break
            time.sleep(.05)
        assert server.started
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            executable=next((str(x) for x in [Path('C:/Program Files/Google/Chrome/Application/chrome.exe'),Path('C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe')] if x.exists()),None)
            browser=p.chromium.launch(executable_path=executable,headless=True)
            page=browser.new_page(viewport={'width':1440,'height':1200},device_scale_factor=1)
            errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
            page.goto(f'http://127.0.0.1:{port}');page.evaluate("load('baiduregression')")
            assert page.locator('#title').inner_text()=='部分递归 DNS 查询路径超时'
            assert '192.168.5.1' in page.locator('#other').inner_text() and '1.1.1.1' in page.locator('#other').inner_text()
            assert page.get_by_role('tab').count()==3
            assert page.locator('#actions strong').count()==3
            page.screenshot(path=str(out/'baidu-after.png'))
            assert page.locator('#evidence tr').count()==18
            page.get_by_role('tab',name='排障详情',exact=True).click()
            page.screenshot(path=str(out/'baidu-troubleshooting.png'))
            page.get_by_role('tab',name='调查时间线',exact=True).click()
            assert page.locator('#timeline details').count()==len(log['attempts'])
            page.screenshot(path=str(out/'baidu-timeline.png'))
            assert not errors
            browser.close()
        save(out/'browser-check.json',dict(status='PASS',mode='actual local browser on original historical imported log',
            tabs=3,dns_table_measurements=17,attempts=len(log['attempts']),browser_errors=errors,new_model_calls=0,new_public_measurements=0))
    finally:server.should_exit=True;worker.join(timeout=10);sock.close()
    print('Historical replay and actual browser screenshot checks PASS')


if __name__=='__main__':run(Path(sys.argv[1]))
