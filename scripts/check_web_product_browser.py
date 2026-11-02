"""Browser acceptance on local server; --live explicitly invokes real model/public DNS."""
import argparse
import json
import os
import re
import subprocess
from pathlib import Path
from playwright.sync_api import sync_playwright

ROOT=Path(__file__).resolve().parents[1]
OUT=ROOT/'docs/v06-polish'
BASE='http://127.0.0.1:8765'

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--live',action='store_true');args=parser.parse_args()
    OUT.mkdir(exist_ok=True)
    previous=json.loads((OUT/'browser-result.json').read_text(encoding='utf8')) if (OUT/'browser-result.json').exists() else {}
    with sync_playwright() as p:
        executable=os.environ.get('WEB_BROWSER') or next((str(x) for x in [Path(r'C:\Program Files\Google\Chrome\Application\chrome.exe'),Path(r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')] if x.exists()),None)
        browser=p.chromium.launch(executable_path=executable,headless=True)
        page=browser.new_page(viewport={'width':1440,'height':1050});errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
        page.goto(BASE);page.screenshot(path=str(OUT/'empty.png'),full_page=True)
        def load_file(path):
            page.locator('#file').set_input_files(str(path));page.wait_for_function('()=>document.querySelector("#status").textContent.includes("报告已加载")')
            page.wait_for_timeout(150)
        def shot(name):
            assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
            page.screenshot(path=str(OUT/(name+'.png')),full_page=True)
        load_file(ROOT/'data/regressions/baidu-investigation.json');shot('baidu')
        assert '整体 DNS 不可用' in page.locator('#explanation').inner_text()
        assert '5 次查询超时' in page.locator('#paths').inner_text()
        # Capture the baseline assets against the same immutable historical report.
        old_html=subprocess.check_output(['git','show','15f9fe9:src/dns_investigator/assets/web.html'],cwd=ROOT).decode('utf8')
        old_js=subprocess.check_output(['git','show','15f9fe9:src/dns_investigator/assets/web.js'],cwd=ROOT)
        old_css=subprocess.check_output(['git','show','15f9fe9:src/dns_investigator/assets/web.css'],cwd=ROOT)
        token=page.locator('meta[name=local-token]').get_attribute('content');key=page.evaluate('current')
        old=browser.new_page(viewport={'width':1440,'height':1050})
        old.route(BASE+'/',lambda route:route.fulfill(content_type='text/html',body=old_html.replace('{{ token }}',token)))
        old.route('**/assets/web.js',lambda route:route.fulfill(content_type='application/javascript',body=old_js))
        old.route('**/assets/web.css',lambda route:route.fulfill(content_type='text/css',body=old_css))
        old.goto(BASE);old.evaluate('(key)=>load(key)',key);old.screenshot(path=str(OUT/'before.png'),full_page=True);old.close()
        page.locator('#evidence details.resolver').first.locator('summary').click();shot('evidence')
        for tab,name in [('排障详情','details'),('调查时间线','timeline')]:
            page.get_by_role('tab',name=tab,exact=True).click();assert page.get_by_role('tab',name=tab).get_attribute('aria-selected')=='true';shot(name)
        with page.expect_download() as download:page.locator('#export-html').click()
        download.value.save_as(OUT/'baidu-report.html')
        with page.expect_download() as download:page.locator('#export').click()
        audit=json.loads(Path(download.value.path()).read_text(encoding='utf8'))
        original=json.loads((ROOT/'data/regressions/baidu-investigation.json').read_text(encoding='utf8'))
        assert audit['evidence']==original['evidence'] and audit['dns_attempts']==original['dns_attempts']
        offline=browser.new_page(viewport={'width':1440,'height':1050});requests=[]
        offline.on('request',lambda req:requests.append(req.url));offline.goto((OUT/'baidu-report.html').as_uri());offline.screenshot(path=str(OUT/'html-export.png'),full_page=False)
        assert not [url for url in requests if url.startswith(('http://','https://'))]
        assert offline.locator('script').count()==0;offline.emulate_media(media='print');offline.pdf(path=str(OUT/'print-check.pdf'));offline.close()
        page.get_by_role('button',name='历史记录',exact=True).click();page.locator('#history-filter').fill('baidu.com');page.wait_for_timeout(600)
        assert page.locator('.history-row').count()>0
        assert all('baidu.com' in x for x in page.locator('.history-row strong').all_inner_texts());shot('history')
        page.locator('.history-row').first.click();page.wait_for_selector('#report:not([hidden])')
        page.set_viewport_size({'width':390,'height':844});shot('mobile');page.set_viewport_size({'width':1440,'height':1050})
        for case,name in [('webdemodnssecdsmismatch','dnssec'),('webdemodnsnormal','normal'),('webdemohttp503','http503'),('webdemomultiambiguous','multiple')]:
            page.evaluate('(key)=>load(key)',case);shot(name)
        # Hostile text remains inert in both the online UI and offline HTML.
        payload=json.dumps({'incident':{'target':'evil.test'},'result':{'conclusion':'<script>window.pwned=1</script>'},'evidence':[{'id':'E1','tool_name':'query_dns','data':{'ede':[{'text':'<img src=x onerror=alert(1)>'}]}}]})
        page.locator('#file').set_input_files({'name':'hostile.json','mimeType':'application/json','buffer':payload.encode()});page.wait_for_function('()=>document.querySelector("#title").textContent.includes("证据不足")')
        assert page.evaluate('window.pwned') is None
        with page.expect_download() as download:page.locator('#export-html').click()
        hostile=OUT/'hostile-check.html';download.value.save_as(hostile)
        off=browser.new_page();off.goto(hostile.as_uri());assert off.locator('script,img').count()==0;assert off.evaluate('window.pwned') is None;off.close();hostile.unlink()
        live=[]
        if args.live:
            page.locator('#target').fill('example.com');page.locator('#question').fill('查询 example.com 的 A 记录')
            page.locator('#start').click();page.wait_for_selector('#progress:not([hidden])');shot('investigating')
            page.reload();page.wait_for_selector('#progress:not([hidden])');assert page.locator('#start').is_disabled()
            page.wait_for_function('()=>!localStorage.getItem("dns-job")',timeout=240000)
            shot('live-completed');live.append({'mode':'real_model_public_dns','status':page.locator('#status').inner_text(),'report_id':page.evaluate('current')})
            page.locator('#start').click();page.wait_for_selector('#progress:not([hidden])');page.locator('#cancel').click()
            page.wait_for_function('()=>!localStorage.getItem("dns-job")',timeout=30000)
            assert '已取消' in page.locator('#status').inner_text();shot('cancelled');live.append({'mode':'real_model_cancel_request','status':page.locator('#status').inner_text(),'report_id':page.evaluate('current')})
        assert not errors,errors
        browser.close()
        (OUT/'browser-result.json').write_text(json.dumps({'browser':'Chromium','checks':'tabs, resolver expansion, filter, JSON compatibility, offline HTML no requests/scripts, print, mobile overflow, hostile DOM','live':live if args.live else previous.get('live',[]),'errors':errors},ensure_ascii=False,indent=2),encoding='utf8')
        print('Browser acceptance passed; live enabled:',args.live)
if __name__=='__main__':main()
