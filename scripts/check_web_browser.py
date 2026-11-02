from pathlib import Path
from playwright.sync_api import sync_playwright
out=Path('docs/v06-web');out.mkdir(exist_ok=True,parents=True)
with sync_playwright() as p:
 import os
 executable=os.environ.get('WEB_BROWSER')
 if not executable:
  executable=next((str(x) for x in [Path(r'C:\Program Files\Google\Chrome\Application\chrome.exe'),Path(r'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe')] if x.exists()),None)
 browser=p.chromium.launch(executable_path=executable,headless=True)
 page=browser.new_page(viewport={'width':1440,'height':1100},device_scale_factor=1)
 errors=[];page.on('pageerror',lambda e:errors.append(str(e)))
 page.goto('http://127.0.0.1:8765')
 for case in ['dnssecdsmismatch','http503','multiTCP']:
  page.get_by_role('button',name='历史记录',exact=True).click()
  page.wait_for_selector('#history-list button')
  page.evaluate('(key)=>load(key)','webdemo'+case)
  page.wait_for_function('document.querySelector("#report").hidden===false')
  page.wait_for_timeout(300)
  page.screenshot(path=str(out/(case+'.png')),full_page=True)
  for tab in ['解析与证据','排障详情','调查时间线']:
   page.get_by_role('tab',name=tab,exact=True).click()
   assert page.get_by_role('tab',name=tab,exact=True).get_attribute('aria-selected')=='true'
  page.get_by_role('tab',name='排障详情',exact=True).click()
  page.screenshot(path=str(out/(case+'-details.png')),full_page=True)
  page.get_by_role('tab',name='调查时间线',exact=True).click()
  page.screenshot(path=str(out/(case+'-timeline.png')),full_page=True)
 page.set_viewport_size({'width':390,'height':844})
 page.get_by_role('tab',name='解析与证据',exact=True).click()
 assert page.evaluate('document.documentElement.scrollWidth<=innerWidth')
 page.screenshot(path=str(out/'mobile.png'),full_page=True)
 assert not errors,errors
 browser.close()
 print('Browser: three scenarios, three tabs, mobile overflow and console checks passed')
