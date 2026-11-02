import json,re,time
from pathlib import Path
import httpx
c=httpx.Client(base_url='http://127.0.0.1:8765',timeout=30)
token=re.search(r'name="local-token" content="([^"]+)"',c.get('/').text)[1]
r=c.post('/api/start',json={'target':'example.com','question':'检查 example.com 的 DNS 解析是否正常'},headers={'x-local-token':token})
print('start status',r.status_code,flush=True)
if r.status_code==200:
 key=r.json()['id']
 for i in range(500):
  j=c.get('/api/jobs/'+key).json()
  if j['state']!='running':
   print(json.dumps(j,ensure_ascii=True)[:2000]);Path('docs/v06-web/live-check.json').write_text(json.dumps(j,ensure_ascii=False,indent=2),encoding='utf8');break
  time.sleep(1)
else:print(r.text)
