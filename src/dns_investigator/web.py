"""Loopback-only UI. No diagnostic logic lives here."""
import asyncio
import json
import secrets
import uuid
import time
from datetime import datetime, timezone
from pathlib import Path
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.trustedhost import TrustedHostMiddleware
from jinja2 import Environment, FileSystemLoader, select_autoescape
from pydantic import BaseModel, Field
from .agent import investigate
from .config import Config
from .privacy import redact
from .target import parse_target

ASSETS = Path(__file__).parent / 'assets'
ENV = Environment(loader=FileSystemLoader(str(ASSETS)), autoescape=select_autoescape(['html']))
LABELS = {'CONFIRMED_PROTOCOL_ISSUE': '已确认协议异常', 'FAULT_LOCALIZED': '已定位异常范围，根因未确认', 'LIKELY_CAUSE': '存在候选原因，尚待验证', 'NO_FAULT_OBSERVED': '本次未观察到明确故障', 'INSUFFICIENT_EVIDENCE': '证据不足，暂无法确定'}

def present(log):
    from .report_replay import canonical
    log=canonical(log)
    r = log.get('result', log)
    if not isinstance(r, dict): r = {}
    d = r.get('diagnostic_conclusion') or {}
    diagnoses = ([d] if d else []) + r.get('secondary_diagnoses', [])
    parallel = r.get('diagnosis_selection_mode') == 'parallel'
    status = d.get('diagnosis_status', 'INSUFFICIENT_EVIDENCE')
    steps = r.get('remediation_plan') or [s for x in diagnoses for s in x.get('remediation_steps', []) + x.get('verification_steps', [])]
    if parallel:
        checks = [next((s for s in x.get('remediation_steps', []) if s.get('action_type') == 'CHECK'), None) for x in diagnoses]
        checks = [s for s in checks if s]
        steps = checks + [s for s in steps if s not in checks]
    overview=r.get('diagnostic_summary') or {}
    view=dict(title=overview.get('title') or ('多个独立异常，无法确认唯一主因' if parallel else d.get('summary') or r.get('diagnostic_assessment') or r.get('conclusion') or '尚无有效测量'),
        label='多个异常并列' if parallel else LABELS.get(status, LABELS['INSUFFICIENT_EVIDENCE']),
        tone='uncertain' if parallel else 'good' if status == 'NO_FAULT_OBSERVED' else 'bad' if status in ('CONFIRMED_PROTOCOL_ISSUE', 'FAULT_LOCALIZED') else 'uncertain',
        diagnoses=diagnoses, steps=steps, location=d.get('fault_location') or '未取得可确认的位置',
        explanation=d.get('cause') or '请查看实际证据与调查限制。',
        demo=log.get('incident', {}).get('measurement_location') == 'synthetic' or log.get('demo', False) or any(e.get('source_mode') in ('synthetic', 'fixture') for e in log.get('evidence', [])),
        evidence=log.get('evidence') or r.get('measured_facts', []),
        validations=log.get('validation_results') or r.get('validation_results', []),
        attempts=log.get('attempts', []), dns_attempts=log.get('dns_attempts', []),
        limitations=r.get('limitations', []) + ([r['report_fallback_reason']] if r.get('report_fallback_reason') else []),
        issues=r.get('execution_issues', []), state=log.get('status', '历史回放'), result=r,diagnostic_groups=r.get('diagnostic_groups',[]),diagnostic_summary=overview)
    if overview.get('title'):
        view.update(label='部分路径异常' if overview.get('successful_dns') else '路径超时，缺少对照',tone='uncertain',
            location='；'.join(g['fault_location'] for g in r.get('diagnostic_groups',[])),explanation=overview['explanation'])
    from .web_view import enrich
    return enrich(view, log)

class Start(BaseModel):
    target: str = Field(min_length=1, max_length=2048)
    question: str = Field(default='', max_length=4000)

def create_app(history_dir=Path('results/runs')):
    app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=['127.0.0.1', 'localhost', '[::1]', 'testserver'])
    token = secrets.token_urlsafe(32)
    history_dir = Path(history_dir)
    jobs = {}
    tasks = set()
    owners = set()
    def clean(data):
        def strip(value):
            if isinstance(value, dict):
                return {k: strip(v) for k,v in value.items() if k.lower().replace('-', '_') not in {'deepseek_api_key','proxy_authorization','password','proxy_password','secret','secrets','environment','env','config','configuration','private_config','server_key'}}
            if isinstance(value, list): return [strip(v) for v in value]
            return value
        return redact(strip(data), [Config.load().api_key])
    def read(key):
        if not key.isalnum() or len(key) > 80: raise HTTPException(404)
        path = history_dir / (key + '.json')
        if path.is_symlink(): raise HTTPException(404)
        try:
            if path.stat().st_size > 16_000_000: raise HTTPException(413)
            return clean(json.loads(path.read_text(encoding='utf-8')))
        except (OSError, ValueError): raise HTTPException(404)
    @app.middleware('http')
    async def local_only(request, call_next):
        if request.client and request.client.host not in ('127.0.0.1', '::1', 'testclient'):
            return Response(status_code=403)
        if request.method != 'GET' and not secrets.compare_digest(request.headers.get('x-local-token', ''), token):
            return Response(status_code=403)
        response = await call_next(request)
        response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['Cache-Control'] = 'no-store'
        return response
    app.mount('/assets', StaticFiles(directory=ASSETS), name='assets')
    @app.get('/', response_class=HTMLResponse)
    async def index(request: Request):
        owner = request.cookies.get('dns_session')
        if owner not in owners:
            owner = secrets.token_urlsafe(32)
            owners.add(owner)
        response = HTMLResponse(ENV.get_template('web.html').render(token=token))
        response.set_cookie('dns_session', owner, httponly=True, samesite='strict')
        return response
    @app.get('/api/history')
    async def history(domain: str = '', order: str = 'newest'):
        rows = []
        if history_dir.exists():
            for p in sorted(history_dir.glob('*.json'), key=lambda p: p.stat().st_mtime, reverse=True)[:100]:
                try:
                    log = read(p.stem)
                    v=present(log)
                    if domain.casefold() not in str(v['target']).casefold(): continue
                    rows.append(dict(id=p.stem, title=v['short_title'], time=v['measured_at'] or '测量时间未记录', target=v['target'], state=v['state_label'], demo=v['demo'], replay=v['replay']))
                except (HTTPException, ValueError, TypeError, AttributeError): continue
        from .web_view import recorded_time
        rows.sort(key=lambda row: recorded_time(row['time']) or 0, reverse=order != 'oldest')
        return rows
    @app.get('/api/reports/{key}')
    async def report(key: str): return present(read(key))
    @app.get('/api/reports/{key}/export')
    async def export(key: str):
        from .report_replay import canonical
        return Response(json.dumps(canonical(read(key)), ensure_ascii=False, indent=2), media_type='application/json', headers={'Content-Disposition': 'attachment; filename="investigation.json"'})
    @app.get('/api/reports/{key}/html')
    async def html_export(key: str):
        log=read(key)
        from .report_replay import canonical
        log=canonical(log)
        view=present(log)
        page=ENV.get_template('report.html').render(v=view, raw=json.dumps(log,ensure_ascii=False,indent=2), css=(ASSETS/'report.css').read_text(encoding='utf-8-sig'))
        return HTMLResponse(page, headers={'Content-Disposition':'attachment; filename="dns-report.html"'})
    @app.post('/api/import')
    async def import_report(request: Request):
        chunks = bytearray()
        async for chunk in request.stream():
            chunks.extend(chunk)
            if len(chunks) > 16_000_000: raise HTTPException(413, '报告超过 16MB')
        try:
            log = json.loads(chunks)
            if not isinstance(log, dict): raise ValueError()
            # Only reports are accepted; importing never executes tools or commands.
            if not isinstance(log.get('result', log), dict): raise ValueError()
            log = clean(log)
            present(log)
        except (ValueError, TypeError, AttributeError, KeyError, RecursionError): raise HTTPException(400, '无效报告 JSON')
        history_dir.mkdir(parents=True, exist_ok=True)
        key = uuid.uuid4().hex
        (history_dir / (key + '.json')).write_text(json.dumps(log, ensure_ascii=False), encoding='utf-8')
        return {'id': key}
    @app.post('/api/start')
    async def start(data: Start, request: Request):
        try:
            target = parse_target(data.target)
            config = Config.load()
        except ValueError: raise HTTPException(400, '目标或本机配置无效')
        if not config.api_key: raise HTTPException(400, '缺少 DEEPSEEK_API_KEY，请在本机 .env 中配置。')
        owner=request.cookies.get('dns_session')
        if owner not in owners: raise HTTPException(403, '请先打开本机页面')
        if any(j['state'] in ('running','cancelling') for j in jobs.values()): raise HTTPException(409, '已有调查正在进行')
        key = uuid.uuid4().hex
        # Retain completed jobs for reconnects; only prune finished records.
        if len(jobs)>100:
            for old in list(jobs):
                if jobs[old]['state'] not in ('running','cancelling'): jobs.pop(old)
        jobs[key] = dict(state='running', events=[], owner=owner, target=data.target, started_at=datetime.now(timezone.utc).isoformat(), started_clock=time.monotonic())
        async def execute():
            try:
                log, path = await investigate(data.question or data.target, target, config,
                    log_dir=history_dir, target_source='explicit_target',
                    progress=lambda row: jobs[key]['events'].append(clean(row)))
                jobs[key].update(state=log['status'], report_id=path.stem, elapsed_seconds=round(time.monotonic()-jobs[key]['started_clock']))
            except asyncio.CancelledError:
                save_cancelled(key)
            except Exception:
                jobs[key].update(state='failed', error='调查未完成，请检查本机配置与日志。')
        task = asyncio.create_task(execute())
        jobs[key]['task']=task
        tasks.add(task)
        def done(task):
            tasks.discard(task)
            if task.cancelled(): save_cancelled(key)
        task.add_done_callback(done)
        return {'id': key}
    def save_cancelled(key):
        j=jobs[key]
        history_dir.mkdir(parents=True,exist_ok=True)
        report_id=uuid.uuid4().hex
        log=dict(status='cancelled',started_at=j['started_at'],incident={'target':j['target']}, evidence=j['events'],result={'conclusion':'调查由用户取消；仅保留已经取得的证据。','limitations':['取消不代表 DNS 故障；未执行部分仍未知。']})
        (history_dir/(report_id+'.json')).write_text(json.dumps(clean(log),ensure_ascii=False),encoding='utf-8')
        j.update(state='cancelled',report_id=report_id,elapsed_seconds=round(time.monotonic()-j['started_clock']))
    def owned(key, request):
        j=jobs.get(key)
        if not j or request.cookies.get('dns_session') != j['owner']: raise HTTPException(404, '任务不存在或服务已重启')
        return j
    def job_view(j):
        from .web_view import STATES
        return {**{k:v for k,v in j.items() if k not in ('owner','task','started_clock')},'elapsed_seconds':j.get('elapsed_seconds', round(time.monotonic()-j['started_clock'])), 'state_label':STATES.get(j['state'],'状态未记录'), 'call_count':len({e.get('tool_call_id') or e.get('parent_tool_call_id') or e.get('id') for e in j['events']})}
    @app.get('/api/jobs/{key}')
    async def job(key: str, request: Request):
        return job_view(owned(key,request))
    @app.post('/api/jobs/{key}/cancel')
    async def cancel(key: str, request: Request):
        j=owned(key,request)
        if j['state']=='running':
            j['state']='cancelling'
            j['task'].cancel()
        return job_view(j)
    return app

def main():
    import uvicorn
    uvicorn.run(create_app(), host='127.0.0.1', port=8765)

if __name__ == '__main__': main()
