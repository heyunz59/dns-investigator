"""Same-evidence report replay; no network and no model calls."""
import argparse,copy,hashlib,json,subprocess
from pathlib import Path
from dns_investigator.schemas import InvestigationResult
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target
from dns_investigator.reporting import evidence_bound_report


def report(row):
    b=ToolBackend(parse_target(row['target']))
    b.calls=copy.deepcopy(row['evidence']);b.attempts=copy.deepcopy(row['attempts'])
    b.validation_results=copy.deepcopy(row.get('validation_results',[]))
    b.request_context=copy.deepcopy(row.get('request_context',{}))
    b.dns.attempts=copy.deepcopy(row.get('dns_attempts',[]))
    r=InvestigationResult(observations=[],hypotheses=[],conclusion='draft',conclusion_evidence_ids=[],limitations=[],recommendations=[])
    return evidence_bound_report(r,b).model_dump()


def capture(out,baseline=None):
    out.mkdir(parents=True,exist_ok=False);rows=[]
    for p in sorted(Path('results/published/v05-diagnostic-upgrade/final-release').glob('*.json')):
        d=json.loads(p.read_text(encoding='utf-8'))
        if 'evidence' not in d:continue
        rows.append(dict(case=p.stem,source_kind='historical_controlled_measurement_replay',
            original_file=p.as_posix(),original_sha256=hashlib.sha256(p.read_bytes()).hexdigest(),
            target=d['evidence'][0]['input'].get('domain') or 'probe.example',
            **{k:d.get(k,[]) for k in ['evidence','attempts','dns_attempts','validation_results']}))
    for intent in ['TCP','HTTP','ambiguous']:
        es=[]
        for tool,data in [('check_tcp',dict(ip='192.0.2.10',port=443,status='REFUSED')),
                          ('check_http',dict(status_code=503,final_url='https://probe.example/',body_complete=True,error=None))]:
            es.append(dict(id=f'E{len(es)+1}',tool_name=tool,input=dict(ip='192.0.2.10',port=443,url='https://probe.example/'),
                data=data,source_mode='synthetic',execution_status='ok',started_at='2026-11-02T00:00:00+00:00'))
        rows.append(dict(case='multi-'+intent,source_kind='constructed_report_input_not_network_measurement',target='probe.example',evidence=es,attempts=[],
            request_context=dict(focus_layers=[{'TCP':'TCP/Network Transport','HTTP':'HTTP'}[intent]] if intent!='ambiguous' else [],
                target='probe.example',url='https://probe.example/',port=443,intent_source='explicit_user_statement' if intent!='ambiguous' else 'unknown',ambiguous=intent=='ambiguous')))
    template=copy.deepcopy(rows[-2])
    for code in [401,403,404,429,500,502,503,504]:
        row=copy.deepcopy(template);row.update(case='http-'+str(code),evidence=row['evidence'][1:],request_context={})
        row['evidence'][0]['data']['status_code']=code;rows.append(row)
    for name,values in [('tcp-timeout',dict(status='TIMEOUT')),('tcp-network-error',dict(status='NETWORK_ERROR'))]:
        row=copy.deepcopy(template);row.update(case=name,evidence=row['evidence'][:1],request_context={})
        row['evidence'][0]['data'].update(values);rows.append(row)
    for code in [10,62,20,None]:
        row=copy.deepcopy(template);row.update(case='tls-'+str(code),evidence=row['evidence'][1:],request_context={})
        row['evidence'][0]['data'].update(status_code=None,error='TLS_ERROR',error_detail=dict(code='CERTIFICATE_VERIFY_FAILED',certificate=dict(verify_code=code)))
        rows.append(row)
    row=copy.deepcopy(template);row.update(case='body-timeout',evidence=row['evidence'][1:],request_context={})
    row['evidence'][0]['data'].update(status_code=200,error='TIMEOUT',body_state='read_error',body_complete=False);rows.append(row)
    row=copy.deepcopy(template);row.update(case='no-evidence',evidence=[],request_context={});rows.append(row)
    import dns.message,dns.rrset
    from dns_investigator.dns_wire import parse_response
    row=copy.deepcopy(template);row.update(case='cdn-record-difference',evidence=[],request_context={})
    for i,address in enumerate(['192.0.2.10','192.0.2.20']):
        e=copy.deepcopy(template['evidence'][0]);e.update(id=f'E{i+1}',tool_name='query_dns',input=dict(domain='probe.example',record_type='A'))
        q=dns.message.make_query('probe.example','A');m=dns.message.make_response(q)
        m.answer.append(dns.rrset.from_text('probe.example.',60,'IN','A',address))
        e['data']=parse_response(m,'probe.example','A',['1.1.1.1','8.8.8.8'][i]);row['evidence'].append(e)
    rows.append(row)
    row=copy.deepcopy(next(r for r in rows if r['case']=='dnssec-ds_mismatch'))
    row.update(case='dnssec-indeterminate',source_kind='constructed_report_input_validation_state_override_on_historical_measurements')
    row.pop('original_file',None);row.pop('original_sha256',None)
    for a in row['attempts']:
        if a.get('protocol_state',{}).get('validation'):
            a['protocol_state']['validation'].update(dnssec_status='INDETERMINATE',reason_code='POLICY_LIMIT',validation_execution='capability_limited')
    rows.append(row)
    row=copy.deepcopy(template);row.update(case='safety-refusal',evidence=[],request_context={},attempts=[dict(attempt_id='A1',tool_name='check_tcp',input=dict(ip='10.0.0.1',port=443),error=dict(code='INVALID_INPUT',reason='TCP_TARGET_ADDRESS_NOT_AUTHORIZED'))]);rows.append(row)
    row=copy.deepcopy(next(r for r in rows if r['case']=='multi-TCP'));row['case']='focused-tcp-normal';row['evidence'][0]['data']['status']='CONNECTED';rows.append(row)
    import dns_investigator.diagnostic_reasoner as runtime
    source_hash=hashlib.sha256(Path(runtime.__file__).read_bytes().replace(b'\r\n',b'\n')).hexdigest()
    if baseline:
        expected=subprocess.check_output(['git','show',baseline+':src/dns_investigator/diagnostic_reasoner.py'])
        assert hashlib.sha256(expected.replace(b'\r\n',b'\n')).hexdigest()==source_hash
    for row in rows:
        row['input_sha256']=hashlib.sha256(json.dumps({k:v for k,v in row.items() if k!='before'},sort_keys=True).encode()).hexdigest()
        row['before']=report(row)
    (out/'before.json').write_text(json.dumps(dict(source_commit=baseline or subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),loaded_reasoner_sha256=source_hash,cases=rows),ensure_ascii=False,indent=2),encoding='utf-8')
    print('Saved before reports:',len(rows))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('output',type=Path);p.add_argument('--baseline');args=p.parse_args();capture(args.output,args.baseline)
