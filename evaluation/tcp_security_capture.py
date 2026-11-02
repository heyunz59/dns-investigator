"""Actual before/after backend calls with injected DNS and intercepted connects."""
import asyncio,csv,hashlib,json,socket,subprocess,sys,types
from pathlib import Path
from unittest.mock import patch
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target
from dns_investigator.http_safety import HTTPPolicy
from dns_investigator.network_policy import networks

sys.path.insert(0,str(Path('tests').resolve()))
from tcp_support import authorize

BLOCKED=['127.0.0.1','10.0.0.1','192.168.1.1','169.254.169.254','::1','::ffff:10.0.0.1','fe80::1','224.0.0.1','0.0.0.0','ff02::1','::','2002:0808:0808::1','2001:0:4136:e378:8000:63bf:3fff:fdd2','64:ff9b::a00:1','100.100.100.200','fd00:ec2::254']
async def run(out):
    out.mkdir(parents=True,exist_ok=True)
    raw=subprocess.check_output(['git','show','2bacd75:src/dns_investigator/tools.py'])
    module=types.ModuleType('dns_investigator._pre_tcp_audit');module.__package__='dns_investigator'
    exec(compile(raw,'pre_tcp_tools.py','exec'),module.__dict__)
    cases=[(ip,False,'normal') for ip in BLOCKED]+[('1.1.1.1',False,'normal'),('2606:4700:4700::ABCD',False,'normal'),('10.1.2.3',True,'normal'),('10.2.2.3',True,'other_private'),('1.1.1.1',False,'no_evidence'),('1.1.1.1',False,'bad_port'),('10.1.2.3',False,'http_only'),('10.1.2.3',False,'resolver_only'),('1.1.1.1',False,'refused'),('1.1.1.1',False,'timeout')]
    result=[];details=[];original_socket=socket.socket
    for stage,cls in [('before',module.ToolBackend),('after',ToolBackend)]:
        for ip,cidr,kind in cases:
            b=authorize(cls(parse_target('example.com')),ip);b.tcp_networks=networks(('10.1.0.0/16',)) if cidr else ()
            if kind=='no_evidence':b.calls=[]
            if kind=='http_only':b.http_policy=HTTPPolicy(b.target.url,allowed_networks=('10.1.0.0/16',))
            if kind=='resolver_only':b.dns.system=[ip]
            created=[];connected=[]
            def factory(*a,**k):created.append(True);return original_socket(*a,**k)
            async def connect(sock,address):
                connected.append(address)
                if kind=='refused':raise ConnectionRefusedError()
                if kind=='timeout':raise TimeoutError()
            port=22 if kind=='bad_port' else 443
            with patch.object(socket,'socket',factory),patch.object(asyncio.get_running_loop(),'sock_connect',connect):
                r=await b.call('check_tcp',ip=ip,port=port)
            error=r.get('error') or {}
            row=dict(stage=stage,ip=ip,ip_type=kind,dns_evidence_valid=kind!='no_evidence',cidr_authorized=cidr and kind!='other_private',port_authorized=port!=22,
                expected_behavior='DENIED' if ip in BLOCKED and not cidr or kind in {'no_evidence','bad_port','other_private','http_only','resolver_only'} else 'CONNECT_PATH',
                actual_behavior=(r.get('data') or {}).get('status') or 'DENIED',socket_created=len(created),connection_calls=len(connected),
                A=len(b.attempts),Q=len(b.dns.attempts),E_delta=len(b.calls)-(0 if kind=='no_evidence' else 1),error_code=error.get('code'),reason=error.get('reason'),mode='injected current DNS; actual socket allocation intercepted numeric connect, never actual private network')
            result.append(row);details.append(dict(matrix=row,returned=r,attempts=b.attempts,evidence=b.calls))
    with (out/'tcp-security-matrix.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(result[0]));w.writeheader();w.writerows(result)
    (out/'tcp-security-details.json').write_text(json.dumps(details,indent=2),encoding='utf-8')
    assert all(r['connection_calls']==0 and r['socket_created']==0 for r in result if r['stage']=='after' and r['expected_behavior']=='DENIED')
    print('TCP matrix',len(result),'rows; restricted after sockets/connections: zero',flush=True)

if __name__=='__main__':asyncio.run(run(Path(sys.argv[1])))
