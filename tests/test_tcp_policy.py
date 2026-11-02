import asyncio,ipaddress,json
from datetime import datetime,timezone,timedelta
from pathlib import Path
import pytest
from dns_investigator.tools import ToolBackend,InputRejected
from dns_investigator.config import Config
from dns_investigator.target import parse_target
from dns_investigator.network_policy import networks
from dns_investigator.http_safety import HTTPPolicy,HTTPRefused
from tcp_support import authorize

BLOCKED=['127.0.0.1','10.0.0.1','192.168.1.1','169.254.169.254','::1','::ffff:10.0.0.1','fe80::1','224.0.0.1','0.0.0.0','ff02::1','::','2002:0808:0808::1','2001:0:4136:e378:8000:63bf:3fff:fdd2','64:ff9b::a00:1','100.100.100.200','fd00:ec2::254']

@pytest.mark.parametrize('ip',BLOCKED)
async def test_dns_never_grants_network_access(ip,monkeypatch):
    b=authorize(ToolBackend(parse_target('example.com')),ip);b.tcp_networks=()
    import dns_investigator.tools as module
    def forbidden(*a,**kw):raise AssertionError('socket must not be created')
    # Patch only after fixture construction; no real connection to restricted IPs.
    with monkeypatch.context() as m:
        m.setattr(module.socket,'socket',forbidden)
        r=await b.call('check_tcp',ip=ip,port=443)
        assert r['error']['reason']=='TCP_TARGET_ADDRESS_NOT_AUTHORIZED'
        assert len(b.attempts)==1 and len(b.calls)==1 and not b.dns.attempts
        with pytest.raises(InputRejected):await b.check_tcp(ip,443)
        again=await b.call('check_tcp',ip=ip,port=443)
        assert again['error']['code']=='NON_RETRYABLE_DUPLICATE'

@pytest.mark.parametrize('ip',['1.1.1.1','2606:4700:4700::1111','10.0.0.1','2606:4700:4700:0:0:0:0:1111','2606:4700:4700::ABCD'])
async def test_authorized_numeric_connection(ip,monkeypatch):
    b=authorize(ToolBackend(parse_target('example.com')),ip)
    seen=[]
    async def connect(sock,address):seen.append(address)
    monkeypatch.setattr(asyncio.get_running_loop(),'sock_connect',connect)
    r=await b.call('check_tcp',ip=ip,port=443)
    assert r['data']['status']=='CONNECTED' and ipaddress.ip_address(seen[0][0])==ipaddress.ip_address(ip)
    assert len(b.calls)==2 and b.calls[-1]['tool_call_id']=='A1' and len(b.attempts)==1

@pytest.mark.parametrize('mutation',['unknown','stale','synthetic','bad_rcode','truncated','unrelated','no_rrset','bad_port'])
async def test_evidence_and_port_cannot_be_bypassed(mutation,monkeypatch):
    b=authorize(ToolBackend(parse_target('example.com')),'1.1.1.1');e=b.calls[0];ip='1.1.1.1';port=443
    if mutation=='unknown':ip='8.8.8.8'
    if mutation=='stale':e['started_at']=(datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
    if mutation=='synthetic':e['source_mode']='synthetic'
    if mutation=='bad_rcode':e['data']['dns_rcode']='NXDOMAIN'
    if mutation=='truncated':e['data']['flags']['TC']=True
    if mutation=='unrelated':e['data']['qname']='ns.other.test'
    if mutation=='no_rrset':e['data']['answer']=[]
    if mutation=='bad_port':port=22
    r=await b.call('check_tcp',ip=ip,port=port)
    assert r['error']['code']=='INVALID_INPUT' and len(b.calls)==1 and not b.dns.attempts

def test_separate_cidrs_and_configuration(monkeypatch):
    with pytest.raises(ValueError):Config('test',tcp_allowed_networks=('not-cidr',))
    monkeypatch.setenv('TCP_ALLOWED_NETWORKS','10.1.0.0/16,fd01::/64')
    assert Config.load().tcp_allowed_networks==('10.1.0.0/16','fd01::/64')
    b=ToolBackend(parse_target('example.com'),tcp_allowed_networks=('10.1.0.0/16',))
    assert b._tcp_address('10.1.2.3')=='10.1.2.3'
    with pytest.raises(InputRejected):b._tcp_address('10.2.2.3')
    b.http_policy=HTTPPolicy(b.target.url,allowed_networks=('10.0.0.0/8',))
    with pytest.raises(InputRejected):b._tcp_address('10.2.2.3')
    with pytest.raises(HTTPRefused):HTTPPolicy(b.target.url).address('10.1.2.3')
    for ip in ['169.254.169.254','fd00:ec2::254','64:ff9b::a00:1']:
        b.tcp_networks=networks(('0.0.0.0/0','::/0'))
        with pytest.raises(InputRejected):b._tcp_address(ip)

async def test_fixture_cannot_enter_direct_live_socket(monkeypatch):
    b=ToolBackend(parse_target('example.com'),Path('data/fixtures/Q1.json'))
    await b.call('query_dns',domain=b.target.domain)
    def forbidden(*a,**k):raise AssertionError('fixture must never create a socket')
    import dns_investigator.tools as module
    with monkeypatch.context() as m:
        m.setattr(module.socket,'socket',forbidden)
        r=await b.call('check_tcp',ip='192.0.2.10',port=443)
        assert r['source_mode']=='fixture'
        with pytest.raises(InputRejected):await b.check_tcp('192.0.2.10',443)

async def test_current_cname_authorizes_address_but_stale_chain_does_not(monkeypatch):
    import dns.message,dns.rrset
    from dns_investigator.dns_wire import parse_response
    b=ToolBackend(parse_target('example.com'))
    q=dns.message.make_query('example.com','A');r=dns.message.make_response(q)
    r.answer.append(dns.rrset.from_text('example.com.',60,'IN','CNAME','alias.example.'))
    first=b.add_dns_evidence(parse_response(r,'example.com','A','1.1.1.1'),'TEST_DNS')
    q=dns.message.make_query('alias.example','A');r=dns.message.make_response(q)
    r.answer.append(dns.rrset.from_text('alias.example.',60,'IN','A','1.1.1.1'))
    b.add_dns_evidence(parse_response(r,'alias.example','A','1.1.1.1'),'TEST_DNS')
    async def connect(*a):pass
    monkeypatch.setattr(asyncio.get_running_loop(),'sock_connect',connect)
    assert (await b.call('check_tcp',ip='1.1.1.1',port=443))['data']['status']=='CONNECTED'
    first['started_at']=(datetime.now(timezone.utc)-timedelta(days=1)).isoformat()
    assert (await b.call('check_tcp',ip='1.1.1.1',port=443))['error']['code']=='INVALID_INPUT'

async def test_tools_only_loads_tcp_config_without_model_key(monkeypatch):
    from types import SimpleNamespace
    from dns_investigator import main
    seen=[]
    def factory(*args,**kwargs):
        seen.append(kwargs);b=ToolBackend(*args,**kwargs)
        async def call(*a,**kw):return {}
        b.call=call;return b
    monkeypatch.setenv('TCP_ALLOWED_NETWORKS','10.1.0.0/16')
    monkeypatch.setattr(main,'ToolBackend',factory)
    result=await main.run(SimpleNamespace(question='example.com',target=None,tools_only=True,fixture=None,save_tools=None))
    assert result==0 and seen[0]['tcp_allowed_networks']==('10.1.0.0/16',)

async def test_security_refusal_is_execution_issue_not_tcp_measurement():
    from evaluation.fcd_acceptance import report
    b=authorize(ToolBackend(parse_target('example.com')),'10.0.0.1');b.tcp_networks=()
    r=await b.call('check_tcp',ip='10.0.0.1',port=443)
    output=report(b)
    assert r['error']['reason']=='TCP_TARGET_ADDRESS_NOT_AUTHORIZED'
    assert {f['tool'] for f in output.measured_facts}=={'query_dns'}
    assert output.execution_issues[0].error_code=='INVALID_INPUT'
    assert all(e['tool_name']!='check_tcp' for e in b.calls)
