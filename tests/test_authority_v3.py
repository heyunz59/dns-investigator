import asyncio
import dns.asyncquery
import dns.message
import dns.flags
import dns.rrset
import pytest
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target
from dns_investigator.dns_diagnosis import diagnose


async def test_closest_zone_discovery_and_multiple_aa_soa(monkeypatch):
    b=ToolBackend(parse_target("www.dept.example.co.uk"))
    b.dns.system=["1.1.1.1"]
    direct=[]
    async def wire(query,server,**kwargs):
        q=str(query.question[0].name).rstrip(".")
        typ=dns.rdatatype.to_text(query.question[0].rdtype)
        r=dns.message.make_response(query)
        zone="dept.example.co.uk"
        if server=="1.1.1.1":
            if typ=="SOA":
                r.authority.append(dns.rrset.from_text(zone,60,"IN","SOA",f"ns1.example.net hostmaster.example.net 1 60 60 60 60"))
            elif typ=="NS":
                r.answer.append(dns.rrset.from_text(zone,60,"IN","NS","ns1.example.net","ns2.example.net"))
            else:
                r.answer.append(dns.rrset.from_text(q,60,"IN","A","9.9.9.9" if q.startswith("ns1") else "8.8.4.4"))
        else:
            assert not query.flags & dns.flags.RD
            direct.append((q,typ,server))
            r.flags|=dns.flags.AA
            value="192.0.2.10" if typ=="A" else f"ns1.example.net hostmaster.example.net {1 if server=='9.9.9.9' else 2} 60 60 60 60"
            r.answer.append(dns.rrset.from_text(q,60,"IN",typ,value))
        return r
    monkeypatch.setattr(dns.asyncquery,"udp",wire)
    result=await b.call("query_authoritative",domain=b.target.domain)
    assert result["data"]["zone"]=="dept.example.co.uk"
    assert len(direct)==4 and len(b.attempts)==1
    assert any(f["code"]=="AUTH_SERVER_DISAGREEMENT" for f in diagnose(b.calls))
    assert all(q["parent_tool_call_id"]=="A1" for q in b.dns.attempts)


async def test_real_udp_truncation_tcp_and_rd():
    rd=[]
    def reply(data,truncated=False):
        q=dns.message.from_wire(data);rd.append(bool(q.flags & dns.flags.RD))
        r=dns.message.make_response(q);r.flags|=dns.flags.AA
        if truncated:r.flags|=dns.flags.TC
        else:r.answer.append(dns.rrset.from_text("example.com.",60,"IN","A","192.0.2.10"))
        return r.to_wire()
    async def tcp(reader,writer):
        size=int.from_bytes(await reader.readexactly(2),"big")
        data=reply(await reader.readexactly(size))
        writer.write(len(data).to_bytes(2,"big")+data);await writer.drain();writer.close()
    server=await asyncio.start_server(tcp,"127.0.0.1",0)
    port=server.sockets[0].getsockname()[1]
    class UDP(asyncio.DatagramProtocol):
        def connection_made(self,t):self.t=t
        def datagram_received(self,data,addr):self.t.sendto(reply(data,True),addr)
    transport,_=await asyncio.get_running_loop().create_datagram_endpoint(UDP,local_addr=("127.0.0.1",port))
    b=ToolBackend(parse_target("example.com"))
    try:
        r=await b.dns.query("example.com","A","127.0.0.1",parent="integration",role="authoritative",port=port)
        assert r["transport"]=="TCP" and r["flags"]["AA"]
        assert rd==[False,False] and len(b.dns.attempts)==2
        assert [e["data"]["flags"]["TC"] for e in b.calls]==[True,False]
    finally:
        transport.close();server.close();await server.wait_closed()


async def test_parallel_wire_budget_and_cancellation(monkeypatch):
    b=ToolBackend(parse_target("example.com"));b.dns.limit=2
    b.resolvers=("1.1.1.1","8.8.8.8","9.9.9.9")
    count=0
    async def slow(*a,**kw):
        nonlocal count
        count+=1
        await asyncio.sleep(10)
    monkeypatch.setattr(dns.asyncquery,"udp",slow)
    task=asyncio.create_task(b.call("compare_resolvers",domain="example.com"))
    await asyncio.sleep(.02);task.cancel()
    with pytest.raises(asyncio.CancelledError):await task
    assert count==2 and len(b.dns.attempts)==2
    assert all(q["status"]=="cancelled" for q in b.dns.attempts)
    assert not b.calls and b.attempts[0]["status"]=="cancelled"


def test_non_aa_is_not_authoritative_mismatch():
    def e(id,role,code):
        return dict(id=id,execution_status="ok",data=dict(qname="example.com",qtype="A",resolver_role=role,rcode=code,records=[],flags={"AA":False}))
    findings=diagnose([e("E1","recursive","NXDOMAIN"),e("E2","authoritative","NOERROR")])
    assert not any(f["code"]=="RECURSIVE_AUTH_MISMATCH" for f in findings)
