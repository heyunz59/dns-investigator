"""Test-only loopback DNS services. Injection does not relax production permissions.

These servers synthesize responses, not complete recursive caches or DNSSEC validators.
No scoring expectations or injected cause is passed to the Agent.
"""
import asyncio
from contextlib import asynccontextmanager
from unittest.mock import patch
import dns.flags
import dns.message
import dns.rcode
import dns.rrset
from dns_investigator.dns_wire import DNSClient
from dns_investigator.tools import ToolBackend


class Server(asyncio.DatagramProtocol):
    def __init__(self,index,scenario):self.index,self.scenario=index,scenario
    def connection_made(self,transport):self.transport=transport
    def datagram_received(self,data,addr):
        q=dns.message.from_wire(data);name=str(q.question[0].name).rstrip(".")
        typ=dns.rdatatype.to_text(q.question[0].rdtype)
        if self.scenario=="timeout" and self.index==0 and name=="probe.example" and typ=="A":return
        r=dns.message.make_response(q)
        if self.index>=3:r.flags|=dns.flags.AA
        else:r.flags|=dns.flags.RA
        if self.scenario=="mismatch" and self.index<3 and name=="probe.example" and typ=="A":
            r.set_rcode(dns.rcode.NXDOMAIN)
            r.authority.append(dns.rrset.from_text("probe.example.",60,"IN","SOA","ns1.test.example. host.test.example. 1 60 60 60 60"))
        elif typ=="SOA":
            serial=2 if self.scenario=="serial" and self.index==4 else 1
            r.answer.append(dns.rrset.from_text("probe.example.",60,"IN","SOA",f"ns1.test.example. host.test.example. {serial} 60 60 60 60"))
        elif typ=="NS":
            r.answer.append(dns.rrset.from_text(name+".",60,"IN","NS","ns1.test.example.","ns2.test.example."))
        elif typ=="A":
            value="9.9.9.9" if name=="ns1.test.example" else "8.8.4.4" if name=="ns2.test.example" else "192.0.2.11" if self.scenario=="serial" and self.index==4 else "192.0.2.10"
            r.answer.append(dns.rrset.from_text(name+".",60,"IN","A",value))
        self.transport.sendto(r.to_wire(),addr)


@asynccontextmanager
async def controlled(scenario):
    transports=[];endpoints={}
    original_query=DNSClient.query;original_call=ToolBackend.call
    for index,identity in enumerate((None,"1.1.1.1","8.8.8.8","9.9.9.9","8.8.4.4")):
        host=f"127.0.0.{index+1}"
        t,_=await asyncio.get_running_loop().create_datagram_endpoint(lambda i=index:Server(i,scenario),local_addr=(host,0))
        transports.append(t);endpoints[identity]=(host,t.get_extra_info("sockname")[1])
    async def query(client,name,typ="A",resolver=None,timeout=5,parent=None,role="recursive",port=53):
        if resolver not in endpoints:
            return dict(qname=name,qtype=typ,execution_status="error",error=dict(code="CONTROLLED_PATH_NOT_PROVIDED",retryable=False))
        host,port=endpoints[resolver]
        return await original_query(client,name,typ,host,min(timeout,.3),parent,role,port)
    async def call(backend,name,provider_id=None,**args):
        if name not in {"query_dns","compare_resolvers","query_authoritative"}:
            attempt=next((a for a in backend.attempts if provider_id and a.get("provider_call_id")==provider_id and a["status"]=="pending"),None)
            return backend.reject(attempt or backend.register(name,args,provider_id),"CONTROLLED_NON_DNS_DISABLED","本次受控实验只提供 DNS 网络路径。")
        return await original_call(backend,name,provider_id=provider_id,**args)
    try:
        with patch.object(DNSClient,"query",query),patch.object(ToolBackend,"call",call):
            yield dict(scenario=scenario,endpoints=[dict(configured_identity=k,host=v[0],port=v[1]) for k,v in endpoints.items()],
                timeout_seconds=.3,network_scope="loopback_only",limitation="Synthetic DNS wire server; no full recursive cache/delegation/DNSSEC behavior")
    finally:
        for t in transports:t.close()


async def measured_scenario(scenario):
    from dns_investigator.target import parse_target
    from dns_investigator.dns_diagnosis import diagnose
    async with controlled(scenario) as environment:
        backend=ToolBackend(parse_target("probe.example"))
        await backend.call("compare_resolvers",domain="probe.example")
        if scenario in {"mismatch","serial"}:await backend.call("query_authoritative",domain="probe.example")
        return dict(mode="controlled_loopback_dns_no_model",environment=environment,attempts=backend.attempts,
            dns_attempts=backend.dns.attempts,evidence=backend.calls,findings=diagnose(backend.calls))
