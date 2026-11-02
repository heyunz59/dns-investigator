"""Explicit isolated root/parent/child wire lab; never changes production policy."""
import asyncio
from contextlib import asynccontextmanager
import dns.flags,dns.message,dns.rcode,dns.rrset
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target


class UDP(asyncio.DatagramProtocol):
    def __init__(self,lab,index):self.lab,self.index=lab,index
    def connection_made(self,t):self.transport=t
    def datagram_received(self,wire,peer):
        response=self.lab.answer(self.index,dns.message.from_wire(wire))
        if response is not None and self.lab.scenario=="truncation" and self.index==0:
            response.answer.clear();response.authority.clear();response.additional.clear();response.flags|=dns.flags.TC
        if response is not None:self.transport.sendto(response.to_wire(),peer)


class Lab:
    def __init__(self,scenario):self.scenario=scenario;self.received=[];self.endpoints={};self.transports=[]
    def answer(self,index,q):
        qname=q.question[0].name.to_text();typ=dns.rdatatype.to_text(q.question[0].rdtype)
        self.received.append(dict(index=index,qname=qname,qtype=typ,RD=bool(q.flags&dns.flags.RD),DO=bool(q.ednsflags&dns.flags.DO)))
        if self.scenario in {"timeout","fallback"} and index==2:return None
        r=dns.message.make_response(q)
        def referral(zone,hosts):
            r.authority.append(dns.rrset.from_text(zone,60,"IN","NS",*(h for h,_ in hosts)))
            for host,ip in hosts:
                if ip:r.additional.append(dns.rrset.from_text(host,60,"IN","A",ip))
        if index==0:
            referral("evil.test." if self.scenario=="unrelated" else "test.",[("a.test.","127.0.0.11")])
            r.additional.append(dns.rrset.from_text("unrelated.test.",60,"IN","A","10.0.0.1"))
        elif index==1:
            if qname.endswith("other.test."):referral("other.test.",[("ns.other.test.","127.0.0.13")])
            elif self.scenario=="out_of_bailiwick":referral("example.test.",[("ns.other.test.","10.0.0.1")])
            elif self.scenario=="cycle":referral("example.test.",[("ns.example.test.",None)])
            elif self.scenario=="private_glue":referral("example.test.",[("ns.example.test.","10.0.0.1")])
            elif self.scenario=="fallback":referral("example.test.",[("ns1.example.test.","127.0.0.12"),("ns2.example.test.","127.0.0.14")])
            else:referral("example.test.",[("ns.example.test.","127.0.0.12")])
        elif index==3:
            r.flags|=dns.flags.AA
            if typ=="A":r.answer.append(dns.rrset.from_text(qname,60,"IN","A","127.0.0.12" if qname=="ns.other.test." else "192.0.2.10"))
        else:
            if self.scenario!="non_aa":r.flags|=dns.flags.AA
            if self.scenario=="dname":r.answer.append(dns.rrset.from_text("example.test.",60,"IN","DNAME","other.test."))
            elif self.scenario=="cname" and qname=="probe.example.test.":r.answer.append(dns.rrset.from_text(qname,60,"IN","CNAME","target.other.test."))
            elif typ=="A":r.answer.append(dns.rrset.from_text(qname,60,"IN","A","192.0.2.10"))
        return r


@asynccontextmanager
async def protocol_lab(scenario="normal"):
    lab=Lab(scenario)
    tcp_servers=[]
    for index in range(5):
        host=f"127.0.0.{index+10}"
        t,_=await asyncio.get_running_loop().create_datagram_endpoint(lambda i=index:UDP(lab,i),local_addr=(host,0))
        lab.transports.append(t);lab.endpoints[host]=t.get_extra_info("sockname")[1]
        async def tcp(reader,writer,i=index):
            try:
                size=int.from_bytes(await reader.readexactly(2),"big")
                q=dns.message.from_wire(await reader.readexactly(size));r=lab.answer(i,q)
                if r is not None:
                    wire=r.to_wire();writer.write(len(wire).to_bytes(2,"big")+wire);await writer.drain()
            finally:writer.close();await writer.wait_closed()
        tcp_servers.append(await asyncio.start_server(tcp,host,lab.endpoints[host]))
    def backend():
        b=ToolBackend(parse_target("probe.example.test"));b.trace_roots=[dict(ns="a.root.test.",addresses=["127.0.0.10"])]
        b.dns.deep_endpoint_policy=lambda ip,port:port==53 and ip in lab.endpoints
        packet=b.dns.packet
        async def routed(name,typ,server,role,timeout,parent,tcp=False,port=53):
            if server not in lab.endpoints:raise AssertionError("unexpected network endpoint")
            return await packet(name,typ,server,role,timeout,parent,tcp=tcp,port=lab.endpoints[server])
        b.dns.packet=routed
        return b
    lab.backend=backend
    try:yield lab
    finally:
        for t in lab.transports:t.close()
        for s in tcp_servers:s.close();await s.wait_closed()
