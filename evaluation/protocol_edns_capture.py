"""Real loopback DNS EDE observations; no model/public targets."""
import argparse,asyncio,json,hashlib,subprocess
from pathlib import Path
import dns.message,dns.edns,dns.rrset,dns.rcode
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target
from evaluation.fcd_acceptance import report


class Server(asyncio.DatagramProtocol):
    def __init__(self,kind):self.kind=kind
    def connection_made(self,t):self.transport=t
    def datagram_received(self,wire,peer):
        q=dns.message.from_wire(wire);r=dns.message.make_response(q)
        r.use_edns(0,payload=1232,options=[] if self.kind=="no_ede" else [dns.edns.GenericOption(15,b"\x01")] if self.kind=="malformed" else [dns.edns.EDEOption(6,"untrusted reported DNSSEC error")])
        if self.kind=="servfail":r.set_rcode(dns.rcode.SERVFAIL)
        else:r.answer.append(dns.rrset.from_text("example.com",60,"IN","A","192.0.2.10"))
        self.transport.sendto(r.to_wire(),peer)


async def capture(out):
    if out.exists():raise FileExistsError("Preserve snapshots")
    rows=[]
    for kind in ("noerror","servfail","no_ede","malformed"):
        t,_=await asyncio.get_running_loop().create_datagram_endpoint(lambda:Server(kind),local_addr=("127.0.0.1",0))
        b=ToolBackend(parse_target("example.com"));b.dns.system=["127.0.0.1"];packet=b.dns.packet
        async def routed(*a,**kw):kw["port"]=t.get_extra_info("sockname")[1];return await packet(*a,**kw)
        b.dns.packet=routed
        try:returned=await b.call("query_dns",domain="example.com")
        finally:t.close()
        rows.append(dict(case=kind,mode="controlled_loopback_DNS_no_model",attempts=b.attempts,dns_attempts=b.dns.attempts,evidence=b.calls,returned=returned,report=report(b).model_dump()))
    out.write_text(json.dumps(dict(source_ref=subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip(),
        source_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path("src/dns_investigator").glob("*.py")},
        public_network=False,model_invoked=False,runs=rows),ensure_ascii=False,indent=2),encoding="utf-8")
    print("saved controlled DNS cases:",len(rows))


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("out",type=Path);asyncio.run(capture(p.parse_args().out))
