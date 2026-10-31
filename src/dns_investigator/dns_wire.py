"""Bounded DNS wire operations. Each UDP/TCP exchange has its own Q attempt."""
import asyncio
import ipaddress
import time
import dns.asyncquery
import dns.flags
import dns.message
import dns.rcode
import dns.resolver
import dns.exception

TYPES = {"A", "AAAA", "CNAME", "NS", "SOA"}


def parse_response(message, qname, qtype, server, role="recursive", transport="UDP"):
    def section(rrsets):
        return [dict(name=str(rr.name).rstrip("."), type=dns.rdatatype.to_text(rr.rdtype), ttl=rr.ttl,
                     values=[x.to_text() for x in rr]) for rr in rrsets]
    answer, authority = section(message.answer), section(message.authority)
    records = [dict(value=v, ttl=rr["ttl"]) for rr in answer if rr["type"] == qtype for v in rr["values"]]
    chain = [dict(name=rr["name"], target=v.rstrip("."), ttl=rr["ttl"]) for rr in answer if rr["type"] == "CNAME" for v in rr["values"]]
    seen, loop = set(), False
    for link in chain:
        if link["name"] in seen or link["target"] in seen or link["target"] == qname:
            loop = True
        seen.add(link["name"])
    rcode = dns.rcode.to_text(message.rcode())
    flags = {name: bool(message.flags & getattr(dns.flags, name)) for name in ("AA", "RD", "RA", "TC")}
    referral = not flags["AA"] and not answer and any(r["type"] == "NS" for r in authority)
    return dict(qname=qname, qtype=qtype, record_type=qtype, resolver=server,
        responding_resolver=server, resolver_role=role, rcode=rcode,
        result_kind="TRUNCATED" if flags["TC"] else "REFERRAL" if referral else "NODATA" if rcode == "NOERROR" and not records else rcode,
        flags=flags, answer=answer, authority=authority, additional=section(message.additional),
        records=records, cname_chain=chain, canonical_name=chain[-1]["target"] if chain else qname,
        cname_loop=loop, transport=transport, execution_status="ok", error=None,
        soa_serials=[int(v.split()[2]) for rr in answer+authority if rr["type"] == "SOA" for v in rr["values"]])


class DNSClient:
    def __init__(self, backend, limit=32):
        self.backend, self.limit = backend, limit
        self.attempts = []
        self.repeats = {}
        self.system = [str(s) for s in dns.resolver.Resolver().nameservers]

    def permitted(self, ip, authoritative=False):
        address = ipaddress.ip_address(ip)
        return address.is_global if authoritative else address.is_global or ip in self.system

    async def packet(self, name, typ, server, role, timeout, parent, tcp=False, port=53):
        key=(name.lower().rstrip("."),typ,server,role,tcp)
        if self.repeats.get(key,0)>=2:
            return dict(execution_status="error",error={"code":"DNS_REPEAT_LIMIT","retryable":False},qname=name,qtype=typ)
        if len(self.attempts) >= self.limit:
            return dict(execution_status="error", error={"code":"DNS_BUDGET_EXHAUSTED", "retryable":False}, qname=name,qtype=typ)
        self.repeats[key]=self.repeats.get(key,0)+1
        row = dict(query_attempt_id=f"Q{len(self.attempts)+1}", parent_tool_call_id=parent,
                   qname=name,qtype=typ,server=server,port=port,transport="TCP" if tcp else "UDP",status="running")
        self.attempts.append(row)
        start=time.monotonic()
        message=dns.message.make_query(name,typ)
        if role == "authoritative":
            message.flags &= ~dns.flags.RD
        try:
            response = await (dns.asyncquery.tcp if tcp else dns.asyncquery.udp)(message,server,timeout=timeout,port=port)
            data=parse_response(response,name,typ,server,role,row["transport"])
            row["status"]="measured"
        except (dns.exception.Timeout, TimeoutError):
            data=dict(qname=name,qtype=typ,record_type=typ,resolver=server,resolver_role=role,
                      rcode="TIMEOUT",result_kind="TIMEOUT",records=[],execution_status="ok",error=None,transport=row["transport"])
            row["status"]="measured"
        except asyncio.CancelledError:
            row["status"]="cancelled"
            raise
        except Exception:
            row["status"]="execution_error"
            data=dict(qname=name,qtype=typ,resolver=server,resolver_role=role,execution_status="error",
                      error={"code":"DNS_NETWORK_OR_PROTOCOL_ERROR","retryable":False},records=[])
        finally:
            row["duration_ms"]=round((time.monotonic()-start)*1000,2)
            self.backend.emit("dns_attempt",row)
        data["duration_ms"]=row["duration_ms"]
        if data["execution_status"] == "ok":
            evidence=self.backend.add_dns_evidence(data,parent,row["query_attempt_id"])
            row["evidence_id"]=evidence["id"]
            data={**data,"evidence_id":evidence["id"]}
        return data

    async def query(self,name,typ="A",resolver=None,timeout=5,parent=None,role="recursive",port=53):
        servers=[resolver] if resolver else self.system[:2]
        start=time.monotonic()
        history=[]
        last=dict(execution_status="error",error={"code":"NO_RESOLVER_CONFIGURED","retryable":False})
        for server in servers:
            remaining=timeout-(time.monotonic()-start)
            if remaining <= 0:
                break
            last=await self.packet(name,typ,server,role,remaining/max(1,len(servers)),parent,port=port)
            history.append(last.get("evidence_id"))
            if last.get("flags",{}).get("TC"):
                remaining=timeout-(time.monotonic()-start)
                if remaining > 0:
                    last=await self.packet(name,typ,server,role,remaining,parent,tcp=True,port=port)
                    history.append(last.get("evidence_id"))
            if last.get("rcode") not in (None,"TIMEOUT","SERVFAIL","REFUSED"):
                break
        return {**last,"resolvers":servers,"system_resolver_configuration":self.system if resolver is None else None,"query_evidence_ids":[e for e in history if e]}
