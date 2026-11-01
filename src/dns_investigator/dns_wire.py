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

INCOMPLETE_KINDS = {"REFERRAL", "ALIAS_INCOMPLETE", "TRUNCATED", "INDETERMINATE"}


def dns_outcome(row):
    """Non-mutating legacy adapter; timeout never invents a received RCODE."""
    raw=row.get("rcode")
    status=row.get("transport_status")
    if status is None:
        status="timeout" if raw=="TIMEOUT" or row.get("result_kind")=="TIMEOUT" else "network_error" if row.get("execution_status")=="error" else "responded" if raw is not None else "unknown"
    rcode=row.get("dns_rcode",raw if status=="responded" and raw!="TIMEOUT" else None)
    return dict(transport_status=status,dns_rcode=rcode,
                result_kind=row.get("result_kind", "TIMEOUT" if status=="timeout" else rcode))


def comparable_response(row):
    # Old facts without a classification are usable for their explicit RCODE/records,
    # but must not be promoted to a newly established NODATA result.
    if row.get("rcode")=="NOERROR" and not row.get("records") and row.get("result_kind")!="NODATA":
        return False
    state=dns_outcome(row)
    return (state["transport_status"]=="responded" and state["dns_rcode"] is not None
        and row.get("execution_status","ok")=="ok"
        and state["result_kind"] not in INCOMPLETE_KINDS and not row.get("flags",{}).get("TC"))


def classify_response(qname, qtype, rcode, flags, answer, authority):
    """RFC 2308 2.1/2.2: terminal name, relevant RRsets and negative authority."""
    def normal(name):
        return dns.name.from_text(name,origin=dns.name.root).canonicalize()
    original=normal(qname)
    current=original
    links={}
    for rr in answer:
        if rr["type"]=="CNAME":
            links.setdefault(normal(rr["name"]),set()).update(normal(v) for v in rr["values"])
    chain=[]
    seen=set()
    invalid=False
    while current in links:
        if current in seen or len(links[current])!=1:
            invalid=True
            break
        seen.add(current)
        target=next(iter(links[current]))
        ttl=next(rr["ttl"] for rr in answer if rr["type"]=="CNAME" and normal(rr["name"])==current)
        chain.append(dict(name=str(current).rstrip("."),target=str(target).rstrip("."),ttl=ttl))
        current=target
    terminal=original if qtype=="CNAME" else current
    records=[dict(value=v,ttl=rr["ttl"]) for rr in answer
             if rr["type"]==qtype and normal(rr["name"])==terminal for v in rr["values"]]
    soa=[rr for rr in authority if rr["type"]=="SOA"]
    ns=[rr for rr in authority if rr["type"]=="NS"]
    relevant_soa=[rr for rr in soa if terminal.is_subdomain(normal(rr["name"]))]
    relevant_ns=[rr for rr in ns if terminal.is_subdomain(normal(rr["name"]))]
    if flags["TC"]:
        kind="TRUNCATED"
    elif invalid:
        kind="INDETERMINATE"
    elif rcode=="NXDOMAIN":
        kind="INDETERMINATE" if records else "NXDOMAIN"
    elif rcode!="NOERROR":
        kind=rcode
    elif records:
        kind="NOERROR"
    elif relevant_soa:
        # SOA (even together with NS) is a negative result for the terminal name.
        kind="NODATA"
    elif soa:
        kind="INDETERMINATE"  # unrelated SOA cannot prove terminal-name absence
    elif relevant_ns:
        # AA may cover the alias's zone, not the chain target. Do not require AA=0.
        kind="REFERRAL"
    elif ns:
        kind="INDETERMINATE"
    elif chain and qtype!="CNAME":
        # RFC 2308 2.2.1 warns that broken servers can omit a terminal NXDOMAIN.
        kind="ALIAS_INCOMPLETE"
    elif answer:
        kind="INDETERMINATE"  # unrelated answer RRsets, no terminal proof
    else:
        kind="NODATA"  # RFC 2308 type 3: no relevant answers and no NS
    negative=kind in {"NODATA","NXDOMAIN"}
    return dict(records=records,result_kind=kind,cname_loop=invalid,cname_chain=chain,
        canonical_name=str(current).rstrip("."),
        negative_name=str(terminal).rstrip(".") if negative else None,
        negative_scope=("original_name" if terminal==original else "cname_target") if negative else None,
        resolution_complete=kind not in INCOMPLETE_KINDS)


def parse_response(message, qname, qtype, server, role="recursive", transport="UDP"):
    def section(rrsets):
        return [dict(name=str(rr.name).rstrip("."), type=dns.rdatatype.to_text(rr.rdtype), ttl=rr.ttl,
                     values=[x.to_text() for x in rr]) for rr in rrsets]
    answer, authority = section(message.answer), section(message.authority)
    rcode = dns.rcode.to_text(message.rcode())
    flags = {name: bool(message.flags & getattr(dns.flags, name)) for name in ("AA", "RD", "RA", "TC")}
    classification=classify_response(qname,qtype,rcode,flags,answer,authority)
    return dict(qname=qname, qtype=qtype, record_type=qtype, resolver=server,
        responding_resolver=server, resolver_role=role, rcode=rcode,dns_rcode=rcode,transport_status="responded",
        flags=flags, answer=answer, authority=authority, additional=section(message.additional),
        transport=transport, execution_status="ok", error=None,
        **classification,
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
                      rcode=None,dns_rcode=None,transport_status="timeout",result_kind="TIMEOUT",records=[],execution_status="ok",error=None,transport=row["transport"])
            row["status"]="measured"
        except asyncio.CancelledError:
            row["status"]="cancelled"
            raise
        except Exception:
            row["status"]="execution_error"
            data=dict(qname=name,qtype=typ,resolver=server,resolver_role=role,execution_status="error",
                      dns_rcode=None,rcode=None,transport_status="network_error",result_kind="EXECUTION_ERROR",
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
            if dns_outcome(last)["result_kind"] not in (None,"TIMEOUT","SERVFAIL","REFUSED","EXECUTION_ERROR"):
                break
        return {**last,"resolvers":servers,"system_resolver_configuration":self.system if resolver is None else None,"query_evidence_ids":[e for e in history if e]}
