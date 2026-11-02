"""Bounded RD=0 delegation engine. No OS/recursive address resolution."""
import asyncio
import hashlib
import json
import time
from importlib.resources import files
import dns.name
from .dns_wire import WireOptions,dns_outcome


def name(value):return dns.name.from_text(value,origin=dns.name.root).canonicalize()
def text(value):return value.to_text()


def root_hints():
    asset=files("dns_investigator").joinpath("assets")
    raw=asset.joinpath("named.root").read_bytes()
    source=json.loads(asset.joinpath("sources.json").read_text())["named.root"]
    if hashlib.sha256(raw).hexdigest()!=source["sha256"]:raise ValueError("ROOT_HINTS_INTEGRITY_ERROR")
    roots={}
    for line in raw.decode("ascii").splitlines():
        parts=line.split()
        if len(parts)>=4 and parts[-2] in {"A","AAAA"} and not line.lstrip().startswith(";"):
            roots.setdefault(parts[0].lower(),[]).append(parts[-1])
    return [dict(ns=k,addresses=v) for k,v in roots.items()],source


class TraceStopped(Exception):
    def __init__(self,code):self.code=code;super().__init__(code)


class TraceEngine:
    def __init__(self,backend,parent,mode="trace",timeout=3):
        self.backend,self.parent,self.mode=backend,parent,mode
        self.client=backend.dns
        self.timeout=min(timeout,5)
        self.roots,self.hints=root_hints() if getattr(backend,"trace_roots",None) is None else (backend.trace_roots,dict(source="explicit_test_injection"))
        self.steps=[];self.measurements=[];self.responses=[];self.memo={};self.active=set();self.dependencies=0
        self.state=dict(mode=mode,completed=False,stop_reason="IN_PROGRESS",last_successful_zone=None,steps=self.steps,
            zones=[],resolutions=[],cache_hits=[],root_hints=self.hints,discovery=self.measurements,responses=self.responses,
            independence="RD=0; no recursive resolver/getaddrinfo; glue is bootstrap, not cryptographic trust")
        self.attempt=next((a for a in backend.attempts if a["attempt_id"]==parent),None)
        if self.attempt is not None:self.attempt["protocol_state"]=self.state

    async def ask(self,qname,typ,server,zone,stage,**context):
        key=(qname,typ,server,zone,self.mode)
        cached=self.memo.get(key)
        if cached and cached[0]>time.monotonic():
            self.state["cache_hits"].append(dict(evidence_id=cached[1].get("evidence_id"),stage=stage,qname=qname,qtype=typ,server=server))
            self.steps.append(dict(zone=zone,qname=qname,qtype=typ,server=server,stage=stage,evidence_id=cached[1].get("evidence_id"),cache_hit=True,**context))
            return cached[1]
        options=WireOptions(rd=False,do=self.mode=="dnssec",mode=self.mode,stage=stage,zone=zone)
        r=await self.client.request(qname,typ,server,self.parent,options,timeout=self.timeout)
        self.measurements.append(r)
        self.steps.append(dict(zone=zone,qname=qname,qtype=typ,server=server,stage=stage,
            result_kind=dns_outcome(r)["result_kind"],evidence_id=r.get("evidence_id"),query_attempt_ids=r.get("query_attempt_ids",[]),**context))
        if (r.get("error") or {}).get("code") in {"DNS_BUDGET_EXHAUSTED","DNS_REPEAT_LIMIT"}:
            raise TraceStopped(r["error"]["code"])
        if dns_outcome(r)["transport_status"]=="responded" and not r.get("flags",{}).get("TC"):
            ttls=[x["ttl"] for s in ("answer","authority") for x in r.get(s,[])]
            ttl=min(ttls,default=0)
            if ttl>0:self.memo[key]=(time.monotonic()+min(ttl,300),r)
        return r

    def candidates(self,servers):
        result=[]
        for item in servers[:self.backend.max_auth_servers]:
            for ip in item["addresses"][:2]:
                if self.client.deep_endpoint_policy(ip,53):result.append((item["ns"],ip))
        return result

    async def addresses(self,host,depth):
        self.dependencies+=1
        if depth>4 or self.dependencies>16:raise TraceStopped("NS_DEPENDENCY_BUDGET")
        for typ in ("A","AAAA"):
            try:r=await self.resolve(host,typ,depth)
            except TraceStopped as exc:
                self.steps.append(dict(stage="ns-address-dependency",ns=host,stop_reason=exc.code))
                if exc.code in {"DNS_BUDGET_EXHAUSTED","NS_DEPENDENCY_BUDGET","NS_OR_ALIAS_DEPENDENCY_CYCLE"}:raise
                continue
            ips=[v["value"] for v in r.get("records",[]) if self.client.deep_endpoint_policy(v["value"],53)]
            if ips:return ips
        return []

    async def resolve(self,qname,typ,depth=0,aliases=()):
        qname=text(name(qname));identity=(qname,typ)
        if identity in self.active:raise TraceStopped("NS_OR_ALIAS_DEPENDENCY_CYCLE")
        if len(aliases)>8 or qname in aliases:raise TraceStopped("ALIAS_DEPTH_OR_CYCLE")
        self.active.add(identity)
        zone=".";servers=self.roots;visited=set();path=[]
        try:
            for level in range(17):
                if depth==0:self.state["current_zone"]=zone
                if level==16:raise TraceStopped("DELEGATION_DEPTH_LIMIT")
                candidates=self.candidates(servers)
                if not candidates:raise TraceStopped("NO_AUTHORIZED_NS_ADDRESS")
                progressed=False;last_reason="NO_AUTHORITATIVE_RESPONSE"
                for ns,ip in candidates:
                    marker=(zone,ip,qname,typ,depth)
                    if marker in visited:raise TraceStopped("NON_PROGRESSING_REFERRAL_CYCLE")
                    visited.add(marker)
                    r=await self.ask(qname,typ,ip,zone,"trace-query",ns=ns,address_source=[s.get("source") for s in servers if s["ns"]==ns])
                    outcome=dns_outcome(r)
                    if outcome["transport_status"]!="responded" or r.get("flags",{}).get("TC"):
                        last_reason=(r.get("error") or {}).get("code") or outcome["result_kind"] or "NO_RESPONSE";continue
                    if any(rr["type"]=="DNAME" for rr in r.get("answer",[])):raise TraceStopped("UNSUPPORTED_DNAME")
                    chain=r.get("cname_chain",[])
                    if chain and typ!="CNAME":
                        if not r.get("flags",{}).get("AA") or r.get("cname_loop"):last_reason="UNUSABLE_ALIAS";continue
                        if any(not name(edge["name"]).is_subdomain(name(zone)) for edge in chain[:1]):raise TraceStopped("ALIAS_OUTSIDE_AUTHORITY")
                        target=text(name(chain[-1]["target"]))
                        self.steps.append(dict(stage="alias",qname=qname,target=target,evidence_id=r.get("evidence_id"),zone=zone))
                        leaf=await self.resolve(target,typ,depth,aliases+(qname,))
                        return leaf
                    if r.get("flags",{}).get("AA") and outcome["result_kind"] in {"NOERROR","NODATA","NXDOMAIN"}:
                        if depth==0:self.state["last_successful_zone"]=zone
                        self.state["zones"].append(dict(zone=zone,candidates=candidates,answer_evidence_id=r.get("evidence_id")))
                        self.responses.append(r)
                        self.state["resolutions"].append(dict(qname=qname,qtype=typ,zone=zone,server=ip,path=path[:],terminal_evidence_id=r.get("evidence_id")))
                        return r
                    if outcome["dns_rcode"]!="NOERROR":last_reason=outcome["result_kind"];continue
                    refs=[rr for rr in r.get("authority",[]) if rr["type"]=="NS" and name(qname).is_subdomain(name(rr["name"]))
                        and name(rr["name"]).is_subdomain(name(zone)) and name(rr["name"])!=name(zone)]
                    if not refs:
                        last_reason="NON_AUTHORITATIVE_ANSWER" if r.get("answer") else "UNRELATED_OR_NON_PROGRESSING_REFERRAL";continue
                    referral=max(refs,key=lambda x:len(name(x["name"]).labels));child=text(name(referral["name"]))
                    if r.get("flags",{}).get("AA"):last_reason="INCONSISTENT_REFERRAL_AA";continue
                    # A valid parent referral is an observed successful layer,
                    # even if the child NS-address dependency cannot be resolved.
                    if depth==0:self.state["last_successful_zone"]=zone
                    selected=[];dependency_errors=[]
                    for host in referral["values"][:self.backend.max_auth_servers]:
                        host=text(name(host));glue=[]
                        if name(host).is_subdomain(name(child)):
                            for rr in r.get("additional",[]):
                                if name(rr["name"])==name(host) and rr["type"] in {"A","AAAA"}:
                                    for address in rr["values"]:
                                        if self.client.deep_endpoint_policy(address,53):glue.append(address)
                        if glue:source=dict(kind="in_bailiwick_bootstrap_glue",evidence_id=r.get("evidence_id"),cryptographically_trusted=False)
                        else:
                            try:glue=await self.addresses(host,depth+1)
                            except TraceStopped as exc:
                                if exc.code in {"DNS_BUDGET_EXHAUSTED","NS_DEPENDENCY_BUDGET"}:raise
                                dependency_errors.append(exc.code);continue
                            source=dict(kind="independent_NS_address_dependency",cryptographically_trusted=False)
                        if glue:selected.append(dict(ns=host,addresses=glue,source=source))
                    if not selected:last_reason=dependency_errors[-1] if dependency_errors else "NS_ADDRESS_DEPENDENCY_UNRESOLVED";continue
                    cut=dict(zone=zone,child_zone=child,parent_server=ip,qname=qname,qtype=typ,
                        referral_evidence_id=r.get("evidence_id"),selected_ns=selected)
                    self.state["zones"].append(cut);path.append(cut)
                    self.steps.append(dict(stage="delegation",zone=zone,next_zone=child,evidence_id=r.get("evidence_id"),selected_ns=selected))
                    zone,servers=child,selected
                    if depth==0:
                        self.state["last_successful_zone"]=cut["zone"]
                        self.state["last_delegated_zone"]=child
                    progressed=True;break
                if not progressed:raise TraceStopped(last_reason)
        finally:self.active.remove(identity)

    async def run(self,qname,typ):
        try:
            async with asyncio.timeout(self.backend.dns_tool_timeout):
                final=await self.resolve(qname,typ)
                self.state.update(completed=True,stop_reason="AUTHORITATIVE_TERMINAL_ANSWER",terminal_evidence_id=final.get("evidence_id"))
        except TraceStopped as exc:self.state["stop_reason"]=exc.code
        except TimeoutError:self.state["stop_reason"]="TRACE_DEADLINE"
        except asyncio.CancelledError:
            self.state["stop_reason"]="CANCELLED";raise
        return self.state
