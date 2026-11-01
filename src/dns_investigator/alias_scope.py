"""Evidence-derived DNS-only authorization. Not DNSSEC trust or general target expansion."""
from .target import domain
from .dns_wire import dns_outcome

MAX_ALIAS_DEPTH=8
MAX_ALIAS_TARGETS=8


def alias_paths(backend):
    origin=backend.target.domain
    mode="fixture" if backend.fixture is not None else "live"
    allowed={origin:dict(target=origin,depth=0,links=[],evidence_ids=[])}
    # A later evidence row can extend a previously observed chain; order-independent.
    for _ in range(MAX_ALIAS_DEPTH):
        changed=False
        for e in backend.calls:
            if e.get("execution_status")!="ok" or e.get("source_mode")!=mode or e.get("tool_name")!="query_dns":continue
            r=e["data"]
            if dns_outcome(r)["transport_status"]!="responded" or r.get("flags",{}).get("TC") or r.get("cname_loop"):continue
            try:
                name=domain(r.get("qname",""));chain=r.get("cname_chain",[])
                if name not in allowed:continue
                base=allowed[name];current=name;seen={origin}|{link["target"] for link in base["links"]}
                pending=[]
                for link in chain:
                    if domain(link["name"])!=current:break  # ignore unrelated names
                    target=domain(link["target"])
                    if target in seen:
                        pending=[];break  # do not grant a loop's intermediate targets
                    seen.add(target)
                    depth=base["depth"]+len(pending)+1
                    if depth>MAX_ALIAS_DEPTH:break
                    pending.append(dict(name=current,target=target,evidence_id=e["id"]))
                    current=target
                for i,link in enumerate(pending):
                    target=link["target"]
                    if target in allowed:continue
                    if len(allowed)-1>=MAX_ALIAS_TARGETS:break
                    links=base["links"]+pending[:i+1]
                    allowed[target]=dict(target=target,depth=len(links),links=links,
                        evidence_ids=list(dict.fromkeys(x["evidence_id"] for x in links)),source_mode=mode,
                        warning="观测链路，不代表 DNSSEC 验证")
                    changed=True
            except (ValueError,KeyError,TypeError,UnicodeError):continue
        if not changed:break
    return allowed


def already_resolved(backend,name,typ):
    mode="fixture" if backend.fixture is not None else "live"
    for e in backend.calls:
        r=e.get("data",{})
        if e.get("source_mode")!=mode or e.get("execution_status")!="ok" or e.get("tool_name")!="query_dns":continue
        if (r.get("canonical_name","").lower().rstrip(".")==name and r.get("qtype")==typ
                and dns_outcome(r)["result_kind"]=="NOERROR" and r.get("records")
                and not r.get("flags",{}).get("TC")):
            return e["id"]
    return None
