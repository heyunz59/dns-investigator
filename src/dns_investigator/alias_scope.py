"""Evidence-derived DNS-only authorization. Not DNSSEC trust or general target expansion."""
from .target import domain
from .dns_wire import dns_outcome
from .dns_wire import comparable_response
from datetime import datetime
from .dns_compare import normal,MAX_COMPARISON_SECONDS

MAX_ALIAS_DEPTH=8
MAX_ALIAS_TARGETS=8


def completed_followups(rows):
    """Link later terminal observations to original aliases; never rewrite packets.

    Reconciliation requires explicit, validated provenance, the same source/path/type
    and a bounded timestamp gap. A different path remains a separate observation.
    """
    known={r["evidence_id"]:r for r in rows}
    completed={}
    def same_path(a,b):
        return (a.get("resolver") is not None and a.get("source_mode") in {"live","fixture","synthetic"}
            and (a.get("resolver"),a.get("resolver_role","recursive"),a.get("source_mode"))==
                (b.get("resolver"),b.get("resolver_role","recursive"),b.get("source_mode")))
    def near_after(a,b):
        try:
            delta=(datetime.fromisoformat(b["measured_at"])-datetime.fromisoformat(a["measured_at"])).total_seconds()
            return 0<=delta<=MAX_COMPARISON_SECONDS
        except (KeyError,ValueError,TypeError):return False
    for origin in rows:
        if origin.get("result_kind") not in {"REFERRAL","ALIAS_INCOMPLETE","INDETERMINATE"} or not origin.get("cname_chain") or origin.get("cname_loop"):continue
        for leaf in rows:
            kind=dns_outcome(leaf)["result_kind"]
            if not comparable_response(leaf) or kind not in {"NOERROR","NODATA","NXDOMAIN"}:continue
            if kind=="NOERROR" and not leaf.get("records"):continue
            if leaf.get("qtype")!=origin.get("qtype") or not same_path(origin,leaf) or not near_after(origin,leaf):continue
            authorization=leaf.get("target_authorization") or {}
            links=authorization.get("links",[])
            if (origin["evidence_id"] not in authorization.get("evidence_ids",[]) or len(links)>MAX_ALIAS_DEPTH
                    or authorization.get("source_mode")!=origin.get("source_mode")
                    or normal(authorization.get("target"))!=normal(leaf.get("qname"))):continue
            start=next((i for i,link in enumerate(links) if link.get("evidence_id")==origin["evidence_id"] and normal(link.get("name"))==normal(origin["qname"])),None)
            if start is None:continue
            current=normal(origin["qname"]);seen={current};proof=[origin["evidence_id"]]
            valid=True
            for link in links[start:]:
                parent=known.get(link.get("evidence_id"));target=normal(link.get("target"))
                if (parent is None or normal(link.get("name"))!=current or not target or target in seen
                        or not same_path(origin,parent) or not near_after(origin,parent) or not near_after(parent,leaf)
                        or dns_outcome(parent)["transport_status"]!="responded" or parent.get("flags",{}).get("TC")
                        or not any(isinstance(edge,dict) and normal(edge.get("name"))==current and normal(edge.get("target"))==target for edge in parent.get("cname_chain",[]))):
                    valid=False;break
                seen.add(target);current=target;proof.append(parent["evidence_id"])
            if valid and current==normal(leaf.get("qname")):
                completed.setdefault(origin["evidence_id"],[]).append(list(dict.fromkeys(proof+[leaf["evidence_id"]])))
    return completed


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
