"""DNSSEC collection via TraceEngine plus a hard-terminable validation process."""
import asyncio,json,multiprocessing,time
import dns.name,dns.rdatatype
from .trace import TraceEngine,TraceStopped
from .trust import anchors
from .dnssec_validation import worker,POLICY_VERSION


def cohosted_signer_hint(data,zone,qname,typ):
    """Untrusted descendant hint only. DS validation must establish the cut.

    An AA answer can come from a child zone cohosted at the reached parent's
    endpoint, without a referral. A signer string alone is never trusted.
    """
    names=set();base=dns.name.from_text(zone);q=dns.name.from_text(qname,origin=dns.name.root)
    for section in ("answer","authority"):
        for rr in data.get(section,[]):
            if rr["type"]!="RRSIG":continue
            owner=dns.name.from_text(rr["name"],origin=dns.name.root)
            for value in rr["values"]:
                parts=value.split()
                if len(parts)<9:continue
                if not ((section=="answer" and owner==q and parts[0]==typ) or (section=="authority" and parts[0]=="SOA" and q.is_subdomain(owner))):continue
                signer=dns.name.from_text(parts[7],origin=dns.name.root).canonicalize()
                if q.is_subdomain(signer) and signer.is_subdomain(base):names.add(signer)
    if base in names:return None
    if len(names)>1:raise ValueError("AMBIGUOUS_UNTRUSTED_SIGNER_ZONES")
    return next(iter(names)).to_text() if names else None


async def isolated_validate(bundle,seconds=4):
    if len(json.dumps(bundle).encode())>2_000_000:
        return dict(validation_execution="resource_limited",dnssec_status="INDETERMINATE",reason_code="VALIDATION_INPUT_LIMIT",results=[])
    context=multiprocessing.get_context("spawn")
    reader,writer=context.Pipe(duplex=False)
    process=context.Process(target=worker,args=(bundle,writer),daemon=True)
    process.start();writer.close();deadline=time.monotonic()+seconds
    try:
        while time.monotonic()<deadline:
            if await asyncio.to_thread(reader.poll,.05):
                try:return await asyncio.to_thread(reader.recv)
                except EOFError:break
            if not process.is_alive():break
        return dict(validation_execution="resource_limited",dnssec_status="INDETERMINATE",reason_code="VALIDATION_PROCESS_TIMEOUT_OR_EXIT",results=[])
    finally:
        if process.is_alive():process.terminate()
        await asyncio.to_thread(process.join,1)
        if process.is_alive():process.kill();await asyncio.to_thread(process.join,1)
        reader.close();process.close()


def publish(backend,parent,result):
    if not hasattr(backend,"validation_results"):backend.validation_results=[]
    mapping={row["id"]:f"V{len(backend.validation_results)+index+1}" for index,row in enumerate(result.get("results",[]))}
    known={e["id"] for e in backend.owned_evidence(parent)}
    for row in result.get("results",[]):
        if set(row["evidence_ids"])-known or set(row.get("validation_result_ids",[]))-mapping.keys():
            raise ValueError("VALIDATION_REFERENCES_UNKNOWN_OR_FOREIGN_SOURCE")
    if set(result.get("validation_result_ids",[]))-mapping.keys():raise ValueError("VALIDATION_REFERENCES_UNKNOWN_RESULT")
    for row in result.pop("results",[]):
        row={**row,"id":mapping[row["id"]],"parent_tool_call_id":parent,
            "validation_result_ids":[mapping[v] for v in row.get("validation_result_ids",[])]}
        backend.validation_results.append(row);backend.emit("validation_result",row)
    result["validation_result_ids"]=[mapping[v] for v in result.get("validation_result_ids",[])]
    result.setdefault("algorithm_policy",POLICY_VERSION)
    return result


async def investigate_dnssec(backend,parent,qname,typ,timeout):
    engine=TraceEngine(backend,parent,"dnssec",timeout)
    state=engine.state
    def incomplete(reason,execution="incomplete"):
        state.setdefault("trace_completed",bool(state["completed"]))
        state["completed"]=False
        state["validation"]=dict(validation_execution=execution,dnssec_status="INDETERMINATE",reason_code=reason,
            algorithm_policy=POLICY_VERSION,validation_scope=dict(qname=qname,qtype=typ),validation_result_ids=[])
        return state
    try:
        anchor=getattr(backend,"dnssec_test_anchor",None) or anchors()
    except (ValueError,OSError,KeyError):return incomplete("TRUST_ANCHOR_UNAVAILABLE_OR_STALE")
    if anchor["zone"]!=".":return incomplete("NON_ROOT_ANCHOR_NOT_SUPPORTED","capability_limited")
    await engine.run(qname,typ)
    state["trace_completed"]=state["completed"]
    if not state["completed"]:return incomplete(state["stop_reason"])
    if any(s.get("stage")=="alias" for s in state["steps"]):return incomplete("DNSSEC_ALIAS_CHAIN_NOT_SUPPORTED","capability_limited")
    path=next((p for p in state["resolutions"] if p["terminal_evidence_id"]==state["terminal_evidence_id"]),None)
    if path is None:return incomplete("TRACE_PATH_UNAVAILABLE")
    validation_time=time.time();chain=[]
    try:
        root_server=path["path"][0]["parent_server"] if path["path"] else path["server"]
        root=await engine.ask(".","DNSKEY",root_server,".","dnssec-root-key")
        for index,cut in enumerate(path["path"]):
            child=cut["child_zone"]
            ds=await engine.ask(child,"DS",cut["parent_server"],cut["zone"],"dnssec-parent-ds")
            child_server=path["path"][index+1]["parent_server"] if index+1<len(path["path"]) else path["server"]
            key=await engine.ask(child,"DNSKEY",child_server,child,"dnssec-child-key")
            chain.append(dict(parent_zone=cut["zone"],child_zone=child,ds_eid=ds.get("evidence_id"),dnskey_eid=key.get("evidence_id")))
        terminal=next(e["data"] for e in backend.owned_evidence(parent) if e["id"]==state["terminal_evidence_id"])
        try:hint=cohosted_signer_hint(terminal,path["zone"],qname,typ)
        except ValueError:return incomplete("AMBIGUOUS_UNTRUSTED_SIGNER_ZONES","capability_limited")
        if hint:
            state["cohosted_zone_hint"]=dict(zone=hint,parent_zone=path["zone"],source_evidence_id=state["terminal_evidence_id"],trusted=False)
            ds=await engine.ask(hint,"DS",path["server"],path["zone"],"dnssec-cohosted-parent-ds")
            key=await engine.ask(hint,"DNSKEY",path["server"],hint,"dnssec-cohosted-child-key")
            chain.append(dict(parent_zone=path["zone"],child_zone=hint,ds_eid=ds.get("evidence_id"),dnskey_eid=key.get("evidence_id"),cut_source="untrusted_signer_hint"))
    except TraceStopped as exc:return incomplete(exc.code,"resource_limited")
    bundle=dict(qname=qname,qtype=typ,validation_time=validation_time,anchor=anchor,
        root_dnskey_eid=root.get("evidence_id"),chain=chain,terminal_eid=state["terminal_evidence_id"],
        terminal_query_zone=path["zone"],
        evidence=[dict(id=e["id"],source_mode=e["source_mode"],data=e["data"]) for e in backend.owned_evidence(parent)])
    state["validation"]=dict(validation_execution="running",dnssec_status="INDETERMINATE",reason_code="VALIDATION_RUNNING")
    try:result=await isolated_validate(bundle)
    except asyncio.CancelledError:
        incomplete("VALIDATION_CANCELLED");raise
    state["validation"]=publish(backend,parent,result)
    if state.get("cohosted_zone_hint"):
        hint=state["cohosted_zone_hint"]
        hint["authenticated_parent_ds_result_ids"]=[v["id"] for v in backend.validation_results
            if v["parent_tool_call_id"]==parent and v["kind"]=="rrset_signature" and v["local_result"]=="SIGNATURE_CHECK_PASSED"
            and v.get("scope",{}).get("qtype")=="DS" and v.get("scope",{}).get("owner")==hint["zone"]]
    state["completed"]=state["validation"].get("validation_execution")=="completed"
    return state
