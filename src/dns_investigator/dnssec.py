"""DNSSEC collection via TraceEngine plus a hard-terminable validation process."""
import asyncio,json,multiprocessing,time
from .trace import TraceEngine,TraceStopped
from .trust import anchors
from .dnssec_validation import worker,POLICY_VERSION


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
    except TraceStopped as exc:return incomplete(exc.code,"resource_limited")
    bundle=dict(qname=qname,qtype=typ,validation_time=validation_time,anchor=anchor,
        root_dnskey_eid=root.get("evidence_id"),chain=chain,terminal_eid=state["terminal_evidence_id"],
        evidence=[dict(id=e["id"],source_mode=e["source_mode"],data=e["data"]) for e in backend.owned_evidence(parent)])
    state["validation"]=dict(validation_execution="running",dnssec_status="INDETERMINATE",reason_code="VALIDATION_RUNNING")
    try:result=await isolated_validate(bundle)
    except asyncio.CancelledError:
        incomplete("VALIDATION_CANCELLED");raise
    state["validation"]=publish(backend,parent,result)
    state["completed"]=state["validation"].get("validation_execution")=="completed"
    return state
