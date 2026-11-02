"""Bounded recursive-assisted authority discovery with explicit stage completion."""
import asyncio
from .dns_compare import compare
from .dns_wire import dns_outcome,comparable_response,ATTEMPT_OBSERVER


def usable_answer(row):
    return (comparable_response(row) and row.get("flags",{}).get("AA",False)
            and dns_outcome(row)["result_kind"] in {"NOERROR","NODATA","NXDOMAIN"})


async def investigate_authority(backend,name,typ,timeout,parent):
    client=backend.dns;discovery=[];answers=[];zone=None;servers=[]
    progress=dict(zone_found=False,ns_found=False,ns_total=0,ns_selected=0,addressed_servers=0,
        target_queries_executed=0,target_responses_received=0,authoritative_answers=0,servers=servers)
    state=dict(discovery_status="IN_PROGRESS",completed=False,zone=None,progress=progress)
    attempt=next((a for a in backend.attempts if a["attempt_id"]==parent),None)
    if attempt is not None:attempt["authority_state"]=state
    def finish(status):
        state.update(discovery_status=status,completed=status=="AUTHORITATIVE_QUERY_COMPLETED",zone=zone)
        return dict(zone=zone,discovery=discovery,responses=answers,discovery_status=status,
            completed=status=="AUTHORITATIVE_QUERY_COMPLETED",progress=progress,
            differences=compare([r for r in answers if r.get("qtype")==typ]),
            limitation="Recursive-assisted discovery; bounded selected NS subset, not complete iterative or DNSSEC validation.")
    async with asyncio.timeout(backend.dns_tool_timeout):
        labels=name.split(".")
        for index in range(min(len(labels),8)):
            candidate=".".join(labels[index:])
            progress["stage"]="SOA_DISCOVERY"
            result=await client.query(candidate,"SOA",timeout=timeout,parent=parent)
            discovery.append(result)
            if dns_outcome(result)["transport_status"]=="timeout":return finish("SOA_DISCOVERY_TIMEOUT")
            if result.get("execution_status")=="error":return finish("SOA_DISCOVERY_FAILED")
            if dns_outcome(result)["dns_rcode"] not in {"NOERROR","NXDOMAIN"}:return finish("SOA_DISCOVERY_FAILED")
            soa=[r for r in result.get("answer",[])+result.get("authority",[]) if r["type"]=="SOA"]
            owners=[r["name"] for r in soa if name==r["name"] or name.endswith("."+r["name"])]
            if owners:
                zone=max(owners,key=len);progress["zone_found"]=True;break
        if not zone:return finish("ZONE_UNKNOWN")
        state["zone"]=zone;progress["stage"]="NS_DISCOVERY"
        ns=await client.query(zone,"NS",timeout=timeout,parent=parent);discovery.append(ns)
        if dns_outcome(ns)["transport_status"]=="timeout":return finish("NS_DISCOVERY_TIMEOUT")
        if ns.get("execution_status")=="error" or dns_outcome(ns)["dns_rcode"]!="NOERROR":return finish("NS_DISCOVERY_FAILED")
        hosts=list(dict.fromkeys(r["value"].rstrip(".") for r in ns.get("records",[])))
        progress.update(ns_found=bool(hosts),ns_total=len(hosts),ns_selected=min(len(hosts),backend.max_auth_servers))
        if not hosts:return finish("NO_USABLE_NS")
        for host in hosts[:backend.max_auth_servers]:
            server=dict(ns_name=host,address_found=False,query_executed=False,response_received=False,aa=False,target_complete=False,soa_complete=typ=="SOA")
            servers.append(server)
            progress["stage"]="NS_ADDRESS_RESOLUTION"
            addresses=await client.query(host,"A",timeout=timeout,parent=parent);discovery.append(addresses)
            if not addresses.get("records") and (addresses.get("error") or {}).get("code")!="DNS_BUDGET_EXHAUSTED":
                addresses=await client.query(host,"AAAA",timeout=timeout,parent=parent);discovery.append(addresses)
            ips=[]
            for record in addresses.get("records",[]):
                try:
                    if client.permitted(record["value"],authoritative=True):ips.append(record["value"])
                except ValueError:pass
            if not ips:
                server["status"]="NS_ADDRESS_RESOLUTION_FAILED"
                if (addresses.get("error") or {}).get("code")=="DNS_BUDGET_EXHAUSTED":break
                continue
            ip=ips[0];server.update(address_found=True,ip=ip);progress["addressed_servers"]+=1
            progress["stage"]="AUTHORITATIVE_TARGET_QUERY"
            server["query_attempt_ids"]=[]
            def allocated(query):
                if query["parent_tool_call_id"]!=parent:return
                server["query_attempt_ids"].append(query["query_attempt_id"])
                if not server["query_executed"]:
                    server["query_executed"]=True;progress["target_queries_executed"]+=1
            token=ATTEMPT_OBSERVER.set(allocated)
            try:response=await client.query(name,typ,ip,timeout,parent,role="authoritative")
            finally:ATTEMPT_OBSERVER.reset(token)
            response["ns_name"]=host;answers.append(response)
            server.update(response_received=dns_outcome(response)["transport_status"]=="responded",
                aa=response.get("flags",{}).get("AA",False),target_complete=usable_answer(response),target_evidence_id=response.get("evidence_id"),
                status="ANSWERED" if usable_answer(response) else "NO_AUTHORITATIVE_RESPONSE")
            progress["target_responses_received"]+=server["response_received"]
            progress["authoritative_answers"]+=server["target_complete"]
            if (response.get("error") or {}).get("code")=="DNS_BUDGET_EXHAUSTED":break
            if typ!="SOA":
                progress["stage"]="AUTHORITATIVE_SOA_QUERY"
                soa=await client.query(zone,"SOA",ip,timeout,parent,role="authoritative")
                soa["ns_name"]=host;answers.append(soa);server["soa_complete"]=usable_answer(soa)
                if (soa.get("error") or {}).get("code")=="DNS_BUDGET_EXHAUSTED":break
        all_complete=(len(servers)==progress["ns_selected"] and all(s["target_complete"] and s["soa_complete"] for s in servers))
        if all_complete:return finish("AUTHORITATIVE_QUERY_COMPLETED")
        if progress["authoritative_answers"]:return finish("PARTIAL_AUTHORITATIVE_DISCOVERY")
        if not progress["addressed_servers"]:return finish("NS_ADDRESS_RESOLUTION_FAILED")
        return finish("NO_AUTHORITATIVE_RESPONSE")
