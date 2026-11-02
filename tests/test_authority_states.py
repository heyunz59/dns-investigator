import pytest
from evaluation.controlled_dns import controlled
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target
from evaluation.fcd_acceptance import report


@pytest.mark.parametrize("scenario,status",[("soa_timeout","SOA_DISCOVERY_TIMEOUT"),("ns_timeout","NS_DISCOVERY_TIMEOUT"),
    ("ns_empty","NO_USABLE_NS"),("ns_refused","NS_DISCOVERY_FAILED"),("ns_servfail","NS_DISCOVERY_FAILED"),
    ("address_failed","NS_ADDRESS_RESOLUTION_FAILED"),("non_aa","NO_AUTHORITATIVE_RESPONSE"),
    ("partial_auth","PARTIAL_AUTHORITATIVE_DISCOVERY"),("auth_timeout","NO_AUTHORITATIVE_RESPONSE"),
    ("normal","AUTHORITATIVE_QUERY_COMPLETED")])
async def test_controlled_discovery_stage_states(scenario,status):
    async with controlled(scenario):
        b=ToolBackend(parse_target("probe.example"))
        returned=await b.call("query_authoritative",domain="probe.example")
    d=returned["data"];p=d["progress"]
    assert d["discovery_status"]==status and d["completed"]==(scenario=="normal")
    assert len(b.dns.attempts)==len(b.calls) and len(b.attempts)==1
    assert {q["query_attempt_id"] for q in b.dns.attempts}=={e["query_attempt_id"] for e in b.calls}
    r=report(b)
    assert r.authority_investigations[0]["discovery_status"]==status
    if scenario!="normal":assert status in r.diagnostic_assessment and "尚未完成" in r.diagnostic_assessment
    if scenario.startswith("ns_"):
        assert p["zone_found"] and not p["ns_found"] and p["target_queries_executed"]==0
    if scenario=="non_aa":assert p["target_responses_received"]==2 and p["authoritative_answers"]==0
    if scenario=="partial_auth":assert p["authoritative_answers"]==1 and p["ns_selected"]==2
    if scenario=="normal":assert p["authoritative_answers"]==p["target_queries_executed"]==2


@pytest.mark.parametrize("budget",[1,2,3])
async def test_budget_interruption_never_claims_authority_completed(budget):
    async with controlled("normal"):
        b=ToolBackend(parse_target("probe.example"));b.dns.limit=budget
        r=await b.call("query_authoritative",domain="probe.example")
    assert len(b.dns.attempts)==budget and len(b.calls)==budget
    assert not r["data"]["completed"] and b.attempts[0]["error"]["code"]=="PARTIAL_DNS_EXECUTION_ERROR"
    assert any(i["error"]["code"]=="DNS_BUDGET_EXHAUSTED" for i in b.attempts[0]["dns_execution_issues"])


async def test_cancel_preserves_last_completed_stage_and_owned_measurement():
    import asyncio
    async with controlled("normal"):
        b=ToolBackend(parse_target("probe.example"));entered=asyncio.Event();release=asyncio.Event();query=b.dns.query
        async def block(name,typ="A",*args,**kw):
            if typ=="NS":entered.set();await release.wait()
            return await query(name,typ,*args,**kw)
        b.dns.query=block
        task=asyncio.create_task(b.call("query_authoritative",domain="probe.example"))
        await entered.wait();task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
    a=b.attempts[0]
    assert a["status"]=="cancelled" and a["authority_state"]["progress"]["zone_found"]
    assert a["authority_state"]["progress"]["stage"]=="NS_DISCOVERY" and not a["authority_state"]["completed"]
    assert len(b.calls)==len(b.dns.attempts)==1 and b.calls[0]["tool_call_id"]=="A1"
