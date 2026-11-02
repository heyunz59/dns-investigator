import socket
import pytest
from evaluation.protocol_lab import protocol_lab
from evaluation.fcd_acceptance import report
from dns_investigator.agent_summary import current_state


@pytest.mark.parametrize("scenario,completed",[("normal",True),("out_of_bailiwick",True),("fallback",True),("cname",True),("truncation",True),("unrelated",False),("cycle",False),("private_glue",False),("non_aa",False),("timeout",False),("dname",False)])
async def test_independent_wire_trace_and_boundaries(monkeypatch,scenario,completed):
    async with protocol_lab(scenario) as lab:
        b=lab.backend()
        def forbidden(*a,**kw):raise AssertionError("OS name resolution is forbidden in trace")
        monkeypatch.setattr(socket,"getaddrinfo",forbidden)
        returned=await b.call("query_authoritative",domain=b.target.domain,mode="trace",timeout=.1)
    state=returned["data"]
    assert state["mode"]=="trace" and state["completed"] is completed
    assert all(not q["RD"] for q in lab.received)
    assert len(b.dns.attempts)==len(b.calls) and len(b.attempts)==1
    assert all(q["parent_tool_call_id"]=="A1" for q in b.dns.attempts)
    assert current_state(b,returned)["protocol_investigations"][0]["stop_reason"]==state["stop_reason"]
    assert "trace" in report(b).diagnostic_assessment
    if scenario=="out_of_bailiwick":assert any(q["qname"]=="ns.other.test." and q["index"]==3 for q in lab.received)
    if scenario=="unrelated":assert {q["index"] for q in lab.received}=={0}
    if scenario=="cycle":assert state["stop_reason"]=="NS_OR_ALIAS_DEPENDENCY_CYCLE"
    if scenario=="truncation":assert [q["transport"] for q in b.dns.attempts][:2]==["UDP","TCP"]
    if scenario=="cname":assert any(q["qname"]=="target.other.test." for q in lab.received)
    if scenario=="timeout":assert state["last_successful_zone"]=="test." and state["last_delegated_zone"]=="example.test."
    if completed:
        assert state["terminal_evidence_id"] in {e["id"] for e in b.calls}
        b._validate("check_tcp",dict(ip="192.0.2.10",port=443))
        # Internal NS addresses do not authorize TCP probes, even in the same ledger.
        denied=await b.call("check_tcp",ip="127.0.0.11",port=443)
        assert denied["error"]["code"]=="INVALID_INPUT"


async def test_trace_budget_preserves_last_level_without_phantom_evidence():
    async with protocol_lab() as lab:
        b=lab.backend();b.dns.limit=2
        r=await b.call("query_authoritative",domain=b.target.domain,mode="trace")
    assert not r["data"]["completed"] and r["data"]["stop_reason"]=="DNS_BUDGET_EXHAUSTED"
    assert len(b.dns.attempts)==len(b.calls)==2 and len(b.attempts)==1
    assert b.attempts[0]["error"]["code"]=="PARTIAL_DNS_EXECUTION_ERROR"


async def test_unimplemented_mode_cannot_silently_execute_basic():
    async with protocol_lab() as lab:
        b=lab.backend();r=await b.call("query_authoritative",domain=b.target.domain,mode="dnssec")
    assert r["error"]["code"]=="MODE_NOT_IMPLEMENTED" and not b.calls and not b.dns.attempts
