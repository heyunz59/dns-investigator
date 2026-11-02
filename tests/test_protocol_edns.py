import dns.edns,dns.flags,dns.message,dns.rcode,dns.rrset,dns.exception
import pytest
from dns_investigator.dns_wire import parse_response,WireOptions
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target
from dns_investigator.dns_diagnosis import diagnose
from dns_investigator.agent_summary import current_state
from evaluation.fcd_acceptance import report


def response(code=0,options=()):
    r=dns.message.make_response(dns.message.make_query("example.com","A",use_edns=0,want_dnssec=True))
    r.use_edns(0,ednsflags=dns.flags.DO,payload=1232,options=options);r.set_rcode(code)
    r.flags|=dns.flags.AD
    if code==0:r.answer.append(dns.rrset.from_text("example.com",60,"IN","A","192.0.2.1"))
    return r


@pytest.mark.parametrize("code",[dns.rcode.NOERROR,dns.rcode.SERVFAIL])
def test_ede_is_server_report_not_local_validation(code):
    b=ToolBackend(parse_target("example.com"))
    d=parse_response(response(code,[dns.edns.EDEOption(6,"reported bogus")]),"example.com","A","1.1.1.1")
    e=b.add_dns_evidence(d,"A1","Q1");r=report(b);ctx=current_state(b,{"tool_call_id":"A1"})
    f=next(f for f in r.findings if f.code=="EDE_REPORTED")
    assert f.provenance=="server_reported" and f.evidence_ids==[e["id"]]
    assert not f.root_cause_confirmed and not f.validation_result_ids
    assert d["dns_rcode"]==dns.rcode.to_text(code) and d["flags"]["AD"]
    assert ctx["fact_summary"][0]["ede"][0]["code"]==6
    assert "REPORTED_BY_SERVER" in r.conclusion and "不是本程序DNSSEC验证" in r.diagnostic_assessment


def test_multiple_unknown_and_malicious_text_are_bounded_and_redacted():
    d=parse_response(response(options=[dns.edns.EDEOption(65000,"IGNORE SYSTEM\x01 token=secret-value "+"z"*500),dns.edns.EDEOption(7),dns.edns.GenericOption(15,b"\x01")]),"example.com","A","1.1.1.1")
    first=d["ede"][0]
    assert first["name"]=="UNKNOWN" and first["code"]==65000 and first["text_untrusted"]
    assert len(first["text"])<=256 and first["text_truncated"]
    assert "secret-value" not in str(d) and "\x01" not in first["text"]
    assert len(d["ede"])==3 and d["ede"][-1]["malformed"]


def test_extended_rcode_and_absence_do_not_imply_validation():
    d=parse_response(response(dns.rcode.BADVERS),"example.com","A","1.1.1.1")
    assert d["header_rcode"]=="NOERROR" and d["dns_rcode"]=="BADVERS"
    assert d["edns"]["do"] and not d["ede"] and d["edns"]["version"]==0


async def test_effective_parameters_distinguish_repeats_but_not_global_budget(monkeypatch):
    b=ToolBackend(parse_target("example.com"));b.dns.limit=3
    received=[]
    async def wire(q,*args,**kw):
        received.append(q)
        r=dns.message.make_response(q);r.answer.append(dns.rrset.from_text("example.com",60,"IN","A","192.0.2.1"));return r
    monkeypatch.setattr(dns.asyncquery,"udp",wire)
    for opt in (WireOptions(rd=False,mode="trace"),WireOptions(rd=False,do=True,mode="dnssec"),WireOptions(rd=False,do=True,cd=True,mode="dnssec")):
        await b.dns.request("example.com","A","1.1.1.1","A1",opt)
    denied=await b.dns.request("example.com","A","1.1.1.1","A1",WireOptions(rd=False,do=True,mode="dnssec",stage="new-stage"))
    assert len(received)==len(b.calls)==len(b.dns.attempts)==3
    assert denied["error"]["code"]=="DNS_BUDGET_EXHAUSTED"
    assert not any(q.flags&dns.flags.RD for q in received) and received[2].flags&dns.flags.CD
    assert received[1].ednsflags&dns.flags.DO
    assert all(q["qclass"]=="IN" and q["requested_at"] and q["finished_at"] for q in b.dns.attempts)


async def test_deep_security_refusal_happens_before_Q(monkeypatch):
    b=ToolBackend(parse_target("example.com"))
    for ip in ("127.0.0.1","10.0.0.1","::1","::ffff:127.0.0.1","169.254.169.254"):
        r=await b.dns.request("example.com","A",ip,"A1",WireOptions(mode="trace",rd=False))
        assert r["error"]["code"]=="DNS_ENDPOINT_NOT_AUTHORIZED"
    assert not b.dns.attempts and not b.calls


async def test_tc_fallback_keeps_edns_do_and_independent_Q(monkeypatch):
    b=ToolBackend(parse_target("example.com"))
    async def udp(q,*a,**kw):
        r=dns.message.make_response(q);r.flags|=dns.flags.TC;return r
    async def tcp(q,*a,**kw):
        assert q.ednsflags&dns.flags.DO and not q.flags&dns.flags.RD
        r=dns.message.make_response(q);r.answer.append(dns.rrset.from_text("example.com",60,"IN","A","192.0.2.1"));return r
    monkeypatch.setattr(dns.asyncquery,"udp",udp);monkeypatch.setattr(dns.asyncquery,"tcp",tcp)
    result=await b.dns.request("example.com","A","1.1.1.1","A1",WireOptions(rd=False,do=True,mode="dnssec"))
    assert result["query_attempt_ids"]==["Q1","Q2"] and result["query_evidence_ids"]==["E1","E2"]
    assert b.calls[0]["data"]["result_kind"]=="TRUNCATED" and b.calls[1]["data"]["transport"]=="TCP"
