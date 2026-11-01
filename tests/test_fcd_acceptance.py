"""Acceptance regressions across tools, ledger, findings and visible report."""
import copy
import pytest
from evaluation.fcd_acceptance import followed_alias,discovery_refusal,report
from dns_investigator.dns_diagnosis import diagnose


async def test_followed_alias_converges_without_mutating_measurements(tmp_path):
    b=await followed_alias(tmp_path);original=copy.deepcopy(b.calls)
    r=report(b)
    f=next(f for f in r.findings if f.code=="ALIAS_FOLLOWUP_COMPLETED")
    assert f.evidence_ids==["E1","E2"] and f.scope["target"]=="probe.example"
    assert not any(f.code=="ALIAS_RESOLUTION_INCOMPLETE" for f in r.findings)
    assert "target.other" in r.diagnostic_assessment and "NOERROR" in r.diagnostic_assessment
    assert "没有最终地址或否定回答" not in r.diagnostic_assessment
    assert not any("仅沿 probe.example" in x for x in r.recommendations)
    assert b.calls==original and r.measured_facts[0]["result"]=="ALIAS_INCOMPLETE"
    assert r.measured_facts[1]["target"]=="target.other"


@pytest.mark.parametrize("change",["source","type","resolver","role","time","no_time","no_provenance","unrelated_link","timeout"])
async def test_unrelated_or_incomplete_followup_does_not_resolve_original(tmp_path,change):
    b=await followed_alias(tmp_path);leaf=b.calls[-1]
    if change=="source":leaf["source_mode"]="live"
    elif change=="type":leaf["data"]["qtype"]="AAAA"
    elif change=="resolver":leaf["data"]["resolver"]="8.8.8.8"
    elif change=="role":leaf["data"]["resolver_role"]="authoritative"
    elif change=="time":leaf["started_at"]="2099-01-01T00:00:00+00:00"
    elif change=="no_time":leaf.pop("started_at")
    elif change=="no_provenance":leaf.pop("target_authorization")
    elif change=="unrelated_link":leaf["target_authorization"]["links"][0]["name"]="unrelated.example"
    elif change=="timeout":leaf["data"].update(rcode="TIMEOUT",result_kind="TIMEOUT",records=[])
    codes={f["code"] for f in diagnose(b.calls)}
    assert "ALIAS_FOLLOWUP_COMPLETED" not in codes and "ALIAS_RESOLUTION_INCOMPLETE" in codes


@pytest.mark.parametrize("kind",["NXDOMAIN","NODATA"])
async def test_negative_followup_is_scoped_to_alias_target(tmp_path,kind):
    b=await followed_alias(tmp_path);b.calls[-1]["data"].update(rcode="NXDOMAIN" if kind=="NXDOMAIN" else "NOERROR",result_kind=kind,
        records=[],negative_name="target.other",negative_scope="original_name")
    r=report(b)
    f=next(f for f in r.findings if f.code=="ALIAS_FOLLOWUP_COMPLETED")
    assert f.evidence_ids==["E1","E2"]
    assert "target.other" in r.diagnostic_assessment and kind in r.diagnostic_assessment
    negative=next(f for f in r.findings if f.code==kind+"_OBSERVED")
    assert negative.scope["target"]=="target.other" and not f.root_cause_confirmed


async def test_discovery_budget_refusal_survives_all_report_channels():
    b,returned,events=await discovery_refusal();r=report(b)
    assert len(b.attempts)==len(b.dns.attempts)==len(b.calls)==1
    assert returned["error"]["code"]=="PARTIAL_DNS_EXECUTION_ERROR"
    issue=b.attempts[0]["dns_execution_issues"][0]
    assert issue["query_stage"]=="discovery" and issue["qtype"]=="NS"
    assert issue["error"]["code"]=="DNS_BUDGET_EXHAUSTED"
    assert r.execution_issues[0].attempt_id=="A1"
    paths=[p for p in r.dns_comparison["paths"] if p["execution_status"]=="error"]
    assert len(paths)==1 and paths[0]["evidence_id"] is None and paths[0]["query_attempt_id"] is None
    assert paths[0]["query_stage"]=="discovery" and paths[0]["record_type"]=="NS"
    assert "权威发现" in r.diagnostic_assessment and "DNS_BUDGET_EXHAUSTED" in r.diagnostic_assessment
    assert "新的有预算调查" in r.recommendations[0]
    finished=next(e for e in events if e["event"]=="attempt_finished")
    assert finished["error"]["code"]=="PARTIAL_DNS_EXECUTION_ERROR"
    assert returned["data"]["discovery_status"]=="NS_DISCOVERY_FAILED"


async def test_multi_hop_followup_keeps_all_provenance(tmp_path):
    b=await followed_alias(tmp_path)
    b.calls[1]["data"].update(result_kind="ALIAS_INCOMPLETE",records=[],canonical_name="last.other",
        cname_chain=[dict(name="target.other",target="last.other")])
    b.fixture.append(dict(tool="query_dns",match=dict(domain="last.other"),data=dict(rcode="NOERROR",result_kind="NOERROR",
        qtype="A",resolver="192.0.2.53",records=[dict(value="192.0.2.11",ttl=60)])))
    await b.call("query_dns",domain="last.other")
    findings=diagnose(b.calls)
    root=next(f for f in findings if f["code"]=="ALIAS_FOLLOWUP_COMPLETED" and f["scope"]["target"]=="probe.example")
    assert root["evidence_ids"]==["E1","E2","E3"]
    assert not any(f["code"]=="ALIAS_RESOLUTION_INCOMPLETE" for f in findings)


async def test_resolved_sample_does_not_erase_an_unresolved_sample(tmp_path):
    from dns_investigator.tools import now
    b=await followed_alias(tmp_path)
    row=copy.deepcopy(b.calls[0]);row.pop("id");row["tool_call_id"]="A3";row["started_at"]=now()
    row["data"]["cname_chain"]=[dict(name="probe.example",target="unqueried.other")]
    b.save_evidence(row)
    findings=diagnose(b.calls)
    assert next(f for f in findings if f["code"]=="ALIAS_FOLLOWUP_COMPLETED")["evidence_ids"]==["E1","E2"]
    assert next(f for f in findings if f["code"]=="ALIAS_RESOLUTION_INCOMPLETE")["evidence_ids"]==["E3"]


async def test_discovery_wire_error_has_one_Q_linked_issue(monkeypatch):
    import dns.asyncquery,dns.rdatatype
    from evaluation.controlled_dns import controlled
    from dns_investigator.tools import ToolBackend
    from dns_investigator.target import parse_target
    original=dns.asyncquery.udp
    async def wire(q,*args,**kw):
        if q.question[0].rdtype==dns.rdatatype.NS:raise OSError("controlled transport failure")
        return await original(q,*args,**kw)
    monkeypatch.setattr(dns.asyncquery,"udp",wire)
    async with controlled("normal"):
        b=ToolBackend(parse_target("probe.example"))
        await b.call("query_authoritative",domain="probe.example")
    r=report(b)
    failed=[p for p in r.dns_comparison["paths"] if p["execution_status"]=="error"]
    assert len(b.dns.attempts)==2 and len(b.calls)==1 and len(failed)==1
    assert failed[0]["query_attempt_id"]=="Q2" and failed[0]["query_stage"]=="discovery"
    assert failed[0]["error"]["code"]=="DNS_NETWORK_OR_PROTOCOL_ERROR"
