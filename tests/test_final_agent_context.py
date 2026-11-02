import copy
import pytest
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target
from dns_investigator.agent_summary import current_state
from evaluation.accuracy_cases import evidence
from evaluation.controlled_dns import controlled
from evaluation.fcd_acceptance import report


async def test_logical_test_identities_do_not_expand_production_network_permission():
    async with controlled("serial",logical_identities=True):
        b=ToolBackend(parse_target("probe.example"))
        result=await b.call("query_authoritative",domain="probe.example")
        assert result["data"]["completed"] and len(b.calls)==8
        assert all(q["server"].startswith("127.") and q["port"]!=53 for q in b.dns.attempts)
        assert {e["data"]["resolver"] for e in b.calls}=={"1.0.0.1","9.9.9.9","8.8.4.4"}
        count=len(b.dns.attempts)
        denied=await b.call("query_dns",domain="probe.example",resolver="127.0.0.4")
        assert denied["error"]["code"]=="INVALID_INPUT" and len(b.dns.attempts)==count


@pytest.mark.parametrize("args,reason",[
    ({"domain":"ns1.test.example"},"DNS_TARGET_NOT_AUTHORIZED"),
    ({"domain":"probe.example","resolver":"127.0.0.4"},"DNS_RESOLVER_NOT_AUTHORIZED"),
])
async def test_invalid_arguments_explain_scope_and_do_not_become_measurements(args,reason):
    b=ToolBackend(parse_target("probe.example"));b.dns.system=["1.0.0.1"]
    rejected=await b.call("query_dns",**args)
    assert rejected["error"].get("reason")==reason
    context=current_state(b,rejected)
    assert context["non_retryable_requests"][0]["arguments"]==args
    assert context["query_scope"]["independent_tool_targets"]==["probe.example"]
    repeated=await b.call("query_dns",**args)
    assert repeated["error"]["code"]=="NON_RETRYABLE_DUPLICATE"
    assert len(b.attempts)==2 and not b.calls and not b.dns.attempts


def test_omitted_record_difference_remains_visible_to_agent():
    b=ToolBackend(parse_target("probe.example"))
    common=[dict(value=f"192.0.2.{i}",ttl=60) for i in range(1,17)]
    b.calls=[evidence(1,records=common+[dict(value="192.0.2.100",ttl=60)]),
        evidence(2,resolver="8.8.8.8",records=common+[dict(value="192.0.2.101",ttl=60)])]
    before=copy.deepcopy(b.calls)
    state=current_state(b,{"attempt_id":"A2"});left,right=state["fact_summary"]
    assert left["records"]==right["records"] and len(left["records"])==16
    assert left["records_omitted_count"]==1 and left["record_aggregate"]["total_count"]==17
    assert left["record_aggregate"]["value_set_sha256"]!=right["record_aggregate"]["value_set_sha256"]
    assert any(f["code"]=="RECORD_SET_DIFFERENCE" for f in state["current_findings"])
    assert b.calls==before


async def test_failed_secondary_discovery_does_not_erase_completed_primary_check():
    async with controlled("serial"):
        b=ToolBackend(parse_target("probe.example"))
        await b.call("query_authoritative",domain="probe.example")
        b.dns.limit=len(b.dns.attempts)+1
        await b.call("query_authoritative",domain="probe.example",record_type="SOA")
    r=report(b)
    assert r.authority_investigations[0]["completed"] is True
    assert "A2" in r.recommendations[0] and "A1" in r.recommendations[0]
    assert "本次权威发现未完成" not in r.recommendations[0]
    assert "新的有预算调查" in r.recommendations[0]


def test_negative_scope_and_aa_status_survive_model_summary():
    b=ToolBackend(parse_target("probe.example"))
    b.calls=[evidence(1,"NXDOMAIN",role="authoritative",negative_name="target.other",negative_scope="cname_target",canonical_name="target.other")]
    fact=current_state(b,{"attempt_id":"A1"})["fact_summary"][0]
    assert fact.get("negative_scope")=="cname_target" and fact.get("authoritative_answer") is True
    assert fact["negative_name"]=="target.other" and fact["target"]=="probe.example"


def test_legacy_opaque_soa_does_not_crash_compact_summary():
    b=ToolBackend(parse_target("probe.example"))
    b.calls=[evidence(1,qtype="SOA",records=[dict(value=f"opaque-{i}",ttl=60) for i in range(17)])]
    f=current_state(b,{"attempt_id":"A1"})["fact_summary"][0]
    assert f["records_omitted_count"]==1 and f["record_aggregate"]["soa_serials"]==[]


async def test_single_request_safety_message_survives_query_presentation():
    from test_http_security import backend,response
    from dns_investigator.reporting import evidence_bound_report
    b,c,_=backend([response("http://127.0.0.1/")])
    await b.call("check_http",url=b.target.url)
    r=report(b);r.request_kind="query";r=evidence_bound_report(r,b)
    assert "安全策略" in r.diagnostic_assessment and "安全策略" in r.recommendations[0]
    assert len(c.calls)==1
