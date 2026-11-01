"""Bounded, source-isolated CNAME authorization without extra Agent tools."""
import json
import pytest
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target
from dns_investigator.alias_scope import alias_paths,MAX_ALIAS_DEPTH,MAX_ALIAS_TARGETS


def alias(b,target="target.other",start="probe.example",mode="fixture",**extra):
    return b.save_evidence(dict(tool_call_id="A0",tool_name="query_dns",source_mode=mode,execution_status="ok",input={},
        data=dict(qname=start,qtype="A",rcode="NOERROR",result_kind="ALIAS_INCOMPLETE",records=[],
            cname_chain=[dict(name=start,target=target)],**extra)))


def fixture_backend(tmp_path,max_calls=10):
    p=tmp_path/"alias.json"
    p.write_text(json.dumps([dict(tool="query_dns",match=dict(domain="target.other",record_type="A"),
        data=dict(rcode="NOERROR",result_kind="NOERROR",records=[dict(value="192.0.2.10",ttl=60)]))]),encoding="utf-8")
    return ToolBackend(parse_target("probe.example"),p,max_calls=max_calls)


async def test_cross_domain_follow_keeps_parent_evidence(tmp_path):
    b=fixture_backend(tmp_path);first=alias(b)
    r=await b.call("query_dns",domain="target.other")
    assert r["id"]=="E2" and r["tool_call_id"]=="A1"
    assert r["target_authorization"]["evidence_ids"]==[first["id"]]
    assert r["data"]["qname"]=="target.other" and b.calls[0]["data"]["qname"]=="probe.example"
    assert not b.dns.attempts
    from dns_investigator.dns_diagnosis import diagnose
    b.calls[-1]["data"].update(rcode="SERVFAIL",result_kind="SERVFAIL",records=[])
    scoped=next(f for f in diagnose(b.calls) if f["code"]=="DNS_SERVFAIL")
    assert scoped["scope"]["target"]=="target.other" and scoped["scope"]["dns_followup_only"]
    assert "外部专项检查" in scoped["next_checks"][0]
    denied=await b.call("query_authoritative",domain="target.other")
    assert denied["error"]["code"]=="INVALID_INPUT"  # authority scope is not silently reassigned


@pytest.mark.parametrize("mode",["fixture","live"])
async def test_sources_do_not_grant_each_other_permissions(tmp_path,mode):
    b=fixture_backend(tmp_path)
    if mode=="live":b.fixture=None
    alias(b,mode="live" if mode=="fixture" else "fixture")
    r=await b.call("query_dns",domain="target.other")
    assert r["error"]["code"]=="INVALID_INPUT" and len(b.calls)==1 and not b.dns.attempts


async def test_unrelated_names_http_and_additional_do_not_authorize(tmp_path):
    b=fixture_backend(tmp_path)
    alias(b,start="unrelated.example")
    alias(b,target="linked.other",additional=[dict(name="target.other",type="A",values=["192.0.2.10"])])
    b.save_evidence(dict(tool_call_id="A0",tool_name="check_http",source_mode="fixture",execution_status="ok",data=dict(final_url="https://target.other/")))
    r=await b.call("query_dns",domain="target.other")
    assert r["error"]["code"]=="INVALID_INPUT"


def test_loops_depth_total_and_reversed_evidence_order(tmp_path):
    b=fixture_backend(tmp_path)
    row=alias(b);row["data"]["cname_chain"].append(dict(name="target.other",target="probe.example"))
    assert list(alias_paths(b))==["probe.example"]
    b.calls=[]
    # Independent but connected evidence rows, deliberately reversed.
    for i in reversed(range(12)):
        alias(b,start="probe.example" if i==0 else f"n{i}.other",target=f"n{i+1}.other")
    allowed=alias_paths(b)
    assert len(allowed)==1+min(MAX_ALIAS_DEPTH,MAX_ALIAS_TARGETS)
    assert "n8.other" in allowed and "n9.other" not in allowed


async def test_missing_alias_fixture_never_falls_back_and_is_not_retried(tmp_path,monkeypatch):
    b=fixture_backend(tmp_path);alias(b,target="missing.other")
    async def forbidden(*a,**k):raise AssertionError("fixture escaped to network")
    monkeypatch.setattr(b.dns,"query",forbidden)
    r=await b.call("query_dns",domain="missing.other")
    again=await b.call("query_dns",domain="missing.other")
    assert r["error"]["code"]=="FIXTURE_NOT_COVERED"
    assert again["error"]["code"]=="NON_RETRYABLE_DUPLICATE" and len(b.calls)==1


async def test_alias_cannot_bypass_budget_or_repeat_complete_result(tmp_path):
    b=fixture_backend(tmp_path,max_calls=1);alias(b)
    r=await b.call("query_dns",domain="target.other")
    denied=await b.call("query_dns",domain="target.other")
    assert r["id"]=="E2" and denied["error"]["code"]=="BUDGET_EXHAUSTED"
    b=fixture_backend(tmp_path);row=alias(b)
    row["data"].update(result_kind="NOERROR",canonical_name="target.other",records=[dict(value="192.0.2.10",ttl=60)])
    denied=await b.call("query_dns",domain="target.other")
    assert denied["error"]["code"]=="ALIAS_ALREADY_RESOLVED" and len(b.calls)==1


async def test_followed_dns_request_still_uses_q_budget(tmp_path):
    b=fixture_backend(tmp_path);b.fixture=None
    alias(b,mode="live");b.dns.limit=0
    r=await b.call("query_dns",domain="target.other")
    assert r["error"]["code"]=="DNS_BUDGET_EXHAUSTED" and len(b.calls)==1 and not b.dns.attempts


def test_one_deep_chain_and_total_branch_cap(tmp_path):
    b=fixture_backend(tmp_path);row=alias(b)
    row["data"]["cname_chain"]=[dict(name="probe.example" if i==0 else f"d{i}.other",target=f"d{i+1}.other") for i in range(12)]
    allowed=alias_paths(b)
    assert "d8.other" in allowed and "d9.other" not in allowed
    b.calls=[]
    for i in range(12):alias(b,target=f"branch{i}.other")
    assert len(alias_paths(b))==1+MAX_ALIAS_TARGETS


async def test_agent_can_select_connected_followup_without_extra_tool(tmp_path):
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.messages import ModelResponse,ToolCallPart
    from dns_investigator.agent import investigate
    from dns_investigator.config import Config
    fixture=tmp_path/"agent-alias.json"
    fixture.write_text(json.dumps([
        dict(tool="query_dns",match=dict(domain="probe.example"),data=dict(rcode="NOERROR",result_kind="ALIAS_INCOMPLETE",records=[],
            cname_chain=[dict(name="probe.example",target="target.other")])),
        dict(tool="query_dns",match=dict(domain="target.other"),data=dict(rcode="NOERROR",result_kind="NOERROR",records=[dict(value="192.0.2.10",ttl=60)]))
    ]),encoding="utf-8")
    def model(messages,info):
        returns=[p.content for m in messages for p in m.parts if getattr(p,"part_kind",None)=="tool-return" and getattr(p,"tool_name",None)=="query_dns"]
        assert len(info.function_tools)==5
        if len(returns)<2:
            if returns:assert any(t["target"]=="target.other" for t in returns[0]["allowed_dns_targets"])
            return ModelResponse(parts=[ToolCallPart("query_dns",{"domain":"probe.example" if not returns else "target.other"})])
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,dict(request_kind="investigation",outcome="answered",
            hypotheses=[],analysis_summary="本次取得别名末端记录，未确认其他原因",limitations=["脚本模型测试"],next_directions=[]))])
    log,_=await investigate("调查 probe.example",parse_target("probe.example"),Config("test"),fixture=fixture,model=FunctionModel(model),log_dir=tmp_path/"logs")
    assert log["status"]=="completed" and [a["input"]["domain"] for a in log["attempts"]]==["probe.example","target.other"]
    assert log["result"]["measured_facts"][1]["target_authorization"]["evidence_ids"]==["E1"]
