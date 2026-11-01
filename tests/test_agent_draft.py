import json
from pathlib import Path
import pytest
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.messages import ModelResponse,ToolCallPart
from dns_investigator.agent import investigate
from dns_investigator.config import Config
from dns_investigator.target import parse_target
from dns_investigator.schemas import AgentDraft,InvestigationResult
from dns_investigator.agent_summary import current_state
from evaluation.controlled_dns import controlled
from evaluation.fcd_acceptance import discovery_refusal

ROOT=Path(__file__).resolve().parents[1]


def draft(**extra):return dict(request_kind="investigation",outcome="answered",**extra)


async def run(tmp_path,final):
    def model(messages,info):
        if not any(getattr(p,"tool_name",None)=="query_dns" and p.part_kind=="tool-return" for m in messages for p in m.parts):
            return ModelResponse(parts=[ToolCallPart("query_dns",dict(domain="example.com"))])
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,final(messages))])
    return await investigate("调查 example.com",parse_target("example.com"),Config("test"),fixture=ROOT/"data/fixtures/Q1.json",model=FunctionModel(model),log_dir=tmp_path)


def test_model_schema_excludes_program_report_fields():
    assert set(AgentDraft.model_fields)=={"request_kind","outcome","hypotheses","analysis_summary","limitations","next_directions"}
    assert AgentDraft.model_json_schema()["additionalProperties"] is False


async def test_valid_minimal_decision_needs_no_generated_report_fields(tmp_path):
    log,_=await run(tmp_path,lambda messages:draft())
    assert log["status"]=="completed" and log["agent_execution_status"]=="completed"
    assert log["result"]["measured_facts"][0]["evidence_id"]=="E1"
    assert log["output_resubmissions"]==0 and log["report_origin"]=="deterministic_evidence_report"


async def test_invalid_hypothesis_reference_produces_precise_retry_and_useful_fallback(tmp_path):
    log,path=await run(tmp_path,lambda messages:draft(hypotheses=[dict(id="H1",statement="候选解释",status="获得支持",supporting_evidence_ids=["E999"])]))
    assert log["status"]==log["agent_execution_status"]=="failed"
    assert log["report_availability"]=="available" and log["report_origin"]=="application_fallback"
    assert log["result"]["measured_facts"][0]["evidence_id"]=="E1"
    assert len(log["raw_model_drafts"])==3 and log["output_resubmissions"]==2
    assert all("hypotheses.H1.supporting_evidence_ids" in msg and "E999" in msg for msg in log["validation_errors"])
    assert log["usage"]["requests"]>0 and "E999" not in log["result"]["conclusion"]
    assert json.loads(path.read_text(encoding="utf-8"))["fallback_reason"]


async def test_model_cannot_smuggle_program_facts_into_draft(tmp_path):
    log,_=await run(tmp_path,lambda messages:draft(measured_facts=[dict(evidence_id="E999",result="NXDOMAIN")]))
    assert log["status"]=="failed" and log["raw_model_drafts"][0]["measured_facts"]
    assert [f["evidence_id"] for f in log["result"]["measured_facts"]]==["E1"]


async def test_compact_context_retains_discovery_failure_without_raw_packet_duplication():
    b,returned,_=await discovery_refusal();context=current_state(b,returned)
    assert context["partial_dns_issues"][0]["queries"][0]["qtype"]=="NS"
    assert context["budget"]["dns_requests_remaining"]==0 and len(context["fact_summary"])==1
    assert context["authority_investigations"][0]["completed"] is False
    assert "answer" not in str(context.keys()) and b.calls[0]["data"]["answer"]


async def test_complex_authority_script_returns_minimal_valid_decision(tmp_path):
    count=0
    def model(messages,info):
        nonlocal count
        count+=1
        if count==1:return ModelResponse(parts=[ToolCallPart("query_authoritative",dict(domain="probe.example"))])
        assert len(info.function_tools)==5
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,draft())])
    async with controlled("serial"):
        log,_=await investigate("调查 probe.example 的权威一致性",parse_target("probe.example"),Config("test"),model=FunctionModel(model),log_dir=tmp_path)
    assert log["status"]=="completed" and log["output_resubmissions"]==0
    assert any(f["code"]=="AUTHORITATIVE_RESPONSE_DISAGREEMENT" for f in log["result"]["findings"])
    assert all("answer" in e["data"] for e in log["evidence"])


def test_legacy_formal_report_still_reads():
    for p in (ROOT/"results/published/dns-accuracy-f0787c0/controlled-final").glob("*.json"):
        obj=json.loads(p.read_text(encoding="utf-8"))
        if isinstance(obj,dict) and "result" in obj:InvestigationResult.model_validate(obj["result"])
