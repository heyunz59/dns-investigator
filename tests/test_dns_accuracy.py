"""Acceptance counterexamples: expectations stay outside Agent input."""
import copy
import json
from pathlib import Path
import pytest
from dns_investigator.dns_compare import compare_details
from dns_investigator.dns_wire import dns_outcome
from dns_investigator.dns_diagnosis import diagnose
from evaluation.accuracy_cases import cases,evidence

ROOT=Path(__file__).resolve().parents[1]


def rows(case):
    return [{**e["data"],"evidence_id":e["id"],"source_mode":e["source_mode"],"measured_at":e["started_at"]} for e in cases()[case]]


def test_timeout_is_availability_not_content_or_ttl():
    r=compare_details(rows("timeout"))
    assert r["differences"]==["QUERY_AVAILABILITY_DIFFERENCE"]
    assert r["observations"]==[] and r["paths"][0]["dns_rcode"] is None
    assert not r["pairs"][0]["comparable"]


def test_partial_failure_preserves_responding_subset():
    data=rows("partial")+[dict(qname="probe.example",qtype="A",source_mode="synthetic",execution_status="error",error={"code":"INTERNAL"})]
    r=compare_details(data)
    assert "RCODE_DISAGREEMENT" in r["differences"]
    assert any(p["path_indices"]==[1,2] and p["comparable"] for p in r["pairs"])
    assert r["paths"][3]["evidence_id"] is None
    assert any(p["reason"]=="EXECUTION_FAILED" for p in r["pairs"])


@pytest.mark.parametrize("change,reason",[
    ({"qtype":"AAAA"},"QUERY_SCOPE_DIFFERS"),({"qname":"other.example"},"QUERY_SCOPE_DIFFERS"),
    ({"source_mode":"live"},"SOURCE_MODE_DIFFERS"),({"measured_at":"2026-11-01T00:10:00+00:00"},"TIME_WINDOW_DIFFERS"),
    ({"result_kind":"NODATA","records":[],"negative_name":"other.example"},"NEGATIVE_SCOPE_DIFFERS"),
    ({"resolver_role":"authoritative","flags":{"AA":False}},"AUTHORITY_NOT_CONFIRMED")])
def test_comparison_scope(change,reason):
    data=rows("normal");data[1].update(change)
    r=compare_details(data)
    assert r["differences"]==["COMPARISON_INCONCLUSIVE"] and r["pairs"][0]["reason"]==reason


def test_ttl_latency_observations_not_faults():
    data=rows("ttl");data[1]["duration_ms"]=10.01
    r=compare_details(data)
    assert r["differences"]==["NO_SIGNIFICANT_DIFFERENCE"]
    assert r["observations"][0]["ttl_values"]==[[60],[58]]


def test_legacy_adapter_does_not_mutate_or_invent_rcode():
    data=rows("timeout")[0];original=copy.deepcopy(data)
    assert dns_outcome(data)==dict(transport_status="timeout",dns_rcode=None,result_kind="TIMEOUT")
    assert data==original


@pytest.mark.parametrize("case",list(cases()))
def test_fixed_evidence_acceptance(case):
    expected=json.loads((ROOT/"evaluation/accuracy_expectations.json").read_text(encoding="utf-8"))["cases"][case]
    result=diagnose(cases()[case]);codes={f["code"] for f in result}
    assert set(expected.get("required",[]))<=codes
    assert not set(expected.get("forbidden",[])) & codes
    assert all(not f["root_cause_confirmed"] for f in result)
    assert all(set(f["evidence_ids"])<={e["id"] for e in cases()[case]} for f in result)


def test_aggregation_keeps_groups_and_exceptions():
    data=cases()["partial"]+[evidence(4,"TIMEOUT",resolver="4.4.4.4")]
    f=diagnose(data)
    timeouts=[x for x in f if x["code"]=="RECURSIVE_QUERY_TIMEOUT"]
    assert len(timeouts)==1 and timeouts[0]["localization"]["affected_evidence_ids"]==["E1","E4"]
    assert set(timeouts[0]["evidence_ids"])=={"E1","E2","E3","E4"}
    differences=[x for x in f if x["code"]=="RECURSIVE_RESPONSE_DISAGREEMENT"]
    assert len(differences)==1 and differences[0]["evidence_ids"]==["E2","E3"]
    assert {x["evidence_id"] for x in differences[0]["localization"]["other_paths"]}=={"E1","E4"}


def test_source_time_scope_never_aggregates_unrelated_paths():
    data=cases()["nxdomain"]
    data[1]["source_mode"]="live"
    assert "RECURSIVE_RESPONSE_DISAGREEMENT" not in {f["code"] for f in diagnose(data)}
    data[1]["source_mode"]="synthetic";data[1]["started_at"]="2026-11-01T00:10:00+00:00"
    assert "RECURSIVE_RESPONSE_DISAGREEMENT" not in {f["code"] for f in diagnose(data)}


def test_single_candidate_is_not_an_answered_gate():
    from dns_investigator.tools import ToolBackend
    from dns_investigator.target import parse_target
    from dns_investigator.schemas import InvestigationResult,Hypothesis
    from dns_investigator.reporting import evidence_bound_report
    b=ToolBackend(parse_target("probe.example"));b.calls=cases()["timeout"]
    r=InvestigationResult(observations=[],hypotheses=[Hypothesis(id="H1",statement="查询路径可能不可用",status="无法确定",missing_information=["服务与路径仍未知"])],
        conclusion="draft",conclusion_evidence_ids=[],limitations=[],recommendations=[])
    r=evidence_bound_report(r,b)
    assert r.outcome=="answered" and len(r.hypotheses)==1 and r.assessment_level=="scope_localized"
    assert "1.1.1.1" in r.diagnostic_assessment and "8.8.8.8=NOERROR" in r.diagnostic_assessment
    assert "没有取得超时路径的记录内容" in r.diagnostic_assessment
    assert any("probe.example A" in step and "query_dns" in step for step in r.recommendations)


async def test_final_model_failure_keeps_useful_scoped_report(tmp_path):
    from pydantic_ai.models.function import FunctionModel
    from pydantic_ai.messages import ModelResponse,ToolCallPart
    from dns_investigator.agent import investigate
    from dns_investigator.config import Config
    from dns_investigator.target import parse_target
    def model(messages,info):
        if not any(getattr(p,"part_kind",None)=="tool-return" for m in messages for p in m.parts):
            return ModelResponse(parts=[ToolCallPart("query_dns",{"domain":"example.com"})])
        raise RuntimeError("controlled final model failure")
    log,_=await investigate("调查 example.com",parse_target("example.com"),Config("test"),fixture=ROOT/"data/fixtures/Q1.json",model=FunctionModel(model),log_dir=tmp_path)
    assert log["status"]=="failed" and log["result_origin"]=="application_fallback"
    assert log["result"]["measured_facts"][0]["evidence_id"]=="E1"
    assert log["result"]["diagnostic_assessment"] and "RuntimeError" in log["result"]["report_fallback_reason"]
