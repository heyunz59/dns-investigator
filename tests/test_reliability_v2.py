"""Scripted models test orchestration only; these are not DeepSeek acceptance runs."""
import json
from pathlib import Path
import pytest
from pydantic_ai import ModelRetry
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.messages import ModelResponse, ToolCallPart
from dns_investigator.agent import investigate, validate_references
from dns_investigator.schemas import InvestigationResult
from dns_investigator.tools import ToolBackend
from dns_investigator.config import Config
from dns_investigator.target import parse_target
from dns_investigator.accounting import statistics, call_reviews

ROOT = Path(__file__).resolve().parents[1]
FIX = ROOT / "data/fixtures"


def answer(kind="investigation", outcome="answered", refs=()):
    return dict(request_kind=kind, outcome=outcome,
        observations=[dict(evidence_id=r, observation="返回测量") for r in refs], hypotheses=[],
        conclusion="DNS 解析器坏了", conclusion_evidence_ids=list(refs),
        limitations=["缺少测量，无法确认"], recommendations=["补充有效事实"])


def final(info, value):
    return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, value)])


async def run_script(tmp_path, respond, text="调查 example.com", **kwargs):
    return await investigate(text, parse_target("example.com"), Config("test", model="scripted", max_tool_calls=6),
        model=FunctionModel(respond), log_dir=tmp_path, **kwargs)


async def test_original_empty_evidence_diagnosis_is_not_completed(tmp_path):
    log, _ = await run_script(tmp_path, lambda messages, info: final(info, answer()))
    assert log["status"] == "failed" and not log["requirements_met"]
    assert not log["attempts"] and not log["evidence"]
    assert log["result_origin"] == "application_fallback"
    assert "坏了" not in log["result"]["conclusion"]


async def test_insufficient_flag_cannot_smuggle_no_evidence_diagnosis(tmp_path):
    log, _ = await run_script(tmp_path, lambda messages, info: final(info, answer(outcome="insufficient_information")))
    assert log["status"] == "limited" and log["execution_status"] == "ended"
    assert not log["requirements_met"]
    assert log["result"]["conclusion"] == "没有取得有效测量证据，无法确认故障原因。"


def test_investigation_hypotheses_and_refs():
    r = InvestigationResult(**answer(refs=["E1"]))
    with pytest.raises(ModelRetry, match="两个"):
        validate_references(r, {"E1"})
    # Construct validated schema for two distinct, explicitly uncertain alternatives.
    data = answer(refs=["E1"])
    data["hypotheses"] = [dict(id=f"H{i}", statement=s, status="无法确定", missing_information=["需要进一步验证"])
        for i, s in enumerate(["解析路径异常", "HTTP 服务异常"], 1)]
    r = InvestigationResult(**data)
    validate_references(r, {"E1"})
    r.conclusion_evidence_ids = ["E99"]
    with pytest.raises(ModelRetry):
        validate_references(r, {"E1"})


async def test_baseline_preprovided_facts_and_single_query(tmp_path):
    facts = [dict(id="E1",tool_name="query_dns",execution_status="ok",input={"domain":"example.com"},
                  data={"rcode":"NOERROR"},source_mode="fixture")]
    log, _ = await run_script(tmp_path, lambda messages, info: final(info, answer(kind="query",refs=["E1"])),
        text="查询 example.com 的 A 记录", baseline_facts=facts)
    assert log["status"] == "completed" and not log["attempts"]
    assert statistics(log, {"required_tools":["query_dns"]})["total_calls"] == 0


async def test_invalid_backend_call_counts_without_evidence():
    b = ToolBackend(parse_target("example.com"), FIX / "C1.json")
    result = await b.call("check_tcp",ip="192.0.2.99",port=443)
    assert result["error"]["code"] == "INVALID_INPUT"
    assert len(b.attempts) == 1 and not b.calls
    log = dict(schema_version=2,attempt_accounting="complete",attempts=b.attempts,evidence=b.calls)
    stats = statistics(log, {"required_tools":["check_tcp"]})
    assert stats["total_calls"] == 1 and stats["missing_required_measurements"]
    assert call_reviews(log,{"id":"C1"})[0]["suggested_correct"] == 0


async def test_framework_schema_rejection_counted_once_and_final_excluded(tmp_path):
    turn = 0
    def respond(messages, info):
        nonlocal turn
        turn += 1
        if turn == 1:
            return ModelResponse(parts=[ToolCallPart("check_tcp", {"ip":"192.0.2.10","port":"not-an-integer"},tool_call_id="bad")])
        return final(info, answer(kind="query",outcome="insufficient_information"))
    log, path = await run_script(tmp_path, respond, text="查询 example.com 的 A 记录",fixture=FIX/"Q1.json")
    assert log["status"] == "limited", log
    assert len(log["attempts"]) == 1 and not log["evidence"]
    assert log["attempts"][0]["status"] == "schema_rejected"
    assert log["attempts"][0]["error"]["code"] == "FRAMEWORK_ARGUMENT_REJECTED"
    assert json.loads(path.read_text(encoding="utf-8"))["attempts"] == log["attempts"]


async def test_fixture_unavailable_and_duplicate_are_not_measurements(monkeypatch):
    b = ToolBackend(parse_target("example.com"), FIX / "MISSING.json")
    async def forbidden(**kw):
        raise AssertionError("must not access live network")
    monkeypatch.setattr(b,"query_dns",forbidden)
    first = await b.call("query_dns",domain="example.com",record_type="AAAA",timeout=5)
    again = await b.call("query_dns",domain="example.com",record_type="AAAA",timeout=3)
    assert first["error"]["code"] == "FIXTURE_NOT_COVERED" and first["error"]["retryable"] is False
    assert again["error"]["code"] == "NON_RETRYABLE_DUPLICATE"
    assert len(b.attempts) == 2 and not b.calls and "id" not in first


async def test_empty_fixture_never_becomes_live(tmp_path,monkeypatch):
    path = tmp_path / "empty.json"
    path.write_text("[]")
    b = ToolBackend(parse_target("example.com"),path)
    async def forbidden(**kw):
        raise AssertionError("no fallback")
    monkeypatch.setattr(b,"query_dns",forbidden)
    r = await b.call("query_dns",domain="example.com")
    assert r["source_mode"] == "fixture" and r["error"]["code"] == "FIXTURE_NOT_COVERED"


async def test_soft_budget_allows_summary_and_hard_budget_blocks_batch(tmp_path):
    def respond(messages,info):
        if any(p.part_kind == "tool-return" for m in messages for p in m.parts):
            assert not info.function_tools
            return final(info, answer(kind="query",refs=["E1"]))
        return ModelResponse(parts=[ToolCallPart("query_dns", {"domain":"example.com"}, tool_call_id=f"c{i}") for i in range(3)])
    log,_ = await investigate("查询 example.com 的 A 记录",parse_target("example.com"),Config("test",max_tool_calls=1),
        fixture=FIX/"Q1.json",model=FunctionModel(respond),log_dir=tmp_path)
    assert log["status"] == "completed", log
    assert len(log["attempts"]) == 3 and len(log["evidence"]) == 1
    assert sum((a["error"] or {}).get("code") == "BUDGET_EXHAUSTED" for a in log["attempts"]) == 2


async def test_model_failure_preserves_successful_evidence_and_attempt(tmp_path):
    turns = 0
    def respond(messages,info):
        nonlocal turns
        turns += 1
        if turns == 1:
            return ModelResponse(parts=[ToolCallPart("query_dns",{"domain":"example.com"})])
        raise RuntimeError("private-sdk-details")
    log,path = await run_script(tmp_path,respond,fixture=FIX/"Q1.json")
    assert log["status"] == "failed" and len(log["attempts"]) == len(log["evidence"]) == 1
    assert log["result_origin"] == "application_fallback" and not log["requirements_met"]
    assert "private-sdk-details" not in path.read_text(encoding="utf-8")
    assert "attempt_started" in path.with_suffix(".jsonl").read_text(encoding="utf-8")


def test_legacy_attempt_statistics_are_unknown():
    stats = statistics(dict(evidence=[dict(tool_name="query_dns")]),{"required_tools":["query_dns"]})
    assert stats["attempt_accounting"] == "incomplete" and stats["total_calls"] is None


async def test_c3_needs_two_valid_resolver_measurements():
    b = ToolBackend(parse_target("example.com"),FIX/"C3.json")
    case = dict(required_measurements=[dict(tool="query_dns",input={"resolver":None}),
                                      dict(tool="query_dns",input={"resolver":"1.1.1.1"})])
    await b.call("query_dns",domain="example.com",resolver=None)
    assert len(statistics(dict(evidence=b.calls),case)["missing_required_measurements"]) == 1
    await b.call("query_dns",domain="example.com",resolver="1.1.1.1")
    assert statistics(dict(evidence=b.calls),case)["missing_required_measurements"] == []
