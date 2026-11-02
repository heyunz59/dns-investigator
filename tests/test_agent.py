import json
from pathlib import Path
import pytest
from pydantic_ai import ModelRetry
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.messages import ModelResponse, TextPart, ToolCallPart
from dns_investigator.agent import build_agent, investigate, validate_references
from dns_investigator.config import Config
from dns_investigator.schemas import InvestigationResult
from dns_investigator.target import parse_target


def output():
    return dict(request_kind="query", observations=[dict(evidence_id="E1", observation="A 记录")], hypotheses=[],
                conclusion="查询得到记录", conclusion_evidence_ids=["E1"],
                limitations=["仅本次查询"], recommendations=[])


def test_bad_references():
    result = InvestigationResult(**output())
    with pytest.raises(ModelRetry):
        validate_references(result, set())


async def test_real_framework_tool_loop(tmp_path):
    # Scripted model tests infrastructure only, never real-model acceptance.
    def respond(messages, info):
        if not any(getattr(p, "part_kind", "") == "tool-return" for m in messages for p in m.parts):
            return ModelResponse(parts=[ToolCallPart("query_dns", {"domain": "example.com", "record_type": "A"})])
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name, dict(request_kind="query",outcome="answered"))])
    fixture = Path(__file__).resolve().parents[1] / "data/fixtures/Q1.json"
    log, path = await investigate("查询 example.com 的 A 记录", parse_target("example.com"),
                                  Config("test", model="scripted-test"), fixture,
                                  FunctionModel(respond), log_dir=tmp_path)
    assert log["status"] == "completed", log
    assert [e["tool_name"] for e in log["evidence"]] == ["query_dns"]
    assert path.exists() and path.with_suffix(".jsonl").exists()
