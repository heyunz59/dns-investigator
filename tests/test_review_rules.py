import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("review_rules",ROOT/"evaluation/review_rules.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


def test_attempted_tool_does_not_satisfy_required_measurement():
    log=dict(schema_version=2,attempt_accounting="complete",mode="agent",evidence=[],
        attempts=[dict(attempt_id="A1",tool_name="check_tcp",status="rejected",input={},error={"code":"INVALID_INPUT"})],
        result_origin="application_fallback",execution_status="failed",result={})
    rating=module.screen(log,dict(id="C4",required_tools=["check_tcp"]))
    assert rating["success"] == 0 and rating["correct_calls"] == 0
    assert rating["checks"]["required_measurements_present"] is False


def test_incomplete_root_cause_can_still_satisfy_c1_not_reproduced_task():
    log=dict(schema_version=2,attempt_accounting="complete",mode="baseline",attempts=[],evidence=[],
        result_origin="model",execution_status="ended",requirements_met=False,
        result=dict(conclusion="本次未复现，不能确认唯一原因",limitations=[],hypotheses=[{},{}]))
    rating=module.screen(log,dict(id="C1",required_tools=[]))
    assert rating["success"] == 1
    assert "待独立人工复核" in rating["note"]
