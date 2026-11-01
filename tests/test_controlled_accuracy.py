"""Real DNS datagrams to local controlled services, not fixture or public tests."""
import pytest
from evaluation.controlled_dns import measured_scenario


@pytest.mark.parametrize("scenario,required",[("timeout","RECURSIVE_QUERY_TIMEOUT"),("mismatch","RECURSIVE_AUTH_RESPONSE_MISMATCH"),("serial","AUTHORITATIVE_RESPONSE_DISAGREEMENT")])
async def test_controlled_wire_scenarios(scenario,required):
    log=await measured_scenario(scenario)
    codes={f["code"] for f in log["findings"]}
    assert required in codes
    assert len(log["dns_attempts"])==len(log["evidence"])
    assert len({e["id"] for e in log["evidence"]})==len(log["evidence"])
    assert all(q["server"].startswith("127.") for q in log["dns_attempts"])
    assert all(q["parent_tool_call_id"] in {a["attempt_id"] for a in log["attempts"]} for q in log["dns_attempts"])
    if scenario=="timeout":
        assert "RECURSIVE_RESPONSE_DISAGREEMENT" not in codes
        assert any(e["data"].get("transport_status")=="timeout" and e["data"].get("dns_rcode") is None for e in log["evidence"])
    assert not any(f["root_cause_confirmed"] for f in log["findings"])
