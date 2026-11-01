"""Independent behavior checks against final-verification requirements."""
import copy
import pytest
import httpcore
from dns_investigator.http_safety import HTTPPolicy
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target
from dns_investigator.agent_summary import current_state
from dns_investigator.dns_diagnosis import diagnose
from evaluation.accuracy_cases import cases
from evaluation.fcd_acceptance import followed_alias, report
from evaluation.final_counterexamples import http_body, interrupted_authority
from evaluation.controlled_dns import controlled
from test_http_security import backend, response


@pytest.mark.parametrize("mode", ["complete", "limit", "timeout"])
async def test_body_completion_is_distinct_from_limit_and_read_error(mode):
    async with http_body(mode) as b:
        returned = await b.call("check_http", url=b.target.url, timeout=.25)
    result = report(b)
    fact = result.measured_facts[0]
    expected = {"complete": "complete", "limit": "limit_reached", "timeout": "read_error"}[mode]
    assert returned["data"].get("body_state") == fact.get("body_state") == expected
    assert fact.get("body_complete") == (mode == "complete")
    assert fact["status_code"] == 200 and expected in result.observations[0].observation
    assert (fact["error"] == "TIMEOUT") == (mode == "timeout")
    if mode == "limit":
        assert fact["bytes_read"] == 65536 and fact["request_state"] != "finished_within_check_limits"


async def test_authorized_upgrade_and_port_redirect_reach_exact_numeric_endpoints():
    b, c, _ = backend([response("https://allowed.example/end"), response()])
    b.target = parse_target("http://allowed.example/start")
    b.http_policy = HTTPPolicy(b.target.url)
    r = await b.check_http(b.target.url)
    assert r["error"] is None and c.calls == [("93.184.216.34", 80), ("93.184.216.34", 443)]
    assert c.tls == [("allowed.example", True, __import__("ssl").CERT_REQUIRED)]
    b, c, _ = backend([response("https://allowed.example:8443/end"), response()], origins=("https://allowed.example:8443",))
    assert (await b.check_http(b.target.url))["error"] is None
    assert c.calls == [("93.184.216.34", 443), ("93.184.216.34", 8443)]
    assert any(b"Host: allowed.example:8443\r\n" in data for data in c.writes)


async def test_public_multiaddress_fallback_never_resolves_hostname_again():
    b, c, resolutions = backend([response()], answers=[["1.1.1.1", "8.8.8.8"]])
    connect = c.connect_tcp
    async def flaky(ip, port, **kwargs):
        if ip == "1.1.1.1":
            c.calls.append((ip, port))
            raise httpcore.ConnectError("controlled first-address failure")
        return await connect(ip, port, **kwargs)
    c.connect_tcp = flaky
    r = await b.check_http(b.target.url)
    assert r["error"] is None and resolutions == ["allowed.example"]
    assert c.calls == [("1.1.1.1", 443), ("8.8.8.8", 443)]


async def test_security_refusal_report_does_not_suggest_unrestricted_redirect_following():
    b, c, _ = backend([response("http://127.0.0.1/")])
    await b.call("check_http", url=b.target.url)
    r = report(b)
    assert len(c.calls) == len(b.calls) == 1 and r.measured_facts[0]["status_code"] == 302
    assert "安全策略" in r.diagnostic_assessment and "不是" in r.diagnostic_assessment
    assert not any("curl.exe -v -L" in advice for advice in r.recommendations)
    assert not any("宕机" in h.statement for h in r.hypotheses)


async def test_alias_completion_rejects_two_naive_timestamps(tmp_path):
    b = await followed_alias(tmp_path)
    for e in b.calls:
        e["started_at"] = "2026-11-01T00:00:00"
    before = copy.deepcopy(b.calls)
    codes = {f["code"] for f in diagnose(b.calls)}
    assert "ALIAS_FOLLOWUP_COMPLETED" not in codes and "ALIAS_RESOLUTION_INCOMPLETE" in codes
    assert b.calls == before


def test_unknown_time_timeout_retains_observations_without_contemporaneous_localization():
    b = ToolBackend(parse_target("probe.example"))
    b.calls = cases()["timeout"]
    for e in b.calls:
        e["started_at"] = None
    before = copy.deepcopy(b.calls)
    r = report(b)
    assert r.assessment_level != "scope_localized"
    assert len(r.measured_facts) == 2 and b.calls == before
    f = next(f for f in r.findings if f.code == "RECURSIVE_QUERY_TIMEOUT")
    assert f.evidence_ids == ["E1"] and "时间" in r.diagnostic_assessment


@pytest.mark.parametrize("ending", ["cancel", "timeout"])
async def test_authority_interruption_retains_actual_query_count_and_first_answer(ending):
    b, received = await interrupted_authority(ending)
    a = b.attempts[0]
    progress = a["authority_state"]["progress"]
    assert len(received) == 2 and progress["target_queries_executed"] == 2
    assert progress["authoritative_answers"] == 1 and not a["authority_state"]["completed"]
    assert a["authority_state"].get("interruption", {}).get("code") == ("CANCELLED" if ending == "cancel" else "DNS_TOOL_TIMEOUT")
    assert len(b.dns.attempts) == 7 and len(b.calls) == 6
    summary = current_state(b, {"attempt_id": a["attempt_id"]})
    assert summary["authority_investigations"][0]["progress"]["target_queries_executed"] == 2
    r = report(b)
    assert "实际目标查询=2" in r.diagnostic_assessment and "有效 AA=1" in r.diagnostic_assessment


async def test_selected_authority_subset_is_not_all_discovered_servers():
    async with controlled("ns_many"):
        b=ToolBackend(parse_target("probe.example"))
        await b.call("query_authoritative",domain="probe.example")
    r=report(b);p=r.authority_investigations[0]["progress"]
    assert p["ns_total"]==3 and p["ns_selected"]==p["target_queries_executed"]==p["authoritative_answers"]==2
    assert r.authority_investigations[0]["completed"] is True
    assert "发现 NS=3" in r.diagnostic_assessment and "选中 NS=2" in r.diagnostic_assessment
    assert "不代表全部权威服务器正常" in r.diagnostic_assessment
    unselected={"ns1.test.example","ns2.test.example","ns3.test.example"}-{s["ns_name"] for s in p["servers"]}
    assert not any(q["qname"] in unselected for q in b.dns.attempts)


async def test_query_observer_cannot_absorb_parallel_tool_attempts():
    import asyncio
    async with controlled("normal"):
        b=ToolBackend(parse_target("probe.example"))
        await asyncio.gather(b.call("query_authoritative",domain="probe.example"),b.call("query_dns",domain="probe.example",record_type="AAAA"))
    p=b.attempts[0]["authority_state"]["progress"]
    observed={qid for server in p["servers"] for qid in server["query_attempt_ids"]}
    assert p["target_queries_executed"]==2 and len(observed)==2
    assert all(q["parent_tool_call_id"]=="A1" and q["resolver_role"]=="authoritative" for q in b.dns.attempts if q["query_attempt_id"] in observed)
    assert {e["id"] for e in b.owned_evidence("A1")}.isdisjoint(e["id"] for e in b.owned_evidence("A2"))
