import csv
import importlib.util
import json
from pathlib import Path
import pytest
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target
from dns_investigator.accounting import statistics

ROOT = Path(__file__).resolve().parents[1]


async def test_internal_failure_is_logged_separately_and_not_retried(monkeypatch):
    b = ToolBackend(parse_target("example.com"))
    count = 0
    async def broken(**kwargs):
        nonlocal count
        count += 1
        raise RuntimeError("private internal message")
    monkeypatch.setattr(b,"query_dns",broken)
    first = await b.call("query_dns",domain="example.com")
    second = await b.call("query_dns",domain="example.com",timeout=3)
    assert first["error"]["code"] == "INTERNAL_EXECUTION_ERROR"
    assert second["error"]["code"] == "NON_RETRYABLE_DUPLICATE"
    assert count == 1 and len(b.attempts) == 2 and not b.calls
    assert "private internal message" not in json.dumps(b.attempts)


async def test_attempt_terminal_events_not_duplicated():
    events = []
    b = ToolBackend(parse_target("example.com"),ROOT/"data/fixtures/MISSING.json",on_evidence=events.append)
    await b.call("query_dns",domain="example.com",record_type="AAAA")
    assert [e["event"] for e in events] == ["attempt_started","attempt_finished"]


def test_old_summary_does_not_guess_attempt_denominator(tmp_path):
    spec = importlib.util.spec_from_file_location("summarize",ROOT/"evaluation/summarize.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    rows = [dict(arm=arm,success="1",reviewer="automatic_rules_pending_human_review",total_calls="1",correct_calls="1",elapsed_seconds="1") for arm in ["A","B"]]
    source = tmp_path/"legacy.csv"
    with source.open("w",newline="",encoding="utf-8-sig") as f:
        w=csv.DictWriter(f,fieldnames=list(rows[0]));w.writeheader();w.writerows(rows)
    module.summarize(source,tmp_path/"out")
    data=list(csv.DictReader((tmp_path/"out/evaluation.csv").open()))
    assert data[0]["tool_accuracy"] == "N/A"
    assert data[1]["tool_accuracy"] == "INCOMPLETE"


async def test_network_timeout_is_valid_evidence_not_tool_error(monkeypatch):
    b = ToolBackend(parse_target("example.com"))
    async def timeout(**kwargs):
        return {"rcode":"TIMEOUT","records":[]}
    monkeypatch.setattr(b,"query_dns",timeout)
    r=await b.call("query_dns",domain="example.com")
    assert r["id"] == "E1" and b.attempts[0]["status"] == "measured"
    assert r["error"] is None
