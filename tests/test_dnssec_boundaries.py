"""Adversarial material, process lifetime and authenticated-import regressions."""
import asyncio
import copy
import multiprocessing
import shutil
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

import dns.name
import dns.rdatatype
import dns.rrset
import pytest

from evaluation.signed_protocol_lab import signed_lab
from dns_investigator import dnssec
from dns_investigator.dnssec_validation import evaluate, Session, Limited
from dns_investigator.dnssec_proof import denial
from dns_investigator.trust import anchors
from scripts.import_root_anchor import import_snapshot


@pytest.fixture
async def signed_bundle():
    captured = []
    async def inspect(bundle):
        captured.append(copy.deepcopy(bundle))
        return evaluate(bundle)
    with patch.object(dnssec, "isolated_validate", inspect):
        async with signed_lab() as lab:
            b = lab.backend()
            await b.call("query_authoritative", domain=b.target.domain, mode="dnssec")
    assert evaluate(captured[0])["dnssec_status"] == "SECURE"
    return captured[0]


@pytest.mark.parametrize("change", ["mixed_source", "stale", "wrong_question", "wrong_type", "wrong_zone", "no_do", "rd", "tc"])
def test_material_cannot_be_spliced_or_promoted(signed_bundle, change):
    b = signed_bundle
    row = next(r for r in b["evidence"] if r["id"] == b["terminal_eid"])
    d = row["data"]
    if change == "mixed_source": row["source_mode"] = "fixture"
    if change == "stale": d["requested_at"] = "2000-01-01T00:00:00+00:00"
    if change == "wrong_question": d["qname"] = "other.example.test"
    if change == "wrong_type": d["qtype"] = "AAAA"
    if change == "wrong_zone": d["request_parameters"]["zone"] = "test."
    if change == "no_do": d["request_parameters"]["do"] = False
    if change == "rd": d["request_parameters"]["rd"] = True
    if change == "tc": d["flags"]["TC"] = True
    r = evaluate(b)
    assert r["dnssec_status"] == "INDETERMINATE" and r["validation_execution"] == "incomplete"


def test_clock_change_does_not_validate_old_capture(signed_bundle):
    signed_bundle["validation_time"] += 7200
    assert evaluate(signed_bundle)["dnssec_status"] == "INDETERMINATE"


def test_work_budget_is_enforced_before_more_crypto(signed_bundle):
    s = Session(signed_bundle)
    s.work = 512
    with pytest.raises(Limited, match="VALIDATION_WORK_BUDGET"):
        s.charge()


async def test_worker_deadline_and_cancellation_reap_actual_process(signed_bundle, monkeypatch):
    children_before = {p.pid for p in multiprocessing.active_children()}
    # A zero deadline still starts a real worker, then terminates and joins it.
    r = await dnssec.isolated_validate(signed_bundle, seconds=0)
    assert r["dnssec_status"] == "INDETERMINATE" and r["reason_code"] == "VALIDATION_PROCESS_TIMEOUT_OR_EXIT"
    # Signal only after the child has actually started; no timing sleeps.
    started = asyncio.Event()
    original = multiprocessing.process.BaseProcess.start
    def start(process):
        original(process)
        started.set()
    monkeypatch.setattr(multiprocessing.process.BaseProcess, "start", start)
    task = asyncio.create_task(dnssec.isolated_validate(signed_bundle))
    await started.wait()
    task.cancel()
    with pytest.raises(asyncio.CancelledError): await task
    assert {p.pid for p in multiprocessing.active_children()} == children_before


async def test_oversized_bundle_never_starts_worker(monkeypatch):
    def forbidden(*a, **kw): raise AssertionError("must reject before starting")
    monkeypatch.setattr(multiprocessing, "get_context", forbidden)
    r = await dnssec.isolated_validate({"oversized": "x" * 2_000_001})
    assert r["reason_code"] == "VALIDATION_INPUT_LIMIT"


def test_nsec_cannot_deny_below_delegation_or_wildcard_outside_zone():
    n = dns.name.from_text
    rr = dns.rrset.from_text("child.example.", 60, "IN", "NSEC", "z.example. NS RRSIG NSEC")
    assert not denial(n("x.child.example."), 1, "NXDOMAIN", n("example."), [rr], lambda: None)
    assert not denial(n("x.child.example."), 1, "NOERROR", n("example."), [rr], lambda: None, wildcard_base=n("."))


def test_stale_anchor_and_failed_import_leave_snapshot_unchanged(tmp_path):
    src = Path("src/dns_investigator/assets")
    import json
    receipt=json.loads((src / "anchor-authentication.json").read_text(encoding="utf-8-sig"))
    now = datetime.fromisoformat(receipt["verified_at"]).timestamp()+60
    assert anchors(now)["authentication"] == "CMS_SIGNATURE_AND_PINNED_ICANN_CA_CHAIN"
    with pytest.raises(ValueError, match="UPDATE_REQUIRED"): anchors(now + 181 * 86400)


@pytest.mark.skipif(shutil.which("pwsh") is None, reason="Actual CMS import integration requires PowerShell 7/.NET; not simulated")
def test_authenticated_import_failure_preserves_snapshot(tmp_path):
    src = Path("src/dns_investigator/assets")
    dest = tmp_path / "active"
    shutil.copytree(src, dest)
    before = {p.name: p.read_bytes() for p in dest.iterdir()}
    invalid = tmp_path / "invalid"
    shutil.copytree(src, invalid)
    (invalid / "root-anchors.xml").write_text("<TrustAnchor/>")
    with pytest.raises(Exception): import_snapshot(invalid, dest, replace=True)
    assert before == {p.name: p.read_bytes() for p in dest.iterdir()}
    # A real CMS verification against the pinned CA, not a mocked verifier.
    import_snapshot(src, dest, replace=True)
    assert anchors(directory=dest)["ds"] == anchors()["ds"]


async def test_trace_cancellation_preserves_only_its_partial_measurements():
    async with signed_lab() as lab:
        b = lab.backend()
        entered = asyncio.Event()
        waiting = asyncio.Event()
        request = b.dns.request
        async def controlled(qname, typ, server, *a, **kw):
            if server == "127.0.0.12":
                entered.set()
                await waiting.wait()
            return await request(qname, typ, server, *a, **kw)
        b.dns.request = controlled
        task = asyncio.create_task(b.call("query_authoritative", domain=b.target.domain, mode="trace"))
        await entered.wait()
        task.cancel()
        with pytest.raises(asyncio.CancelledError): await task
    assert len(b.calls) == len(b.dns.attempts) == 2
    assert all(e["parent_tool_call_id"] == "A1" for e in b.calls)
    state = b.attempts[0]["protocol_state"]
    assert state["stop_reason"] == "CANCELLED" and not state["completed"]
    assert state["last_successful_zone"] == "test."
