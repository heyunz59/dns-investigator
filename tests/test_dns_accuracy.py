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
