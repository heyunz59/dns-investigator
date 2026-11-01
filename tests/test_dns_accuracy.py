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
