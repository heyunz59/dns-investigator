import copy
import pytest
from evaluation.accuracy_cases import cases
from dns_investigator.dns_compare import compare_details,evidence_rows
from dns_investigator.dns_diagnosis import diagnose


@pytest.mark.parametrize("times,state,conflict",[
    (("2026-11-01T00:00:00+00:00","2026-11-01T00:00:10+00:00"),"TIME_COMPARABLE",True),
    (("2026-11-01T00:00:00+00:00","2026-11-01T00:05:01+00:00"),"TIME_WINDOW_DIFFERS",False),
    ((None,"2026-11-01T00:00:10+00:00"),"TIME_UNKNOWN",False),((None,None),"TIME_UNKNOWN",False),
    (("invalid","2026-11-01T00:00:10+00:00"),"TIME_INVALID",False),
    (("2026-11-01T00:00:00","2026-11-01T00:00:10+00:00"),"TIME_INVALID",False),
    (("2026-11-01T08:00:00+08:00","2026-11-01T00:00:00+00:00"),"TIME_COMPARABLE",True)])
def test_time_relation_without_inventing_history(times,state,conflict):
    evidence=cases()["nxdomain"]
    for e,t in zip(evidence,times):e["started_at"]=t
    before=copy.deepcopy(evidence)
    result=compare_details(evidence_rows(evidence));pair=result["pairs"][0]
    assert pair["time_status"]==state and pair["comparable"]==conflict
    findings=diagnose(evidence);codes={f["code"] for f in findings}
    assert ("RECURSIVE_RESPONSE_DISAGREEMENT" in codes)==conflict
    assert ("DNS_TEMPORAL_DIFFERENCE" in codes)==(not conflict)
    assert evidence==before and "RCODE_DISAGREEMENT" in pair["codes"]


def test_unknown_time_record_difference_is_observation_not_localization():
    evidence=cases()["cdn"]
    for e in evidence:e.pop("started_at")
    f=diagnose(evidence)
    assert {r["code"] for r in f}=={"DNS_TEMPORAL_DIFFERENCE"}
    assert f[0]["localization"]=={} and not f[0]["root_cause_confirmed"]


def test_no_transitive_five_minute_window_chain():
    evidence=cases()["nxdomain"]
    third=copy.deepcopy(evidence[1]);third["id"]="E3";third["data"]["resolver"]="9.9.9.9"
    evidence.append(third)
    for e,t in zip(evidence,["00:00:00","00:04:00","00:08:00"]):e["started_at"]="2026-11-01T"+t+"+00:00"
    for finding in diagnose(evidence):
        if finding["code"]=="RECURSIVE_RESPONSE_DISAGREEMENT":assert not {"E1","E3"}<=set(finding["evidence_ids"])


def test_finding_time_bounds_follow_instants_not_timezone_string_order():
    from datetime import datetime
    evidence=cases()["nxdomain"]
    evidence[0]["started_at"]="2026-11-01T00:01:00+00:00"
    evidence[1]["started_at"]="2026-11-01T08:00:00+08:00"
    original=copy.deepcopy(evidence)
    f=next(f for f in diagnose(evidence) if f["code"]=="RECURSIVE_RESPONSE_DISAGREEMENT")
    assert datetime.fromisoformat(f["scope"]["time_start"])<=datetime.fromisoformat(f["scope"]["time_end"])
    assert f["scope"]["time_start"]==evidence[1]["started_at"] and evidence==original
