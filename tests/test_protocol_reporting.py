import dns.rdatatype
import pytest
from test_dnssec_boundaries import signed_bundle
from evaluation.signed_protocol_lab import signed_lab
from evaluation.fcd_acceptance import report
from dns_investigator.reporting import evidence_bound_report
from dns_investigator.agent_summary import current_state
from dns_investigator.dnssec_validation import Session,Limited,name


@pytest.mark.parametrize("scenario,status,limit",[("secure","SECURE",32),("tampered","BOGUS",32),("secure","INDETERMINATE",2)])
async def test_single_protocol_request_keeps_its_real_outcome_and_next_checks(scenario,status,limit):
    async with signed_lab(scenario) as lab:
        b=lab.backend();b.dns.limit=limit
        returned=await b.call("query_authoritative",domain=b.target.domain,mode="dnssec",timeout=.2)
    r=report(b);r.request_kind="query";r=evidence_bound_report(r,b)
    validation=r.protocol_investigations[0]["validation"]
    assert validation["dnssec_status"]==status
    assert status in r.conclusion and "单项查询结果已列出" not in " ".join(r.recommendations)
    f=next(f for f in r.findings if f.code=="DNSSEC_VALIDATION")
    assert r.recommendations[0]==f.next_checks[0]
    assert any("E/V" in limit for limit in r.limitations)
    # Original target with a final DNS dot is still the same authorized target.
    assert not any("独立目标授权未扩展" in text and b.target.domain in text for text in r.recommendations)
    if status in {"SECURE","BOGUS"}:
        ctx=current_state(b,returned)
        last=ctx["validation_results"][-1]
        assert last["rrsig_summary"]["count"]==1 and last["rrsig_summary"]["algorithms"]==[15]
        observed=validation["signature_observations"][0]
        assert observed["validation_result_id"]==last["id"] and observed["rrsig_summary"]["count"]==1
        assert observed["scope"]["owner"]==b.target.domain+"."


def test_signature_budget_counts_only_executed_crypto(signed_bundle,monkeypatch):
    s=Session(signed_bundle);s.signatures=64
    target=signed_bundle["terminal_eid"];cut=signed_bundle["chain"][-1]
    keys=s.find(cut["dnskey_eid"],name(cut["child_zone"]),dns.rdatatype.DNSKEY)
    rr=s.find(target,name(signed_bundle["qname"]),dns.rdatatype.A)
    def forbidden(*a,**kw):raise AssertionError("must not execute 65th signature")
    monkeypatch.setattr("dns.dnssec.validate_rrsig",forbidden)
    with pytest.raises(Limited,match="SIGNATURE_ATTEMPT_BUDGET"):
        s.signature(rr,target,keys,name(cut["child_zone"]),cut["dnskey_eid"])
    assert s.signatures==64
