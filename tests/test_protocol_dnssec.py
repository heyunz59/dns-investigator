import pytest
from evaluation.signed_protocol_lab import signed_lab


@pytest.mark.parametrize("scenario,status",[("secure","SECURE"),("ds_mismatch","BOGUS"),("multi_ds","SECURE"),("rollover","SECURE"),
    ("tampered","BOGUS"),("expired","BOGUS"),("future","BOGUS"),("missing_sig","BOGUS"),("insecure","INSECURE"),
    ("nxdomain","SECURE"),("nodata","SECURE"),("bad_nsec","BOGUS"),("nsec3_nxdomain","SECURE"),("nsec3_nodata","SECURE"),
    ("nsec3_policy","INDETERMINATE"),("opt_out","INDETERMINATE"),("wildcard","SECURE"),("wildcard_nsec3","SECURE"),("wildcard_missing","BOGUS"),
    ("key_timeout","INDETERMINATE"),("algorithm8","SECURE"),("algorithm13","SECURE"),("algorithm14","SECURE"),
    ("algorithm16","INDETERMINATE"),("digest4","SECURE"),("wrong_signer","BOGUS"),("wrong_type","BOGUS"),
    ("multi_sig","SECURE"),("ede_conflict","SECURE"),("nsec3_insecure","INSECURE"),("bad_nsec3","BOGUS")])
async def test_complete_chain_and_supported_proofs_from_real_wire(scenario,status):
    async with signed_lab(scenario) as lab:
        b=lab.backend();r=await b.call("query_authoritative",domain=b.target.domain,mode="dnssec",timeout=.2)
    assert r["data"].get("validation",{}).get("dnssec_status")==status,r
    assert all(q["DO"] and not q["RD"] for q in lab.received)
    assert len(b.calls)==len(b.dns.attempts) and len(b.attempts)==1
    assert all(v["parent_tool_call_id"]=="A1" for v in b.validation_results)
    assert all(set(v["evidence_ids"])<={e["id"] for e in b.calls} for v in b.validation_results)
    assert len({v["id"] for v in b.validation_results})==len(b.validation_results)
    if status=="SECURE":
        assert b.validation_results[-1]["local_result"]=="SIGNATURE_CHECK_PASSED"
        assert r["data"]["validation"]["trust_anchor"]["authentication"]=="EXPLICIT_TEST_ANCHOR"
    if scenario=="ds_mismatch":assert r["data"]["validation"]["failure_stage"]=="child-ds-match"
    if scenario=="missing_sig":assert r["data"]["validation"]["failure_stage"]=="target-signature"
