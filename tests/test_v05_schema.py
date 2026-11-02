from dns_investigator.schemas import InvestigationResult, DiagnosticConclusion


def test_old_report_roundtrip_defaults():
    old=dict(observations=[],hypotheses=[],conclusion='old',conclusion_evidence_ids=[],limitations=[],recommendations=[])
    r=InvestigationResult.model_validate(old)
    assert r.diagnostic_conclusion is None and r.remediation_plan==[]
    assert InvestigationResult.model_validate_json(r.model_dump_json()).conclusion=='old'


def test_unknown_is_not_false():
    r=DiagnosticConclusion(diagnosis_status='INSUFFICIENT_EVIDENCE',primary_issue='unknown',summary='unknown',
        fault_location='unknown',cause='unknown',reason='no evidence')
    assert r.fault_detected is None and r.cause_status=='UNKNOWN'
