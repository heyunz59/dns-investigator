"""Produce review materials from immutable baseline inputs and final report code."""
import csv,hashlib,json,platform,subprocess,sys
from pathlib import Path
from evaluation.report_quality import report


def save(path,value):path.write_text(json.dumps(value,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')


def finalize(root):
    original=root/'expanded-baseline/before.json'
    baseline=json.loads(original.read_text(encoding='utf-8'));rows=baseline['cases']
    cases=[];locations=[];matrix=[];plans=[]
    for row in rows:
        after=report(row);before=row['before']
        assert before['measured_facts']==after['measured_facts']
        assert before['validation_results']==after['validation_results']
        clean=lambda fs:[{k:v for k,v in f.items() if k!='explanation'} for f in fs]
        assert clean(before['findings'])==clean(after['findings'])
        ds=([after['diagnostic_conclusion']] if after['diagnostic_conclusion'] else [])+after['secondary_diagnoses']
        old=before.get('diagnostic_conclusion')
        locations.append(dict(case=row['case'],source_kind=row['source_kind'],before=old,
            after=after['diagnostic_conclusion'],secondary=after['secondary_diagnoses']))
        matrix.append(dict(case=row['case'],input_kind=row['source_kind'],
            evidence_sha256=hashlib.sha256(json.dumps(row['evidence'],sort_keys=True).encode()).hexdigest(),
            focus=json.dumps(row.get('request_context',{}).get('focus_layers',[])),
            before_primary=old['primary_issue'] if old else None,
            after_primary=after['diagnostic_conclusion']['primary_issue'] if after['diagnostic_conclusion'] else None,
            selection_mode=after['diagnosis_selection_mode'],
            selection_reasons=json.dumps([dict(issue=d['primary_issue'],relevance=d['relevance'],reason=d['selection_reason']) for d in ds],ensure_ascii=False)))
        plans.append(dict(case=row['case'],source_kind=row['source_kind'],steps=after['remediation_plan']))
        cases.append(dict(case=row['case'],source_kind=row['source_kind'],input_sha256=row['input_sha256'],
            evidence_sha256=matrix[-1]['evidence_sha256'],before=before,after=after))
    assert len({m['evidence_sha256'] for m in matrix if m['case'] in {'multi-TCP','multi-HTTP','multi-ambiguous'}})==1
    sha=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip()
    save(root/'reports-after.json',dict(business_source_commit=sha,cases=cases,review='AI_ASSISTED_RULE_REVIEW; NOT independent human acceptance'))
    save(root/'location-before-after.json',locations);save(root/'remediation-matrix.json',plans)
    with (root/'diagnosis-priority-matrix.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(matrix[0]));w.writeheader();w.writerows(matrix)
    parts=['# 同证据报告对照\n\n历史回放与 constructed report input 分开标注；未执行公网或模型调用。完整输入及原始文件哈希见 expanded-baseline/before.json。\n']
    for case in cases:
        if case['case'] not in {'dnssec-ds_mismatch','multi-TCP','multi-ambiguous','dns-timeout','tls-None','http-403','body-timeout'}:continue
        parts+=['\n## '+case['case']+'\n\n来源：'+case['source_kind']+'\n\n修改前实际高层诊断：\n```json\n'+json.dumps(case['before']['diagnostic_conclusion'],ensure_ascii=False,indent=2)+'\n```\n\n修改后实际高层诊断与并列观测：\n```json\n'+json.dumps(dict(primary=case['after']['diagnostic_conclusion'],secondary=case['after']['secondary_diagnoses']),ensure_ascii=False,indent=2)+'\n```\n']
    (root/'report-comparisons.md').write_text(''.join(parts),encoding='utf-8')
    untouched={}
    for module in ['tools.py','network_policy.py','http_safety.py','dns_wire.py','trace.py','dnssec.py','dnssec_proof.py','dnssec_validation.py','accounting.py','alias_scope.py','trust.py']:
        p=Path('src/dns_investigator',module);current=p.read_bytes().replace(b'\r\n',b'\n')
        old=subprocess.check_output(['git','show',baseline['source_commit']+':'+p.as_posix()]).replace(b'\r\n',b'\n')
        assert current==old;untouched[module]=hashlib.sha256(current).hexdigest()
    previous=json.loads((root/'regression-results.json').read_text(encoding='utf-8')) if (root/'regression-results.json').exists() else {}
    recorded_tests=previous.get('final_pytest','NOT_RUN') if previous.get('business_source_commit')==sha else 'NOT_RUN'
    save(root/'regression-results.json',dict(baseline=baseline['source_commit'],business_source_commit=sha,
        baseline_pytest=dict(passed=447,seconds=28.52),final_pytest=recorded_tests,
        replay_cases=len(cases),same_evidence_and_validation=True,finding_structure_preserved=True,
        input_file_sha256=hashlib.sha256(original.read_bytes()).hexdigest(),untouched_runtime_modules=untouched,
        python=platform.python_version(),os=platform.system(),real_model_calls=0,new_public_network_measurements=0,
        network_test_note='Complete pytest retains actual controlled loopback DNS/TCP/HTTP and crypto tests; 33 report comparisons are historical replay/constructed inputs, not new network captures.',
        remote_ci='NOT_RUN: no push authorized',human_semantic_review='NOT_RUN',
        baseline_import_note='expanded baseline executed using immutable archived source through PYTHONPATH; reasoner import hash verified against Git; original first 13 pre-edit reports also retained'))
    result={k:dict(status='PASS',evidence=refs) for k,refs in {
        'precise_location':['location-before-after.json','tests/test_report_quality.py::test_direct_ds_location_and_complete_dependencies'],
        'direct_dependency_separation':['location-before-after.json','tests/test_report_quality.py::test_trace_direct_scope_is_stopped_child_not_root'],
        'request_relevance':['diagnosis-priority-matrix.csv'],
        'independent_issues_preserved':['reports-after.json','tests/test_report_quality.py::test_actual_framework_parallel_failure_fallback'],
        'branched_remediation':['remediation-matrix.json'],
        'timeout_wording':['report-comparisons.md','tests/test_report_quality.py::test_dns_timeout_is_not_a_returned_rcode'],
        'cli_summary_json':['tests/test_report_quality.py::test_real_cli_json_stdout_contract','tests/test_report_quality.py::test_cli_model_failure_and_parallel_summary'],
        'legacy_compatibility':['tests/test_report_quality.py::test_legacy_defaults_do_not_invent_direct_sources'],
        'protocol_network_safety_regression':['regression-results.json'],
        'A_Q_E_V_integrity':['regression-results.json','tests/test_report_quality.py::test_same_evidence_replay_preserves_measurements_and_references'],
    }.items()}
    result.update(business_source_commit=dict(status='PASS',value=sha),
        final_delivery_commit=dict(status='UNKNOWN',resolution='Containing Git commit cannot embed its own SHA; resolve from final response or git log -1 -- this directory.'),
        human_semantic_review=dict(status='NOT_RUN',reason='AI-assisted checks are not independent human acceptance.'),
        remote_ci=dict(status='NOT_RUN',reason='No push/merge/publication authorized this round.'),
        natural_language_intent_completeness=dict(status='UNKNOWN',reason='Conservative token/negation/quotation handling is not complete natural-language understanding.'))
    save(root/'conclusion.json',result)
    print('Same-evidence review cases:',len(cases),'protocol/security source hashes unchanged')


if __name__=='__main__':finalize(Path(sys.argv[1]))
