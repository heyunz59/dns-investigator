"""Finalization tests: constructed provenance, unchanged admission, CLI allocation."""
import copy
import json
from pathlib import Path
import pytest
from dns_investigator.remediation import dns_method
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target
from dns_investigator.main import summary
from evaluation.report_quality import report


def sample(parent='query_dns',server='10.0.0.53',requested=None,explicit=True):
    b=ToolBackend(parse_target('probe.example'));b.dns.system=['10.0.0.53','10.0.0.54']
    args=dict(domain='probe.example',record_type='A')
    if explicit:args['resolver']=requested
    b.attempts=[dict(attempt_id='A1',tool_name=parent,input=args)]
    b.calls=[dict(id='E1',tool_call_id='A1',source_mode='live')]
    f=dict(evidence_id='E1',target='probe.example',record_type='A',resolver=server,source_mode='live')
    return b,f


@pytest.mark.parametrize('explicit',[True,False])
def test_system_path_maps_none_not_private_ip(explicit):
    b,f=sample(explicit=explicit);before=copy.deepcopy((b.calls,b.attempts,b.dns.attempts,b.dns.system,b.resolvers))
    m=dns_method(f,b)
    assert m['parameters']['resolver'] is None and m['supported_by_current_tools']
    assert m['authorization_status']=='accepted_by_current_validation' and not m['can_execute_now']
    b._validate('query_dns',m['parameters'])
    assert before==(b.calls,b.attempts,b.dns.attempts,b.dns.system,b.resolvers)


def test_explicit_public_maps_and_passes_existing_policy():
    b,f=sample(server='1.1.1.1',requested='1.1.1.1');m=dns_method(f,b)
    assert m['parameters']['resolver']=='1.1.1.1' and m['supported_by_current_tools']
    b._validate('query_dns',m['parameters'])


def test_other_private_rejected_without_widening_policy():
    b,f=sample(server='10.20.0.53',requested='10.20.0.53');before=(b.dns.system[:],b.resolvers)
    m=dns_method(f,b)
    assert m['parameters_constructed'] and not m['supported_by_current_tools']
    assert m['authorization_status']=='rejected' and not m['can_execute_now']
    assert before==(b.dns.system,b.resolvers)


@pytest.mark.parametrize('case',['no_parent','mismatched_ip','wrong_parent','missing_target','overlap','no_backend'])
def test_incomplete_or_ambiguous_provenance_is_not_direct_execution(case):
    b,f=sample()
    if case=='no_parent':b.attempts=[]
    if case=='mismatched_ip':b.attempts[0]['input']['resolver']='1.1.1.1'
    if case=='wrong_parent':b.attempts[0]['tool_name']='query_authoritative'
    if case=='missing_target':b.attempts[0]['input'].pop('domain')
    if case=='overlap':
        b.attempts[0]['tool_name']='compare_resolvers';b.dns.system=['1.1.1.1'];f['resolver']='1.1.1.1'
    m=dns_method(f,None if case=='no_backend' else b)
    assert m['authorization_status']=='unknown' and not m['supported_by_current_tools']
    assert not m['can_execute_now']


@pytest.mark.parametrize('server,resolver',[('10.0.0.53',None),('1.1.1.1','1.1.1.1')])
def test_compare_paths_require_unique_origin(server,resolver):
    b,f=sample(parent='compare_resolvers',server=server);m=dns_method(f,b)
    assert m['parameters']['resolver']==resolver and m['supported_by_current_tools']


def parallel_report():
    p=Path('results/published/v05-report-quality-fixes/20261102-report-quality/before.json')
    row=next(r for r in json.loads(p.read_text(encoding='utf-8'))['cases'] if r['case']=='multi-ambiguous')
    return report(row)


def test_parallel_gets_check_for_each_issue_without_mutating_json(capsys):
    r=parallel_report();before=copy.deepcopy(r);summary(r);text=capsys.readouterr().out
    assert '[TCP_REFUSED] CHECK' in text and '[HTTP_503] CHECK' in text
    assert text.count('（尚未执行）')<=3 and r==before
    assert r['diagnostic_conclusion'] is None and len(r['secondary_diagnoses'])==2


def test_parallel_truncation_is_explicit(capsys):
    r=parallel_report()
    for index in range(3):
        d=copy.deepcopy(r['secondary_diagnoses'][0]);d['primary_issue']='EXTRA_'+str(index);r['secondary_diagnoses'].append(d)
    before=copy.deepcopy(r);summary(r);text=capsys.readouterr().out
    assert '另有 2 项独立观测的 CHECK' in text and text.count('（尚未执行）')==3
    assert 'EXTRA_2' not in '\n'.join(s for s in text.splitlines() if '（尚未执行）' in s)
    assert r==before


def test_primary_still_gets_first_action(capsys):
    r=parallel_report();r['diagnostic_conclusion']=r['secondary_diagnoses'].pop();r['diagnosis_selection_mode']='primary'
    expected=r['diagnostic_conclusion']['primary_issue'];summary(r)
    lines=[s for s in capsys.readouterr().out.splitlines() if '（尚未执行）' in s]
    assert lines[0].startswith('['+expected+'] CHECK')
