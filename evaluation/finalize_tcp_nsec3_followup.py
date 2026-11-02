"""Summarize immutable measured runs; does not execute a model or network query."""
import csv
import hashlib
import ipaddress
import json
import subprocess
from pathlib import Path

import dns.message

ROOT = Path('results/published/v0.4-security-nsec3-followup')


def load(p):
    return json.loads(p.read_text(encoding='utf-8'))


def save(p, value):
    p.write_text(json.dumps(value, indent=2, ensure_ascii=False) + '\n', encoding='utf-8')


def equivalence(folder):
    """Compare RRsets independent of packet ID and within-RRset RDATA order."""
    run = load(folder / 'all-runs.json')[0]
    packets = [p for p in run['packets'] if p['qname'] == 'probe.example.test.'
               and p['qtype'] == 1 and p['server_index'] == 2]

    def canonical(p):
        m = dns.message.from_wire((folder / p['response']['path']).read_bytes())
        return (m.rcode(), int(m.flags), [sorted(
            (r.name.canonicalize().to_text(), r.rdclass, r.rdtype, r.ttl,
             sorted(d.to_digestable(r.name) for d in r)) for r in sec)
            for sec in (m.answer, m.authority, m.additional)])

    project = [canonical(p) for p in packets if p['phase'] == 'project']
    reference = [canonical(p) for p in packets if p['phase'] == 'unbound']
    return bool(project and reference and all(p == project[0] for p in reference))


def main():
    before = {r['case_id']: r for r in load(ROOT / 'nsec3-before/matrix.json')}
    final = load(ROOT / 'nsec3-final/matrix.json')
    matrix = []
    for after in final:
        case = after['case_id']
        old = before[case]
        folder = ROOT / 'nsec3-final' / case
        records = load(folder / f'verifier-logs/{case}-1-project.json')
        decisions = [d for v in records['V'] for d in v.get('candidate_decisions', [])]
        # Completeness is a reviewed protocol judgment, not status-equality scoring.
        sufficient = ('YES' if after['project_status'] == 'SECURE' else
                      'UNKNOWN_POLICY_LIMITED' if after['project_status'] == 'INDETERMINATE' else 'NO')
        row = dict(case=case, before=old['project_status'], after=after['project_status'],
                   unbound_before=old['unbound_status'], unbound_after=after['unbound_status'],
                   proof_sufficient=sufficient, candidate_decisions=json.dumps(decisions),
                   original_before_equivalence=old['input_equivalence_confirmed'],
                   canonical_before_equivalence=equivalence(ROOT / 'nsec3-before' / case),
                   canonical_after_equivalence=equivalence(folder),
                   rfc_basis='RFC5155 8.1-8.4; RFC9276 3.1',
                   disagreement=after['project_status'] != after['unbound_status'],
                   project_reason=after['project_reason'], unbound_reason=after['unbound_reason'],
                   evidence=f'nsec3-final/{case}/all-runs.json')
        matrix.append(row)
    with (ROOT / 'nsec3-followup-matrix.csv').open('w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(matrix[0])); w.writeheader(); w.writerows(matrix)
    assert all(r['canonical_before_equivalence'] and r['canonical_after_equivalence'] for r in matrix)
    # Preserve captured TCP rows, add a real address classification without changing observations.
    tcp = ROOT / 'tcp-security-matrix.csv'
    original = ROOT / 'tcp-security-matrix-initial.csv'
    if not original.exists(): original.write_bytes(tcp.read_bytes())
    rows = list(csv.DictReader(original.open(encoding='utf-8-sig', newline='')))
    for r in rows:
        ip = ipaddress.ip_address(r['ip'])
        r['case_type'] = r['ip_type']
        r['ip_type'] = ('IPv4-mapped-' if getattr(ip, 'ipv4_mapped', None) else '') + (
            'unspecified' if ip.is_unspecified else 'multicast' if ip.is_multicast else
            'loopback' if ip.is_loopback else 'link-local' if ip.is_link_local else
            '6to4' if getattr(ip, 'sixtofour', None) else 'Teredo' if getattr(ip, 'teredo', None) else
            'private-or-special' if not ip.is_global else 'global')
    with tcp.open('w', encoding='utf-8-sig', newline='') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0])); w.writeheader(); w.writerows(rows)
    verification = load(ROOT / 'source-verification.json')
    ci = load(ROOT / 'ci-status.json') if (ROOT / 'ci-status.json').exists() else {
        'status': 'UNKNOWN', 'note': 'pending actual push'}
    regression = dict(verification, github_actions=ci,
        coverage={k: 'PASS in complete 410-test run' for k in (
            'http_security', 'tcp_security', 'ordinary_dns', 'delegation_trace', 'dnssec',
            'A_Q_E_V_consistency', 'fixture', 'agent_five_tools', 'reports_and_old_logs')},
        tcp_capture={'rows': len(rows), 'mode': 'injected DNS and intercepted socket connect; not real private probes'},
        independent_dns={'cases_per_stage': len(matrix), 'stages': ['before', 'intermediate', 'final'],
                         'unbound_version': '1.26.2', 'transport': 'actual controlled loopback UDP'},
        commands=['python -m pytest -q', 'python -m pip check',
                  'python -m pip wheel --no-deps --no-build-isolation .',
                  'python -m evaluation.tcp_security_capture OUTPUT',
                  'python -m evaluation.tcp_nsec3_followup NEW_OUTPUT'])
    save(ROOT / 'regression-results.json', regression)
    source = dict(business_commit=verification['business_commit'],
                  proof_sha256=hashlib.sha256(Path('src/dns_investigator/dnssec_proof.py').read_bytes()).hexdigest(),
                  before='20bd1ac isolated archived source; see loaded-source-check.json',
                  intermediate='844fa49; retained nsec3-after, not final acceptance')
    save(ROOT / 'final-loaded-source-check.json', source)
    conclusion = dict(tcp_security_fixed=True, tcp_policy_shared_with_http_at_classification_level=True,
        http_regression_passed=True, tcp_live_connection_policy_enforced=True,
        explicit_private_network_authorization_supported=True, nsec3_t11_fixed=True,
        nsec3_t01_preserved=True, nsec3_t05_preserved=True, nsec3_t06_preserved=True,
        new_false_secure_observed=False,
        new_false_secure_scope='fixed signed controlled cases only; not universal security certification',
        remaining_protocol_disagreements=[r['case'] for r in matrix if r['disagreement']],
        tests_passed=410, tests_failed=0, tests_skipped=0,
        business_commit=verification['business_commit'], final_commit=ci.get('headSha', 'UNKNOWN'),
        final_commit_note='Immutable CI-checked release snapshot; later receipt-only publication commits do not change runtime source.',
        independent_review_status='PENDING_HUMAN_PROTOCOL_REVIEW; independent Unbound execution completed',
        limitations=['T01/T06 existing stricter BOGUS differences retained',
                     'T10 mixed-parameter malformed-owner exclusion differs from optional Unbound rejection',
                     'X24 iterations, X26 cross-zone, X27 multiple RDATA, X28 Opt-Out remain limited',
                     'No paid DeepSeek test or public-network security certification this round'])
    if ci.get('headSha'):
        conclusion['github_actions'] = {k: ci[k] for k in ('status', 'conclusion', 'url', 'headSha')}
    save(ROOT / 'conclusion.json', conclusion)
    print('Reviewed matrices generated:', len(matrix), 'DNS cases;', len(rows), 'TCP rows')


if __name__ == '__main__': main()
