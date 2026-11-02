"""Actual before/after report replay on newly acquired controlled measurements, no LLM."""
import asyncio
import hashlib
import json
import subprocess
import sys
import types
from pathlib import Path
from dns_investigator.schemas import InvestigationResult
from dns_investigator.reporting import evidence_bound_report
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target
from dns_investigator.http_safety import HTTPPolicy,PinnedTransport,AuthorizedBackend
from evaluation.controlled_dns import controlled
from evaluation.signed_protocol_lab import signed_lab
from evaluation.protocol_lab import protocol_lab

BASELINE='aed194ac53b9f9af8f2637c8b4d2efd9fd772317'


def fresh():
    return InvestigationResult(observations=[],hypotheses=[],conclusion='draft',conclusion_evidence_ids=[],limitations=[],recommendations=[])


async def capture(out):
    out.mkdir(parents=True,exist_ok=False)
    old=types.ModuleType('dns_investigator._v04_report_replay');old.__package__='dns_investigator'
    exec(subprocess.check_output(['git','show',BASELINE+':src/dns_investigator/reporting.py']).decode('utf-8'),old.__dict__)
    cases=[]
    def save(label,b,mode):
        before=old.evidence_bound_report(fresh(),b).model_dump()
        after=evidence_bound_report(fresh(),b).model_dump()
        assert before['measured_facts']==after['measured_facts']
        row=dict(case=label,source_mode=mode,evidence=b.calls,attempts=b.attempts,dns_attempts=b.dns.attempts,
            validation_results=getattr(b,'validation_results',[]),before=before,after=after,
            review='AUTOMATIC_STRUCTURAL_AND_RULE_CHECKS; PENDING_INDEPENDENT_HUMAN_SEMANTIC_REVIEW')
        (out/(label+'.json')).write_text(json.dumps(row,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
        cases.append(dict(case=label,status=after['diagnostic_conclusion']['diagnosis_status'],
            layer=after['diagnostic_conclusion']['fault_layer'],file=label+'.json'))
    for scenario in ['timeout','normal','mismatch']:
        async with controlled(scenario):
            b=ToolBackend(parse_target('probe.example'))
            await b.call('compare_resolvers',domain=b.target.domain,timeout=.15)
            if scenario=='mismatch':await b.call('query_authoritative',domain=b.target.domain,timeout=.15)
        save('dns-'+scenario,b,'actual_controlled_loopback_udp_no_model')
    for scenario in ['ds_mismatch','tampered','insecure']:
        async with signed_lab(scenario) as lab:
            b=lab.backend();await b.call('query_authoritative',domain=b.target.domain,mode='dnssec',timeout=.2)
        save('dnssec-'+scenario,b,'actual_signed_loopback_dns_local_crypto_no_model')
    for scenario in ['normal','non_aa','timeout']:
        async with protocol_lab(scenario) as lab:
            b=lab.backend();await b.call('query_authoritative',domain=b.target.domain,mode='trace',timeout=.1)
        save('trace-'+scenario,b,'actual_controlled_loopback_trace_no_model')
    async def handler(reader,writer):
        try:
            await reader.readuntil(b'\r\n\r\n')
            writer.write(b'HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n');await writer.drain()
        finally:writer.close();await writer.wait_closed()
    server=await asyncio.start_server(handler,'127.0.0.1',0)
    try:
        port=server.sockets[0].getsockname()[1];b=ToolBackend(parse_target(f'http://probe.example:{port}/status'))
        b.http_policy=HTTPPolicy(b.target.url,allowed_networks=('127.0.0.1/32',))
        async def resolver(*a):return ['127.0.0.1']
        b.http_transport_factory=lambda p:PinnedTransport(p,AuthorizedBackend(p,resolver=resolver))
        await b.call('check_http',url=b.target.url)
        save('http-503',b,'actual_loopback_http_test_only_explicit_permission_no_model')
    finally:server.close();await server.wait_closed()
    metadata=dict(baseline_report_function=BASELINE,
        business_commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        source_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path('src/dns_investigator').glob('*.py')},
        model_calls=0,public_network_tests=0,controlled_cases=cases,
        baseline_replay_note='Original reporting.py loaded from immutable Git baseline, compatibility schemas from current checkout; no historical measurement rewritten.')
    (out/'index.json').write_text(json.dumps(metadata,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(cases,indent=2))


if __name__=='__main__':asyncio.run(capture(Path(sys.argv[1])))
