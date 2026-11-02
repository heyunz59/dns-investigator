"""Controlled cross-module followup; no model or real internal connection."""
import asyncio,csv,hashlib,json,subprocess,sys
from pathlib import Path
from unittest.mock import patch
import dns.rrset
from evaluation.nsec3_divergence import run as audit

EXTRA={
 'X13':('unknown_hash',True),'X14':('unknown_hash',False),
 'X15':('reserved_flags',True),'X16':('reserved_flags',False),
 'X17':('both_unknown',True),'X18':('both_unknown',False),
 'X19':('short_next',True),'X20':('short_next',False),'X21':('only_short_next',False),
 'X22':('known_noncover',False),'X23':('bad_signatures',True),
 'X24':('policy_iterations',True),'X25':('only_unknown',False),
 'X26':('wrong_zone',True),'X27':('multi_rdata',True),'X28':('opt_out',False)}
ORIGINAL=audit.variant

def variant(lab,response,case):
    if case not in EXTRA:return ORIGINAL(lab,response,case)
    factor,complete=EXTRA[case];s=lab.signed;zone='example.test.'
    base=s.nsec3([zone,'ns.example.test.'],{zone:'SOA NS DNSKEY RRSIG NSEC3','ns.example.test.':'A RRSIG NSEC3'}) if complete else audit.proofs(response)[:1]
    extra=dns.rrset.from_text('0'*32+'.'+zone,60,'IN','NSEC3','1 0 0 - '+'V'*32+' A RRSIG NSEC3')
    d=extra[0]
    if factor in {'unknown_hash','both_unknown','only_unknown'}:d=d.replace(algorithm=250)
    if factor in {'reserved_flags','both_unknown'}:d=d.replace(flags=128)
    if 'short_next' in factor:d=d.replace(next=b'\xff'*19)
    if factor=='known_noncover':d=d.replace(next=b'\0'*19+b'\1')
    if factor=='policy_iterations':d=d.replace(iterations=1)
    if factor=='opt_out':d=d.replace(flags=1)
    extra=dns.rrset.from_rdata_list(extra.name,60,[d])
    if factor=='wrong_zone':extra.name=dns.name.from_text('0'*32+'.other.'+zone)
    if factor=='multi_rdata':extra.add(d.replace(next=b'\0'*20))
    if factor in {'only_short_next','only_unknown','opt_out'}:base=[]
    rows=base if factor=='bad_signatures' else base+[extra]
    response.authority[:]=[r for r in response.authority if r.rdtype not in {50,46} or r.rdtype==46 and r.covers!=50]
    for rr in rows:
        sig=s.sig(rr,zone)
        if factor=='bad_signatures':sig=dns.rrset.from_rdata_list(sig.name,60,[sig[0].replace(signature=b'\0'*64)])
        response.authority.extend([rr,sig])
    return response

async def run(out):
    out.mkdir(parents=True,exist_ok=False)
    audit.FACTORS += [str(EXTRA[f'X{i}']) for i in range(13,29)]
    audit.variant=variant
    manifest=[]
    for case in [f'T{i:02}' for i in range(1,13)]+list(EXTRA):
        await audit.run(out/case,case)
        row=json.loads((out/case/'all-runs.json').read_text(encoding='utf-8'))[0]
        manifest.append({k:row[k] for k in ['case_id','project_status','unbound_status','project_reason','unbound_reason','input_equivalence_confirmed']})
        (out/'matrix.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')

if __name__=='__main__':asyncio.run(run(Path(sys.argv[1])))
