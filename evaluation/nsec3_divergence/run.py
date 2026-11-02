import asyncio,base64,csv,hashlib,json,platform,subprocess,sys,time,uuid
from pathlib import Path
from unittest.mock import patch
from importlib.metadata import version
import dns.message,dns.rdatatype,dns.dnssec,dns.rrset
from evaluation.protocol_lab import UDP
from evaluation.signed_protocol_lab import signed_lab
from .reference import reference,reference_ports
from dns_investigator.dnssec_proof import denial,between
from dns_investigator.dnssec_validation import POLICY_VERSION

ROOT=Path('results/published/nsec3-divergence-audit')
FACTORS=['unchanged original','remove malformed','malformed only','valid ring','valid ring + extra malformed','same as T01 incomplete + malformed','replace malformed by valid noncovering owner','signed exact Q hash contradicts NXDOMAIN','valid semantics but invalid signatures','extra iterations=1 parameter','extra unknown algorithm/flags','no denial records']
def sha(b):return hashlib.sha256(b).hexdigest()
def save(p,d):p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(d,ensure_ascii=False,indent=2),encoding='utf-8')
def proofs(response):return [r for r in response.authority if r.rdtype==50]
def variant(lab,response,case):
    if case=='T01':return response
    original=proofs(response);bad=original[-1];signed=lab.signed;zone='example.test.';q='probe.example.test.'
    valid=signed.nsec3([zone,'ns.example.test.'],{zone:'SOA NS DNSKEY RRSIG NSEC3','ns.example.test.':'A RRSIG NSEC3'})
    rs=original
    if case=='T02':rs=original[:1]
    if case=='T03':rs=[bad]
    if case=='T04':rs=valid
    if case=='T05':rs=valid+[bad]
    if case=='T07':rs=original[:1]+[dns.rrset.from_text('0'*32+'.'+zone,60,'IN','NSEC3','1 0 0 - '+'0'*31+'1 A')]
    if case=='T08':rs=signed.nsec3([zone,q],{zone:'SOA NS DNSKEY RRSIG NSEC3',q:'A RRSIG NSEC3'})
    if case=='T09':rs=valid
    if case=='T10':rs=valid+[dns.rrset.from_rdata_list(bad.name,60,[bad[0].replace(iterations=1)])]
    if case=='T11':rs=valid+[dns.rrset.from_rdata_list(bad.name,60,[bad[0].replace(algorithm=250,flags=128)])]
    if case=='T12':rs=[]
    response.authority[:]=[r for r in response.authority if r.rdtype not in {50,46} or r.rdtype==46 and r.covers!=50]
    for r in rs:
        sig=signed.sig(r,zone)
        if case=='T09':sig=dns.rrset.from_rdata_list(sig.name,60,[sig[0].replace(signature=b'\0'*64)])
        response.authority.extend([r,sig])
    return response

async def run(out=ROOT,only=None):
    out.mkdir(parents=True,exist_ok=False);wire=out/'raw-wire';wire.mkdir();logs=out/'verifier-logs';logs.mkdir()
    baseline=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip();raw=Path('results/runs/nsec3-audit')/uuid.uuid4().hex
    env=dict(git_commit=baseline,business_source_commit=subprocess.check_output(['git','log','-1','--format=%H','--','src/dns_investigator'],text=True).strip(),python_version=platform.python_version(),os=platform.system(),
        harness_hashes={p.name:sha(p.read_bytes()) for p in Path('evaluation/nsec3_divergence').glob('*.py')},
        dnspython_version=version('dnspython'),cryptography_version=version('cryptography'),unbound_version='1.26.2',
        unbound_binary_sha256=sha(Path('results/runs/reference-tools/unbound-1.26.2/libunbound/libunbound-8.dll').read_bytes()),
        business_hashes={p.name:sha(p.read_bytes()) for p in Path('src/dns_investigator').glob('dnssec*.py')},dnssec_algorithm_policy=POLICY_VERSION,
        experiment_configuration='Original Unbound config unchanged; new spawned context per run; no historical cache; only observer/response-variant injection',
        source_mode='actual controlled loopback UDP; no LLM; signing seeds test-only, private material not exported')
    save(out/'environment.json',env);index=[];runs=[];analysis=None
    plan=[('T01',i) for i in range(1,4)]+[(f'T{i:02}',1) for i in range(2,13)]
    if only:plan=[(only,1)]
    for case,repeat in plan:
        label=f'{case}-{repeat}';packets=[];phase=['project']
        async with signed_lab('nsec3_invalid_owner') as lab:
            lab.audit_debug=len(sys.argv)>3 and sys.argv[3]=='debug'
            original=lab.answer
            def answer(i,q):
                r=original(i,q)
                if r and i==2 and q.question[0].rdtype==1 and str(q.question[0].name)=='probe.example.test.':r=variant(lab,r,case)
                return r
            lab.answer=answer
            def receive(protocol,raw,peer):
                q=dns.message.from_wire(raw);r=lab.answer(protocol.index,q)
                if r is None:return
                data=r.to_wire();seq=len(packets)
                row=dict(phase=phase[0],server_index=protocol.index,qname=str(q.question[0].name),qtype=q.question[0].rdtype)
                for kind,b in [('query',raw),('response',data)]:
                    name=f'{label}-{seq:03}-{kind}.wire';(wire/name).write_bytes(b);row[kind]=dict(path='raw-wire/'+name,sha256=sha(b))
                packets.append(row);protocol.transport.sendto(data,peer)
            with patch.object(UDP,'datagram_received',receive):
                b=lab.backend();ret=await b.call('query_authoritative',domain=b.target.domain,mode='dnssec',timeout=.2)
                phase[0]='unbound'
                async with reference_ports(lab):ref=await reference(lab,'results/runs/reference-tools/unbound-1.26.2',raw/label)
            save(logs/(label+'-project.json'),dict(returned=ret,attempts=b.attempts,Q=b.dns.attempts,E=b.calls,V=b.validation_results))
            save(logs/(label+'-unbound.json'),ref)
            conf=raw/label/'reference.conf'
            # Disposable local root-hints path is replaced by an explicit alias.
            text=conf.read_text();text='\n'.join(' root-hints: "CONTROLLED_ROOT_HINTS"' if l.strip().startswith('root-hints:') else l for l in text.splitlines())
            (logs/(label+'-reference.conf')).write_text(text,encoding='utf-8')
            if (raw/label/'unbound-debug.log').exists():
                (logs/(label+'-unbound-debug.log')).write_bytes((raw/label/'unbound-debug.log').read_bytes())
            target=[p for p in packets if p['qname']=='probe.example.test.' and p['qtype']==1 and p['server_index']==2]
            def canonical(p):
                m=dns.message.from_wire((out/p['response']['path']).read_bytes())
                return sorted((r.name.to_text(),r.rdtype,r.to_text()) for sec in [m.answer,m.authority,m.additional] for r in sec)
            pe=[p for p in target if p['phase']=='project'];ue=[p for p in target if p['phase']=='unbound']
            equal=bool(pe and ue and all(canonical(p)==canonical(pe[0]) for p in ue))
            status='UNKNOWN' if ref.get('error') else 'SECURE' if ref['secure'] else 'BOGUS' if ref['bogus'] else 'INSECURE'
            v=ret['data']['validation'];row=dict(case_id=case,repeat=repeat,changed_factor=FACTORS[int(case[1:])-1],project_status=v['dnssec_status'],
                unbound_status=status,project_reason=v['reason_code'],unbound_reason=ref.get('why_bogus') or ref.get('error'),
                input_equivalence_confirmed=equal,input_hash=pe[0]['response']['sha256'] if pe else None,
                packets=packets,validation_time=lab.signed.now,project_validation_time=v['validation_scope'].get('validation_time'),
                anchor=lab.signed.anchor,anchor_fingerprint=sha(json.dumps(lab.signed.anchor,sort_keys=True).encode()),
                reference_cache='new libunbound context/process; empty at start',reference_requests=sum(p['phase']=='unbound' for p in packets),
                project_requests=len(b.dns.attempts),proof_sufficient='PENDING_PROTOCOL_ANALYSIS',evidence_files=f'verifier-logs/{label}-project.json',
                rfc_basis='RFC5155 8.1-8.4',interpretation='not adjudicated from status equality')
            runs.append(row);index.extend(packets)
            if case=='T01' and repeat==1:
                msg=dns.message.from_wire((out/pe[0]['response']['path']).read_bytes());zone=dns.name.from_text('example.test.');q=dns.name.from_text('probe.example.test.');wc=dns.name.from_text('*.example.test.')
                hashes={str(n):dns.dnssec.nsec3_hash(n,b'',0,1) for n in [zone,q,wc]};rrs=[]
                for rr in proofs(msg):
                    d=rr[0];owner=rr.name.labels[0].decode();nxt=base64.b32hexencode(d.next).decode()
                    sig=next(r for r in msg.authority if r.rdtype==46 and r.name==rr.name and r.covers==50)
                    dns.dnssec.validate(rr,sig,{zone:lab.signed.keys['example.test.']},now=lab.signed.now)
                    rrs.append(dict(owner=str(rr.name),owner_hash=owner,next_hash=nxt,bitmap=d.to_text().split()[5:],base32hex_valid=all(c in '0123456789ABCDEFGHIJKLMNOPQRSTUV' for c in owner.upper()),
                        signature_validation='PASSED',signature=sig.to_text(),parameters=dict(algorithm=d.algorithm,iterations=d.iterations,salt=d.salt.hex(),flags=d.flags),
                        covers={k:between(owner.upper(),h,nxt) for k,h in hashes.items()},exact={k:owner.upper()==h for k,h in hashes.items()},
                        project_used='invalid owner rejects complete proof pool',unbound_used='UNKNOWN: infer via differential tests plus source, not instrumented internal execution'))
                analysis=dict(qname=str(q),qtype='A',qclass='IN',zone=str(zone),closest_encloser=str(zone),next_closer=str(q),wildcard=str(wc),hashes=hashes,records=rrs)
        save(out/'all-runs.json',runs);print(label,v['dnssec_status'],status,'equivalent',equal,flush=True)
    save(wire/'index.json',index);save(out/'original-reproduction.json',runs[:3]);save(out/'proof-analysis.json',analysis)
    with (out/'differential-matrix.csv').open('w',encoding='utf-8-sig',newline='') as f:
        fields=['case_id','input_hash','changed_factor','project_status','unbound_status','project_reason','unbound_reason','proof_sufficient','evidence_files','rfc_basis','interpretation']
        w=csv.DictWriter(f,fieldnames=fields);w.writeheader();w.writerows({k:r[k] for k in fields} for r in [runs[0]]+runs[3:])

if __name__=='__main__':asyncio.run(run(Path(sys.argv[1]) if len(sys.argv)>1 else ROOT,sys.argv[2] if len(sys.argv)>2 else None))
