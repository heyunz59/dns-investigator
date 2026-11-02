import pytest
import dns.name,dns.rrset
from evaluation.signed_protocol_lab import Signed,signed_lab
from evaluation.nsec3_divergence.run import variant
from dns_investigator.dnssec_proof import denial

@pytest.mark.parametrize('label',['!'*32,'A'*31,'Z'*32])
def test_valid_complete_proof_is_not_poisoned_by_bad_owner(label):
    s=Signed('secure');z='example.test.'
    valid=s.nsec3([z,'ns.example.test.'],{z:'SOA NS DNSKEY RRSIG NSEC3','ns.example.test.':'A RRSIG NSEC3'})
    bad=dns.rrset.from_text(label+'.'+z,60,'IN','NSEC3','1 0 0 - '+'V'*32+' A')
    q=dns.name.from_text('probe.example.test.');zone=dns.name.from_text(z)
    assert denial(q,1,'NXDOMAIN',zone,valid+[bad],lambda:None)
    assert not denial(q,1,'NXDOMAIN',zone,[bad],lambda:None)

@pytest.mark.parametrize('case,expected',[('T05','SECURE'),('T06','BOGUS'),('T09','BOGUS')])
async def test_authenticated_wire_subsets_cannot_bypass_signature_or_coverage(case,expected):
    async with signed_lab('nsec3_invalid_owner') as lab:
        original=lab.answer
        def reply(i,q):
            r=original(i,q)
            return variant(lab,r,case) if r and i==2 and q.question[0].rdtype==1 else r
        lab.answer=reply;b=lab.backend()
        r=await b.call('query_authoritative',domain=b.target.domain,mode='dnssec')
    assert r['data']['validation']['dnssec_status']==expected
    assert all(set(v['evidence_ids'])<={e['id'] for e in b.calls} for v in b.validation_results)
