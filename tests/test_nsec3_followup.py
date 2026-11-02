import dns.name,dns.rrset
import pytest
from evaluation.signed_protocol_lab import Signed
from dns_investigator.dnssec_proof import denial,ProofUnsupported,nsec3_candidate

@pytest.mark.parametrize('kind',['unknown','flags','both','next','zone'])
@pytest.mark.parametrize('complete',[True,False])
def test_ineligible_candidates_cannot_poison_or_complete_proof(kind,complete):
    s=Signed('secure');z=dns.name.from_text('example.test.');q=dns.name.from_text('probe.example.test.')
    valid=s.nsec3([str(z),'ns.example.test.'],{str(z):'SOA NS DNSKEY RRSIG NSEC3','ns.example.test.':'A RRSIG NSEC3'}) if complete else []
    rr=dns.rrset.from_text('0'*32+'.'+str(z),60,'IN','NSEC3','1 0 0 - '+'V'*32+' A')
    d=rr[0]
    if kind in {'unknown','both'}:d=d.replace(algorithm=250)
    if kind in {'flags','both'}:d=d.replace(flags=128)
    if kind=='next':d=d.replace(next=b'\xff'*19)
    rr=dns.rrset.from_rdata_list(rr.name,60,[d])
    if kind=='zone':rr.name=dns.name.from_text('0'*32+'.other.example.test.')
    assert nsec3_candidate(rr,z)[0]=='ignored'
    assert denial(q,1,'NXDOMAIN',z,valid+[rr],lambda:None) is complete

@pytest.mark.parametrize('kind',['iteration','salt','optout','multi'])
def test_unsupported_material_keeps_explicit_policy_limit(kind):
    rr=dns.rrset.from_text('0'*32+'.example.test.',60,'IN','NSEC3','1 0 0 - '+'V'*32+' A')
    d=rr[0]
    if kind=='iteration':d=d.replace(iterations=1)
    if kind=='salt':d=d.replace(salt=b'x')
    if kind=='optout':d=d.replace(flags=1)
    rr=dns.rrset.from_rdata_list(rr.name,60,[d])
    if kind=='multi':rr.add(d.replace(next=b'\0'*20))
    with pytest.raises(ProofUnsupported):denial(dns.name.from_text('probe.example.test.'),1,'NXDOMAIN',dns.name.from_text('example.test.'),[rr],lambda:None)
