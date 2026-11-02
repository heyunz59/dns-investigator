"""Authenticated but malformed denial content must not establish absence."""
import dns.dnssec,dns.name,dns.rdatatype,dns.rrset
import pytest
from dns_investigator.dnssec_proof import denial,ProofUnsupported


def material(invalid_owner=False,dname=False):
    zone=dns.name.from_text("example.test.");q=dns.name.from_text("probe.example.test.")
    ce=dns.dnssec.nsec3_hash(zone,b"",0,1)
    next_name=dns.dnssec.nsec3_hash(q,b"",0,1) if invalid_owner else ce
    apex=dns.rrset.from_text(ce+"."+str(zone),60,"IN","NSEC3",f"1 0 0 - {next_name} SOA NS DNSKEY RRSIG NSEC3"+(" DNAME" if dname else ""))
    rows=[apex]
    if invalid_owner:
        rows.append(dns.rrset.from_text("!"*32+"."+str(zone),60,"IN","NSEC3","1 0 0 - "+"V"*32+" A RRSIG NSEC3"))
    return zone,q,rows


def test_invalid_base32_owner_cannot_supply_missing_nsec3_cover():
    zone,q,rows=material(invalid_owner=True)
    assert not denial(q,1,"NXDOMAIN",zone,rows,lambda:None)


@pytest.mark.parametrize("wildcard",[False,True])
def test_dname_at_closest_encloser_is_not_normal_negative_or_wildcard_proof(wildcard):
    zone,q,rows=material(dname=True)
    with pytest.raises(ProofUnsupported,match="DNAME"):
        denial(q,1,"NXDOMAIN" if not wildcard else "NOERROR",zone,rows,lambda:None,wildcard_base=zone if wildcard else None)
