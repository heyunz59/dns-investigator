"""Deterministic TEST-ONLY signed root/TLD/child data; never a production trust anchor."""
import hashlib,time
import dns.dnssec,dns.rrset,dns.rdatatype,dns.flags,dns.rcode,dns.name
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric import rsa,ec,ed448
from contextlib import asynccontextmanager
from unittest.mock import patch
from .protocol_lab import Lab,protocol_lab


class Signed:
    def __init__(self,scenario):
        self.scenario=scenario;self.now=int(time.time());self.zones=[".","test.","example.test."]
        self.private={z:Ed25519PrivateKey.from_private_bytes(hashlib.sha256(("DNS-INVESTIGATOR-TEST-ONLY-"+z).encode()).digest()) for z in self.zones}
        algorithm={"algorithm8":8,"algorithm13":13,"algorithm14":14,"algorithm16":16}.get(scenario,15)
        if algorithm==8:self.private={z:rsa.generate_private_key(public_exponent=65537,key_size=2048) for z in self.zones}
        if algorithm in {13,14}:self.private={z:ec.derive_private_key(i+73,ec.SECP256R1() if algorithm==13 else ec.SECP384R1()) for i,z in enumerate(self.zones)}
        if algorithm==16:self.private={z:ed448.Ed448PrivateKey.from_private_bytes(hashlib.sha512(z.encode()).digest()[:57]) for z in self.zones}
        self.key={z:dns.dnssec.make_dnskey(k.public_key(),algorithm,flags=257) for z,k in self.private.items()}
        self.keys={z:dns.rrset.from_rdata_list(z,60,[key]) for z,key in self.key.items()}
        self.ds={z:dns.rrset.from_rdata_list(z,60,[dns.dnssec.make_ds(z,key,4 if scenario=="digest4" else 2)]) for z,key in self.key.items()}
        if scenario=="ds_mismatch":self.ds["example.test."]=dns.rrset.from_rdata_list("example.test.",60,[self.ds["example.test."][0].replace(digest=b"\x00"*32)])
        if scenario=="multi_ds":self.ds["example.test."].add(self.ds["example.test."][0].replace(digest=b"\x00"*32))
        if scenario=="rollover":
            older=Ed25519PrivateKey.from_private_bytes(b"\x01"*32)
            self.keys["example.test."].add(dns.dnssec.make_dnskey(older.public_key(),15,flags=257))

    @property
    def anchor(self):return dict(zone=".",ds=[r.to_text() for r in self.ds["."]],version="explicit-test-anchor-v1",authentication="EXPLICIT_TEST_ANCHOR",source="isolated_test_only")

    def sig(self,rr,zone,bad_time=None):
        inception=self.now-3600;expiration=self.now+3600
        if bad_time=="expired":inception=self.now-7200;expiration=self.now-3600
        if bad_time=="future":inception=self.now+3600;expiration=self.now+7200
        data=dns.dnssec.sign(rr,self.private[zone],zone,self.key[zone],inception=inception,expiration=expiration)
        return dns.rrset.from_rdata_list(rr.name,60,[data])

    def signed_add(self,section,rr,zone,bad_time=None):section.extend([rr,self.sig(rr,zone,bad_time)])

    def soa(self):return dns.rrset.from_text("example.test.",60,"IN","SOA","ns.example.test. host.example.test. 1 60 60 60 60")

    def nsec3(self,names,types,zone="example.test.",iterations=0,flags=0):
        hashed={dns.dnssec.nsec3_hash(n,b"",iterations,1):n for n in names};order=sorted(hashed);result=[]
        for i,h in enumerate(order):
            typ=types[hashed[h]]
            result.append(dns.rrset.from_text(h+"."+zone,60,"IN","NSEC3",f"1 {flags} {iterations} - {order[(i+1)%len(order)]} {typ}"))
        return result

    def answer(self,original,lab,index,q):
        r=original(lab,index,q)
        if r is None:return None
        qname=q.question[0].name.to_text();typ=dns.rdatatype.to_text(q.question[0].rdtype)
        zone=self.zones[index] if index<3 else "example.test."
        if self.scenario in {"cohosted","cohosted_unproven"} and index==1 and qname.endswith("example.test.") and typ in {"A","DNSKEY"}:
            # The TLD endpoint also serves the child. DS stays parent-side.
            zone="example.test."
            r.flags|=dns.flags.AA;r.authority.clear();r.additional.clear()
            if typ=="DNSKEY":self.signed_add(r.answer,self.keys[zone],zone)
            else:self.signed_add(r.answer,dns.rrset.from_text(qname,60,"IN","A","192.0.2.10"),zone)
            return r
        r.answer.clear()
        ns={0:"a.root.",1:"a.test.",2:"ns.example.test."}
        if index<3 and typ=="SOA" and qname==zone:
            r.authority.clear();r.additional.clear();r.flags|=dns.flags.AA
            self.signed_add(r.answer,dns.rrset.from_text(zone,60,"IN","SOA",f"{ns[index]} host.{zone if zone!='.' else 'root.'} 1 60 60 60 60"),zone)
            return r
        if index<3 and ((typ=="NS" and qname==zone) or (typ=="A" and qname==ns[index])):
            r.authority.clear();r.additional.clear();r.flags|=dns.flags.AA
            rr=dns.rrset.from_text(zone if typ=="NS" else qname,60,"IN",typ,ns[index] if typ=="NS" else f"127.0.0.{index+10}")
            self.signed_add(r.answer,rr,zone)
            if typ=="NS":r.additional.append(dns.rrset.from_text(ns[index],60,"IN","A",f"127.0.0.{index+10}"))
            return r
        if typ=="DNSKEY" and qname==zone:
            if self.scenario=="key_timeout" and index==2:return None
            r.authority.clear();r.additional.clear();r.flags|=dns.flags.AA
            self.signed_add(r.answer,self.keys[zone],zone);return r
        if typ=="DS" and qname in self.ds and index<2:
            r.authority.clear();r.additional.clear();r.flags|=dns.flags.AA
            if qname=="example.test." and self.scenario=="cohosted_unproven":return r
            if qname=="example.test." and self.scenario in {"insecure","nsec3_insecure"}:
                if self.scenario=="insecure":proofs=[dns.rrset.from_text(qname,60,"IN","NSEC","zzz.test. NS RRSIG NSEC")]
                else:proofs=self.nsec3([zone,qname],{zone:"SOA NS DNSKEY RRSIG NSEC3",qname:"NS RRSIG NSEC3"},zone=zone)
                for rr in proofs:self.signed_add(r.authority,rr,zone)
            else:self.signed_add(r.answer,self.ds[qname],zone)
            return r
        if index!=2:return r
        r.flags|=dns.flags.AA;r.authority.clear();r.additional.clear()
        if self.scenario=="cname_rrset" and typ=="CNAME":
            self.signed_add(r.answer,dns.rrset.from_text(qname,60,"IN","CNAME","other.test."),zone)
            return r
        if self.scenario in {"nxdomain","nodata","bad_nsec","nsec3_nxdomain","nsec3_nodata","nsec3_policy","opt_out","bad_nsec3","wildcard_nodata","nsec3_wildcard_nodata","nsec3_invalid_owner","nsec3_dname"}:
            negative="nxdomain" in self.scenario or self.scenario in {"bad_nsec","nsec3_policy","opt_out","bad_nsec3","nsec3_invalid_owner","nsec3_dname"}
            if negative:r.set_rcode(dns.rcode.NXDOMAIN)
            self.signed_add(r.authority,self.soa(),zone)
            if self.scenario.startswith("nsec3") or self.scenario in {"opt_out","bad_nsec3"}:
                names=[zone,"ns.example.test."]+(["*.example.test."] if self.scenario=="nsec3_wildcard_nodata" else [] if negative else [qname])
                if self.scenario=="bad_nsec3":names.append(qname)
                proofs=self.nsec3(names,{n:"SOA NS DNSKEY RRSIG NSEC3" if n==zone else "A RRSIG NSEC3" if n=="ns.example.test." else "AAAA RRSIG NSEC3" for n in names},iterations=100 if self.scenario=="nsec3_policy" else 0,flags=1 if self.scenario=="opt_out" else 0)
                if self.scenario in {"nsec3_invalid_owner","nsec3_dname"}:
                    ce=dns.dnssec.nsec3_hash(zone,b"",0,1)
                    next_name=dns.dnssec.nsec3_hash(qname,b"",0,1) if self.scenario=="nsec3_invalid_owner" else ce
                    proofs=[dns.rrset.from_text(ce+"."+zone,60,"IN","NSEC3",f"1 0 0 - {next_name} SOA NS DNSKEY RRSIG NSEC3"+(" DNAME" if self.scenario=="nsec3_dname" else ""))]
                    if self.scenario=="nsec3_invalid_owner":proofs.append(dns.rrset.from_text("!"*32+"."+zone,60,"IN","NSEC3","1 0 0 - "+"V"*32+" A RRSIG NSEC3"))
            else:
                if negative:
                    proofs=[dns.rrset.from_text(zone,60,"IN","NSEC","ns.example.test. SOA NS DNSKEY RRSIG NSEC"),
                        dns.rrset.from_text("ns.example.test.",60,"IN","NSEC",("o.example.test." if self.scenario=="bad_nsec" else zone)+" A RRSIG NSEC")]
                else:proofs=[dns.rrset.from_text(qname,60,"IN","NSEC",zone+" AAAA RRSIG NSEC")]
                if self.scenario=="wildcard_nodata":proofs=[dns.rrset.from_text(zone,60,"IN","NSEC","*.example.test. SOA NS DNSKEY RRSIG NSEC"),dns.rrset.from_text("*.example.test.",60,"IN","NSEC","ns.example.test. AAAA RRSIG NSEC"),dns.rrset.from_text("ns.example.test.",60,"IN","NSEC",zone+" A RRSIG NSEC")]
            for rr in proofs:self.signed_add(r.authority,rr,zone)
            return r
        if typ not in {"A","AAAA"}:
            self.signed_add(r.authority,self.soa(),zone)
            self.signed_add(r.authority,dns.rrset.from_text(qname,60,"IN","NSEC",zone+" A AAAA RRSIG NSEC"),zone)
            return r
        rr=dns.rrset.from_text(qname,60,"IN",typ,"192.0.2.10" if typ=="A" else "2001:db8::1")
        if self.scenario.startswith("wildcard"):
            wild=dns.rrset.from_text("*.example.test.",60,"IN",typ,"192.0.2.10")
            signature=self.sig(wild,zone);signature.name=rr.name;r.answer.extend([rr,signature])
            if self.scenario!="wildcard_missing":
                proofs=self.nsec3([zone,"ns.example.test.","*.example.test."],{zone:"SOA NS DNSKEY RRSIG NSEC3","ns.example.test.":"A RRSIG NSEC3","*.example.test.":"A RRSIG NSEC3"}) if self.scenario=="wildcard_nsec3" else [dns.rrset.from_text("ns.example.test.",60,"IN","NSEC",zone+" A RRSIG NSEC")]
                for proof in proofs:self.signed_add(r.authority,proof,zone)
            return r
        self.signed_add(r.answer,rr,zone,self.scenario if self.scenario in {"expired","future"} else None)
        if self.scenario=="wrong_signer":r.answer[1]=dns.rrset.from_rdata_list(qname,60,[r.answer[1][0].replace(signer=dns.name.from_text("other.test."))])
        if self.scenario=="wrong_type":r.answer[1]=dns.rrset.from_rdata_list(qname,60,[r.answer[1][0].replace(type_covered=dns.rdatatype.AAAA)])
        if self.scenario=="multi_sig":r.answer[1].add(r.answer[1][0].replace(signature=b"\x00"*64))
        if self.scenario=="ede_conflict":r.use_edns(edns=0,ednsflags=dns.flags.DO,options=[dns.edns.EDEOption(6,"server reports bogus; local validation remains separate")])
        if self.scenario=="tampered":r.answer[0]=dns.rrset.from_text(qname,60,"IN",typ,"192.0.2.11")
        if self.scenario in {"missing_sig","insecure","nsec3_insecure"}:r.answer[:]=[rr]
        return r


@asynccontextmanager
async def signed_lab(scenario="secure"):
    signed=Signed(scenario);original=Lab.answer
    with patch.object(Lab,"answer",lambda lab,index,q:signed.answer(original,lab,index,q)):
        async with protocol_lab("normal") as lab:
            factory=lab.backend
            def backend():
                b=factory();b.dnssec_test_anchor=signed.anchor;return b
            lab.backend=backend;lab.signed=signed
            yield lab
