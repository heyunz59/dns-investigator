"""Pure DNSSEC validation worker. No network, model, or self-selected trust anchor."""
import time
from datetime import datetime,timezone
import dns.name,dns.rrset,dns.rdatatype,dns.dnssec,dns.exception
from .dnssec_proof import denial,ProofUnsupported

POLICY_VERSION="dns-investigator-dnssec-v1:8,13,14,15;DS2,4;RSA2048-4096;NSEC3-0-empty-salt"
ALGORITHMS={8,13,14,15};DIGESTS={2,4}


def name(value):return dns.name.from_text(value,origin=dns.name.root).canonicalize()


class Limited(Exception):pass


class Session:
    def __init__(self,bundle):
        self.bundle=bundle;self.now=bundle["validation_time"];self.results=[];self.work=0;self.signatures=0
        self.messages={r["id"]:r["data"] for r in bundle["evidence"]}

    def charge(self):
        self.work+=1
        if self.work>512:raise Limited("VALIDATION_WORK_BUDGET")

    def record(self,kind,status,ids,reason,dependencies=(),**extra):
        row=dict(id=f"V{len(self.results)+1}",kind=kind,local_result=status,evidence_ids=list(dict.fromkeys(x for x in ids if x)),
            validation_result_ids=list(dependencies),validation_time=self.now,algorithm_policy=POLICY_VERSION,
            trust_anchor=self.bundle["anchor"],provenance="locally_validated",reason_code=reason,**extra)
        self.results.append(row);return row

    def rrsets(self,eid):
        data=self.messages.get(eid,{})
        result=[]
        for section in ("answer","authority"):
            for rr in data.get(section,[]):
                result.append(dns.rrset.from_text_list(name(rr["name"]),rr["ttl"],rr.get("rdclass","IN"),rr["type"],rr["values"]))
        return result

    def find(self,eid,owner,typ):
        return next((r for r in self.rrsets(eid) if r.name==owner and r.rdtype==typ),None)

    def usable(self,eid,qname,qtype,zone):
        r=self.messages.get(eid,{})
        try:
            stamp=datetime.fromisoformat(r["requested_at"])
            if stamp.tzinfo is None or abs(stamp.timestamp()-self.now)>300:return False
        except (KeyError,ValueError,TypeError):return False
        parameters=r.get("request_parameters",{})
        return (r.get("transport_status")=="responded" and not r.get("flags",{}).get("TC") and r.get("execution_status")=="ok"
            and name(r.get("qname","."))==qname and r.get("qtype")==qtype and r.get("qclass")=="IN"
            and name(parameters.get("zone") or ".")==zone
            and parameters.get("mode")=="dnssec" and parameters.get("do") is True and parameters.get("rd") is False)

    def allowed_key(self,key):
        if key.algorithm not in ALGORITHMS:return False
        if not key.flags&256 or key.flags&128 or key.protocol!=3:return False
        if len(key.key)>600:return False
        if key.algorithm==8:
            public=dns.dnssec.get_algorithm_cls(key.algorithm).public_cls.from_dnskey(key)
            if not 2048<=public.key.key_size<=4096 or public.key.public_numbers().e.bit_length()>32:return False
        return True

    def signature(self,rr,eid,keys,zone,key_eid,dependencies=()):
        scope=dict(owner=rr.name.to_text(),qtype=dns.rdatatype.to_text(rr.rdtype),zone=zone.to_text(),qclass="IN")
        sigsets=[s for s in self.rrsets(eid) if s.rdtype==dns.rdatatype.RRSIG and s.name==rr.name and s.covers==rr.rdtype]
        if not sigsets:return self.record("rrset_signature","MISSING_EVIDENCE",[eid,key_eid],"RRSIG_MISSING",dependencies,scope=scope)
        unsupported=False;tried=False
        for ss in sigsets:
            for sig in ss:
                self.charge()
                if sig.algorithm not in ALGORITHMS:unsupported=True;continue
                if sig.signer!=zone or not rr.name.is_subdomain(zone) or sig.labels<len(zone.labels)-1 or rr.rdclass!=1 or sig.rdclass!=rr.rdclass:continue
                for key in keys:
                    if key.algorithm!=sig.algorithm or dns.dnssec.key_id(key)!=sig.key_tag:continue
                    try:allowed=self.allowed_key(key)
                    except (ValueError,dns.exception.DNSException):allowed=False
                    if not allowed:unsupported=True;continue
                    self.charge();self.signatures+=1
                    if self.signatures>64:raise Limited("SIGNATURE_ATTEMPT_BUDGET")
                    trusted=dns.rrset.from_rdata_list(zone,keys.ttl,[key])
                    tried=True
                    try:
                        dns.dnssec.validate_rrsig(rr,sig,{zone:trusted},now=self.now)
                        effective_ttl=max(0,min(rr.ttl,ss.ttl,sig.original_ttl,sig.expiration-self.now))
                        return self.record("rrset_signature","SIGNATURE_CHECK_PASSED",[eid,key_eid],"CRYPTOGRAPHIC_SIGNATURE_VALID",dependencies,
                            scope=scope,key_tag=sig.key_tag,algorithm=int(sig.algorithm),original_ttl=sig.original_ttl,effective_ttl=effective_ttl,
                            wildcard_labels=sig.labels if sig.labels<len(rr.name.labels)-1 else None)
                    except (dns.dnssec.ValidationFailure,dns.dnssec.UnsupportedAlgorithm,ValueError):pass
        return self.record("rrset_signature","UNSUPPORTED_OR_POLICY_LIMITED" if unsupported else "SIGNATURE_CHECK_FAILED",
            [eid,key_eid],"ALGORITHM_OR_KEY_POLICY" if unsupported else "NO_SIGNATURE_VALIDATED",dependencies,scope=scope,cryptographic_attempted=tried)

    def match_ds(self,zone,ds,keys,ids,dependencies=()):
        matched=[];unsupported=False
        if len(keys)>16 or len(ds)>16:raise Limited("DS_KEY_CANDIDATE_LIMIT")
        for record in ds:
            if record.digest_type not in DIGESTS or record.algorithm not in ALGORITHMS:unsupported=True;continue
            for key in keys:
                if key.algorithm!=record.algorithm or dns.dnssec.key_id(key)!=record.key_tag:continue
                self.charge()
                try:
                    if not self.allowed_key(key):unsupported=True;continue
                    if dns.dnssec.make_ds(zone,key,record.digest_type,validating=True)==record:matched.append(key)
                except (ValueError,dns.exception.DNSException):continue
        selected=dns.rrset.from_rdata_list(zone,keys.ttl,matched) if matched else None
        result=self.record("ds_digest","SIGNATURE_CHECK_PASSED" if matched else "UNSUPPORTED_OR_POLICY_LIMITED" if unsupported else "SIGNATURE_CHECK_FAILED",
            ids,"DS_DIGEST_MATCH" if matched else "DS_ALGORITHM_OR_POLICY" if unsupported else "DS_DIGEST_MISMATCH",dependencies,scope=dict(zone=zone.to_text()))
        return selected,result

    def proof(self,eid,q,typ,zone,keys,key_eid,dependencies=(),rcode="NOERROR",wildcard_base=None,delegation=False):
        valid=[];ids=[eid,key_eid];vs=list(dependencies);limited=False
        for rr in self.rrsets(eid):
            if rr.rdtype not in {dns.rdatatype.NSEC,dns.rdatatype.NSEC3} or not rr.name.is_subdomain(zone):continue
            result=self.signature(rr,eid,keys,zone,key_eid,dependencies)
            vs.append(result["id"])
            if result["local_result"]=="SIGNATURE_CHECK_PASSED":valid.append(rr)
            if result["local_result"]=="UNSUPPORTED_OR_POLICY_LIMITED":limited=True
        try:
            covered=denial(q,typ,rcode,zone,valid,self.charge,wildcard_base,delegation)
        except ProofUnsupported as exc:
            return self.record("denial_proof","UNSUPPORTED_OR_POLICY_LIMITED",ids,str(exc),vs)
        return self.record("denial_proof","SIGNATURE_CHECK_PASSED" if covered else "UNSUPPORTED_OR_POLICY_LIMITED" if limited else "SIGNATURE_CHECK_FAILED",
            ids,"DENIAL_COVERS_QUESTION" if covered else "DENIAL_POLICY_LIMIT" if limited else "DENIAL_DOES_NOT_COVER_QUESTION",vs,
            scope=dict(qname=q.to_text(),qtype=dns.rdatatype.to_text(typ),zone=zone.to_text(),rcode=rcode,delegation=delegation))

    def finish(self,status,reason,stage,dependencies=(),execution="completed"):
        return dict(validation_execution=execution,dnssec_status=status,reason_code=reason,failure_stage=stage,
            validation_scope=dict(qname=self.bundle["qname"],qtype=self.bundle["qtype"],validation_time=self.now),
            trust_anchor=self.bundle["anchor"],algorithm_policy=POLICY_VERSION,implementation="dnspython2.9.1/cryptography50.0.0+bounded-protocol-v1",
            validation_result_ids=list(dependencies),results=self.results,compute=dict(work_units=self.work,signature_attempts=self.signatures),
            operational_root_cause_confirmed=False)

    def failed(self,result,stage,trusted=True):
        status=result["local_result"]
        if status=="UNSUPPORTED_OR_POLICY_LIMITED":return self.finish("INDETERMINATE",result["reason_code"],stage,[result["id"]],"capability_limited")
        return self.finish("BOGUS" if trusted else "INDETERMINATE",result["reason_code"],stage,[result["id"]])

    def run(self):
        root=name(self.bundle["anchor"]["zone"])
        eid=self.bundle["root_dnskey_eid"]
        if not self.usable(eid,root,"DNSKEY",root):return self.finish("INDETERMINATE","ROOT_MATERIAL_UNAVAILABLE","root",execution="incomplete")
        keys=self.find(eid,root,dns.rdatatype.DNSKEY)
        if keys is None:return self.finish("INDETERMINATE","ROOT_DNSKEY_MISSING","root",execution="incomplete")
        anchors=dns.rrset.from_text_list(root,3600,"IN","DS",self.bundle["anchor"]["ds"])
        matched,ds_result=self.match_ds(root,anchors,keys,[eid])
        if matched is None:return self.failed(ds_result,"root-key")
        result=self.signature(keys,eid,matched,root,eid,[ds_result["id"]])
        if result["local_result"]!="SIGNATURE_CHECK_PASSED":return self.failed(result,"root-dnskey")
        trusted_v=result["id"];zone=root;key_eid=eid
        for cut in self.bundle["chain"]:
            child=name(cut["child_zone"])
            if name(cut["parent_zone"])!=zone or not child.is_subdomain(zone) or child==zone or not name(self.bundle["qname"]).is_subdomain(child):
                return self.finish("INDETERMINATE","CHAIN_ZONE_GAP","delegation",execution="incomplete")
            deid=cut["ds_eid"]
            if not self.usable(deid,child,"DS",zone):return self.finish("INDETERMINATE","DS_MATERIAL_UNAVAILABLE","parent-ds",[trusted_v],"incomplete")
            ds=self.find(deid,child,dns.rdatatype.DS)
            if ds is None:
                proof=self.proof(deid,child,dns.rdatatype.DS,zone,keys,key_eid,[trusted_v],delegation=True)
                if proof["local_result"]=="SIGNATURE_CHECK_PASSED":return self.finish("INSECURE","AUTHENTICATED_UNSIGNED_DELEGATION","parent-ds",[proof["id"]])
                return self.failed(proof,"parent-no-ds")
            result=self.signature(ds,deid,keys,zone,key_eid,[trusted_v])
            if result["local_result"]!="SIGNATURE_CHECK_PASSED":return self.failed(result,"parent-ds")
            ceid=cut["dnskey_eid"]
            if not self.usable(ceid,child,"DNSKEY",child):return self.finish("INDETERMINATE","CHILD_KEY_MATERIAL_UNAVAILABLE","child-dnskey",[result["id"]],"incomplete")
            childkeys=self.find(ceid,child,dns.rdatatype.DNSKEY)
            if childkeys is None:return self.finish("BOGUS","DNSKEY_MISSING_AFTER_AUTHENTICATED_DS","child-dnskey",[result["id"]])
            matched,digest=self.match_ds(child,ds,childkeys,[deid,ceid],[result["id"]])
            if matched is None:return self.failed(digest,"child-ds-match")
            keyresult=self.signature(childkeys,ceid,matched,child,ceid,[digest["id"]])
            if keyresult["local_result"]!="SIGNATURE_CHECK_PASSED":return self.failed(keyresult,"child-dnskey")
            keys,zone,key_eid,trusted_v=childkeys,child,ceid,keyresult["id"]
        target=self.bundle["terminal_eid"]
        if not self.usable(target,name(self.bundle["qname"]),self.bundle["qtype"],zone):return self.finish("INDETERMINATE","TARGET_MATERIAL_UNAVAILABLE","target",[trusted_v],"incomplete")
        data=self.messages[target];q=name(self.bundle["qname"]);typ=dns.rdatatype.from_text(self.bundle["qtype"])
        if not q.is_subdomain(zone):return self.finish("INDETERMINATE","TARGET_ZONE_MISMATCH","target",execution="incomplete")
        if data.get("cname_chain") and typ!=dns.rdatatype.CNAME:return self.finish("INDETERMINATE","DNSSEC_CNAME_CHAIN_NOT_SUPPORTED","alias",execution="capability_limited")
        rr=self.find(target,q,typ)
        if rr is not None and data.get("dns_rcode")=="NOERROR":
            result=self.signature(rr,target,keys,zone,key_eid,[trusted_v])
            if result["local_result"]!="SIGNATURE_CHECK_PASSED":return self.failed(result,"target-signature")
            if result.get("wildcard_labels") is not None:
                base=dns.name.Name(q.labels[-(result["wildcard_labels"]+1):])
                proof=self.proof(target,q,typ,zone,keys,key_eid,[result["id"]],wildcard_base=base)
                if proof["local_result"]!="SIGNATURE_CHECK_PASSED":return self.failed(proof,"wildcard-proof")
                result=proof
            return self.finish("SECURE","SUPPORTED_ANSWER_AUTHENTICATED","answer",[result["id"]])
        if data.get("dns_rcode") not in {"NOERROR","NXDOMAIN"}:
            return self.finish("INDETERMINATE","NO_USABLE_TARGET_ANSWER","target",[trusted_v],"incomplete")
        soa=self.find(target,zone,dns.rdatatype.SOA)
        if soa is None:return self.finish("BOGUS","NEGATIVE_SOA_MISSING","negative-soa",[trusted_v])
        soa_result=self.signature(soa,target,keys,zone,key_eid,[trusted_v])
        if soa_result["local_result"]!="SIGNATURE_CHECK_PASSED":return self.failed(soa_result,"negative-soa")
        proof=self.proof(target,q,typ,zone,keys,key_eid,[trusted_v,soa_result["id"]],rcode=data["dns_rcode"])
        if proof["local_result"]!="SIGNATURE_CHECK_PASSED":return self.failed(proof,"negative-proof")
        return self.finish("SECURE","SUPPORTED_NEGATIVE_ANSWER_AUTHENTICATED","answer",[proof["id"]])


def evaluate(bundle):
    session=Session(bundle)
    modes={row.get("source_mode") for row in bundle["evidence"]}
    if len(modes)!=1 or not modes.issubset({"live","fixture","synthetic"}):return session.finish("INDETERMINATE","MATERIAL_SOURCE_MISMATCH","material",execution="incomplete")
    if not dns.dnssec._have_pyca:return session.finish("INDETERMINATE","CRYPTO_LIBRARY_UNAVAILABLE","capability",execution="capability_limited")
    try:return session.run()
    except (Limited,ProofUnsupported) as exc:return session.finish("INDETERMINATE",str(exc),"resource-policy",execution="resource_limited")
    except (ValueError,dns.exception.DNSException,KeyError,TypeError):return session.finish("INDETERMINATE","MALFORMED_OR_MISSING_MATERIAL","material",execution="incomplete")


def worker(bundle,connection):
    try:connection.send(evaluate(bundle))
    finally:connection.close()
