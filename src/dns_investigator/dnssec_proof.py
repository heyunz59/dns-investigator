"""Denial meaning checks on already authenticated RRsets, never on bare server data."""
import dns.name,dns.rdatatype,dns.dnssec


class ProofUnsupported(Exception):pass


def bitmap(data,typ):
    value=int(dns.rdatatype.from_text(typ)) if isinstance(typ,str) else int(typ)
    for window,bits in data.windows:
        offset=value-window*256
        if 0<=offset<len(bits)*8:return bool(bits[offset//8]&(0x80>>(offset%8)))
    return False


def between(left,item,right):
    return left<item<right if left<right else item>left or item<right if left>right else item!=left


def ancestors(q,zone):
    while q.is_subdomain(zone):
        yield q
        if q==zone:break
        q=q.parent()


def denial(q,typ,rcode,zone,rrsets,charge,wildcard_base=None,delegation=False):
    """RFC4035/5155. True means proof covers this question, not an operational cause."""
    if not q.is_subdomain(zone):return False
    if wildcard_base is not None and (not wildcard_base.is_subdomain(zone) or not q.is_subdomain(wildcard_base) or q==wildcard_base):return False
    nsec=[r for r in rrsets if r.rdtype==dns.rdatatype.NSEC]
    nsec3=[r for r in rrsets if r.rdtype==dns.rdatatype.NSEC3]
    if not nsec and not nsec3:return False
    if any(bitmap(data,128) for rr in nsec+nsec3 for data in rr):raise ProofUnsupported("COMPACT_DENIAL_NXNAME")
    if nsec:
        values=[];exists={zone}
        for rr in nsec:
            if len(rr)!=1 or not rr.name.is_subdomain(zone):return False
            data=rr[0]
            if not data.next.is_subdomain(zone):return False
            if bitmap(data,"DNAME") and q!=rr.name and q.is_subdomain(rr.name):raise ProofUnsupported("DNAME_DENIAL_NOT_SUPPORTED")
            values.append((rr.name,data))
            exists.update(ancestors(rr.name,zone));exists.update(ancestors(data.next,zone))
        def cover(target):
            for owner,data in values:
                # Parent-side delegation NSEC cannot deny data beneath the cut.
                if bitmap(data,"NS") and not bitmap(data,"SOA") and target.is_subdomain(owner) and target!=owner:continue
                if between(owner,target,data.next) and target not in exists:return True
            return False
        def no_type(target):
            return any(owner==target and not bitmap(data,typ) and not bitmap(data,"CNAME") and
                (not(bitmap(data,"NS") and not bitmap(data,"SOA")) or typ==dns.rdatatype.DS) for owner,data in values)
        if delegation:
            return any(owner==q and bitmap(data,"NS") and not bitmap(data,"SOA") and not bitmap(data,"DS") for owner,data in values)
        if wildcard_base is not None:
            closer=dns.name.Name(q.labels[-(len(wildcard_base.labels)+1):])
            return q.is_subdomain(wildcard_base) and q!=wildcard_base and cover(closer)
        if rcode=="NOERROR" and no_type(q):return True
        closest=next((a for a in ancestors(q,zone) if a in exists),None)
        if closest==q and rcode=="NOERROR":raise ProofUnsupported("NSEC_EMPTY_NONTERMINAL_NODATA")
        if closest is None or closest==q:return False
        wildcard=dns.name.Name((b"*",)+closest.labels)
        if rcode=="NXDOMAIN":return cover(q) and cover(wildcard)
        if rcode=="NOERROR":return cover(q) and no_type(wildcard)
        return False
    # Deliberately bounded RFC9276 profile; no expensive arbitrary iterations.
    values=[];parameters=set()
    for rr in nsec3:
        if len(rr)!=1 or rr.name.parent()!=zone:return False
        data=rr[0]
        if data.algorithm!=1 or data.iterations!=0 or data.salt or data.flags:
            raise ProofUnsupported("NSEC3_PARAMETERS_OR_OPT_OUT")
        if len(data.next)!=20 or len(rr.name.labels[0])!=32:return False
        # RFC5155/4648 base32hex, not an arbitrary 32-byte DNS label. Lexically
        # sorting malformed labels can manufacture a false covering interval.
        if any(c not in b"0123456789ABCDEFGHIJKLMNOPQRSTUV" for c in rr.name.labels[0].upper()):return False
        parameters.add((data.algorithm,data.iterations,data.salt))
        values.append((rr.name.labels[0].decode("ascii").upper(),data))
    if len(parameters)!=1:return False
    memo={}
    def hashed(target):
        if target not in memo:
            charge();memo[target]=dns.dnssec.nsec3_hash(target,b"",0,1)
        return memo[target]
    def exact(target):return next((data for owner,data in values if owner==hashed(target)),None)
    def cover(target):
        import base64
        h=hashed(target)
        if any(owner==h for owner,_ in values):return False
        return any(between(owner,h,base64.b32hexencode(data.next).decode().upper()) for owner,data in values)
    def no_type(target):
        data=exact(target)
        return data is not None and not bitmap(data,typ) and not bitmap(data,"CNAME") and (typ==dns.rdatatype.DS or not(bitmap(data,"NS") and not bitmap(data,"SOA")))
    if delegation:
        data=exact(q)
        return data is not None and bitmap(data,"NS") and not bitmap(data,"SOA") and not bitmap(data,"DS")
    if wildcard_base is not None:
        data=exact(wildcard_base)
        if data is not None and bitmap(data,"DNAME"):raise ProofUnsupported("DNAME_DENIAL_NOT_SUPPORTED")
        closer=dns.name.Name(q.labels[-(len(wildcard_base.labels)+1):])
        return data is not None and not(bitmap(data,"NS") and not bitmap(data,"SOA")) and cover(closer)
    if rcode=="NOERROR" and no_type(q):return True
    closest=next((a for a in ancestors(q,zone) if exact(a) is not None),None)
    if closest is None or closest==q:return False
    ce=exact(closest)
    if bitmap(ce,"DNAME"):raise ProofUnsupported("DNAME_DENIAL_NOT_SUPPORTED")
    if bitmap(ce,"NS") and not bitmap(ce,"SOA"):return False
    closer=dns.name.Name(q.labels[-(len(closest.labels)+1):])
    wildcard=dns.name.Name((b"*",)+closest.labels)
    if rcode=="NXDOMAIN":return cover(closer) and cover(wildcard) and exact(q) is None
    return rcode=="NOERROR" and cover(closer) and no_type(wildcard)
