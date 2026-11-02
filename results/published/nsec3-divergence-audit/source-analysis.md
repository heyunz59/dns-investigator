# 源码路径（修复前快照）

- `src/dns_investigator/dnssec_proof.py:27`：`def denial(q,typ,rcode,zone,rrsets,charge,wildcard_base=None,delegation=False):`
- `src/dns_investigator/dnssec_proof.py:44`：`def cover(target):`
- `src/dns_investigator/dnssec_proof.py:76`：`if any(c not in b"0123456789ABCDEFGHIJKLMNOPQRSTUV" for c in rr.name.labels[0].upper()):return False`
- `src/dns_investigator/dnssec_proof.py:86`：`def cover(target):`
- `src/dns_investigator/dnssec_validation.py:114`：`def proof(self,eid,q,typ,zone,keys,key_eid,dependencies=(),rcode="NOERROR",wildcard_base=None,delegation=False):`
- `src/dns_investigator/dnssec_validation.py:123`：`covered=denial(q,typ,rcode,zone,valid,self.charge,wildcard_base,delegation)`
- `src/dns_investigator/dnssec_validation.py:127`：`ids,"DENIAL_COVERS_QUESTION" if covered else "DENIAL_POLICY_LIMIT" if limited else "DENIAL_DOES_NOT_COVER_QUESTION",vs,`
- `src/dns_investigator/dnssec_validation.py:139`：`def failed(self,result,stage,trusted=True):`
- `src/dns_investigator/dnssec_validation.py:142`：`return self.finish("BOGUS" if trusted else "INDETERMINATE",result["reason_code"],stage,[result["id"]])`
- `src/dns_investigator/dnssec_validation.py:175`：`if childkeys is None:return self.finish("BOGUS","DNSKEY_MISSING_AFTER_AUTHENTICATED_DS","child-dnskey",[result["id"]])`
- `src/dns_investigator/dnssec_validation.py:202`：`if soa is None:return self.finish("BOGUS","NEGATIVE_SOA_MISSING","negative-soa",[trusted_v])`
- `src/dns_investigator/dnssec.py:52`：`def publish(backend,parent,result):`
- `src/dns_investigator/reporting.py:55`：`def protocol_findings(backend):`

- Unbound val_nsec3.c:868：nsec3_covers(uint8_t* zone, struct nsec3_cached_hash* hash,
- Unbound val_nsec3.c:896：len = sldns_b32_pton_extended_hex((char*)rrset->rk.dname+1,
- Unbound val_nsec3.c:930：find_covering_nsec3(struct module_env* env, struct nsec3_filter* flt,
- Unbound val_nsec3.c:965：if(nsec3_covers(flt->zone, hash, s, i_rr,
- Unbound val_nsec3.c:992：nsec3_find_closest_encloser(struct module_env* env, struct nsec3_filter* flt,
- Unbound val_nsec3.c:1075：if(!nsec3_find_closest_encloser(env, flt, ct, qinfo, ce, calculations)) {
- Unbound val_nsec3.c:1129：if(!find_covering_nsec3(env, flt, ct, nc, nc_len,
- Unbound val_nsec3.c:1211：if(!find_covering_nsec3(env, flt, ct, wc, wclen, &wc_rrset, &wc_rr, calc)) {
- Unbound val_nsec3.c:1239：nsec3_prove_nameerror(struct module_env* env, struct val_env* ve,
- Unbound val_nsec3.c:1492：if(!find_covering_nsec3(env, &flt, ct, nc, nc_len,

Unbound release-1.26.2 官方源码SHA256：a125e8a38aa1a1bfc39da78f02c87a2f700f6e9165b127954eb2c3e0737468a9。来源 https://raw.githubusercontent.com/NLnetLabs/unbound/release-1.26.2/validator/val_nsec3.c 。

关键区别：nsec3_covers先比较原始owner标签与查询hash、二进制next；普通区间路径直接成功，base32解码发生在后面的环绕路径。原始 ! 标签字典序小于合法hash，next全FF又大于查询hash，因此普通路径满足条件，无需走到解码失败。不是“忽略坏记录后用其余完整证明”。T02移除该记录后失败，T03缺少closest-encloser也失败。实际内部PC/单条选择未插桩，标记UNKNOWN；源码条件与最小反事实实验构成机制解释，不冒充调试回溯。

项目：读取并验签NSEC3→owner字母表检查全局False→Session.proof局部SIGNATURE_CHECK_FAILED→已有父DS/子密钥可信上下文的Session.failed整体BOGUS→publish分配V→protocol_findings并入正式报告。全部E/V见verifier-logs/T01-1-project.json。