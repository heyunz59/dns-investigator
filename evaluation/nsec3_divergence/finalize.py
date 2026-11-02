import json,csv,re,base64,hashlib
from pathlib import Path
import dns.message,dns.dnssec,dns.rrset,dns.rdatatype
from .run import ROOT,save,sha

def finalize():
    before=json.loads((ROOT/'all-runs.json').read_text(encoding='utf-8'));after=json.loads((ROOT/'after-isolated/all-runs.json').read_text(encoding='utf-8'))
    corrected=json.loads((ROOT/'t07-corrected-v2/all-runs.json').read_text(encoding='utf-8'))[0]
    analyses=[];table=[]
    for stage,rs,prefix in [('before',[before[0]]+before[3:],''),('after',[after[0]]+after[3:],'after-isolated/')]:
        for r in rs:
            if stage=='before' and r['case_id']=='T07':r=corrected;pre='t07-corrected-v2/'
            else:pre=prefix
            sufficient=True if r['case_id'] in ['T04','T05','T11'] else 'UNKNOWN: mixed parameter envelope' if r['case_id']=='T10' else False
            table.append(dict(stage=stage,scenario=r['case_id'],input_hash=r['input_hash'],changed_factor=r['changed_factor'],project_status=r['project_status'],unbound_status=r['unbound_status'],project_reason=r['project_reason'],unbound_reason=r['unbound_reason'],proof_sufficient=sufficient,evidence_files=pre+r['evidence_files'],rfc_basis='RFC5155 8.1-8.4; RFC4648 3.3/7',interpretation='T11 remains policy-limited; T01/T06 keep divergence; no blanket agreement criterion'))
            path=ROOT/pre/r['evidence_files'];log=json.loads(path.read_text(encoding='utf-8'))
            keys=next(rr for e in log['E'] for rr in e['data'].get('answer',[]) if rr['type']=='DNSKEY' and rr['name'].rstrip('.')=='example.test')
            kr=dns.rrset.from_text_list('example.test.',keys['ttl'],'IN','DNSKEY',keys['values']);zone=dns.name.from_text('example.test.')
            packet=next(p for p in r['packets'] if p['phase']=='project' and p['server_index']==2 and p['qname']=='probe.example.test.' and p['qtype']==1)
            m=dns.message.from_wire((ROOT/pre/packet['response']['path']).read_bytes());items=[]
            for rr in m.authority:
                if rr.rdtype!=50:continue
                data=rr[0];label=rr.name.labels[0].decode();valid=len(label)==32 and all(c in '0123456789ABCDEFGHIJKLMNOPQRSTUV' for c in label.upper())
                sig=next(s for s in m.authority if s.rdtype==46 and s.name==rr.name and s.covers==50)
                try:dns.dnssec.validate(rr,sig,{zone:kr},now=r['project_validation_time']);check='PASSED'
                except Exception as exc:check=type(exc).__name__
                items.append(dict(owner=str(rr.name),base32hex_valid=valid,decoded_owner_length=len(base64.b32hexdecode(label.upper())) if valid else None,next_hash=base64.b32hexencode(data.next).decode(),signature=check,rdata=data.to_text(),rrsig=sig.to_text(),unbound_individual_selection='UNKNOWN; debug trace verifies both original signatures but not per-interval PC'))
            analyses.append(dict(stage=stage,case=r['case_id'],records=items,valid_proof_sufficiency=sufficient,raw_response=pre+packet['response']['path']))
    (ROOT/'verifier-logs/differential-matrix-pilot.csv').write_bytes((ROOT/'differential-matrix.csv').read_bytes())
    with (ROOT/'differential-matrix.csv').open('w',encoding='utf-8-sig',newline='') as f:
        w=csv.DictWriter(f,fieldnames=list(table[0]));w.writeheader();w.writerows(table)
    save(ROOT/'all-case-proof-analysis.json',analyses)
    proof=json.loads((ROOT/'proof-analysis.json').read_text(encoding='utf-8'))
    for r in proof['records']:
        r['covers_interpretation']='Raw lexical comparison only; invalid owner is not a valid hash interval' if not r['base32hex_valid'] else 'Strict base32hex interval'
        r['proof_role']='Authenticated closest-encloser exact match and wildcard cover, missing next-closer cover' if r['base32hex_valid'] else 'Invalid candidate, cannot form valid proof; reference fast-path condition supplied missing cover'
        r['necessary_for_valid_proof']=r['base32hex_valid'];r['may_ignore']=not r['base32hex_valid'];r['ignore_basis']='Unusable owner; ignoring does not waive remaining proof requirements'
    save(ROOT/'proof-analysis.json',proof)
    old=json.loads((ROOT/'conclusion.json').read_text(encoding='utf-8'));old.update(fix_implemented=True,fix_commit='e1ecd9e',followup_tests_passed='362 passed in 25.71s; isolated T01-T12 complete',false_secure_risk='No new project SECURE on insufficient/bad-signature samples; not a universal safety proof',unresolved_questions=old['unresolved_questions']+['General malformed-response treatment: UNRESOLVED_PROTOCOL_INTERPRETATION outside tested necessary/subset cases'])
    save(ROOT/'conclusion.json',old)
    full=json.loads((ROOT/'full-reference-isolated.json').read_text(encoding='utf-8'));prior=json.loads(Path('results/published/v0.4-protocol/reference-133b49a.json').read_text(encoding='utf-8'))
    previous={r['scenario']:r['project']['dnssec_status'] for r in prior['runs']}
    changes=[r['scenario'] for r in full['runs'] if previous[r['scenario']]!=r['project']['dnssec_status']]
    save(ROOT/'regression-summary.json',dict(offline_passed=362,offline_seconds=25.71,old_tests_passed=356,new_tests=6,full_reference_cases=len(full['runs']),project_status_changes_from_133b49a=changes,LLM_calls=0,score_policy_changed=False,independent_human_review='PENDING'))
    report=ROOT/'audit-report.md';text=report.read_text(encoding='utf-8')
    text+='''
## 修复与最终复核（独立于原始观察）

报告提交78ca1eb之后，最小修复e1ecd9e仅修改owner长度/字符不合法时的候选过滤（return False→continue），其他证明条件、签名、政策、预算不改。完整362 passed in25.71s（原356＋6回归）。after-isolated含修复后三次原始复现和完整12场景，全部保存wire、目标材料等价。T05从BOGUS变SECURE；T01/T06仍BOGUS，与Unbound的原始SECURE分歧保留；T02/T03/T07/T08/T09/T12仍BOGUS，没有新增错误放行。完整原37场景重新Unbound对照保存full-reference-isolated.json，项目状态与133b49a逐例无变化。

首轮T07循环区间错误另存pilot CSV；正式CSV并列before/after，before T07明确使用t07-corrected-v2。没有修改原始all-runs、旧业务评分或删除原始分歧。after-fix目录和full-reference-after.json因两个独立进程争用127.0.0.x:53而可能污染，全部排除验收且保留；真正验收为串行after-isolated和full-reference-isolated。包装器早期import/编码错误也保留，均非DNS结论。after-isolated/environment中business_source_commit沿用133b49a是记录器元数据错误：实际git_commit为e1ecd9e，业务哈希也对应修复；保留原字段并在此纠正，未来记录器已按Git最近业务提交获取。

reference-debug额外只改verbosity=4/logfile，不改变验证政策；日志958–976附近明确显示两个原始NSEC3签名通过、closest-encloser为example.test.、最终NAME ERROR验证成功。info渲染将!显示为?，真实wire仍为!。单个区间候选选择PC仍未插桩，不能把源码推导伪装成观测。额外返回的answer_wire_hex可无损解码检查最终RCODE/AD/EDNS；不是只看AD判断。原始三次始终verbosity0、空缓存。完整命令及退出信息在verifier-logs/commands.json；未观测的子进程退出码保持UNKNOWN。

## 规范等级补充

MUST：RFC5155 8.1忽略未知hash，8.2忽略未知保留flags；8.3/8.4必须具备对应完整证明，不能使用单纯签名成功替代名称/区间语义。SHOULD：3节建议NSEC3 TTL与SOA negative TTL一致，是缓存建议，不决定本次证明覆盖；7.4对未知算法区的加载/响应建议与验证器行为不同。MAY：6节允许Opt-Out与非Opt-Out混合，不能把所有非零flag一律当协议非法；本项目未承诺其验证语义。RFC9276更新参数运行建议，不能拿历史10.3的高迭代许可当当前安全推荐。参数0/空salt、资源限制是本地政策；Unbound先参数一致性检查和覆盖快路径是实现行为。未找到“任一额外坏owner必须使整个响应失败”的MUST。一般混合畸形/冲突材料超出本次可证明子集的解释，仍标UNRESOLVED_PROTOCOL_INTERPRETATION。

T11未知hash/flags的本地全局INDETERMINATE仍是已知政策/可用性不足，与“RFC规定必须全响应未知”不同；本轮没有借修复字符过滤去放宽未知算法或Opt-Out。原始false_bogus计数是对参考状态的机械分歧，不是协议裁决；本调查将原始D与独立T05的B分开。
'''
    report.write_text(text,encoding='utf-8')
    assert not changes,changes
    # Preserve raw diagnostic text privately before scrubbing incidental host paths.
    for p in (ROOT/'reference-debug/verifier-logs').glob('*'):
        if p.suffix not in {'.log','.conf'}:continue
        raw=p.read_bytes();private=Path('results/runs/nsec3-debug-original')/p.name;private.parent.mkdir(exist_ok=True);private.write_bytes(raw)
        t=raw.decode('utf-8');t=re.sub(r'(?i)[A-Z]:[/\\]Users[/\\][^\s"\n]+','LOCAL_PATH_REDACTED',t);p.write_text(t,encoding='utf-8')
    cmds=json.loads((ROOT/'verifier-logs/commands.json').read_text(encoding='utf-8'));cmds.update(python_harness_exit_code=0,final_command='python -m evaluation.nsec3_divergence.run <new directory>; serialize reference experiments on shared port53',full_reference='python -m evaluation.dnssec_reference_capture <new output> --scenarios <37 original IDs>',debug='python -m evaluation.nsec3_divergence.run <new directory> T01 debug',unbound_debug_trace='reference-debug/verifier-logs/T01-1-unbound-debug.log')
    save(ROOT/'verifier-logs/commands.json',cmds)
    manifest=[dict(path=str(p.relative_to(ROOT)).replace('\\','/'),sha256=sha(p.read_bytes()),purpose='DNS wire' if p.suffix=='.wire' else 'experiment ledger/configuration/report',scenario=next(iter(re.findall(r'T\d{2}',str(p))), 'shared'),source_version='see per-run environment git_commit; before9ac06c0 / fixe1ecd9e') for p in ROOT.rglob('*') if p.is_file() and p.name!='evidence-manifest.json']
    save(ROOT/'evidence-manifest.json',dict(self_exclusion='manifest excludes its own recursive hash; Git commit protects manifest',files=manifest))

if __name__=='__main__':finalize()
