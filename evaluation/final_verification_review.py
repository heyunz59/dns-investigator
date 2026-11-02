"""Evidence checks and explicitly AI-assisted review notes; no semantic accuracy score."""
from collections import Counter
import json
from pathlib import Path
import statistics
from dns_investigator.privacy import redact
from dns_investigator.reporting import facts
from .summarize_security_stability import verify_source


def read(path):return json.loads(path.read_text(encoding="utf-8"))


def review(log,scenario):
    actual={f["evidence_id"]:f for f in facts(log["evidence"])}
    scope_fields=("target","resolver","record_type","measured_at","source_mode","result")
    claims=log["result"].get("measured_facts",[])
    match=all(c.get("evidence_id") in actual and all(c.get(k)==actual[c["evidence_id"]].get(k) for k in scope_fields) for c in claims)
    auth=[e["data"] for e in log["evidence"] if e["data"].get("resolver_role")=="authoritative" and e["data"].get("flags",{}).get("AA")]
    coverage=(all(len({r.get("resolver") for r in auth if r.get("qtype")==typ})>=2 for typ in ("A","SOA")) if scenario=="serial" else
        any(e["data"].get("qtype")=="NS" and e["data"].get("result_kind")=="TIMEOUT" for e in log["evidence"]) and not auth if scenario=="ns_timeout" else
        len(log["attempts"])==1 and log["attempts"][0]["tool_name"]=="query_dns" and log["attempts"][0]["input"].get("record_type","A")=="A")
    notes={
        "serial":["测量支持选中路径的A/SOA差异；不能从Serial断定复制故障。", "模型候选中缓存/同步/调度等因果措辞仍可能过强，即使status为无法确定。", "检查建议是否将次要重复发现失败误写为整次权威调查未完成。"],
        "ns_timeout":["可支持系统NS查询超时及未取得直接权威回答；未证明权威不可用或注册失败。", "公共NS成功不验证权威连通性；宽泛的权威/注册候选及而非域名侧措辞仍需复核。"],
        "normal":["单项A地址和TTL可对应唯一测量；不要求故障假设或全部工具。", "旧建议收集故障设备信息与单项问题不符，新报告已简化。"],
    }[scenario]
    return dict(measured_scope_matches_evidence=match,mechanical_key_measurement_coverage=coverage,
        independent_semantic_review="PENDING",root_cause_assertion_count=None,
        AI_assisted_semantic_review=dict(reviewer="development_assistant_not_independent_human",notes=notes,
            disposition="测量范围可核对；候选因果文字和建议另行复核" if scenario!="normal" else "单项事实可核对，不扩展为其他路径健康证明"),
        hypothesis_statements=[dict(id=h["id"],statement=h["statement"],status=h["status"],
            supporting_evidence_ids=h.get("supporting_evidence_ids",[])) for h in log["result"].get("hypotheses",[])])


def main():
    root=Path("results/published/final-verification")
    out=root/"real-model-comparison"
    out.mkdir(parents=True,exist_ok=False)
    summaries={};all_rows=[];configs=[]
    for arm,ref in (("baseline","d26d6b7"),("current","92be49a")):
        raw=Path(f"results/runs/final-verification-model-{arm}-{ref}")
        metadata=read(raw/"experiment.json")
        verified=verify_source(metadata)
        configs.append({k:metadata[k] for k in ("model","temperature","thinking","tool_budget","dns_budget","model_timeout","controlled_dns_timeout","controlled_logical_identities")})
        dest=out/arm;dest.mkdir()
        rows=read(raw/"manifest.json")
        for row in rows:
            log=read(raw/row["run_file"])
            assert all(q["server"].startswith("127.0.0.") and q["port"]!=53 for q in log["dns_attempts"])
            (dest/row["run_file"]).write_text(json.dumps(redact(log),ensure_ascii=False,indent=2),encoding="utf-8")
            row["review"]=review(log,row["scenario"])
            row["error_categories"]=dict(Counter((a.get("error") or {}).get("code","none") for a in log["attempts"]))
            row["rejection_reasons"]=dict(Counter((a.get("error") or {}).get("reason","unspecified") for a in log["attempts"] if a.get("error")))
            all_rows.append(row)
        for name,value in (("experiment.json",metadata),("manifest.json",rows)):
            (dest/name).write_text(json.dumps(redact(value),ensure_ascii=False,indent=2),encoding="utf-8")
        summaries[arm]=dict(source_ref=ref,source_hash_verification=verified,runs=len(rows),
            validated_outputs=sum(r["validated_agent_output"] for r in rows),fallbacks=sum(r["fallback"] for r in rows),
            mechanical_coverage=sum(r["review"]["mechanical_key_measurement_coverage"] for r in rows),
            totals={k:sum(r[k] for r in rows) for k in ("A","Q","E","output_resubmissions")},
            error_categories=dict(sum((Counter(r["error_categories"]) for r in rows),Counter())),
            mean_seconds=round(statistics.mean(r["elapsed_seconds"] for r in rows),3),
            usage_known_runs=sum(r.get("usage") is not None for r in rows),
            tokens={k:sum((r.get("usage") or {}).get(k,0) for r in rows if r.get("usage") is not None) for k in ("input_tokens","output_tokens","requests")})
    assert configs[0]==configs[1]
    historical=[]
    old=Path("results/published/security-stability/real-model-comparison")
    for arm in ("baseline","current"):
        for row in read(old/arm/"manifest.json"):
            log=read(old/arm/row["run_file"])
            historical.append(dict(source_file=(old/arm/row["run_file"]).as_posix(),arm=arm,scenario=row["scenario"],repeat=row["repeat"],
                status=log["status"],review=review(log,row["scenario"])))
    (root/"historical-AI-review.json").write_text(json.dumps(historical,ensure_ascii=False,indent=2),encoding="utf-8")
    result=dict(mode="real_DeepSeek_API_controlled_loopback_DNS_not_public_network",config=configs[0],arms=summaries,runs=all_rows,
        review="AI_assisted_and_mechanical_checks_not_independent_human_accuracy",
        conclusions=["Both arms validated 7/7; this batch does not establish an improved success rate.",
            "A increased from 30 to 38; invalid target attempts from 2 to 6. Query-choice improvement is not demonstrated.",
            "Logical identities remove a testing-interface ambiguity; historical 40 cannot be fairly compared with new 38 as a code effect.",
            "All attempts and partial failures remain counted. Semantic root-cause assertion count is unknown, not zero.",
            "Sequential arms share host/configuration, but service load/cache/time and unpinned model version remain uncontrolled.",
            "Only one bounded batch per arm; no additional paid runs to select favorable results.",
            "Current paid source is 92be49a. Later timezone-bound ordering repair is separately replayed; it is not a paid model run."])
    (out/"summary.json").write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding="utf-8")
    print(json.dumps(summaries,ensure_ascii=True))


if __name__=="__main__":main()
