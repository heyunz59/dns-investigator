"""Same-question baseline/current DeepSeek experiments using only controlled DNS.

Run each source in its own process/PYTHONPATH. Expectations never enter the prompt.
"""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import sys
from datetime import datetime,timezone
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))
from evaluation.controlled_dns import controlled
from dns_investigator.agent import investigate
from dns_investigator.config import Config
from dns_investigator.target import parse_target
import dns_investigator.agent

QUESTIONS=dict(serial="调查 probe.example 的权威 DNS 回答是否一致，按证据说明记录和 SOA 的差异与边界。",
    ns_timeout="调查 probe.example 的权威 DNS 查询能否完成，按实际证据说明已完成的阶段、故障范围及未知因素。",
    normal="查询 probe.example 的 A 记录。")


async def run(out,arm,ref,repeats,logical_identities=False):
    out.mkdir(parents=True,exist_ok=False)
    config=Config.load()
    if not config.api_key:
        (out/"not-executed.json").write_text(json.dumps(dict(reason="missing_local_key",model_invoked=False)));return
    config.max_tool_calls=8;config.dns_query_budget=24;config.model_timeout=45
    source=Path(dns_investigator.agent.__file__).parent
    metadata=dict(arm=arm,source_ref=ref,model=config.model,temperature=0,thinking="disabled",tool_budget=8,
        dns_budget=24,model_timeout=45,controlled_dns_timeout=.3,repeats_critical=repeats,repeats_control=1,
        start_utc=datetime.now(timezone.utc).isoformat(),source_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in source.glob("*.py")},
        mode="real_deepseek_with_controlled_loopback_dns",public_network_targets=False,scoring_not_in_prompt=True,
        controlled_logical_identities=logical_identities)
    (out/"experiment.json").write_text(json.dumps(metadata,indent=2),encoding="utf-8")
    manifest=[]
    for repeat in range(1,repeats+1):
        for scenario in ("serial","ns_timeout"):
            started=time.monotonic()
            async with controlled(scenario,logical_identities=logical_identities) as environment:
                log,path=await investigate(QUESTIONS[scenario],parse_target("probe.example"),config,log_dir=out)
            row=review(log,path,arm,scenario,repeat,started,environment)
            manifest.append(row);persist(out,manifest,row)
            if (log.get("error") or {}).get("category") in {"ModelHTTPError","AuthenticationError"}:return
    async with controlled("normal",logical_identities=logical_identities) as environment:
        started=time.monotonic();log,path=await investigate(QUESTIONS["normal"],parse_target("probe.example"),config,log_dir=out)
    row=review(log,path,arm,"normal",1,started,environment);manifest.append(row);persist(out,manifest,row)


def review(log,path,arm,scenario,repeat,started,environment):
    parts=[p for m in log.get("visible_messages",[]) for p in m["parts"]]
    outputs=[p for p in parts if p.get("part_kind")=="tool-call" and p.get("tool_name")=="final_result"]
    valid=log.get("execution_status")=="ended" and log.get("result_origin")=="model_with_evidence_bound_report"
    return dict(arm=arm,scenario=scenario,repeat=repeat,run_file=path.name,status=log["status"],
        validated_agent_output=valid,report_has_measurements=bool(log.get("result",{}).get("measured_facts")),
        fallback=log.get("result_origin")=="application_fallback",A=len(log["attempts"]),Q=len(log["dns_attempts"]),E=len(log["evidence"]),
        output_attempts=len(outputs),output_resubmissions=max(0,len(outputs)-1),usage=log.get("usage"),
        elapsed_seconds=round(time.monotonic()-started,3),finding_codes=[f["code"] for f in log.get("findings",[])],
        authority_states=log.get("result",{}).get("authority_investigations",[]),environment=environment,
        diagnosis_correctness="PENDING_HUMAN_REVIEW",root_cause_assertions="PENDING_HUMAN_REVIEW",
        localization_correctness="PENDING_HUMAN_REVIEW",error=log.get("error"))


def persist(out,manifest,row):
    (out/"manifest.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding="utf-8")
    print(row["arm"],row["scenario"],row["repeat"],row["status"],row["A"],row["Q"],row["E"],row["output_resubmissions"],flush=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("out",type=Path);parser.add_argument("--arm",required=True)
    parser.add_argument("--source-ref",required=True);parser.add_argument("--repeats",type=int,default=3)
    parser.add_argument("--logical-identities",action="store_true")
    args=parser.parse_args()
    if not 1<=args.repeats<=5:parser.error("repeats must be 1..5")
    asyncio.run(run(args.out,args.arm,args.source_ref,args.repeats,args.logical_identities))
