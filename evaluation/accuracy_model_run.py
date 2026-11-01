"""Bounded real DeepSeek run in injected loopback environment, for old/new source processes."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import sys
import time

ROOT=Path(__file__).resolve().parents[1]
sys.path.append(str(ROOT))
from evaluation.controlled_dns import controlled,measured_scenario
from dns_investigator.agent import investigate
from dns_investigator.config import Config
from dns_investigator.target import parse_target
import dns_investigator.agent

QUESTIONS=dict(timeout="调查 probe.example 当前 DNS 解析是否存在异常，按需比较路径并说明故障范围；不需要网站访问测试。",
    mismatch="调查 probe.example 的 DNS 响应及递归与权威是否一致，按证据说明范围和未知原因。",
    serial="调查 probe.example 的权威 DNS 回答是否一致，按证据说明记录和 SOA 的差异与边界。",
    normal="查询 probe.example 的 A 记录。")


async def run(out,arm,scenarios,wire_only=False):
    out.mkdir(parents=True,exist_ok=True)
    config=Config.load()
    if not wire_only and not config.api_key:
        print("NOT_EXECUTED: missing local DeepSeek key");return
    config.max_tool_calls=8;config.dns_query_budget=24;config.model_timeout=45
    source=Path(dns_investigator.agent.__file__).parent
    manifest=[]
    for scenario in scenarios:
        start=time.monotonic()
        if wire_only:
            log=await measured_scenario(scenario);path=out/f"{scenario}-wire.json"
            path.write_text(json.dumps(log,ensure_ascii=False,indent=2),encoding="utf-8")
            row=dict(arm=arm,scenario=scenario,mode=log["mode"],run_file=path.name,A=len(log["attempts"]),Q=len(log["dns_attempts"]),E=len(log["evidence"]))
        else:
            async with controlled(scenario) as environment:
                log,path=await investigate(QUESTIONS[scenario],parse_target("probe.example"),config,log_dir=out)
            row=dict(arm=arm,scenario=scenario,mode="real_deepseek_with_controlled_loopback_dns",environment=environment,
                run_file=path.name,status=log["status"],A=len(log["attempts"]),Q=len(log["dns_attempts"]),E=len(log["evidence"]),
                usage=log.get("usage"),error=log.get("error"),question=QUESTIONS[scenario])
        row.update(elapsed_seconds=round(time.monotonic()-start,3),finding_codes=[f["code"] for f in log["findings"]],
            source_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in source.glob("*.py")},
            semantic_review="AI_assisted_pending_independent_human_review")
        manifest.append(row)
        (out/f"{arm}-manifest.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding="utf-8")
        print(arm,scenario,row.get("status","measured"),row["A"],row["Q"],row["E"],flush=True)
        if log.get("error",{}).get("category") in {"ModelHTTPError","AuthenticationError"}:break


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("out",type=Path);p.add_argument("--arm",default="new");p.add_argument("--wire-only",action="store_true")
    p.add_argument("--scenarios",nargs="+",choices=list(QUESTIONS),default=list(QUESTIONS))
    a=p.parse_args();asyncio.run(run(a.out,a.arm,a.scenarios,a.wire_only))
