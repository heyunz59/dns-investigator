"""One bounded real-model/fixture check of partial execution issues, no public DNS."""
import asyncio
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from evaluation.accuracy_cases import cases
from dns_investigator.agent import investigate
from dns_investigator.config import Config
from dns_investigator.target import parse_target


async def run(out):
    out.mkdir(parents=True,exist_ok=False)
    config=Config.load()
    if not config.api_key:
        (out/"not-executed.json").write_text(json.dumps(dict(reason="missing_local_key")))
        return
    config.max_tool_calls=8;config.dns_query_budget=24;config.model_timeout=45
    rows=[e["data"] for e in cases()["nxdomain"]]
    rows.append(dict(qname="probe.example",qtype="A",resolver="9.9.9.9",resolver_role="recursive",execution_status="error",
        error=dict(code="FIXTURE_PATH_NOT_PROVIDED",retryable=False),records=[]))
    fixture=out/"raw-fixture.json"
    fixture.write_text(json.dumps([dict(tool="compare_resolvers",match=dict(domain="probe.example",record_type="A"),data=dict(responses=rows))],indent=2),encoding="utf-8")
    log,path=await investigate("比较不同递归解析器对 probe.example A 记录的回答，调查差异及其范围；保留未获得的事实。",parse_target("probe.example"),config,fixture=fixture,log_dir=out)
    source=Path("src/dns_investigator")
    manifest=dict(mode="real_deepseek_with_fixture_no_network",source_commit=subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip(),
        source_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in source.glob("*.py")},
        model=config.model,thinking="disabled",temperature=0,run_file=path.name,status=log["status"],
        A=len(log["attempts"]),Q=len(log["dns_attempts"]),E=len(log["evidence"]),usage=log.get("usage"),
        elapsed_seconds=log["elapsed_seconds"],semantic_review="AI_assisted_pending_independent_human_review")
    (out/"manifest.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding="utf-8")
    print(log["status"],manifest["A"],manifest["Q"],manifest["E"],manifest["elapsed_seconds"],flush=True)


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("out",type=Path)
    asyncio.run(run(p.parse_args().out))
