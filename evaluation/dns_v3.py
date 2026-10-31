"""DNS v3 model runs + deterministic findings. Not semantic accuracy scoring."""
import asyncio
import json
import uuid
import sys
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/"src"))
from dns_investigator.agent import investigate
from dns_investigator.config import Config
from dns_investigator.target import parse_target
from dns_investigator.accounting import statistics


async def main():
    config=Config.load()
    if not config.api_key:
        print("BLOCKED: no API key; real-model DNS evaluation not executed")
        return
    out=ROOT/"results/runs"/("dns-v3-"+uuid.uuid4().hex)
    out.mkdir(parents=True)
    rows=[]
    for i in range(1,11):
        question="查询 example.com 的 A 记录" if i==10 else "调查 example.com 的 DNS 解析故障。请比较递归解析器；如存在实质响应差异可查询权威 DNS，SOA 信息也可辅助调查。根据证据承认未知，不必执行 TCP/HTTP。"
        log,path=await investigate(question,parse_target("example.com"),config,
            fixture=ROOT/f"data/fixtures/dns-v3/D{i}.json",log_dir=out)
        s=statistics(log,{"required_tools":[]})
        rows.append(dict(case=f"D{i}",status=log["status"],run_file=path.name,
            tool_calls=s["total_calls"],dns_network_attempts=s["dns_network_attempts"],measurements=s["measurements"],
            elapsed_seconds=log["elapsed_seconds"],finding_codes=sorted({f["code"] for f in log["findings"]}),
            dns_categories=sorted({e["data"].get("result_kind",e["data"].get("rcode","UNKNOWN")) for e in log["evidence"]}),
            unnecessary_calls=sum(a["tool_name"]!="query_dns" for a in log["attempts"]) if i==10 else None,
            incorrect_root_assertions="PENDING_HUMAN_REVIEW",tool_reasonableness="PENDING_HUMAN_REVIEW",
            category_correctness="PENDING_HUMAN_REVIEW",key_measurement_coverage="PENDING_HUMAN_REVIEW",
            rule_baseline="deterministic findings on the same observed evidence; no additional measurements"))
        (out/"summary.json").write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding="utf-8")
        print(f"D{i}",log["status"],s["total_calls"],flush=True)
    print(out,flush=True)


if __name__=="__main__":asyncio.run(main())
