"""Five selected real-model checks; live and fixture results remain distinct."""
import asyncio
import json
import hashlib
import subprocess
import uuid
from pathlib import Path
from dns_investigator.agent import investigate
from dns_investigator.config import Config
from dns_investigator.target import parse_target
from dns_investigator.tools import ToolBackend


async def main():
    c=Config.load()
    if not c.api_key:print("NOT EXECUTED: missing API key");return
    out=Path("results/runs")/("manual-fixes-"+uuid.uuid4().hex);out.mkdir(parents=True)
    meta=dict(base_commit=subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip(),model=c.model,thinking="disabled",temperature=0,
        source_hashes={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in Path("src/dns_investigator").glob("*.py")})
    (out/"metadata.json").write_text(json.dumps(meta,indent=2),encoding="utf-8")
    rows=[]
    cases=[("case3","dns-check.invalid","调查 dns-check.invalid 的 DNS，比较解析器，记录实际查询组合及用途。",None),
        ("case4","https://expired.badssl.com/","调查 https://expired.badssl.com/，检查 HTTPS 及必要 DNS/TCP，不能根据域名断定证书过期。",None),
        ("case7","example.com","调查 https://example.com/ 的访问情况，比较 IPv4/IPv6 TCP 与 HTTP，保留工具差异。",None),
        ("case9","example.com","调查 example.com 的 DNS：先查 A，再查 AAAA；说明模拟事实和缺失来源，不重复不可重试请求。",Path("data/fixtures/MISSING.json")),
        ("query","example.com","只查询 example.com 的 A 记录，报告地址和应答 TTL。",None)]
    for label,target,text,fixture in cases:
        log,path=await investigate(text,parse_target(target),c,fixture=fixture,log_dir=out)
        rows.append(dict(case=label,source="fixture+real-model" if fixture else "live+real-model",status=log["status"],run_file=path.name,
            attempts=len(log["attempts"]),measurements=len(log["evidence"]),issues=log.get("result",{}).get("execution_issues",[]),
            semantic_review="PENDING_HUMAN_REVIEW"))
        (out/"summary.json").write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding="utf-8")
        print(label,log["status"],path.name,flush=True)
    # Same-environment independent TCP / HTTP comparison, no model inference.
    backend=ToolBackend(parse_target("example.com"))
    aaaa=await backend.call("query_dns",domain="example.com",record_type="AAAA")
    ips=[r["value"] for r in aaaa.get("data",{}).get("records",[])][:1]
    if ips:await backend.call("check_tcp",ip=ips[0],port=443)
    await backend.call("check_http",url="https://example.com/")
    (out/"network-comparison.json").write_text(json.dumps(dict(evidence=backend.calls,attempts=backend.attempts,dns_attempts=backend.dns.attempts),ensure_ascii=False,indent=2),encoding="utf-8")
    print(out,flush=True)


if __name__=="__main__":asyncio.run(main())
