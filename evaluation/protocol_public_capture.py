"""Small bounded public deep-mode sample, no LLM and no recursive fallback."""
import argparse,asyncio,hashlib,json,subprocess
from pathlib import Path
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target
from evaluation.fcd_acceptance import report


async def capture(out,domain="cloudflare.com"):
    if out.exists():raise FileExistsError("Preserve experiments")
    rows=[]
    for mode in ("trace","dnssec"):
        b=ToolBackend(parse_target(domain));b.max_auth_servers=1;b.dns_tool_timeout=12;b.dns.limit=16
        returned=await b.call("query_authoritative",domain=b.target.domain,mode=mode,timeout=2)
        rows.append(dict(mode=mode,returned=returned,attempts=b.attempts,dns_attempts=b.dns.attempts,
            evidence=b.calls,validation_results=getattr(b,"validation_results",[]),report=report(b).model_dump()))
        print(mode,[(a.get("protocol_state") or {}).get("stop_reason") for a in b.attempts],flush=True)
    out.write_text(json.dumps(dict(source_ref=subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip(),
        source_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path("src/dns_investigator").glob("*.py")},
        mode="public_network_no_model",not_a_network_availability_guarantee=True,runs=rows),ensure_ascii=False,indent=2),encoding="utf-8")


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("out",type=Path);parser.add_argument("--domain",default="cloudflare.com")
    args=parser.parse_args();asyncio.run(capture(args.out,args.domain))
