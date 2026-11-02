"""Independent RD=0 wire experiments, with explicit lab roots/endpoint policy."""
import argparse,asyncio,hashlib,json,subprocess
from pathlib import Path
from .protocol_lab import protocol_lab
from .fcd_acceptance import report


async def capture(out):
    if out.exists():raise FileExistsError("Preserve results")
    runs=[]
    for scenario in ("normal","out_of_bailiwick","cname","fallback","unrelated","cycle","private_glue","non_aa","timeout","dname","truncation","budget"):
        async with protocol_lab("normal" if scenario=="budget" else scenario) as lab:
            events=[];b=lab.backend();b.on_evidence=events.append
            if scenario=="budget":b.dns.limit=2
            returned=await b.call("query_authoritative",domain=b.target.domain,mode="trace",timeout=.1)
        runs.append(dict(scenario=scenario,mode="controlled_DNS_UDP_TCP_no_model",attempts=b.attempts,dns_attempts=b.dns.attempts,
            evidence=b.calls,server_received=lab.received,returned=returned,events=events,report=report(b).model_dump()))
    out.write_text(json.dumps(dict(source_ref=subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip(),
        source_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path("src/dns_investigator").glob("*.py")},
        public_network=False,model_invoked=False,runs=runs),ensure_ascii=False,indent=2),encoding="utf-8")
    print("saved trace experiments:",len(runs))


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("out",type=Path);asyncio.run(capture(p.parse_args().out))
