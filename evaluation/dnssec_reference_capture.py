import argparse,asyncio,json,hashlib,subprocess,uuid
from pathlib import Path
from .signed_protocol_lab import signed_lab
from .unbound_reference import reference,reference_ports
from .fcd_acceptance import report


async def capture(out,scenarios):
    if out.exists():raise FileExistsError("Preserve original experiments")
    rows=[];raw=Path("results/runs/dnssec-reference")/uuid.uuid4().hex
    for scenario in scenarios:
        async with signed_lab(scenario) as lab:
            b=lab.backend();r=await b.call("query_authoritative",domain=b.target.domain,mode="dnssec",timeout=.2)
            project_packets=list(lab.received);lab.received.clear()
            async with reference_ports(lab):
                ref=await reference(lab,"results/runs/reference-tools/unbound-1.26.2",raw/scenario)
            external_packets=list(lab.received)
        rows.append(dict(scenario=scenario,project=r["data"].get("validation"),reference=ref,
            attempts=b.attempts,dns_attempts=b.dns.attempts,evidence=b.calls,validation_results=getattr(b,"validation_results",[]),
            project_packets=project_packets,external_reference_packets=external_packets,report=report(b).model_dump()))
        print(scenario,(r["data"].get("validation") or {}).get("dnssec_status"),json.dumps(ref),flush=True)
    out.write_text(json.dumps(dict(source_ref=subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip(),
        source_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path("src/dns_investigator").glob("*.py")},
        mode="controlled_signed_DNS_plus_independent_Unbound_not_public_targets",model_invoked=False,
        reference_download=json.loads(Path("results/runs/reference-tools/download.json").read_text()),runs=rows),ensure_ascii=False,indent=2),encoding="utf-8")


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("out",type=Path);p.add_argument("--scenarios",nargs="+",default=["secure"])
    a=p.parse_args();asyncio.run(capture(a.out,a.scenarios))
