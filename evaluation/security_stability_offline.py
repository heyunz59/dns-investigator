"""Independent offline/controlled snapshots; expectations stay outside tool facts."""
import argparse
import asyncio
import hashlib
import json
from pathlib import Path
import sys
from unittest.mock import patch
import httpx
ROOT=Path(__file__).resolve().parents[1];sys.path.append(str(ROOT))
from evaluation.controlled_dns import controlled
from evaluation.accuracy_cases import cases
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target
from dns_investigator.dns_diagnosis import diagnose
from dns_investigator.dns_compare import compare_details,evidence_rows
from dns_investigator.schemas import InvestigationResult
from dns_investigator.reporting import evidence_bound_report
import dns_investigator.agent


def report(b):
    return evidence_bound_report(InvestigationResult(observations=[],hypotheses=[],conclusion="draft",conclusion_evidence_ids=[],limitations=[],recommendations=[]),b).model_dump()


async def run(out,ref):
    if out.exists():raise FileExistsError("Do not overwrite snapshots")
    rows=[]
    for scenario in ["timeout","mismatch","serial","soa_timeout","ns_timeout","ns_empty","ns_refused","ns_servfail","address_failed","non_aa","partial_auth","auth_timeout","normal","budget"]:
        async with controlled("normal" if scenario=="budget" else scenario) as environment:
            b=ToolBackend(parse_target("probe.example"))
            if scenario=="budget":b.dns.limit=1
            returned=await b.call("query_dns" if scenario=="normal" else "query_authoritative",domain="probe.example")
        rows.append(dict(case=scenario,mode="controlled_loopback_dns_no_model",environment=environment,A=len(b.attempts),Q=len(b.dns.attempts),E=len(b.calls),
            attempts=b.attempts,evidence=b.calls,dns_attempts=b.dns.attempts,returned=returned,report=report(b)))
    times=[]
    for kind,values in [("known",["2026-11-01T00:00:00+00:00","2026-11-01T00:00:10+00:00"]),
        ("missing_one",[None,"2026-11-01T00:00:10+00:00"]),("missing_both",[None,None]),
        ("invalid",["bad-time","2026-11-01T00:00:10+00:00"]),
        ("outside_window",["2026-11-01T00:00:00+00:00","2026-11-01T00:10:00+00:00"])]:
        data=cases()["nxdomain"]
        for e,t in zip(data,values):e["started_at"]=t
        times.append(dict(case=kind,mode="fixed_evidence_replay",evidence=data,comparison=compare_details(evidence_rows(data)),findings=diagnose(data)))
    dispatched=[];original=httpx.AsyncClient
    class Body(httpx.AsyncByteStream):
        async def __aiter__(self):yield b"controlled"
    def mock(request):
        dispatched.append(str(request.url))
        return httpx.Response(302,headers={"location":"http://127.0.0.1/"}) if len(dispatched)==1 else httpx.Response(200,stream=Body())
    def client(**kwargs):kwargs["transport"]=httpx.MockTransport(mock);return original(**kwargs)
    b=ToolBackend(parse_target("https://allowed.example/"))
    with patch.object(httpx,"AsyncClient",client):http_result=await b.check_http(b.target.url)
    source=Path(dns_investigator.agent.__file__).parent
    data=dict(source_ref=ref,source_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in source.glob("*.py")},
        model_invoked=False,public_network_invoked=False,authority=rows,time=times,
        redirect=dict(mode="mock_http_dispatch_not_real_network",dispatched_urls=dispatched,result=http_result),
        review="automatic_rules_pending_independent_human_review")
    out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding="utf-8")
    print(out.as_posix(),"controlled cases",len(rows),"time replays",len(times),"HTTP dispatches",len(dispatched),flush=True)


if __name__=="__main__":
    parser=argparse.ArgumentParser();parser.add_argument("out",type=Path);parser.add_argument("--source-ref",required=True)
    args=parser.parse_args();asyncio.run(run(args.out,args.source_ref))
