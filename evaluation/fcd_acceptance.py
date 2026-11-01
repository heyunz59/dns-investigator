"""Reproduce report convergence and discovery refusal; no model or public network."""
import argparse
import asyncio
import hashlib
import json
import subprocess
import uuid
from pathlib import Path
from dns_investigator.reporting import evidence_bound_report
from dns_investigator.schemas import InvestigationResult
from dns_investigator.target import parse_target
from dns_investigator.tools import ToolBackend
from evaluation.controlled_dns import controlled


def report(backend):
    return evidence_bound_report(InvestigationResult(observations=[],hypotheses=[],conclusion="draft",
        conclusion_evidence_ids=[],limitations=[],recommendations=[]),backend)


async def followed_alias(directory):
    fixture=directory/"alias.json"
    fixture.write_text(json.dumps([
        dict(tool="query_dns",match=dict(domain="probe.example"),data=dict(qname="probe.example",qtype="A",resolver="192.0.2.53",rcode="NOERROR",
            result_kind="ALIAS_INCOMPLETE",records=[],cname_chain=[dict(name="probe.example",target="target.other",ttl=60)],canonical_name="target.other")),
        dict(tool="query_dns",match=dict(domain="target.other"),data=dict(qname="target.other",qtype="A",resolver="192.0.2.53",rcode="NOERROR",
            result_kind="NOERROR",records=[dict(value="192.0.2.10",ttl=60)],canonical_name="target.other"))
    ]),encoding="utf-8")
    backend=ToolBackend(parse_target("probe.example"),fixture)
    await backend.call("query_dns",domain="probe.example")
    await backend.call("query_dns",domain="target.other")
    return backend


async def discovery_refusal():
    async with controlled("normal"):
        events=[]
        backend=ToolBackend(parse_target("probe.example"),on_evidence=events.append)
        backend.dns.limit=1
        returned=await backend.call("query_authoritative",domain="probe.example")
    return backend,returned,events


async def capture(out):
    if out.exists():raise FileExistsError("Do not overwrite a saved reproduction")
    directory=Path("results/runs")/("fcd-acceptance-"+uuid.uuid4().hex)
    directory.mkdir(parents=True)
    alias=await followed_alias(directory)
    auth,returned,events=await discovery_refusal()
    data=dict(source_commit=subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip(),
        source_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in Path("src/dns_investigator").glob("*.py")},
        model_invoked=False,public_network_invoked=False,review="automatic_checks_pending_human_review",
        alias=dict(mode="fixture_no_model",evidence=alias.calls,attempts=alias.attempts,report=report(alias).model_dump()),
        authority=dict(mode="controlled_loopback_dns_no_model",evidence=auth.calls,attempts=auth.attempts,dns_attempts=auth.dns.attempts,
            returned=returned,events=events,report=report(auth).model_dump()))
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding="utf-8")
    print(out.as_posix())


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("out",type=Path)
    asyncio.run(capture(p.parse_args().out))
