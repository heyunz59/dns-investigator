"""Snapshot fixed-evidence replay, not new live measurements or Agent decisions."""
import argparse
import hashlib
import json
import subprocess
import sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from evaluation.accuracy_cases import cases
from dns_investigator.dns_diagnosis import diagnose
from dns_investigator.dns_compare import compare
from dns_investigator.reporting import evidence_bound_report
from dns_investigator.schemas import InvestigationResult,Finding
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target


def capture(destination):
    source=ROOT/"results/published/dns-v3/live-agent.json"
    historical=json.loads(source.read_text(encoding="utf-8"))
    inputs={**cases(),"historical_live_agent":historical["evidence"]}
    rows={}
    for name,evidence in inputs.items():
        finding=diagnose(evidence)
        backend=ToolBackend(parse_target("probe.example"));backend.calls=evidence
        result=InvestigationResult(observations=[],hypotheses=[],conclusion="draft",conclusion_evidence_ids=[],limitations=[],recommendations=[],
            outcome="answered" if evidence else "insufficient_information",findings=[Finding(**f) for f in finding])
        report=evidence_bound_report(result,backend)
        rows[name]=dict(evidence=evidence,comparison=compare([e["data"] for e in evidence]),findings=finding,report=report.model_dump())
    payload=dict(mode="fixed_evidence_replay",paid_model=False,new_network_measurements=False,
        commit=subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip(),
        source_hashes={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in (ROOT/"src/dns_investigator").glob("*.py")},
        historical_source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),cases=rows)
    destination.parent.mkdir(parents=True,exist_ok=True)
    if destination.exists():raise FileExistsError("Do not overwrite a saved replay")
    destination.write_text(json.dumps(payload,ensure_ascii=False,indent=2),encoding="utf-8")
    print(destination.as_posix())


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("destination",type=Path)
    capture(p.parse_args().destination)
