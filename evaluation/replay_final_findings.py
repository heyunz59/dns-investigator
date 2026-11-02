"""Re-evaluate saved measurements only; never re-label a replay as a model run."""
import argparse
import hashlib
import json
from pathlib import Path
from dns_investigator.dns_diagnosis import diagnose
import dns_investigator.dns_diagnosis


def main(out,ref):
    if out.exists():raise FileExistsError("Preserve replay snapshots")
    rows=[]
    for root in (Path("results/published/security-stability/real-model-comparison"),Path("results/published/final-verification/real-model-comparison")):
        for arm in ("baseline","current"):
            for item in json.loads((root/arm/"manifest.json").read_text(encoding="utf-8")):
                path=root/arm/item["run_file"]
                log=json.loads(path.read_text(encoding="utf-8"))
                findings=diagnose(log["evidence"])
                rows.append(dict(source_file=path.as_posix(),finding_codes=[f["code"] for f in findings],
                    finding_count=len(findings),sha256=hashlib.sha256(json.dumps(findings,sort_keys=True,ensure_ascii=False).encode()).hexdigest()))
    source=Path(dns_investigator.dns_diagnosis.__file__)
    out.write_text(json.dumps(dict(source_ref=ref,diagnosis_module_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
        mode="saved_evidence_replay_not_a_model_or_network_run",runs=rows),indent=2),encoding="utf-8")
    print("replayed saved runs:",len(rows))


if __name__=="__main__":
    p=argparse.ArgumentParser();p.add_argument("out",type=Path);p.add_argument("--source-ref",required=True)
    a=p.parse_args();main(a.out,a.source_ref)
