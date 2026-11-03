"""Same-evidence report replay; no network and no model calls."""
import argparse,copy,hashlib,json,subprocess
from pathlib import Path
from dns_investigator.schemas import InvestigationResult
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target
from dns_investigator.reporting import evidence_bound_report


def report(row):
    b=ToolBackend(parse_target(row['target']))
    b.calls=copy.deepcopy(row['evidence']);b.attempts=copy.deepcopy(row['attempts'])
    b.validation_results=copy.deepcopy(row.get('validation_results',[]))
    b.request_context=copy.deepcopy(row.get('request_context',{}))
    b.dns.attempts=copy.deepcopy(row.get('dns_attempts',[]))
    r=InvestigationResult(observations=[],hypotheses=[],conclusion='draft',conclusion_evidence_ids=[],limitations=[],recommendations=[])
    return evidence_bound_report(r,b).model_dump()


def capture(out,baseline=None):
    out.mkdir(parents=True,exist_ok=False)
    source=Path(__file__).resolve().parents[1]/'tests/fixtures/reports/report-quality.json'
    rows=copy.deepcopy(json.loads(source.read_text(encoding='utf-8'))['cases'])
    for row in rows:
        row['replayed_result']=report(row)
    result=dict(source_commit=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        fixture_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),cases=rows,
        new_public_measurements=0,new_model_calls=0,semantic_review='PENDING_HUMAN_REVIEW')
    (out/'replay.json').write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
    print('Replayed frozen report cases:',len(rows))


if __name__=='__main__':
    p=argparse.ArgumentParser();p.add_argument('output',type=Path);args=p.parse_args();capture(args.output)
