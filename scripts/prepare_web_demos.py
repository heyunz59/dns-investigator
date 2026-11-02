"""Prepare explicit demos from frozen v0.5 controlled evidence, never public measurements."""
import json
from pathlib import Path
from evaluation.report_quality import report

def main():
    rows=json.loads(Path('results/published/v05-report-quality-fixes/20261102-report-quality/before.json').read_text(encoding='utf8'))['cases']
    path=Path('results/runs');path.mkdir(exist_ok=True,parents=True)
    for row in rows:
        log={k:row.get(k,[]) for k in ['evidence','attempts','dns_attempts','validation_results']}
        log.update(result=report(row),demo=True,status='historical_replay',started_at='2026-11-02',incident={'measurement_location':'synthetic'})
        key='webdemo'+row['case'].replace('-','').replace('_','')
        (path/(key+'.json')).write_text(json.dumps(log,ensure_ascii=False),encoding='utf8')
    print('Prepared 13 labeled historical/constructed demo reports.')
if __name__=='__main__':main()
