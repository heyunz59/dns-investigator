"""Rebuild formal reports from existing ledgers only; never executes a tool/model."""
from copy import deepcopy
from pydantic_ai import ModelRetry


def canonical(log):
    r=log.get('result')
    if not isinstance(r,dict) or 'diagnostic_groups' in r or not log.get('evidence'):return log
    if not any(f.get('code')=='RECURSIVE_QUERY_TIMEOUT' for f in r.get('findings',[])):return log
    try:
        from .tools import ToolBackend
        from .target import parse_target
        from .schemas import InvestigationResult
        from .reporting import evidence_bound_report
        t=log.get('incident',{}).get('target',{})
        target=t.get('url') or t.get('domain') if isinstance(t,dict) else t
        b=ToolBackend(parse_target(target));b.calls=deepcopy(log['evidence']);b.attempts=deepcopy(log.get('attempts',[]))
        b.dns.attempts=deepcopy(log.get('dns_attempts',[]));b.validation_results=deepcopy(log.get('validation_results',[]))
        b.request_context=deepcopy(log.get('request_context',{}))
        current=evidence_bound_report(InvestigationResult.model_validate(r),b)
    except (ValueError,KeyError,TypeError,ModelRetry):return log # incomplete legacy log remains explicitly legacy
    return dict(log,result=current.model_dump(),original_result=deepcopy(r),
        report_replay=dict(mode='historical_ledger_only',new_measurements=0,new_model_calls=0))
