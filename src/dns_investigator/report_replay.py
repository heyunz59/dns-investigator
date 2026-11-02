"""Rebuild formal reports from existing ledgers only; never executes a tool/model."""
from copy import deepcopy
from types import SimpleNamespace
from pydantic_ai import ModelRetry


def historical_context(log,result,target):
    """Stored formal context wins, including explicit unknown/invalid values."""
    source='result.request_context' if 'request_context' in result else 'request_context' if 'request_context' in log else 'unknown'
    ctx=result.get('request_context') if source=='result.request_context' else log.get('request_context',{})
    if not isinstance(ctx,dict):return {},source,'invalid_type'
    if not ctx:return {},source,'unknown'
    from .target import domain,parse_target
    allowed={'Recursive DNS','Authoritative DNS','Delegation','DNSSEC','CNAME/Alias Resolution','TCP/Network Transport','TLS','HTTP','Client Environment','Unknown'}
    try:
        if ctx.get('target') is not None and (not isinstance(ctx['target'],str) or domain(ctx['target'])!=target.domain):raise ValueError()
        if ctx.get('url') is not None:
            url=parse_target(ctx['url'])
            if url.domain!=target.domain or url.port!=target.port:raise ValueError()
        if 'port' in ctx and (type(ctx['port']) is not int or ctx['port']!=target.port):raise ValueError()
        if 'request_kind' in ctx and ctx['request_kind']!=result.get('request_kind','investigation'):raise ValueError()
        layers=ctx.get('focus_layers',[])
        if not isinstance(layers,list) or any(not isinstance(x,str) or x not in allowed for x in layers):raise ValueError()
        if 'ambiguous' in ctx and type(ctx['ambiguous']) is not bool:raise ValueError()
        if 'negated_mentions' in ctx and type(ctx['negated_mentions']) is not bool:raise ValueError()
        if layers and (len(layers)!=1 or ctx.get('ambiguous') is not False or ctx.get('intent_source')!='explicit_user_statement'):raise ValueError()
        if 'intent_source' in ctx and ctx['intent_source'] not in {'explicit_user_statement','ambiguous_or_unspecified','unknown'}:raise ValueError()
    except (ValueError,TypeError,AttributeError):return {},source,'invalid_structure_or_scope'
    # Do not restore arbitrary commands/environment metadata from an open dict.
    keys={'target','url','port','request_kind','focus_layers','ambiguous','intent_source','negated_mentions'}
    return deepcopy({k:v for k,v in ctx.items() if k in keys}),source,'validated_stored_fields'


class HistoricalBackend(SimpleNamespace):
    """Only ledger copies and pure report attributes, no live backend."""
    def _validate(self,*args,**kwargs):
        raise ValueError('Historical data does not authorize current execution')


def canonical(log):
    r=log.get('result')
    if not isinstance(r,dict) or 'diagnostic_groups' in r or not log.get('evidence'):return log
    if not any(f.get('code')=='RECURSIVE_QUERY_TIMEOUT' for f in r.get('findings',[])):return log
    try:
        from .target import parse_target
        from .schemas import InvestigationResult
        from .reporting import evidence_bound_report
        incident=log.get('incident')
        t=incident.get('target') if isinstance(incident,dict) else None
        target=t.get('url') or t.get('domain') if isinstance(t,dict) else t
        if not isinstance(target,str):return log
        target=parse_target(target)
        ctx,ctx_source,ctx_status=historical_context(log,r,target)
        modes={e.get('source_mode') for e in log['evidence']}
        b=HistoricalBackend(target=target,calls=deepcopy(log['evidence']),attempts=deepcopy(log.get('attempts',[])),
            dns=SimpleNamespace(attempts=deepcopy(log.get('dns_attempts',[])),system=()),resolvers=(),
            validation_results=deepcopy(log.get('validation_results',[])),request_context=ctx,fixture=[] if modes=={'fixture'} else None)
        current=evidence_bound_report(InvestigationResult.model_validate(dict(r,request_context=ctx)),b)
        for step in current.remediation_plan:
            method=step.method
            method.update(authorization_status='requires_revalidation',can_execute_now=False,
                available_tool_capability=method.get('tool_name') or ('query_dns' if method.get('parameters_constructed') else None),supported_by_current_tools=False)
            if method.get('kind')=='current_tool':method['kind']='external_read_only'
            method['description']='历史调用/参数仅供核对，不代表当前授权。新调查须重新确认目标、解析器、网络和预算；本次未执行检查。'
    except (ValueError,KeyError,TypeError,ModelRetry):return log # incomplete legacy log remains explicitly legacy
    return dict(log,result=current.model_dump(),original_result=deepcopy(r),
        report_replay=dict(mode='historical_ledger_only',new_measurements=0,new_model_calls=0,
            request_context_source=ctx_source,request_context_validation=ctx_status,current_environment_used=False))
