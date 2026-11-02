import asyncio
import socket
import ssl
import json
from pathlib import Path
import httpx
import pytest
from pydantic_ai import ModelRetry
from dns_investigator.schemas import InvestigationResult,ExecutionIssue
from dns_investigator.reporting import facts,evidence_bound_report,validate_issue_refs,validate_fact_claims
from dns_investigator.network_errors import describe
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target


def result():
    return InvestigationResult(observations=[],hypotheses=[],conclusion="三解析器所有类型均 NXDOMAIN",conclusion_evidence_ids=[],limitations=[],recommendations=[])


def e(id,type,resolver,mode="live"):
    return dict(id=id,tool_name="query_dns",source_mode=mode,started_at="timestamp",input={},data=dict(qname="dns-check.invalid",qtype=type,resolver=resolver,rcode="NXDOMAIN",records=[]))


def test_partial_resolver_matrix_not_cartesian_expanded():
    b=ToolBackend(parse_target("dns-check.invalid"))
    b.calls=[e("E1","A","system"),e("E2","AAAA","system"),e("E3","NS","system"),e("E4","SOA","system"),e("E5","A","1.1.1.1"),e("E6","A","8.8.8.8")]
    r=evidence_bound_report(result(),b)
    assert len(r.measured_facts)==6
    assert {(f["resolver"],f["record_type"]) for f in r.measured_facts}=={("system",t) for t in ["A","AAAA","NS","SOA"]}|{("1.1.1.1","A"),("8.8.8.8","A")}
    assert "三解析器所有" not in r.conclusion and "未测" in r.conclusion
    assert "续费" not in str(r.recommendations) and "hosts" in str(r.recommendations)
    r.measured_facts=[dict(evidence_id="E5",resolver="1.1.1.1",record_type="AAAA")]
    with pytest.raises(ModelRetry):validate_fact_claims(r,b.calls)


def test_failed_aaaa_has_own_attempt_reference_and_fixture_boundary():
    b=ToolBackend(parse_target("example.com"));b.calls=[e("E1","A","fixture","fixture")]
    b.attempts=[dict(attempt_id="A2",tool_name="query_dns",input=dict(domain="example.com",record_type="AAAA"),error=dict(code="FIXTURE_NOT_COVERED",message="未提供事实"))]
    r=result();r.execution_issues=[ExecutionIssue(attempt_id="A2",tool_name="query_dns",target="example.com",record_type="AAAA",error_code="FIXTURE_NOT_COVERED")]
    validate_issue_refs(r,b.attempts)
    r.execution_issues[0].record_type="A"
    with pytest.raises(ModelRetry):validate_issue_refs(r,b.attempts)
    r=evidence_bound_report(result(),b)
    assert r.execution_issues[0].attempt_id=="A2" and r.execution_issues[0].record_type=="AAAA"
    assert all("AAAA" not in o.observation for o in r.observations)
    assert "live" in r.recommendations[0] and "fixture" in r.conclusion


@pytest.mark.parametrize("category",["client_environment","endpoint_intent","certificate_validation"])
def test_success_does_not_support_unmeasured_cause(category):
    b=ToolBackend(parse_target("example.com"));b.calls=[e("E1","A","system")]
    r=result()
    from dns_investigator.schemas import Hypothesis
    r.hypotheses=[Hypothesis(id="H1",category=category,statement="已确认客户端/按设计/过期",status="获得支持",supporting_evidence_ids=["E1"],contradicting_evidence_ids=["E1"])]
    r=evidence_bound_report(r,b)
    h=r.hypotheses[0]
    assert h.status=="无法确定" and not h.supporting_evidence_ids and not h.contradicting_evidence_ids
    assert "已确认" not in h.statement


def test_exception_context_args_and_secrets_are_safe():
    cert=ssl.SSLCertVerificationError(1,"private URL and secret")
    cert.verify_code=10
    wrapper=httpx.ConnectError("private URL")
    wrapper.__context__=RuntimeError(cert)
    detail=describe(wrapper)
    assert detail["code"]=="CERTIFICATE_VERIFY_FAILED" and detail["certificate"]["verify_code"]==10
    assert "private" not in json.dumps(detail)
    assert describe(httpx.ConnectError("expired.badssl.com"))["code"]=="CONNECTION_FAILED"


async def test_ipv6_controlled_loopback():
    try:server=await asyncio.start_server(lambda r,w:w.close(),"::1",0)
    except OSError as exc:pytest.skip(f"IPv6 loopback unavailable: {type(exc).__name__} errno={exc.errno}")
    b=ToolBackend(parse_target("example.com"))
    try:
        from tcp_support import authorize
        authorize(b,'::1',server.sockets[0].getsockname()[1])
        r=await b.check_tcp("::1",server.sockets[0].getsockname()[1])
        assert r["status"]=="CONNECTED",r
    finally:server.close();await server.wait_closed()


async def test_tcp_oserror_details(monkeypatch):
    loop=asyncio.get_running_loop()
    async def fail(*args):raise OSError(10022,"private data")
    monkeypatch.setattr(loop,"sock_connect",fail)
    from tcp_support import authorize
    r=await authorize(ToolBackend(parse_target("example.com")),'::1').check_tcp("::1",443)
    assert r["status"]=="NETWORK_ERROR" and r["error_detail"]["chain"][0]["errno"]==10022
    assert "private" not in json.dumps(r)


async def test_redundant_batch_query_is_counted_but_not_executed():
    b=ToolBackend(parse_target("example.com"))
    b.register("compare_resolvers",dict(domain="example.com",record_type="A"),"compare")
    r=await b.call("query_dns",domain="example.com",record_type="A")
    assert r["error"]["code"]=="REDUNDANT_QUERY" and len(b.attempts)==2 and not b.dns.attempts


async def test_invalid_timeout_explains_bound_without_execution():
    b=ToolBackend(parse_target("example.com"))
    r=await b.call("check_http",url="https://example.com/",timeout=25)
    assert "15" in r["error"]["message"] and len(b.attempts)==1 and not b.calls


async def test_cli_records_supplement_source(monkeypatch,tmp_path):
    from dns_investigator import main as cli
    from dns_investigator.config import Config
    import argparse
    captured={}
    async def fake(*args,**kwargs):
        captured.update(kwargs)
        return dict(status="limited",result={}),tmp_path/"run.json"
    monkeypatch.setattr(cli,"investigate",fake)
    monkeypatch.setattr(cli.Config,"load",lambda:Config("test"))
    monkeypatch.setattr("builtins.input",lambda prompt:"example.com")
    await cli.run(argparse.Namespace(question="网站打不开",target=None,tools_only=False,fixture=None))
    assert captured["target_source"]=="interactive_supplement"
    assert captured["supplement_events"]==[{"event":"target_requested_and_supplied"}]


def test_query_report_removes_hypotheses_and_inconclusive_badge():
    b=ToolBackend(parse_target("example.com"));b.calls=[e("E1","A","system")]
    r=result();r.request_kind="query"
    from dns_investigator.schemas import Finding
    r.findings=[Finding(code="DNS_INCONCLUSIVE",stage="dns",status="insufficient_information",evidence_ids=["E1"],explanation="",limitations=[],next_checks=[])]
    r=evidence_bound_report(r,b)
    assert not r.hypotheses and not r.findings and "应答 TTL" in r.limitations[0]
