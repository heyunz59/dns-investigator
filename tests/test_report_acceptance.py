"""Report-level counterexamples; no public-network or paid-model assumptions."""
import asyncio
from pathlib import Path
import pytest
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.messages import ModelResponse,ToolCallPart
from pydantic_ai import ModelRetry
from dns_investigator.agent import investigate
from dns_investigator.config import Config
from dns_investigator.schemas import InvestigationResult,Hypothesis
from dns_investigator.reporting import evidence_bound_report
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target


def result(**kw):
    return InvestigationResult(observations=[],hypotheses=[],conclusion="draft",conclusion_evidence_ids=[],limitations=[],recommendations=[],**kw)


def evidence(data,tool="query_dns",mode="live",id="E1"):
    return dict(id=id,tool_name=tool,input=dict(domain="probe.invalid",record_type="A",url="https://example.com/start",port=443),
        data=data,source_mode=mode,started_at="controlled-time",execution_status="ok")


@pytest.mark.parametrize("scenario",["none","timeout","fixture","empty_fixture","private_address","mismatched_target"])
def test_invalid_background_does_not_invent_observation(scenario):
    b=ToolBackend(parse_target("probe.invalid"))
    if scenario=="empty_fixture":b.fixture=[]
    if scenario not in {"none","empty_fixture"}:
        b.calls=[evidence(dict(qname="other.invalid" if scenario=="mismatched_target" else "probe.invalid",qtype="A",resolver="192.168.1.1",
            rcode="TIMEOUT" if scenario=="timeout" else "NXDOMAIN" if scenario=="fixture" else "NOERROR",
            records=[] if scenario!="private_address" else [dict(value="10.0.0.7",ttl=10)]),mode="fixture" if scenario=="fixture" else "live")]
    r=evidence_bound_report(result(outcome="insufficient_information"),b)
    suggestions=" ".join(r.recommendations)
    assert "本次公网 NXDOMAIN" not in suggestions and "背景知识" in suggestions
    assert "hosts" in suggestions
    if scenario in {"fixture","empty_fixture"}:assert "fixture/synthetic" in suggestions


async def test_full_investigate_no_measurements_invalid(tmp_path):
    def model(messages,info):
        r=result(outcome="insufficient_information")
        r.recommendations=["需要测量"];r.limitations=["无证据"]
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,r.model_dump())])
    log,_=await investigate("调查 probe.invalid",parse_target("probe.invalid"),Config("test"),model=FunctionModel(model),log_dir=tmp_path)
    assert log["status"]=="limited" and not log["evidence"]
    assert "本次公网 NXDOMAIN" not in str(log["result"])


def test_http_redirect_error_and_certificate_are_visible():
    b=ToolBackend(parse_target("example.com"))
    b.calls=[evidence(dict(status_code=200,error="TIMEOUT",bytes_read=0,final_url="https://example.com/final",redirects=[dict(status=302,url="https://example.com/final")]),"check_http")]
    r=evidence_bound_report(result(),b)
    assert r.measured_facts[0]["request_state"]=="incomplete"
    for value in ["200","TIMEOUT","302","/final","读取字节=0"]:
        assert value in r.conclusion and value in r.observations[0].observation
    b.calls[0]["data"].update(error="TLS_ERROR",error_detail=dict(code="CERTIFICATE_VERIFY_FAILED",certificate=dict(verify_code=10)))
    r=evidence_bound_report(result(),b)
    assert "CERTIFICATE_VERIFY_FAILED" in r.conclusion and "verify_code" in r.conclusion and "10" in r.conclusion


async def test_real_local_headers_200_then_body_timeout_report():
    release=asyncio.Event()
    async def handler(reader,writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n");await writer.drain()
        await release.wait();writer.close();await writer.wait_closed()
    server=await asyncio.start_server(handler,"127.0.0.1",0)
    b=ToolBackend(parse_target("example.com"))
    try:
        url=f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}/"
        data=await b.check_http(url,timeout=.3)
        assert data["status_code"]==200 and data["error"]=="TIMEOUT"
        b.calls=[evidence(data,"check_http")]
        r=evidence_bound_report(result(),b)
        assert "TIMEOUT" in r.conclusion and "incomplete" in r.conclusion and "200" in r.conclusion
    finally:
        release.set();server.close();await server.wait_closed()


def test_tcp_includes_port():
    b=ToolBackend(parse_target("example.com"));b.calls=[evidence(dict(ip="192.0.2.10",port=8443,status="CONNECTED"),"check_tcp")]
    r=evidence_bound_report(result(),b)
    assert r.measured_facts[0]["port"]==8443 and "8443" in r.conclusion and "192.0.2.10" in r.conclusion


@pytest.mark.parametrize("error",[None,"TOO_MANY_REDIRECTS"])
def test_redirect_success_and_failure_keep_full_chain(error):
    b=ToolBackend(parse_target("example.com"))
    chain=[dict(status=302,url="https://example.com/middle"),dict(status=302,url="https://example.com/final")]
    b.calls=[evidence(dict(status_code=200 if error is None else 302,final_url="https://example.com/final",redirects=chain,error=error,bytes_read=5),"check_http")]
    r=evidence_bound_report(result(),b)
    assert r.measured_facts[0]["redirects"]==chain
    assert "middle" in r.conclusion and "final" in r.conclusion
    assert r.measured_facts[0]["request_state"]==("incomplete" if error else "finished_within_check_limits")
    if error:assert error in r.observations[0].observation


def test_same_category_distinct_causes_preserve_identity_and_answered():
    b=ToolBackend(parse_target("probe.invalid"));b.calls=[evidence(dict(qname="probe.invalid",qtype="A",rcode="TIMEOUT",records=[]))]
    names=["递归解析器本身发生故障","权威服务器无响应导致递归失败"]
    r=result();r.hypotheses=[Hypothesis(id=f"H{i}",category="dns_resolution",statement=s,status="无法确定",missing_information=["需要不同证据验证"] ) for i,s in enumerate(names)]
    r=evidence_bound_report(r,b)
    assert [h.statement for h in r.hypotheses]==names and r.outcome=="answered"


def test_scoped_observable_failure_can_have_counterevidence():
    b=ToolBackend(parse_target("probe.invalid"));b.calls=[evidence(dict(qname="probe.invalid",qtype="A",resolver="1.1.1.1",rcode="NOERROR",records=[]))]
    h=Hypothesis(id="H1",category="dns_resolution",statement="本次 1.1.1.1 对 probe.invalid 的 A 查询失败",status="被削弱",contradicting_evidence_ids=["E1"],testable_claim="dns_query_failure",measurement_scope=dict(target="probe.invalid",resolver="1.1.1.1",record_type="A",source_mode="live"))
    r=result();r.hypotheses=[h]
    r=evidence_bound_report(r,b)
    assert h.contradicting_evidence_ids==["E1"] and h.status=="被削弱"
    h.measurement_scope["record_type"]="AAAA"
    evidence_bound_report(r,b)
    assert not h.contradicting_evidence_ids and h.status=="无法确定"


def test_duplicate_hypotheses_post_transform_and_unknown_refs():
    b=ToolBackend(parse_target("example.com"));b.calls=[evidence(dict(rcode="NOERROR"))]
    r=result();r.hypotheses=[Hypothesis(id=f"H{i}",statement="同一个原因",status="无法确定") for i in range(2)]
    evidence_bound_report(r,b)
    assert len(r.hypotheses)==1 and r.outcome=="insufficient_information"
    r.hypotheses[0].supporting_evidence_ids=["E999"]
    with pytest.raises(ModelRetry):evidence_bound_report(r,b)


def test_duplicate_merge_preserves_missing_information():
    b=ToolBackend(parse_target("example.com"));b.calls=[evidence(dict(rcode="TIMEOUT"))]
    r=result();r.hypotheses=[Hypothesis(id=f"H{i}",statement="同一个原因",status="无法确定",missing_information=[f"检查{i}"]) for i in range(2)]
    r=evidence_bound_report(r,b)
    assert len(r.hypotheses)==1 and r.hypotheses[0].missing_information==["检查0","检查1"]
