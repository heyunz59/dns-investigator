"""Final-source report verification: scripted model, local HTTP, historical replay.

Never calls a paid model or a public network target. Does not edit input records.
"""
import asyncio
import hashlib
import json
import subprocess
import uuid
from pathlib import Path
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.messages import ModelResponse,ToolCallPart
from dns_investigator.agent import investigate
from dns_investigator.config import Config
from dns_investigator.reporting import evidence_bound_report
from dns_investigator.schemas import InvestigationResult,Hypothesis
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target


def empty(**kwargs):
    return InvestigationResult(observations=[],hypotheses=[],conclusion="未测",conclusion_evidence_ids=[],limitations=["受控验证"],recommendations=["需要证据"],**kwargs)


async def main():
    out=Path("results/runs")/("report-acceptance-"+uuid.uuid4().hex);out.mkdir(parents=True)
    hashes={str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in Path("src/dns_investigator").glob("*.py")}
    meta=dict(base_commit=subprocess.check_output(["git","rev-parse","HEAD"],text=True).strip(),source_hashes=hashes,
        verification="offline scripted model + controlled loopback HTTP + historical replay",
        paid_model_invoked=False,public_network_invoked=False)
    rows=[]
    def scripted(messages,info):
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,empty(outcome="insufficient_information").model_dump())])
    log,path=await investigate("调查 probe.invalid",parse_target("probe.invalid"),Config("test",model="scripted-verification"),model=FunctionModel(scripted),log_dir=out)
    assert not log["evidence"] and "本次公网 NXDOMAIN" not in str(log["result"])
    rows.append(dict(case="invalid_without_measurements",status=log["status"],report=log["result"],run_file=path.name,mode="scripted-model"))
    release=asyncio.Event()
    async def handler(reader,writer):
        await reader.readuntil(b"\r\n\r\n")
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n");await writer.drain()
        await release.wait();writer.close();await writer.wait_closed()
    server=await asyncio.start_server(handler,"127.0.0.1",0)
    try:
        backend=ToolBackend(parse_target("example.com"))
        data=await backend.check_http(f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}/",timeout=.3)
        assert data["status_code"]==200 and data["error"]=="TIMEOUT"
        backend.calls=[dict(id="E1",tool_name="check_http",input=dict(url="http://controlled-local-test/"),data=data,source_mode="live",started_at="controlled-test")]
        report=evidence_bound_report(empty(),backend)
        assert "200" in report.conclusion and "TIMEOUT" in report.conclusion and "incomplete" in report.conclusion
        rows.append(dict(case="headers_200_then_timeout",mode="controlled-loopback-http",report=report.model_dump()))
    finally:release.set();server.close();await server.wait_closed()
    source=Path("results/published/manual-fixes-ea2cbd11156f4c729d6f991a1f802d5e")
    for file in source.glob("*.json"):
        old=json.loads(file.read_text(encoding="utf-8"))
        if not isinstance(old,dict) or "result" not in old:continue
        backend=ToolBackend(parse_target(old["incident"]["target"]["url"]))
        backend.calls=old["evidence"];backend.attempts=old["attempts"]
        report=evidence_bound_report(InvestigationResult.model_validate(old["result"]),backend)
        rows.append(dict(case="replay_published_model_record",input_file=str(file),mode="historical-replay-no-model",report=report.model_dump()))
    # Redirect reproduction uses the already anonymized acceptance input.
    reproduction=Path("docs/manual-reviews/20261031_5223c06_验收复现.json")
    if reproduction.exists():
        items=json.loads(reproduction.read_text(encoding="utf-8"))
        data=next(i for i in items if i["case"]=="replay_original_redirect_case")["raw_http"][0]
        backend=ToolBackend(parse_target("https://httpbin.org/relative-redirect/2"))
        backend.calls=[dict(id="E1",tool_name="check_http",input=dict(url=backend.target.url),data=data,source_mode="live",started_at="historical-replay")]
        report=evidence_bound_report(empty(),backend)
        assert len(report.measured_facts[0]["redirects"])==2 and "/get" in report.conclusion
        rows.append(dict(case="replay_original_redirect",mode="historical-replay-no-network",report=report.model_dump()))
    backend=ToolBackend(parse_target("example.com"))
    backend.calls=[dict(id="E1",tool_name="query_dns",input={},data=dict(qname="example.com",qtype="A",rcode="TIMEOUT"),source_mode="fixture",started_at="controlled-test")]
    report=empty();names=["递归解析器本身发生故障","权威服务器无响应导致递归失败"]
    report.hypotheses=[Hypothesis(id=f"H{i}",category="dns_resolution",statement=name,status="无法确定",missing_information=["待验证具体原因"]) for i,name in enumerate(names)]
    report=evidence_bound_report(report,backend)
    assert [h.statement for h in report.hypotheses]==names and report.outcome=="answered"
    rows.append(dict(case="distinct_same_category_hypotheses",mode="constructed-report-input",report=report.model_dump()))
    (out/"metadata.json").write_text(json.dumps(meta,ensure_ascii=False,indent=2),encoding="utf-8")
    (out/"verification.json").write_text(json.dumps(rows,ensure_ascii=False,indent=2),encoding="utf-8")
    print(out,flush=True)
    print("verified cases:",len(rows),flush=True)


if __name__=="__main__":asyncio.run(main())
