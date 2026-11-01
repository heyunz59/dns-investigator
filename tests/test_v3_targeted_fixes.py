"""Deterministic reproductions: no public network or model needed."""
import asyncio
import json
import dns.message
import dns.rrset
import dns.flags
import dns.rcode
import pytest
from dns_investigator.tools import ToolBackend, PARENT
from dns_investigator.target import parse_target
from dns_investigator.dns_wire import parse_response
from dns_investigator.dns_diagnosis import diagnose
from dns_investigator.dns_compare import compare
from dns_investigator.agent import investigate
from dns_investigator.config import Config
from pydantic_ai.models.function import FunctionModel
from pydantic_ai.messages import ModelResponse,ToolCallPart


@pytest.mark.parametrize("first",["dns","http"])
async def test_dns_http_exact_ownership_in_both_orders(monkeypatch,first):
    events=[]
    b=ToolBackend(parse_target("example.com"),on_evidence=events.append)
    entered={k:asyncio.Event() for k in ["dns","http"]}
    release={k:asyncio.Event() for k in entered}
    async def dns(**args):
        entered["dns"].set();await release["dns"].wait()
        data=dict(qname="example.com",qtype="A",rcode="NOERROR",records=[dict(value="192.0.2.10",ttl=60)])
        e=b.add_dns_evidence(data,PARENT.get(),"Q-test")
        return {**data,"evidence_id":e["id"]}
    async def http(**args):
        entered["http"].set();await release["http"].wait()
        return dict(status_code=503,marker="own-http-response")
    monkeypatch.setattr(b,"query_dns",dns);monkeypatch.setattr(b,"check_http",http)
    tasks={"dns":asyncio.create_task(b.call("query_dns",domain="example.com")),
           "http":asyncio.create_task(b.call("check_http",url="https://example.com/"))}
    await asyncio.gather(*(e.wait() for e in entered.values()))
    release[first].set();one=await tasks[first]
    other="http" if first=="dns" else "dns"
    release[other].set();two=await tasks[other]
    assert one["id"]!=two["id"] and len(b.calls)==2
    for label,task in tasks.items():
        result=task.result();e=next(e for e in b.calls if e["id"]==result["id"])
        assert e["tool_call_id"]==result["tool_call_id"]
        assert e["parent_tool_call_id"]==result["tool_call_id"]
        assert e["tool_name"]==("query_dns" if label=="dns" else "check_http")
        assert (e["data"].get("status_code")==503) == (label=="http")
    assert len([e for e in events if e["event"]=="evidence"])==2
    assert len({e["id"] for e in b.calls})==2


@pytest.mark.parametrize("ending",["success","timeout","cancel"])
async def test_composite_interleaving_partial_evidence(monkeypatch,ending):
    b=ToolBackend(parse_target("example.com"))
    child_ready=asyncio.Event();finish=asyncio.Event()
    async def composite(**args):
        e=b.add_dns_evidence(dict(qname="example.com",qtype="A",rcode="TIMEOUT",records=[]),PARENT.get(),"Q-one")
        child_ready.set();await finish.wait()
        if ending=="timeout":raise TimeoutError()
        e2=b.add_dns_evidence(dict(qname="example.com",qtype="A",rcode="NOERROR",records=[]),PARENT.get(),"Q-two")
        return {"responses":[{"evidence_id":e["id"]},{"evidence_id":e2["id"]}]}
    async def http(**args):return {"status_code":503}
    monkeypatch.setattr(b,"compare_resolvers",composite);monkeypatch.setattr(b,"check_http",http)
    task=asyncio.create_task(b.call("compare_resolvers",domain="example.com"))
    await child_ready.wait()
    h=await b.call("check_http",url="https://example.com/")
    if ending=="cancel":
        task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
    else:
        finish.set();r=await task
        ids=r["data"]["evidence_ids"] if ending=="success" else [e["id"] for e in r["partial_evidence"]]
        assert h["id"] not in ids
    owned=[e for e in b.calls if e["parent_tool_call_id"]=="A1"]
    assert all(e["tool_name"]=="query_dns" for e in owned)
    assert len(owned)==(2 if ending=="success" else 1)
    assert b.attempts[0]["evidence_ids"]==[e["id"] for e in owned]
    assert next(e for e in b.calls if e["id"]==h["id"])["data"]["status_code"]==503


async def test_two_simple_http_calls_keep_distinct_content(monkeypatch):
    b=ToolBackend(parse_target("example.com"))
    entered={p:asyncio.Event() for p in ["/one","/two"]}
    release={p:asyncio.Event() for p in entered}
    async def http(url,**kw):
        path="/one" if url.endswith("one") else "/two"
        entered[path].set();await release[path].wait()
        return dict(status_code=200 if path=="/one" else 503,path=path)
    monkeypatch.setattr(b,"check_http",http)
    tasks={p:asyncio.create_task(b.call("check_http",url="https://example.com"+p)) for p in entered}
    await asyncio.gather(*(e.wait() for e in entered.values()))
    release["/two"].set();await tasks["/two"]
    release["/one"].set();await tasks["/one"]
    for p,t in tasks.items():
        result=t.result();e=next(e for e in b.calls if e["id"]==result["id"])
        assert e["data"]["path"]==p and e["tool_call_id"]==result["tool_call_id"]
    assert len(b.calls)==2 and len({e["id"] for e in b.calls})==2


async def test_framework_parallel_calls_json_and_jsonl_mapping(monkeypatch,tmp_path):
    dns_done=asyncio.Event()
    async def dns(self,**kw):
        data=dict(qname="example.com",qtype="A",rcode="NOERROR",records=[dict(value="192.0.2.10",ttl=60)])
        e=self.add_dns_evidence(data,PARENT.get(),"Q-scripted")
        dns_done.set();return {**data,"evidence_id":e["id"]}
    async def http(self,**kw):
        await dns_done.wait();return dict(status_code=503)
    monkeypatch.setattr(ToolBackend,"query_dns",dns);monkeypatch.setattr(ToolBackend,"check_http",http)
    turn=0
    def respond(messages,info):
        nonlocal turn
        turn+=1
        if turn==1:
            return ModelResponse(parts=[ToolCallPart("query_dns",{"domain":"example.com"},tool_call_id="dns-id"),
                ToolCallPart("check_http",{"url":"https://example.com/"},tool_call_id="http-id")])
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,dict(request_kind="investigation",
            outcome="insufficient_information",hypotheses=[],analysis_summary="有限证据，无法确认根因",limitations=["脚本测试"],next_directions=["人工复核"]))])
    log,path=await investigate("调查 example.com",parse_target("example.com"),Config("test"),model=FunctionModel(respond),log_dir=tmp_path)
    assert log["status"]=="limited",log
    assert json.loads(path.read_text(encoding="utf-8"))["evidence"]==log["evidence"]
    events=[json.loads(l) for l in path.with_suffix(".jsonl").read_text(encoding="utf-8").splitlines()]
    evidence_events=[r for r in events if r["event"]=="evidence"]
    assert [(r["id"],r["tool_call_id"],r["tool_name"]) for r in evidence_events]==[("E1","A1","query_dns"),("E2","A2","check_http")]
    assert evidence_events[1]["data"]["status_code"]==503
    assert [{k:v for k,v in r.items() if k!="event"} for r in evidence_events]==log["evidence"]
    assert [a["provider_call_id"] for a in log["attempts"]]==["dns-id","http-id"]
    assert [a["evidence_ids"] for a in log["attempts"]]==[["E1"],["E2"]]
    returns=[p for m in log["visible_messages"] for p in m["parts"] if p.get("part_kind")=="tool-return" and p.get("tool_name") in {"query_dns","check_http"}]
    assert {(p["tool_call_id"],p["content"]["id"]) for p in returns}=={("dns-id","E1"),("http-id","E2")}


def message(case,typ="A"):
    r=dns.message.make_response(dns.message.make_query("alias.example",typ))
    cname=case not in {"referral","nodata","truncated"}
    if cname:
        r.answer.append(dns.rrset.from_text("alias.example.",60,"IN","CNAME","target.other."))
    if case in {"cname_referral","referral"}:
        owner="other." if cname else "example."
        r.authority.append(dns.rrset.from_text(owner,60,"IN","NS","ns.other."))
    if case in {"cname_nodata","nodata","truncated","wrong_soa"}:
        owner="unrelated." if case=="wrong_soa" else "other." if cname else "example."
        r.authority.append(dns.rrset.from_text(owner,60,"IN","SOA","ns.other. hostmaster.other. 1 60 60 60 60"))
    if case=="cname_nxdomain":r.set_rcode(dns.rcode.NXDOMAIN)
    if case=="positive":
        r.answer.append(dns.rrset.from_text("target.other.",60,"IN",typ,"192.0.2.10" if typ=="A" else "2001:db8::10"))
    if case=="truncated":r.flags|=dns.flags.TC
    return r


@pytest.mark.parametrize("case,kind,negative",[
    ("cname_referral","REFERRAL",False),("referral","REFERRAL",False),
    ("positive","NOERROR",False),("alias_only","ALIAS_INCOMPLETE",False),
    ("cname_nodata","NODATA",True),("cname_nxdomain","NXDOMAIN",False),
    ("nodata","NODATA",True),("truncated","TRUNCATED",False),("wrong_soa","INDETERMINATE",False)])
def test_cname_classification_and_findings(case,kind,negative):
    d=parse_response(message(case),"alias.example","A","1.1.1.1")
    assert d["result_kind"]==kind
    f=diagnose([dict(id="E1",execution_status="ok",data=d)])
    assert ("NODATA_OBSERVED" in {x["code"] for x in f})==negative
    if case in {"cname_nodata","cname_nxdomain"}:
        assert d["negative_name"]=="target.other" and d["negative_scope"]=="cname_target"
        assert "target.other" in f[0]["explanation"]
    if case=="nodata":
        assert d["negative_name"]=="alias.example" and d["negative_scope"]=="original_name"
    if kind in {"REFERRAL","ALIAS_INCOMPLETE","TRUNCATED","INDETERMINATE"}:
        full=parse_response(message("positive"),"alias.example","A","8.8.8.8",role="authoritative")
        full["flags"]["AA"]=True
        pair=diagnose([dict(id="E1",execution_status="ok",data=d),dict(id="E2",execution_status="ok",data=full)])
        assert "RECURSIVE_AUTH_RESPONSE_MISMATCH" not in {x["code"] for x in pair}
        assert compare([d,full])==["COMPARISON_INCONCLUSIVE"]


def test_alias_aaaa_answer_is_complete():
    d=parse_response(message("positive","AAAA"),"alias.example","AAAA","1.1.1.1")
    assert d["result_kind"]=="NOERROR" and d["records"][0]["value"]=="2001:db8::10"
    assert "NODATA_OBSERVED" not in {f["code"] for f in diagnose([dict(id="E1",execution_status="ok",data=d)])}


def test_unordered_multi_link_chain_ignores_unrelated_answers():
    r=dns.message.make_response(dns.message.make_query("alias.example","A"))
    r.answer.extend([dns.rrset.from_text("middle.other.",60,"IN","CNAME","target.other."),
        dns.rrset.from_text("unrelated.",60,"IN","A","192.0.2.99"),
        dns.rrset.from_text("alias.example.",60,"IN","CNAME","middle.other."),
        dns.rrset.from_text("target.other.",60,"IN","A","192.0.2.10")])
    d=parse_response(r,"alias.example","A","1.1.1.1")
    assert d["canonical_name"]=="target.other" and d["records"]==[dict(value="192.0.2.10",ttl=60)]
    assert d["result_kind"]=="NOERROR"


def test_negative_soa_with_ns_and_aa_alias_referral():
    r=message("cname_nodata")
    r.authority.append(dns.rrset.from_text("other.",60,"IN","NS","ns.other."))
    d=parse_response(r,"alias.example","A","1.1.1.1")
    assert d["result_kind"]=="NODATA" and d["negative_name"]=="target.other"
    r=message("cname_referral");r.flags|=dns.flags.AA
    d=parse_response(r,"alias.example","A","1.1.1.1")
    assert d["result_kind"]=="REFERRAL"
    assert "NODATA_OBSERVED" not in {f["code"] for f in diagnose([dict(id="E1",execution_status="ok",data=d)])}


def test_saved_dns_evidence_is_not_mutated_by_return_metadata():
    b=ToolBackend(parse_target("example.com"))
    data=dict(qname="example.com",records=[])
    row=b.add_dns_evidence(data,"A1","Q1")
    data["evidence_id"]=row["id"]
    assert "evidence_id" not in row["data"]


def test_type3_empty_nodata_and_legacy_unknown_are_distinct():
    r=dns.message.make_response(dns.message.make_query("alias.example","A"))
    d=parse_response(r,"alias.example","A","1.1.1.1")
    assert d["result_kind"]=="NODATA"  # RFC 2308 type 3, no SOA and no NS
    assert "NODATA_OBSERVED" in {f["code"] for f in diagnose([dict(id="E1",execution_status="ok",data=d)])}
    legacy=dict(qname="alias.example",qtype="A",rcode="NOERROR",records=[])
    assert "NODATA_OBSERVED" not in {f["code"] for f in diagnose([dict(id="E1",execution_status="ok",data=legacy)])}
    assert compare([legacy,d])==["COMPARISON_INCONCLUSIVE"]
