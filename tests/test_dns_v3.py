import asyncio
import json
from pathlib import Path
import dns.message
import dns.flags
import dns.rcode
import dns.rrset
import pytest
from dns_investigator.tools import ToolBackend
from dns_investigator.dns_wire import parse_response
from dns_investigator.dns_compare import compare
from dns_investigator.dns_diagnosis import diagnose
from dns_investigator.target import parse_target
from dns_investigator.agent import investigate
from dns_investigator.config import Config
from pydantic_ai.messages import ModelResponse,ToolCallPart
from pydantic_ai.models.function import FunctionModel

ROOT=Path(__file__).resolve().parents[1]


def response(typ="A",code="NOERROR",aa=False,values=None):
    r=dns.message.make_response(dns.message.make_query("example.com",typ))
    r.set_rcode(dns.rcode.from_text(code))
    if aa:
        r.flags|=dns.flags.AA
    if values:
        r.answer.append(dns.rrset.from_text("example.com",60,"IN",typ,*values))
    return r


@pytest.mark.parametrize("code",["NXDOMAIN","SERVFAIL","REFUSED","NOERROR"])
def test_wire_rcode_and_negative_soa_preserved(code):
    r=response(code=code)
    r.authority.append(dns.rrset.from_text("example.com",60,"IN","SOA","ns.example.com hostmaster.example.com 7 60 60 60 60"))
    data=parse_response(r,"example.com","A","1.1.1.1")
    assert data["rcode"]==code and data["soa_serials"]==[7]
    if code=="NOERROR":
        assert data["result_kind"]=="NODATA"


@pytest.mark.parametrize("typ,value",[("A","192.0.2.10"),("AAAA","2001:db8::10"),("CNAME","alias.example.com."),("NS","ns.example.com."),("SOA","ns.example.com hostmaster.example.com 1 60 60 60 60")])
def test_five_types(typ,value):
    d=parse_response(response(typ,values=[value]),"example.com",typ,"1.1.1.1")
    assert d["records"] and d["qtype"]==typ and all(k in d["flags"] for k in ["AA","RD","RA","TC"])


def test_cname_loop_and_referral():
    r=response()
    r.answer.extend([dns.rrset.from_text("example.com",60,"IN","CNAME","b.example.com"),dns.rrset.from_text("b.example.com",60,"IN","CNAME","example.com")])
    assert parse_response(r,"example.com","A","1.1.1.1")["cname_loop"]
    r=response();r.authority.append(dns.rrset.from_text("example.com",60,"IN","NS","ns.example.com"))
    assert parse_response(r,"example.com","A","1.1.1.1")["result_kind"]=="REFERRAL"


def test_cdn_and_ttl_do_not_become_fault():
    a=parse_response(response(values=["192.0.2.10"]),"example.com","A","1.1.1.1")
    b=parse_response(response(values=["192.0.2.11"]),"example.com","A","8.8.8.8")
    assert "ADDRESS_SET_DIFFERENCE" in compare([a,b])
    f=diagnose([dict(id="E1",execution_status="ok",data=a),dict(id="E2",execution_status="ok",data=b)])
    assert not any(x["code"]=="RESOLVER_DISAGREEMENT" for x in f)


def test_same_cname_with_ttl_difference_is_not_alias_difference():
    a=dict(rcode="NOERROR",records=[],cname_chain=[dict(name="example.com",target="alias.example.com",ttl=5)])
    b=dict(rcode="NOERROR",records=[],cname_chain=[dict(name="example.com",target="alias.example.com",ttl=60)])
    assert "CNAME_DIFFERENCE" not in compare([a,b])


@pytest.mark.parametrize("rcode,code",[("SERVFAIL","DNS_SERVFAIL"),("REFUSED","DNS_REFUSED"),("NXDOMAIN","NXDOMAIN_OBSERVED")])
def test_findings_for_dns_errors(rcode,code):
    d=parse_response(response(code=rcode),"example.com","A","1.1.1.1")
    assert code in {f["code"] for f in diagnose([dict(id="E1",execution_status="ok",data=d)])}


async def test_udp_tcp_fallback_and_budget(monkeypatch):
    b=ToolBackend(parse_target("example.com"));b.dns.system=["127.0.0.1"]
    async def udp(*a,**k):
        r=response();r.flags|=dns.flags.TC;return r
    async def tcp(*a,**k):
        return response(values=["192.0.2.10"])
    monkeypatch.setattr(dns.asyncquery,"udp",udp);monkeypatch.setattr(dns.asyncquery,"tcp",tcp)
    result=await b.call("query_dns",domain="example.com")
    assert result["data"]["transport"]=="TCP" and len(b.dns.attempts)==2 and len(b.calls)==2
    assert len(b.attempts)==1 and {q["parent_tool_call_id"] for q in b.dns.attempts}=={"A1"}
    b.dns.limit=2
    await b.call("query_dns",domain="example.com")
    assert len(b.dns.attempts)==2


async def test_private_authority_and_explicit_target_safety():
    b=ToolBackend(parse_target("example.com"))
    assert not b.dns.permitted("127.0.0.1",True)
    assert not b.dns.permitted("169.254.169.254",True)
    b.dns.system=["192.168.1.1"]
    assert b.dns.permitted("192.168.1.1")
    r=await b.call("query_dns",domain="example.com",resolver="10.123.1.2")
    assert r["error"]["code"]=="INVALID_INPUT"


async def test_composite_real_udp_integration():
    class Server(asyncio.DatagramProtocol):
        def connection_made(self,transport): self.transport=transport
        def datagram_received(self,data,addr):
            query=dns.message.from_wire(data);r=dns.message.make_response(query)
            r.answer.append(dns.rrset.from_text(str(query.question[0].name),30,"IN","A","192.0.2.10"))
            self.transport.sendto(r.to_wire(),addr)
    loop=asyncio.get_running_loop()
    transport,_=await loop.create_datagram_endpoint(Server,local_addr=("127.0.0.1",0))
    port=transport.get_extra_info("sockname")[1]
    b=ToolBackend(parse_target("example.com"))
    try:
        result=await b.dns.query("example.com","A","127.0.0.1",parent="integration",port=port)
        assert result["records"][0]["value"]=="192.0.2.10" and len(b.dns.attempts)==1
        assert b.calls[0]["source_mode"]=="live"
    finally: transport.close()


@pytest.mark.parametrize("case",[f"D{i}" for i in range(1,11)])
async def test_d_cases(case):
    b=ToolBackend(parse_target("example.com"),ROOT/f"data/fixtures/dns-v3/{case}.json")
    if case=="D10":
        await b.call("query_dns",domain="example.com",record_type="A")
        assert len(b.attempts)==1
    else:
        await b.call("compare_resolvers",domain="example.com",record_type="A")
        assert all(r.get("evidence_id","").startswith("E") for r in b.fixture[1]["data"]["responses"])
        if case in {"D4","D5","D9"}:
            await b.call("query_authoritative",domain="example.com",record_type="A")
    codes={f["code"] for f in diagnose(b.calls)}
    expected={"D1":"DNS_INCONCLUSIVE","D2":"RESOLVER_DISAGREEMENT","D3":"DNS_TIMEOUT","D4":"RECURSIVE_AUTH_MISMATCH","D5":"AUTH_SERVER_DISAGREEMENT","D6":"NODATA_OBSERVED","D7":"DNS_TIMEOUT","D8":"DNS_INCONCLUSIVE","D9":"DNS_TIMEOUT","D10":"DNS_INCONCLUSIVE"}
    assert expected[case] in codes
    assert len({e["id"] for e in b.calls})==len(b.calls)
    assert all(set(f["evidence_ids"]) <= {e["id"] for e in b.calls} for f in diagnose(b.calls))


async def test_agent_registers_five_and_selects_new_tools(tmp_path):
    step=0
    def model(messages,info):
        nonlocal step
        step+=1
        assert {t.name for t in info.function_tools}=={"query_dns","compare_resolvers","query_authoritative","check_tcp","check_http"}
        if step<=2:
            return ModelResponse(parts=[ToolCallPart("compare_resolvers" if step==1 else "query_authoritative",{"domain":"example.com"})])
        return ModelResponse(parts=[ToolCallPart(info.output_tools[0].name,dict(request_kind="investigation",outcome="insufficient_information",observations=[],hypotheses=[],conclusion="存在差异，无法确定唯一原因",conclusion_evidence_ids=["E1"],limitations=["未证明根因"],recommendations=["补充查询"]))])
    log,_=await investigate("调查 example.com",parse_target("example.com"),Config("test"),
        fixture=ROOT/"data/fixtures/dns-v3/D4.json",model=FunctionModel(model),log_dir=tmp_path)
    assert log["status"]=="limited",log
    assert [a["tool_name"] for a in log["attempts"]]==["compare_resolvers","query_authoritative"]
