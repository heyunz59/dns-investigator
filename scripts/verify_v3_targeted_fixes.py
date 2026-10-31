"""Two real DeepSeek runs with controlled facts, not public-network acceptance."""
import asyncio
import json
import uuid
from pathlib import Path
import dns.message
import dns.rrset
from dns_investigator.agent import investigate
from dns_investigator.config import Config
from dns_investigator.dns_wire import parse_response
from dns_investigator.target import parse_target


async def main():
    config=Config.load()
    if not config.api_key:
        print("NOT EXECUTED: no DeepSeek API key")
        return
    out=Path("results/runs")/("v3-targeted-"+uuid.uuid4().hex)
    out.mkdir(parents=True,exist_ok=False)
    summaries=[]
    for case in ("parallel_facts","cname_referral"):
        response=dns.message.make_response(dns.message.make_query("example.com","A"))
        if case=="parallel_facts":
            response.answer.append(dns.rrset.from_text("example.com.",60,"IN","A","192.0.2.10"))
            question="调查 https://example.com/ 打不开。请查询 A 和检查 HTTPS，可并行检查。基于实际证据分析可能原因，不必查询其他解析器或权威。"
        else:
            response.answer.append(dns.rrset.from_text("example.com.",60,"IN","CNAME","target.other."))
            response.authority.append(dns.rrset.from_text("other.",60,"IN","NS","ns.other."))
            question="查询 example.com 的 A 记录，只使用 query_dns；说明本次响应是转介、已得到最终记录，还是已确认无记录。"
        data=parse_response(response,"example.com","A","1.1.1.1")
        fixture=out/f"{case}-facts.json"
        fixture.write_text(json.dumps([
            dict(tool="query_dns",match=dict(domain="example.com",record_type="A"),data=data),
            dict(tool="check_http",match=dict(url="https://example.com/"),data=dict(status_code=503,final_url="https://example.com/",error=None))
        ],indent=2),encoding="utf-8")
        log,path=await investigate(question,parse_target("example.com"),config,fixture=fixture,log_dir=out)
        summaries.append(dict(case=case,model=config.model,thinking="disabled",temperature=0,
            status=log["status"],run_file=path.name,tool_names=[a["tool_name"] for a in log["attempts"]],
            evidence=[dict(id=e["id"],call=e["tool_call_id"],tool=e["tool_name"],rcode=e["data"].get("result_kind"),http_status=e["data"].get("status_code")) for e in log["evidence"]],
            semantic_assessment="PENDING_HUMAN_REVIEW",source="real DeepSeek with fixture facts; not live DNS/HTTP"))
        print(case,log["status"],path.name,flush=True)
    (out/"summary.json").write_text(json.dumps(summaries,ensure_ascii=False,indent=2),encoding="utf-8")
    print(out,flush=True)


if __name__=="__main__":asyncio.run(main())
