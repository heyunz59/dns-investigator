"""Explicit live DNS tools and optional real model acceptance, raw logs stay local."""
import asyncio
import json
import uuid
from pathlib import Path
from dns_investigator.agent import investigate
from dns_investigator.config import Config
from dns_investigator.target import parse_target
from dns_investigator.tools import ToolBackend


async def main():
    directory=Path("results/runs")/("dns-v3-live-"+uuid.uuid4().hex)
    directory.mkdir(parents=True)
    backend=ToolBackend(parse_target("example.com"))
    for tool in ["compare_resolvers","query_authoritative"]:
        result=await backend.call(tool,domain="example.com",record_type="A",timeout=3)
        print(tool,result["execution_status"],len(backend.dns.attempts),len(backend.calls),flush=True)
    (directory/"tools.json").write_text(json.dumps(dict(attempts=backend.attempts,evidence=backend.calls,
        dns_attempts=backend.dns.attempts),ensure_ascii=False,indent=2),encoding="utf-8")
    config=Config.load()
    if config.api_key:
        log,path=await investigate("请调查 example.com 的 DNS，比较系统及公共递归解析器，并获取权威 DNS 证据，确认是否一致；如果网络受限请明确未知。",parse_target("example.com"),config,log_dir=directory)
        print("model",log["status"],len(log["attempts"]),len(log["dns_attempts"]),path.name,flush=True)
    else:print("model NOT EXECUTED: no API key",flush=True)
    print(directory,flush=True)


if __name__=="__main__":asyncio.run(main())
