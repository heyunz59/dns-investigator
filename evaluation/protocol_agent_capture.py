"""Actual DeepSeek decisions against explicit controlled DNS, never public targets.

Criteria live in protocol_agent_criteria.json and are not sent to the Agent.
"""
import argparse
import asyncio
import hashlib
import importlib
import json
import subprocess
from pathlib import Path
from unittest.mock import patch

from dns_investigator.config import Config
from dns_investigator.target import parse_target
from dns_investigator.tools import InputRejected
from evaluation.signed_protocol_lab import signed_lab

agent_module = importlib.import_module("dns_investigator.agent")
QUESTIONS = {
    "normal": "查询 probe.example.test 的 A 记录。",
    "basic": "调查 probe.example.test 的权威 A 回答；只做默认 basic 权威检查，不要求独立追踪或 DNSSEC。",
    "trace": "请从根开始独立追踪 probe.example.test 的 A 委派路径，不使用递归代办。按实际路径及停止位置报告。",
    "dnssec": "请直接验证 probe.example.test 的 A 记录 DNSSEC 信任链、签名及必要证明，按程序本地验证结果回答。",
    "bogus": "请验证 probe.example.test 的 A 记录 DNSSEC，按程序本地结果区分协议问题与未知运维原因。",
    "ede": "调查 probe.example.test 的 A 记录及 DNSSEC；先取一次递归 A，若有服务器自报 DNSSEC 线索，请本地验证，区分来源。",
    "budget": "请独立追踪并验证 probe.example.test 的 A 记录 DNSSEC；如果预算不足，保留已测路径，明确停止并报告未知。",
}


async def capture(raw, public, cases):
    config = Config.load()
    if not config.api_key:
        raise RuntimeError("Local DeepSeek configuration unavailable; no mock substitution")
    raw.mkdir(parents=True, exist_ok=False)
    public.mkdir(parents=True, exist_ok=False)
    metadata = dict(source_ref=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        source_hashes={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in Path("src/dns_investigator").glob("*.py")},
        harness_hash=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        model=config.model, thinking="disabled", temperature=0, mode="actual_DeepSeek_plus_controlled_wire_DNS",
        public_target_network=False, test_anchor="explicit_test_only", test_endpoints="explicit_loopback_injection",
        criteria_in_prompt=False, review="developer_automated_checks_pending_independent_human_review",
        repetitions_per_case=1, semantic_accuracy="not_established")
    (public / "experiment.json").write_text(json.dumps(metadata, indent=2), encoding="utf-8")
    manifest = []
    for case in cases:
        config.max_tool_calls=8;config.dns_query_budget=2 if case=="budget" else 32
        config.model_timeout=45;config.dns_tool_timeout=15
        scenario="tampered" if case=="bogus" else "ede_conflict" if case=="ede" else "secure"
        async with signed_lab(scenario) as lab:
            def factory(target, fixture, max_calls, callback):
                assert fixture is None
                b=lab.backend();b.target=target;b.max_calls=max_calls;b.on_evidence=callback
                b.dns.system=["127.0.0.12"]
                # Test-only authoritative loopback authorization for legacy basic;
                # production policy is unchanged. Reject every non-lab destination.
                b.dns.permitted=lambda ip,authoritative=False: ip in lab.endpoints
                async def no_other_network(**args):
                    raise InputRejected("CONTROLLED_DNS_ONLY", "本实验仅允许受控 DNS，不执行真实 TCP/HTTP 探测。")
                b.check_tcp=b.check_http=no_other_network
                return b
            with patch.object(agent_module,"ToolBackend",factory):
                log,path=await agent_module.investigate(QUESTIONS[case],parse_target("probe.example.test"),config,log_dir=raw,target_source="controlled_experiment")
        # All addresses are explicit lab/test documentation addresses; standard
        # privacy filtering already ran inside investigate. Never copy raw JSONL.
        (public/path.name).write_text(json.dumps(log,ensure_ascii=False,indent=2),encoding="utf-8")
        manifest.append(dict(case=case,file=path.name,agent_status=log["agent_execution_status"],status=log["status"],
            report_origin=log["report_origin"],A=len(log["attempts"]),Q=len(log["dns_attempts"]),E=len(log["evidence"]),V=len(log.get("validation_results",[])),
            elapsed_seconds=log["elapsed_seconds"],usage=log.get("usage"),
            calls=[dict(tool=a["tool_name"],mode=a["input"].get("mode","basic"),status=a["status"]) for a in log["attempts"]],
            local_validation=[p.get("validation") for p in log["result"].get("protocol_investigations",[])],
            root_cause_quality="PENDING_HUMAN_REVIEW"))
        (public/"manifest.json").write_text(json.dumps(manifest,ensure_ascii=False,indent=2),encoding="utf-8")
        print(case,log["status"],"A/Q/E/V",manifest[-1]["A"],manifest[-1]["Q"],manifest[-1]["E"],manifest[-1]["V"],flush=True)
        if (log.get("error") or {}).get("category") in {"ModelHTTPError","AuthenticationError"}:break


if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("raw",type=Path);parser.add_argument("public",type=Path)
    parser.add_argument("--cases",nargs="+",choices=list(QUESTIONS),default=list(QUESTIONS))
    args=parser.parse_args()
    asyncio.run(capture(args.raw,args.public,args.cases))
