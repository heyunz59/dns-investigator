import argparse
import asyncio
import json
import sys
from pathlib import Path
from .config import Config
from .target import parse_target, extract_target
from .tools import ToolBackend
from .agent import investigate


async def run(args):
    text = args.question or input("问题（域名或网址）：").strip()
    value = args.target or extract_target(text)
    target_source="explicit_target" if args.target else "question_extraction"
    supplements=[]
    if not value:
        value = input("请补充单个域名或 HTTP/HTTPS 网址：").strip()
        target_source="interactive_supplement"
        supplements=[{"event":"target_requested_and_supplied"}]
    try:
        target = parse_target(value)
    except ValueError as exc:
        print(f"输入错误：{exc}")
        return 2
    if args.tools_only:
        config=Config.load()
        backend = ToolBackend(target, args.fixture,tcp_allowed_networks=config.tcp_allowed_networks)
        backend.dns.limit=config.dns_query_budget;backend.resolvers=config.dns_resolvers
        backend.dns_tool_timeout=config.dns_tool_timeout;backend.max_auth_servers=config.max_auth_servers
        from .http_safety import HTTPPolicy
        backend.http_policy=HTTPPolicy(target.url,config.http_allowed_origins,config.http_allowed_networks)
        await backend.call("query_dns", domain=target.domain, record_type="A")
        records = backend.calls[0]["data"].get("records", []) if backend.calls else []
        if records:
            await backend.call("check_tcp", ip=records[0]["value"], port=target.port)
            await backend.call("check_http", url=target.url)
        print("工具独立验证（固定测试顺序，未调用模型，不是 Agent 验收）")
        print(json.dumps(backend.calls, ensure_ascii=False, indent=2))
        if args.save_tools:
            args.save_tools.parent.mkdir(parents=True, exist_ok=True)
            args.save_tools.write_text(json.dumps(backend.calls, ensure_ascii=False, indent=2), encoding="utf-8")
        return 0
    config = Config.load()
    if not config.api_key:
        print("缺少 DEEPSEEK_API_KEY。请复制 .env.example 为 .env 并在本机填写；可先运行 --tools-only。")
        return 2
    print(f"开始调查：{target.domain}；测量位置：本机；默认 HTTPS：{target.default_https}", flush=True)
    log, path = await investigate(text, target, config, args.fixture,
        target_source=target_source,supplement_events=supplements,
        progress=lambda row: print(f"已记录 {row['id']} · {row['tool_name']} · {row['execution_status']}", flush=True))
    if log.get("request_kind")=="query" and log.get("result"):
        print(log["result"]["conclusion"])
        for issue in log["result"].get("execution_issues",[]):print(json.dumps(issue,ensure_ascii=False))
    else:
        result=log.get("result",{})
        d=result.get('diagnostic_conclusion')
        if d:
            print('诊断结论：'+d['summary']+' ['+d['diagnosis_status']+']')
            print('故障位置：'+d['fault_location'])
            print('原因与等级：'+d['cause']+' ['+d['cause_status']+']')
            for s in d.get('remediation_steps',[])+d.get('verification_steps',[]):
                print(s['action_type']+'（尚未执行）：'+s['description'])
            print('诊断依据：'+', '.join(d['evidence_ids']+d['validation_ids']))
        else:print("诊断摘要："+result.get("diagnostic_assessment",result.get("conclusion","")))
        print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"状态：{log['status']}；日志：{path.resolve()}")
    return 0 if log["status"] == "completed" else 3 if log["status"] == "limited" else 1


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    p = argparse.ArgumentParser(description="DNS 解析失败调查助手")
    p.add_argument("question", nargs="?")
    p.add_argument("--target")
    p.add_argument("--fixture", type=Path)
    p.add_argument("--tools-only", action="store_true")
    p.add_argument("--save-tools", type=Path)
    args = p.parse_args()
    try:
        raise SystemExit(asyncio.run(run(args)))
    except (EOFError, KeyboardInterrupt):
        print("输入已结束")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
