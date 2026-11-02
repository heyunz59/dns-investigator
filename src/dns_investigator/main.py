import argparse
import asyncio
import json
import sys
from pathlib import Path
from .config import Config
from .target import parse_target, extract_target
from .tools import ToolBackend
from .agent import investigate


def error_output(args,code,message):
    if getattr(args,'format','text')=='json':
        print(json.dumps(dict(status='failed',error=dict(code=code,message=message)),ensure_ascii=False))
    else:print(message)


def summary(result):
    def short(text):return str(text)[:260]+('…（完整内容见日志）' if len(str(text))>260 else '')
    d=result.get('diagnostic_conclusion')
    all_d=([d] if d else [])+result.get('secondary_diagnoses',[])
    if not d and all_d:print('并列异常/未完成范围：没有足够依据选择唯一主诊断。')
    for index,item in enumerate(all_d):
        label='诊断结论' if d and index==0 else '并列/次要观测'
        print(label+'：'+item['summary']+' ['+item['diagnosis_status']+']')
        print('位置：'+short(item['fault_location']))
        print('观测与等级：'+short(item['cause'])+' ['+item['cause_status']+']')
        print('选择依据：'+item.get('selection_reason','旧报告缺少问题上下文。'))
        print('直接依据：'+', '.join(item.get('direct_evidence_ids',[])+item.get('direct_validation_ids',[])))
    shown=0
    for item in all_d:
        for step in item.get('remediation_steps',[])+item.get('verification_steps',[]):
            if shown>=3:break
            print(step['action_type']+'（尚未执行）：'+short(step['description']));shown+=1
            for b in step.get('branches',[])[:2]:print('  '+short(b['condition']+' → '+b['interpretation']+' → '+b['next_action']))
        if item.get('verification_steps'):print('验证方式：'+short(item['verification_steps'][0]['verification_method']))
        if shown>=3:break
    for issue in result.get('execution_issues',[]):print('执行问题（不是远端故障）：'+issue['attempt_id']+' '+issue['error_code']+'；目标='+issue.get('target','未知'))
    if result.get('report_fallback_reason'):print('程序回退；模型总结失败：'+result['report_fallback_reason'])
    for item in all_d:
        for limitation in item.get('limitations',[])[:2]:print('未知/范围限制：'+short(limitation))
    if not all_d:print(result.get('diagnostic_assessment') or result.get('conclusion','未取得报告。'))


async def run(args):
    try:return await _run(args)
    except (ValueError,EOFError):
        error_output(args,'INVALID_INPUT','输入或配置无效，或缺少必要目标；请提供问题/--target，检查本地配置。');return 2
    except KeyboardInterrupt:
        error_output(args,'INTERRUPTED','输入已结束');return 2
    except Exception:
        error_output(args,'EXECUTION_ERROR','执行未完成；未取得可用运行结果。');return 1


async def _run(args):
    machine=getattr(args,'format','text')=='json'
    if machine and getattr(args,'verbose',False):
        error_output(args,'ARGUMENT_CONFLICT','--format json 与 --verbose 不可组合；JSON 本身包含完整数据。');return 2
    non_interactive=machine or getattr(args,'non_interactive',False)
    if not args.question and not args.target and non_interactive:
        error_output(args,'MISSING_TARGET','非交互调用请提供问题或 --target。');return 2
    text = args.question or (args.target if args.target and non_interactive else input("问题（域名或网址）：").strip())
    value = args.target or extract_target(text)
    target_source="explicit_target" if args.target else "question_extraction"
    supplements=[]
    if not value:
        if non_interactive:
            error_output(args,'MISSING_TARGET','未找到必要目标，请使用 --target 提供域名或 URL。');return 2
        value = input("请补充单个域名或 HTTP/HTTPS 网址：").strip()
        target_source="interactive_supplement"
        supplements=[{"event":"target_requested_and_supplied"}]
    try:
        target = parse_target(value)
    except ValueError as exc:
        error_output(args,'INVALID_INPUT',f"输入错误：{exc}")
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
        if machine:print(json.dumps(dict(mode='tools_only',status='ended',evidence=backend.calls,attempts=backend.attempts,dns_attempts=backend.dns.attempts),ensure_ascii=False))
        else:
            print("工具独立验证（固定测试顺序，未调用模型，不是 Agent 验收）")
            print(json.dumps(backend.calls, ensure_ascii=False, indent=2))
        if args.save_tools:
            args.save_tools.parent.mkdir(parents=True, exist_ok=True)
            args.save_tools.write_text(json.dumps(backend.calls, ensure_ascii=False, indent=2), encoding="utf-8")
        return 0
    config = Config.load()
    if not config.api_key:
        error_output(args,'MISSING_CONFIGURATION',"缺少 DEEPSEEK_API_KEY。请复制 .env.example 为 .env 并在本机填写；可先运行 --tools-only。")
        return 2
    stream=sys.stderr if machine else sys.stdout
    print(f"开始调查：{target.domain}；测量位置：本机；默认 HTTPS：{target.default_https}", file=stream,flush=True)
    log, path = await investigate(text, target, config, args.fixture,
        target_source=target_source,supplement_events=supplements,
        progress=lambda row: print(f"已记录 {row['id']} · {row['tool_name']} · {row['execution_status']}", file=stream,flush=True))
    if machine:
        print(json.dumps(dict(log,log_path=str(path.resolve())),ensure_ascii=False))
        return 0 if log['status']=='completed' else 3 if log['status']=='limited' else 1
    if log.get("request_kind")=="query" and log.get("result"):
        print(log["result"]["conclusion"])
        for issue in log["result"].get("execution_issues",[]):print(json.dumps(issue,ensure_ascii=False))
    else:
        result=log.get("result",{})
        summary(result)
        if getattr(args,'verbose',False):print(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"状态：{log['status']}；日志：{path.resolve()}")
    return 0 if log["status"] == "completed" else 3 if log["status"] == "limited" else 1


def main():
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    class Parser(argparse.ArgumentParser):
        def error(self,message):
            if '--format=json' in sys.argv or any(sys.argv[i:i+2]==['--format','json'] for i in range(len(sys.argv))):
                print(json.dumps(dict(status='failed',error=dict(code='INVALID_ARGUMENT',message='参数无效，请检查参数名称、值及组合。'))));raise SystemExit(2)
            super().error(message)
    p = Parser(description="DNS 解析失败调查助手")
    p.add_argument("question", nargs="?")
    p.add_argument("--target")
    p.add_argument("--fixture", type=Path)
    p.add_argument("--tools-only", action="store_true")
    p.add_argument("--save-tools", type=Path)
    p.add_argument('--verbose',action='store_true')
    p.add_argument('--format',choices=['text','json'],default='text')
    if ('--help' in sys.argv or '-h' in sys.argv) and ('--format=json' in sys.argv or any(sys.argv[i:i+2]==['--format','json'] for i in range(len(sys.argv)))):
        print(json.dumps(dict(status='help',help=p.format_help()),ensure_ascii=False));raise SystemExit(0)
    args = p.parse_args()
    args.non_interactive=not sys.stdin.isatty()
    try:
        raise SystemExit(asyncio.run(run(args)))
    except (EOFError, KeyboardInterrupt):
        error_output(args,'INTERRUPTED',"输入已结束")
        raise SystemExit(2)


if __name__ == "__main__":
    main()
