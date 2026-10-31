"""Generate a local read-only view of actual, sanitized run logs for screenshots."""
import html
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
for filename, title in [("live-agent-example", "真实 DeepSeek + Live 工具调查"),
                        ("dns-query-example", "真实 DeepSeek + Fixture DNS 单项查询")]:
    data = json.loads((ROOT / f"results/published/{filename}.json").read_text(encoding="utf-8"))
    result = data["result"]
    evidence = "".join(f"<tr><td>{e['id']}</td><td>{e['tool_name']}</td><td>{e['source_mode']}</td><td>{html.escape(json.dumps(e['data'],ensure_ascii=False))}</td></tr>" for e in data["evidence"])
    text = f"""<!doctype html><html lang="zh"><meta charset="utf-8"><title>{title}</title>
<style>body{{font:16px 'Microsoft YaHei',sans-serif;max-width:1100px;margin:36px auto;color:#182d43;background:#f4f7fa}}h1{{color:#124c73}}.meta,section{{background:white;padding:22px;border-radius:12px;margin-bottom:18px}}td:first-child{{min-width:32px;white-space:nowrap}}td:nth-child(2){{min-width:92px;white-space:nowrap}}td:nth-child(3){{min-width:52px;white-space:nowrap}}table{{border-collapse:collapse;width:100%;font-size:13px}}td,th{{text-align:left;padding:10px;border:1px solid #ddd;overflow-wrap:anywhere}}p{{line-height:1.8}}.badge{{color:#146a55}}</style>
<h1>DNS 调查助手 · {title}</h1><p>实际运行日志的浏览器视图；非终端截图。原始返回文字保留，模型判断仍需核对。</p>
<div class="meta"><b class="badge">{data['status']}</b> · {data['model']} · 非思考模式 · {data['started_at']}<br>耗时 {data['elapsed_seconds']} 秒 · 工具证据 {len(data['evidence'])} 条 · 本机解析器已脱敏</div>
<section><h2>证据</h2><table><tr><th>ID</th><th>工具</th><th>来源</th><th>实际返回</th></tr>{evidence}</table></section>
<section><h2>模型结论（原文）</h2><p>{html.escape(result['conclusion'])}</p><h2>限制（原文）</h2><p>{'<br>'.join(html.escape(x) for x in result['limitations'])}</p></section>
<section><h2>开发者复核</h2><p>Live 回答误称工具不支持 IPv6，且对 DNS 排除力度过强；单项查询额外请求了未提供的 AAAA fixture。均作为实际局限保留，不将模型原文自动视为正确答案。</p></section></html>"""
    dest = ROOT / f"docs/screenshots/{filename}.html"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(text, encoding="utf-8")
