'use strict';
const $ = id => document.getElementById(id);
const token = document.querySelector('meta[name="local-token"]').content;
const operations = {query_dns:'查询 DNS', compare_resolvers:'对比解析器', query_authoritative:'检查权威 DNS', check_tcp:'检测 TCP 连接', check_http:'检查 HTTP'};
let current = null, currentJob = null, pollTimer = null;
const el = (tag, text, cls) => {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = typeof text === 'string' ? text : JSON.stringify(text);
  if (cls) node.className = cls;
  return node;
};
const timeText = value => {
  const date = new Date(value);
  return value && !Number.isNaN(date.valueOf()) ? date.toLocaleString('zh-CN', {hour12:false}) : '时间未记录';
};
const duration = value => value === null || value === undefined ? '耗时未记录' : value + ' ms';
function message(text, error = false) { $('status').textContent = text; $('status').className = error ? 'error' : ''; }
async function api(url, options = {}) {
  const response = await fetch(url, {...options, headers:{'Content-Type':'application/json', 'X-Local-Token':token, ...options.headers}});
  if (!response.ok) {
    let body; try { body = await response.json(); } catch {}
    const error = Error(typeof body?.detail === 'string' ? body.detail : '请求未完成（' + response.status + '）');
    error.status = response.status; throw error;
  }
  return response.json();
}
function disclosure(parent, title, data, open = false) {
  const node = el('details'); node.open = open;
  node.append(el('summary', title), el('pre', JSON.stringify(data, null, 2))); parent.append(node); return node;
}
function showTab(id) {
  for (const tab of document.querySelectorAll('[role=tab]')) {
    const selected = tab.getAttribute('aria-controls') === id;
    tab.setAttribute('aria-selected', selected); tab.tabIndex = selected ? 0 : -1;
    $(tab.getAttribute('aria-controls')).hidden = !selected;
  }
}
const tabs = [...document.querySelectorAll('[role=tab]')];
tabs.forEach((tab, i) => {
  tab.onclick = () => showTab(tab.getAttribute('aria-controls'));
  tab.onkeydown = event => {
    const next = {ArrowRight:(i+1)%3, ArrowLeft:(i+2)%3, Home:0, End:2}[event.key];
    if (next !== undefined) { event.preventDefault(); tabs[next].click(); tabs[next].focus(); }
  };
});
function stepDetail(parent, step, open) {
  const node = el('details'); node.open = open;
  const kind = {CHECK:'检查', POSSIBLE_FIX:'满足条件后考虑修正', VERIFY:'修复后验证'}[step.action_type] || '建议';
  node.append(el('summary', kind + ' · ' + step.title));
  node.append(el('p', '尚未执行；历史授权不作为当前执行权限，重新测量前须校验目标、网络与预算。', 'scope-note'));
  for (const [key,label] of [['description','建议'],['target','目标'],['reason','为什么检查'],['instructions','如何检查'],['prerequisites','修改前提'],['expected_outcomes','预期结果'],['verification_method','验证方式'],['safety_notes','操作边界']]) {
    if (step[key]?.length) { node.append(el('h4',label)); for (const text of Array.isArray(step[key]) ? step[key] : [step[key]]) node.append(el('p',text)); }
  }
  for (const branch of step.branches || []) {
    node.append(el('h4',branch.condition), el('p',branch.interpretation), el('p','下一步建议：' + branch.next_action));
    for (const text of branch.change_prerequisites || []) node.append(el('p','修改前提：' + text));
  }
  disclosure(node,'方法、授权记录与关联证据（原始结构）',step); parent.append(node);
}
function renderPaths(view) {
  $('paths').replaceChildren(); const list = el('div',undefined,'path-list');
  const ordered = [...view.paths].sort((a,b) => (a.tone === 'good') - (b.tone === 'good'));
  for (const [index,path] of ordered.entries()) {
    const row = el('div',undefined,'path-row');
    const role = {recursive:'递归',authoritative:'权威',unknown:'角色未记录'}[path.role] || path.role;
    row.append(el('strong',path.resolver), el('span',path.summary,'path-state ' + path.tone));
    row.append(el('p',role + ' · ' + path.queries.join('、')));
    if (index < 4) list.append(row);
    else {
      let more = list.querySelector('details');
      if (!more) { more = el('details'); more.append(el('summary','其他已测路径')); list.append(more); }
      more.append(row);
    }
  }
  $('paths').append(list);
  $('path-note').textContent = view.paths.length ? '颜色仅代表列出的实际查询；各路径限各自名称、类型、来源、位置及测量时刻，不代表整个解析器或域名的可用性。' : '没有可供对照的 DNS 路径记录；未补造正常节点。';
}
function renderEvidence(view) {
  const panel = $('evidence'); panel.replaceChildren(el('h3','本次 DNS 测量 · 按解析器查看'));
  panel.append(el('p','按解析器角色、测量来源和位置分组；展开可查看具体查询和 E/Q 关联。','muted'));
  for (const group of view.resolver_groups) {
    const node = el('details',undefined,'resolver'); const summary = el('summary');
    summary.append(el('strong',group.resolver),el('span',group.summary,group.tone),el('span',({recursive:'递归',authoritative:'权威'}[group.role] || '角色未记录')+' · '+group.source+' · '+group.location)); node.append(summary);
    const wrap = el('div',undefined,'table-wrap'), table = el('table'), head = el('tr');
    for (const name of ['查询名称 / 类型','查询结果','DNS RCODE','执行 / 传输','耗时','E / Q / A','测量时间']) head.append(el('th',name));
    table.append(head);
    for (const row of group.measurements) {
      const tr = el('tr');
      for (const value of [row.name+' '+row.type,row.result,row.rcode,row.execution,duration(row.duration),[row.evidence_id,row.query_id,row.parent_id].filter(Boolean).join(' / ') || '未记录',timeText(row.time)]) tr.append(el('td',value));
      table.append(tr);
    }
    wrap.append(table); node.append(wrap); panel.append(node);
  }
  if (!view.resolver_groups.length) panel.append(el('p','未记录 DNS 路径测量。','muted'));
  for (const sec of view.dnssec) {
    const box = el('section',undefined,'technical'); box.append(el('h3',sec.title),el('p',sec.location || '失败区域未记录'),el('p','失败阶段：'+sec.stage),el('p','直接依据：'+(sec.direct.join('、') || '未记录')),el('p','依赖材料：'+(sec.dependencies.join('、') || '未记录'))); panel.append(box);
  }
  panel.append(el('h3','关键证据与内部验证'));
  const cards = [...view.evidence_cards,...view.validation_cards]; let shown = 0;
  const more = el('button','展开更多证据');
  function appendMore() {
    for (const card of cards.slice(shown,shown+5)) {
      const node = el('details',undefined,'evidence-card'); node.append(el('summary',card.id+' · '+card.title));
      const raw = card.raw;
      node.append(el('p','测量时间：'+timeText(raw.started_at || raw.measured_at || (typeof raw.validation_time === 'number' ? new Date(raw.validation_time*1000).toISOString() : null))+' · 来源：'+(raw.source_mode || '未记录'),'evidence-facts'));
      if (raw.tool_name) node.append(el('p','实际工具：'+(operations[raw.tool_name] || raw.tool_name),'evidence-facts'));
      disclosure(node,'查看原始参数、结果及审计字段',raw); panel.append(node);
    }
    shown += 5; more.remove(); if (shown < cards.length) panel.append(more);
  }
  more.onclick = appendMore; appendMore();
  if (!cards.length) panel.append(el('p','尚无有效证据。','muted'));
}
function renderTimeline(view) {
  const panel = $('timeline'); panel.replaceChildren(el('h3','Agent 实际调查过程'));
  for (const row of view.timeline) {
    const entry = el('article',undefined,'timeline-entry'), node = el('details');
    node.append(el('summary',timeText(row.time)+' · '+row.operation));
    // Visible narrative belongs to the node; raw records stay one level deeper.
    entry.append(node, el('p',row.target+' · '+row.state+' · '+duration(row.duration),'timeline-meta'),el('p',row.summary),el('p',row.refs.join(' / '),'timeline-meta'));
    if (row.error) node.append(el('p','执行问题：'+JSON.stringify(row.error)));
    for (const internal of row.internal_validations || []) disclosure(node,'工具内部验证 · '+internal.title,internal.raw);
    disclosure(node,'实际调用参数与完整事件',row.raw);
    panel.append(entry);
  }
  if (!view.timeline.length) panel.append(el('p','该报告未记录实际调用时间线。没有补造事件或时间。','muted'));
}
async function load(key, fresh = false) {
  const view = await api('/api/reports/'+key); current = key; localStorage.setItem('dns-report',key);
  document.body.classList.add('has-report');
  $('diagnosis').classList.add('active'); $('history').classList.remove('active');
  $('export').disabled = false; $('export-html').disabled = false;
  $('empty').hidden = true; $('history-panel').hidden = true; $('report').hidden = false;
  $('label').textContent = '● '+view.label; $('label').className = view.tone;
  $('source').textContent = (view.demo ? '示例数据 / 非真实公网测量 · ' : '')+(fresh ? '本次测量 · ' : '历史测量 · ')+timeText(view.measured_at)+(view.replay?' · 历史回放':'');
  $('title').textContent = view.short_title; $('explanation').textContent = view.short_explanation;
  $('location').textContent = view.short_location; $('other').replaceChildren();
  $('target').value = typeof view.target === 'string' && view.target !== '目标未记录' ? view.target : $('target').value;
  renderPaths(view);
  if (!view.diagnostic_groups.length) for (const diagnosis of view.diagnoses.slice(1)) $('other').append(el('p',diagnosis.summary));
  $('actions').replaceChildren();
  for (const step of view.steps.slice(0,3)) {
    const li = el('li'); li.append(el('strong',step.title),el('p',step.description)); $('actions').append(li);
  }
  if (!view.steps.length) $('actions').append(el('p','暂无结构化行动建议；请先补充证据。','muted'));
  renderEvidence(view); renderTimeline(view);
  $('details').replaceChildren(el('h3','完整说明与排障建议'));
  $('details').append(el('p',view.full_explanation),el('p','所有建议尚未执行。历史记录中的授权条件须重新校验。','scope-note'));
  view.steps.forEach((step,index) => stepDetail($('details'),step,index === 0));
  for (const diagnosis of view.diagnoses) disclosure($('details'),'诊断范围、确认等级与完整解释',diagnosis);
  for (const limitation of view.limitations) $('details').append(el('p',limitation,'muted'));
  for (const issue of view.issues) disclosure($('details'),'执行问题（不等于远端故障）',issue);
  disclosure($('details'),'完整结构化诊断与分组（原始数据）',view.result);
  showTab('evidence'); message('报告已加载。修复建议尚未执行。');
}
async function pollJob() {
  if (!currentJob) return;
  try {
    const job = await api('/api/jobs/'+currentJob);
    $('progress').hidden = false; $('progress-title').textContent = job.state_label+' · '+job.target;
    $('progress-meta').textContent = '已持续 '+job.elapsed_seconds+' 秒 · 已记录 '+job.call_count+' 次工具调用';
    const last = job.events.at(-1);
    const age = last?.started_at ? Date.now()-Date.parse(last.started_at) : job.elapsed_seconds*1000;
    $('progress-event').textContent = !last || age > 15000 ? '正在等待当前操作完成，尚未收到新的执行记录。' + (last ? ' 最近记录：'+timeText(last.started_at) : '') : '最近实际操作：'+(operations[last.tool_name] || last.tool_name)+' · '+last.id;
    $('cancel').disabled = job.state !== 'running';
    if (job.state === 'running' || job.state === 'cancelling') { pollTimer = setTimeout(pollJob,1000); return; }
    if (job.report_id) await load(job.report_id,true);
    message(job.state_label+(job.error ? '：'+job.error : '；已有证据已保存。'),job.state === 'failed');
    $('progress').hidden = true; finishJob();
  } catch (error) {
    if (error.status === 404) { message('原任务已不存在，服务可能已重启。可从历史记录查看已保存的证据。',true); $('progress').hidden = true; finishJob(); }
    else { message('连接暂时中断，正在尝试恢复任务状态。',true); pollTimer = setTimeout(pollJob,2500); }
  }
}
function finishJob() {
  currentJob = null; localStorage.removeItem('dns-job'); $('start').disabled = false;
  document.body.classList.remove('investigating');
}
$('form').onsubmit = async event => {
  event.preventDefault(); $('start').disabled = true; message('正在启动调查……');
  try {
    const job = await api('/api/start',{method:'POST',body:JSON.stringify({target:$('target').value,question:$('question').value})});
    currentJob = job.id; localStorage.setItem('dns-job',job.id);
    document.body.classList.add('investigating'); $('empty').hidden = true; $('history-panel').hidden = true; $('report').hidden = true;
    pollJob();
  } catch (error) { message(error.message,true); $('start').disabled = false; }
};
$('cancel').onclick = async () => {
  if (!currentJob) return;
  $('cancel').disabled = true;
  try { await api('/api/jobs/'+currentJob+'/cancel',{method:'POST'}); message('已请求取消，正在等待异步操作停止并保存证据。'); }
  catch (error) { message(error.message,true); $('cancel').disabled = false; }
};
$('file').onchange = async () => {
  const file = $('file').files[0]; if (!file) return;
  try { if (file.size > 16000000) throw Error('报告超过 16MB'); const result = await api('/api/import',{method:'POST',body:await file.text()}); await load(result.id); }
  catch (error) { message(error.message,true); } $('file').value = '';
};
async function history() {
  try {
    const rows = await api('/api/history?domain='+encodeURIComponent($('history-filter').value)+'&order='+$('history-order').value);
    document.body.classList.add('has-report'); $('history-panel').hidden = false; $('report').hidden = true; $('empty').hidden = true;
    $('history-list').replaceChildren();
    for (const row of rows) {
      const button = el('button',undefined,'history-row'); button.append(el('strong',row.target),el('span',row.title,'history-title'),el('span',timeText(row.time)+' · '+row.state+' · '+(row.demo?'受控实验 / 模拟数据':'历史测量')+(row.replay?' · 历史回放':'')));
      button.onclick = () => load(row.id).catch(error => message(error.message,true)); $('history-list').append(button);
    }
    if (!rows.length) $('history-list').append(el('p','没有匹配的本地报告。'));
    $('history').classList.add('active'); $('diagnosis').classList.remove('active');
  } catch (error) { message(error.message,true); }
}
$('history').onclick = history;
let filterTimer;
$('history-filter').oninput = () => { clearTimeout(filterTimer); filterTimer = setTimeout(history,200); };
$('history-order').onchange = history;
$('diagnosis').onclick = () => {
  $('history-panel').hidden = true; $('report').hidden = !current; $('empty').hidden = !!current || !!currentJob;
  $('diagnosis').classList.add('active'); $('history').classList.remove('active');
};
$('export').onclick = () => { if (current) window.location.href = '/api/reports/'+current+'/export'; };
$('export-html').onclick = () => { if (current) window.location.href = '/api/reports/'+current+'/html'; };
(async () => {
  const saved = localStorage.getItem('dns-report');
  if (saved) try { await load(saved); } catch { localStorage.removeItem('dns-report'); }
  currentJob = localStorage.getItem('dns-job');
  if (currentJob) { $('start').disabled = true; document.body.classList.add('investigating'); pollJob(); }
})();
