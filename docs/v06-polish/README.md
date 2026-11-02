# v0.6 Web 产品化验收

基线：15f9fe9142c11a57c8fe41f8774ab67891f8dfe7（远端与本地一致）。在 feat/v06-product-polish 分支开发；不合并 main。最终业务提交以本分支源码提交为准。

## 完成内容

- 首页采用受控短标题和两句摘要。完整解释保留在排障详情，未知旧报告回退到证据不足模板，不截断句子、不新增模型摘要。
- 根据真实 E/Q 记录显示路径对照；按解析器、角色、来源、测量位置分组，各名称/类型及时间保留。TIMEOUT 显示为查询超时，不作为 RCODE。仅 NOERROR 且已记录解析完整时使用正常颜色，不将 measured 当作成功。
- 三个原有标签页保留。解析器按需展开查询表，证据摘要与原始 JSON 分两级；DNSSEC 显示失败范围、阶段、直接及依赖 E/V；实际工具调用按真实时间显示中文纵向时间线，缺少时间不补造，不引入第六个工具。
- 调查中显示真实事件、已记录证据所属调用数、持续时间及等待提示，没有百分比。取消通过 task.cancel 终止实际异步任务；Agent 仅新增 CancelledError 分支以保存原账本，沿用原报告生成器。状态在清理结束前保持停止中。已发出的网络请求不能撤回，非异步清理仍须等待完成。
- 当前浏览器会话可刷新或断线恢复任务。服务端重启后旧任务返回不存在，前端明确提示；历史报告独立保存。任务查询和取消绑定 HttpOnly/SameSite 浏览器会话，同时保留本机请求令牌、Host 与回环地址限制。
- 历史记录支持域名筛选、实际测量时间排序，展示目标、摘要、状态、测量时间、模拟及回放标记；未知时间不使用导入时间替代。
- JSON 沿用既有 canonical 导出，兼容测试核对原始 evidence/dns_attempts 完全一致。独立 HTML 含摘要、路径、完整分支建议、DNS/DNSSEC、时间线、限制及脱敏完整 A/Q/E/V；无 JavaScript、无 CDN、无网络请求，支持打印。

## 验证与来源

- 完整 pytest：583 passed（原有 571 项及新增 12 项均通过）。
- 针对性 Web/路径/取消测试通过；真实 Agent + 脚本模型 + fixture 的异步取消测试证明取消后保存 E1，且没有后续工具调用。
- 安全验证：恶意 HTML/EDE/日志保持文本，在线和离线报告不执行脚本；过大导入、非法路径、不可信 Host、远程地址、无令牌操作、其他会话查询/取消被拒绝；导出清除 API Key、URL 凭证、代理授权与私有配置。原始 DNS/网络/预算/密码学/路径聚合规则未修改。
- 浏览器：本机 Chrome，通过全部三个标签页、证据展开、历史筛选、刷新恢复、JSON 下载兼容、离线 HTML 零外部请求、无脚本、打印与 390px 溢出检查。结果见 browser-result.json；人工检查桌面、窄屏及调查中截图。
- Windows 安装验收：editable + wheel、两种 CLI 入口、20 项严格 JSON 场景、模块与 assets 一致性均通过；新 report.html/report.css 包含于 wheel。
- 本轮真实调用 DeepSeek：是。新增公网测量：是，example.com；完成报告 020e6a151fee4022a3efaa027c1ed785（6 条实际 Evidence）。第二次真实任务取消报告 0d1172557da54d589eb02548f4e5480b（取消发生在首条测量前，0 条证据，未伪造证据）。取消保留非空证据另由上述真实 Agent/fixture 测试覆盖。
- 百度样本为既有真实日志的只读回放，绝非本轮百度重新测量；DNSSEC/正常/多故障等截图为标记明确的受控演示数据。

## 交付文件

- before.png / baidu.png：首页改造前后，使用同一份历史账本与基线静态资源进行比较。
- empty.png、investigating.png、live-completed.png、cancelled.png：空白、真实调查中、真实调查完成和取消状态。
- dnssec.png、normal.png、http503.png、multiple.png：受控场景。
- evidence.png、details.png、timeline.png、history.png、mobile.png：三个标签页、历史记录、390px 窄屏。
- baidu-report.html：可双击离线打开的导出样本；html-export.png 为实际打开截图，print-check.pdf 为浏览器打印检查产物。

## 修改文件

src/dns_investigator/web.py、web_view.py；assets/web.html、web.css、web.js、report.html、report.css；agent.py（仅取消处理）；tests/test_web_product.py；scripts/check_web_product_browser.py；README.md；本目录验收资料。

## 限制

仅回环地址、单机串行调查；没有跨服务重启的持久化任务队列。关闭整个浏览器会话后不保证恢复任务所属权限。取消并非撤回已经发出的报文。路径对照只覆盖已测组合，不代表解析器所有类型、整个网站或后续重定向正常。历史建议只读且须重新授权校验，没有自动修复入口。导入报告没有数字签名，保留其原有来源与未知字段，不提供真实性认证。

GitHub Actions 的最终运行链接与结果在最终交付消息列出，以远端实际返回为准。
