# v0.6 Web 验证记录

基线：05cb04afc153e534e4fa9ea566b2b86b676869ec；分支：feat/v06-web。

实现：FastAPI + Jinja2 页面壳 + 原生 HTML/CSS/JavaScript。新增 web.py 负责本机接口与纯展示映射；既有诊断/网络策略/工具模块均未修改。密钥仅服务端使用；状态修改要求随机本机请求令牌；Host 与客户端地址限制为回环；前端动态文本使用 textContent；CSP 禁止内联脚本和外部脚本。导入只保存 JSON，从不执行导入内容。

截图全部来自冻结 v0.5 证据的回放/构造场景，不是公网测量：

- dnssecdsmismatch.png：DNSSEC DS/DNSKEY 不匹配。
- http503.png：HTTP 503。
- multiTCP.png：TCP REFUSED 及独立 HTTP 异常。
- 同名 -details.png / -timeline.png：排障详情与时间线。
- mobile.png：390px 窄屏。

check_web_browser.py 自动实际点击三个标签页，检查选中状态、移动端横向溢出和浏览器脚本错误。所有检查通过；已人工查看桌面与移动端截图。原始 JSON 有滚动高度限制；默认仅展开首个排障建议，证据每次追加五项。

真实接口验收：本机 /api/start 启动 example.com，现有 Agent 完成，状态 completed；实际回调及报告 ID 见 live-check.json。该文件保留已脱敏测量，不包含模型密钥。

测试覆盖既有 13 个受控场景、旧报告、空报告、模型总结失败、DNSSEC 未确定、无故障、定位而非确认根因、HTML 文本、脱敏、导入导出、历史、非法目标、缺密钥、Host、令牌以及真实 Agent 入口调用契约。浏览器脚本另外覆盖三标签交互。

限制：仅 JSON 导出；不绘制信任链图，使用已有故障位置文本以免虚构节点；进度是实际证据到达事件，不提供百分比；无服务器重启后的任务恢复；不提供公网服务。Windows 本机验证，Linux 由现有 GitHub Actions 执行。

修改文件：pyproject.toml、requirements-dev.txt、requirements-web.txt、README.md；src/dns_investigator/web.py；assets/web.html、web.css、web.js；tests/test_web.py；scripts/prepare_web_demos.py、check_web_browser.py、check_web_live.py；本目录验证资料。
