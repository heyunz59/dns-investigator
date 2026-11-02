# v0.6 最终定向修复回执

- before.json：75c16f7 原实现捕获；输入为构造混合观测或旧受控 DNSSEC 材料。
- final-replay/：首轮修复的 9 组实际浏览器与离线 HTML 回放，保留中间检查结果。
- final-source-replay/：最终运行时源码（含不完整目标元数据保护）的独立复测。validation.json 保存两份业务文件的 SHA256；最终提交与哈希对应关系见 verification.json。
- 两个 replay 目录内 imported/ 是冻结输入副本，原日志未改。保留原有 live 标签便于原样核对，不代表本轮真实公网测量。构造来源见 evaluation/v06_review_cases.py。
- 本轮新公网测量=0、新模型调用=0；未进行独立人工语义评分。浏览器截图经开发者辅助检查，不冒充独立人工验收。
- windows-installation.json 验证 editable/wheel 的真实安装、20 个严格单 JSON CLI 子进程和全部模块/静态资产。Linux 回执待实际远程 CI 后追加。
