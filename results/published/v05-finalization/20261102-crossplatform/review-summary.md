# v0.5 报告模块最终收尾与验收

基线 `9e2645ad311ed767b482f823eb98bf74df7fd08b`，分支 `fix/v05-report-quality`。业务源码提交 **`33450e9e454628c28df9a9dd61b718cde5236caa`**；之后仅追加验收材料，不改变业务源码。不合并 main，不删除旧实验和原始失败记录。用户未跟踪的 docs/manual-reviews/ 保持原样。

## 三项最小修复

1. **正常安装项目再验CLI**：实际读取旧 [CI41414761379](https://github.com/heyunz59/dns-investigator/actions/runs/41414761379) 日志，501通过/7失败，失败都是独立进程找不到未安装包。pytest 的 pythonpath 只作用于pytest，不能当Python安装。CI增加正常 editable install，七项CLI子进程测试全部保留、预期退出码不改，不注入Windows路径。新脚本 scripts/check_installation.py 在临时工作目录、移除PYTHONPATH后，实际切换editable和wheel安装，检查import位置、每个源码模块/资产字节、模块与console入口各5次单JSON输出。依赖沿用已安装环境，但项目包确实重新安装，wheel必须从site-packages加载而非借用源码。pyproject自动包发现原本正确，未修改；新模块也在wheel逐文件核对范围内。
2. **解析器建议映射**：remediation.py读取实际E的父A输入，不复制Evidence.resolver数值地址来假定系统路径。直接query_dns的原参数None/缺省映射为None；显式参数需与测量地址一致并通过原 `_validate`。compare_resolvers只有当前系统/显式身份可唯一分辨时才构造对应参数，重叠时未知。缺父调用、目标/类型/地址不匹配、无法确认原路径时外部只读，不标为当前工具可执行。reporting.py仅将现有backend作为只读上下文传给attach，必要改动一行；不改变诊断规则。
3. **并列CHECK公平展示**：primary存在时优先其步骤；parallel时先取每项的首个CHECK，然后用剩余额度补充步骤。最多三项，过多时明确提示未展示的CHECK数；每条均标 `[primary_issue]`。不修改诊断顺序、主次判断、JSON完整计划或任何次要诊断。

最小源码/测试/CI差异见 [minimal-source.diff](minimal-source.diff)。业务改动只在 remediation.py、main.py、reporting.py；其余是CI安装验证脚本、测试和文档。原 test_report_quality.py 仅修正一个不安全的历史建议预期：历史记录数值IP不再被断言为当前可直接调用参数，分支/超时/未执行断言保留；七项CLI集成测试不删不改退出码。

## 建议参数与授权的区别

`parameters_constructed` 表示来源足以映射参数；`authorization_status=accepted_by_current_validation` 表示按当前工具准入规则检查过，不代表已发起查询、预留预算或永久获授权。`can_execute_now=false` 始终保留，`executed=false`；新的调查仍须完整目标、解析器、预算与安全校验。系统配置可能已变化，None复现的是系统逻辑路径，而不是强行固定旧IP。

原工具显式递归解析器策略允许公共IP或当前系统列表地址，并非只允许DNS_RESOLVERS列表；本轮复用原策略，不扩大或缩小它。未授权案例用不在系统列表的私有地址验证拒绝。fixture/synthetic仍使用模拟复核，不能借此进入真实网络。表格 [resolver-mapping.json](resolver-mapping.json) 是人工构造来源/授权元数据，不是网络测量，验证过程没有增加A/Q/E或修改任何允许列表。

## 实际结果

- 基线Windows：508 passed in41.30s；最终业务Windows：**523 passed in41.74s，0 failed/0 skipped，新增15项**。`python -m pytest -q`、`python -m pip check`通过。
- [windows-installation.json](windows-installation.json)：editable + wheel，模块入口/console入口，20例JSON严格解析，所有Python模块和打包资产逐字节一致；脚本已恢复本地editable。没有靠pytest的src路径或工作目录通过检查。
- [uninstalled-reproduction.json](uninstalled-reproduction.json)：新建未安装包的venv中实际复现ModuleNotFoundError。初始本地验证曾遇到Windows stderr编码和未安装setuptools却禁用build isolation的工具设置问题；记录在 [initial-setup-attempts.json](initial-setup-attempts.json)，随后使用UTF8和正常PEP517隔离构建，未改业务代码。
- Linux远程验收：实际 [Actions41417530424](https://github.com/heyunz59/dns-investigator/actions/runs/41417530424) 全部成功（业务33450e9），完整测试、editable安装、wheel安装/模块及console入口均通过；原七项CLI失败测试已全部通过。实际job/step及摘要见 [linux-ci.json](linux-ci.json)，安装artifact见 [linux-installation.json](linux-installation.json)。
- [parallel-cli-output.txt](parallel-cli-output.txt)：实际调用CLI run，调查替换为constructed report input，非真实模型/公网。HTTP503和TCP REFUSED各自有CHECK，第三项才补充条件修复；未重排成唯一主因。原stdout保留本地忽略目录，公开版仅将本地日志绝对路径替换为占位符，见 [parallel-cli-metadata.json](parallel-cli-metadata.json)。

输出摘录（完整分支仍在日志/JSON）：

```text
并列异常/未完成范围：没有足够依据选择唯一主诊断。
[HTTP_503] CHECK（尚未执行）：核对所列 URL、最终 URL、状态码、重定向与请求完成状态；结合服务日志和接口设计确认响应含义。
[TCP_REFUSED] CHECK（尚未执行）：核对所列 IP/端口的服务监听及主机/网络放行规则；区分 REFUSED、TIMEOUT 和 NETWORK_ERROR。
```

## 回归与冻结边界

完整测试继续验证DS/DNSKEY定位example.test.、直接V7/E7/E8、根至父区依赖保留；相关性、并列、分支、TIMEOUT、fixture/live、旧日志和A/Q/E/V关系均保留。15项新增检查覆盖系统/显式/拒绝/未知/重叠映射、只读校验不改账本/策略、并列双CHECK、超额提示及primary优先。[protected-source-hashes.json](protected-source-hashes.json)证明Agent、诊断引擎、Schema、DNS/DNSSEC/NSEC3、trace、网络安全、工具执行与账本源码未变。

没有新增模型调用、自动执行修复或网络授权；安装检查只用help、参数错误和fixture。完整pytest保留原受控DNS/TCP/HTTP测试，不能把这些测试或构造报告当公网现场语义验收。独立人工语义复核未执行；历史NSEC3等能力边界不在本轮扩展。包元数据保持原有0.4.0.dev0，未进行发行版本升级。

已取得Linux实际全部通过结果，v0.5报告模块冻结，停止增加报告生成逻辑。下一阶段v0.6可基于现有结构设计HTML展示；本轮没有提前开发界面。
