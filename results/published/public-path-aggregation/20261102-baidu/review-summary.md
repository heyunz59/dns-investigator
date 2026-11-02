# 真实公网日志反例专项修复

实际基线 **f5fa411**（含已提交Web成果，基于已验收05cb04a），业务源码 **`5e35797e11227fe42b5d64f2b01e27442e15316f`**，分支 `fix/public-path-aggregation`。保留用户Web实现、工作区人工审查材料、原报告/实验；未reset、stash、合并main或强制推送。业务提交之后仅补充文档/CI回执及回放脚本的防覆盖输出目录保护，运行源码不变。

## 正式样本与原始证据

使用用户提供、位于下载目录的investigation.json，未再次访问baidu.com或调用模型。原文件另存本地忽略目录；公开回归副本 [baidu-investigation.json](../../../../data/regressions/baidu-investigation.json) 与原文件字节一致，SHA256 **d71618858ed81eb38f6113250a3910817465e5b45c63b5d901ebce391421fdd4**。检查无本机API Key/token或用户绝对路径；保留诊断必需的实际解析器地址（包括192.168.5.1），不将其隐去后再声称是原样样本。见 [original-manifest.json](original-manifest.json)。

19条Evidence、17条DNS Attempt、6条Agent调用、0条V全部保留；E1～E17仍为原DNS测量，其中7次TIMEOUT。完整Findings（不仅code集合）和原始E/A/Q/V深比较相等，输入对象也未被回放修改。

| 路径组 | 超时E | 对应Q | 查询范围 |
|---|---|---|---|
| 192.168.5.1：5次 | E2/E5/E8/E10/E14 | Q1/Q6/Q8/Q10/Q14 | baidu.com A/SOA/NS、ns3.baidu.com A、ns2.baidu.com A |
| 1.1.1.1：2次 | E4/E7 | Q2/Q5 | baidu.com A，两次观测 |

完整时间、来源、名称/类型见 [group-evidence.csv](group-evidence.csv)。E1、E3、E6、E9、E11、E15是相应递归成功测量；E12/E13及E16/E17是两台选中权威的有效回答。每条成功对照仍按实际名称、类型、角色和时间逐项引用，不扩张成全组合或全部权威正常。

E18仅证明111.63.65.247:443这次独立TCP连接成功。E19仅取得https://baidu.com/的HTTP301，后续跳转因HTTP_REDIRECT_TARGET_NOT_AUTHORIZED未请求；既不称目标不可达，也不称www.baidu.com最终HTTP200。没有把PowerShell额外手测加入Agent证据。

## 根因与规则

原dns_diagnosis.py合理地按QNAME/QTYPE/来源/时间生成5个细粒度Finding。问题发生在高层：reasoner逐个Finding生成同名诊断，planner再为每条生成3步，Web把并列表达成“多个独立异常”。观测细分并不能证明根因独立。

现在只在高层增加路径级聚合，不改原Finding。键包括机制/reason_code、实际resolver、recursive角色、source_mode、measurement_location；同组可靠时间跨度最多300秒，按窗口首时刻限制，不做A接近B/B接近C的传递归并。E的执行状态必须为有效测量，未知时间/位置或来源不全时不强行合并。不同解析器仍为不同路径组，不确认共同或独立根因；不同机制、权威区域配置、DNSSEC和TCP等不参与此合并。

每组保留查询scope、观测数、真实E/Q及原Finding引用。Q编号只有在原Q记录与E关联确实存在时才成为已核实引用；A/Q不能伪装为E。对照需同名同类型、同来源/位置、有效时区时间窗，且DNS响应完整（权威需AA）；正常CDN差异不变故障。

整体diagnostic_summary同时呈现异常组与成功DNS/权威、TCP、HTTP及安全限制。仅当高层观测均为递归路径组时覆盖为“部分递归DNS查询路径超时”；混有DNSSEC BOGUS、TCP REFUSED、权威异常或关注层未测时，保留独立诊断和原相关性选择，不用乐观标题遮蔽其他问题。没有成功对照时明确缺少对照，不写成“其他路径正常”。

## 前后对照与建议

修改前实际捕获 [before-report.json](before-report.json)、[before-regenerated-report.json](before-regenerated-report.json) 和 [before-web.json](before-web.json) 均在改代码前保存。修改后 [after-investigation.json](after-investigation.json) 是同日志只读重建，另留original_result，E/A/Q/V和原始顶层Finding不变；[after-web.json](after-web.json) 与 [after-cli.txt](after-cli.txt) 使用相同正式结果。

| 内容 | 修改前 | 修改后 |
|---|---|---|
| 用户级诊断 | 5条同名RECURSIVE_QUERY_TIMEOUT | 2个实际解析器路径组 |
| 完整行动步骤 | 15项 | 每组CHECK/POSSIBLE_FIX/VERIFY，共6项 |
| 默认首页 | 多个独立异常，无法确认唯一主因 | 部分递归DNS查询路径超时，部分路径异常 |
| 原始E/DNS Q/超时 | 19 / 17 / 7 | 19 / 17 / 7 |

每组建议标明解析器、全部适用QNAME/QTYPE/E/Q/原Finding；分支仍区分持续超时、恢复、所有对照超时、改收SERVFAIL。内部发现NS名不自动获得query_dns独立目标授权。条件修复仅限确认的解析器服务/本地策略问题，明确本次无依据修改目标域名记录；不关防火墙、不禁DNSSEC、不盲切解析器。建议未执行。建议原始前后数据见两份完整报告，数量和不变项见 [comparison.json](comparison.json)。

## Web实页验收

保留原视觉、历史记录、导出及三个标签（解析与证据/排障详情/调查时间线），未增加概览标签。首页列两组解析路径和各自次数，可展开全部名称/类型/E/Q。DNS表修正结果优先取result_kind，超时不会显示为“0条记录/返回RCODE”。证据、完整分支和全部调用时间线仍可展开。

实际本机浏览器从原始旧日志导入/读取，经公共报告生成器回放后截图：[首页](baidu-after.png)、[排障详情](baidu-troubleshooting.png)、[时间线](baidu-timeline.png)。[browser-check.json](browser-check.json)验证3标签、17条DNS表记录、6条A时间线、0页面脚本错误；没有调用/api/start，不触发公网或模型。使用独立临时回环端口，没有停止用户原有8765服务。初始文案截图保留initial-render/，最终截图对应业务5e35797。

旧完整日志只读回放在普通Python report_replay.py中完成，Web不是独立诊断器。导入保存原文件，导出带新result和original_result；CLI/JSON/Web同源。不完整历史日志保守回退原表示，不编造缺失记录。

## 验证与未决边界

实际修改前 **551 passed in40.44s**；最终业务 **571 passed in40.69s，新增20项，0失败/0跳过**，pip check通过。新增用例覆盖真实日志完整保留、三种跨查询归并、不同解析器/时段/来源/位置隔离、非传递时间窗、同解析器成功+失败、全超时/全正常、DNSSEC/TCP/权威独立、缺字段旧日志、Q引用篡改、失败回退、fixture和乱序、Web导入/历史/导出以及CLI同源语义。未放宽旧断言。

DNSClient、dns_diagnosis、DNSSEC/NSEC3、trace、TCP/HTTP安全、账本、CNAME授权和Agent源码逐模块归一化哈希未变，见 [protected-source-hashes.json](protected-source-hashes.json)。只改Schema兼容字段、reasoner聚合入口/来源校验、reporting元数据与摘要、remediation组级建议、CLI摘要及Web数据/展示；新增path_groups.py和report_replay.py，测试/回放/文档/正式样本。源码Diff见 [source.diff](source.diff)。

远程业务提交 [Actions41445946293](https://github.com/heyunz59/dns-investigator/actions/runs/41445946293) 全部成功；实际测试/打包/安装/公开扫描摘要与job状态见 [ci-result.json](ci-result.json)。公开扫描为规则检查而非完整隐私证明。**独立人工语义验收NOT_RUN**，开发助手检查属于AI辅助验证；571通过不是根因准确率。300秒和相同位置只提供有限同期资格，不证明唯一网络原因；未知测量位置不默认本机，不完整日志仍可能保留较细观测。原NSEC3等协议边界未扩展。建议和配置修改均未执行。

重放复核可运行 `python -m pytest tests/test_path_groups.py -q`；生成新截图/材料使用 `python -m evaluation.public_path_replay 新输出目录`（必须是不存在的目录，保留既有材料）。原Web进程若仍驻留旧代码，重启后导入原JSON即可看到新报告，无需重新调用模型。
