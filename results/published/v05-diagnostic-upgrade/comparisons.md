# 四例实际报告对照

数据来自最终 5e86226 受控采集；不是模型或公网验收。旧定位摘要与新高层结论直接从 JSON 提取。

## dns-timeout

旧报告 diagnostic_assessment 实际输出：

```text
probe.example A [来源 live]：127.0.0.1 本次查询超时，其他响应路径为 127.0.0.2=NOERROR, 127.0.0.3=NOERROR；线索限于这些查询路径的可用性，不能区分服务与网络问题，也没有取得超时路径的记录内容（E3、E1、E2）。
```

新报告高层实际输出：

```json
{
  "diagnosis_status": "FAULT_LOCALIZED",
  "summary": "所列递归查询路径本次未响应",
  "fault_location": "probe.example A via 127.0.0.1",
  "cause": "查询 probe.example A：127.0.0.1 对 probe.example 返回 TIMEOUT（E3）。不推断注册状态或服务器宕机。",
  "cause_status": "OBSERVED_MECHANISM",
  "evidence_ids": [
    "E3",
    "E1",
    "E2"
  ],
  "validation_ids": [],
  "remediation_steps": [
    {
      "id": "D1-RECURSIVE_QUERY_TIMEOUT-R1",
      "priority": 1,
      "title": "优先核对与定位",
      "action_type": "CHECK",
      "description": "从相同测量位置复测所列目标、记录类型和解析路径，记录真实复测时间；与已测对照路径比较。；核对该解析器/权威服务状态、网络可达性和查询访问策略，区分服务与路径因素。",
      "target": "probe.example A via 127.0.0.1",
      "reason": "查询 probe.example A：127.0.0.1 对 probe.example 返回 TIMEOUT（E3）。不推断注册状态或服务器宕机。",
      "related_finding_codes": [
        "RECURSIVE_QUERY_TIMEOUT"
      ],
      "evidence_ids": [
        "E3",
        "E1",
        "E2"
      ],
      "validation_ids": [],
      "instructions": [
        "从相同测量位置复测所列目标、记录类型和解析路径，记录真实复测时间；与已测对照路径比较。",
        "核对该解析器/权威服务状态、网络可达性和查询访问策略，区分服务与路径因素。"
      ],
      "expected_outcomes": [
        "缩小到所列异常环节或明确仍缺失的证据；不预设故障已修复。"
      ],
      "verification_method": "从相同位置、记录复测时间，重新检查相同目标/类型/解析器；比较原异常是否消失及对照是否稳定。",
      "prerequisites": [
        "有效的目标授权；配置变更另需管理权限与原因确认。"
      ],
      "safety_notes": [
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。"
      ],
      "executed": false
    },
    {
      "id": "D1-RECURSIVE_QUERY_TIMEOUT-R2",
      "priority": 2,
      "title": "条件成立后的修复",
      "action_type": "POSSIBLE_FIX",
      "description": "仅在对照确认具体缓存、服务或区域配置问题并具备管理权限后，修正对应配置；不要仅凭差异更换 DNS 或改记录。",
      "target": "probe.example A via 127.0.0.1",
      "reason": "查询 probe.example A：127.0.0.1 对 probe.example 返回 TIMEOUT（E3）。不推断注册状态或服务器宕机。",
      "related_finding_codes": [
        "RECURSIVE_QUERY_TIMEOUT"
      ],
      "evidence_ids": [
        "E3",
        "E1",
        "E2"
      ],
      "validation_ids": [],
      "instructions": [
        "仅在对照确认具体缓存、服务或区域配置问题并具备管理权限后，修正对应配置；不要仅凭差异更换 DNS 或改记录。"
      ],
      "expected_outcomes": [
        "缩小到所列异常环节或明确仍缺失的证据；不预设故障已修复。"
      ],
      "verification_method": "从相同位置、记录复测时间，重新检查相同目标/类型/解析器；比较原异常是否消失及对照是否稳定。",
      "prerequisites": [
        "有效的目标授权；配置变更另需管理权限与原因确认。"
      ],
      "safety_notes": [
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。"
      ],
      "executed": false
    }
  ],
  "verification_steps": [
    {
      "id": "D1-RECURSIVE_QUERY_TIMEOUT-R3",
      "priority": 3,
      "title": "复测并保留新证据",
      "action_type": "VERIFY",
      "description": "从相同位置、记录复测时间，重新检查相同目标/类型/解析器；比较原异常是否消失及对照是否稳定。",
      "target": "probe.example A via 127.0.0.1",
      "reason": "查询 probe.example A：127.0.0.1 对 probe.example 返回 TIMEOUT（E3）。不推断注册状态或服务器宕机。",
      "related_finding_codes": [
        "RECURSIVE_QUERY_TIMEOUT"
      ],
      "evidence_ids": [
        "E3",
        "E1",
        "E2"
      ],
      "validation_ids": [],
      "instructions": [
        "从相同位置、记录复测时间，重新检查相同目标/类型/解析器；比较原异常是否消失及对照是否稳定。"
      ],
      "expected_outcomes": [
        "缩小到所列异常环节或明确仍缺失的证据；不预设故障已修复。"
      ],
      "verification_method": "从相同位置、记录复测时间，重新检查相同目标/类型/解析器；比较原异常是否消失及对照是否稳定。",
      "prerequisites": [
        "有效的目标授权；配置变更另需管理权限与原因确认。"
      ],
      "safety_notes": [
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。"
      ],
      "executed": false
    }
  ]
}
```

## dnssec-ds_mismatch

旧报告 diagnostic_assessment 实际输出：

```text
A1 dnssec：追踪完成=True，停止原因=AUTHORITATIVE_TERMINAL_ANSWER，最后成功区域=example.test.；范围仅为所列路径/选中服务器，AA与Root Hints均不是DNSSEC信任证明。 本地验证：{"validation_execution": "completed", "dnssec_status": "BOGUS", "reason_code": "DS_DIGEST_MISMATCH", "failure_stage": "child-ds-match", "validation_scope": {"qname": "probe.example.test", "qtype": "A", "validation_time": 1793604954.688389}, "trust_anchor": {"zone": ".", "ds": ["59055 15 2 d8b593e1295fc2be58fff8ddb97ecf095915c8637b109b2c131e0b3f833c621c"], "version": "explicit-test-anchor-v1", "authentication": "EXPLICIT_TEST_ANCHOR", "source": "isolated_test_only"}, "algorithm_policy": "dns-investigator-dnssec-v1:8,13,14,15;DS2,4;RSA2048-4096;NSEC3-0-empty-salt", "implementation": "dnspython2.9.1/cryptography50.0.0+bounded-protocol-v1", "validation_result_ids": ["V7"], "compute": {"work_units": 11, "signature_attempts": 4}, "signature_observations": [], "operational_root_cause_confirmed": false}
```

新报告高层实际输出：

```json
{
  "diagnosis_status": "CONFIRMED_PROTOCOL_ISSUE",
  "summary": "父区域 DS 与已取得子区域 DNSKEY 无法建立关联",
  "fault_location": ". DNSKEY via 127.0.0.10；test. DS via 127.0.0.10；test. DNSKEY via 127.0.0.11；example.test. DS via 127.0.0.11；example.test. DNSKEY via 127.0.0.12",
  "cause": "父区域 DS 与已取得子区域 DNSKEY 无法建立关联；阶段=child-ds-match，reason_code=DS_DIGEST_MISMATCH，范围={'qname': 'probe.example.test', 'qtype': 'A', 'validation_time': 1793604954.688389}；限本地验证策略。",
  "cause_status": "VERIFIED_PROTOCOL",
  "evidence_ids": [
    "E4",
    "E5",
    "E6",
    "E7",
    "E8"
  ],
  "validation_ids": [
    "V1",
    "V2",
    "V3",
    "V4",
    "V5",
    "V6",
    "V7"
  ],
  "remediation_steps": [
    {
      "id": "D1-DNSSEC_VALIDATION-R1",
      "priority": 1,
      "title": "优先核对与定位",
      "action_type": "CHECK",
      "description": "只读查询并核对父区域发布的 DS 与子区域正在使用的 DNSKEY（含 key tag、算法和 digest）。；核对密钥轮换时间、发布状态与管理权限，确认具体不匹配发生在哪个父子区域。",
      "target": ". DNSKEY via 127.0.0.10；test. DS via 127.0.0.10；test. DNSKEY via 127.0.0.11；example.test. DS via 127.0.0.11；example.test. DNSKEY via 127.0.0.12",
      "reason": "父区域 DS 与已取得子区域 DNSKEY 无法建立关联；阶段=child-ds-match，reason_code=DS_DIGEST_MISMATCH，范围={'qname': 'probe.example.test', 'qtype': 'A', 'validation_time': 1793604954.688389}；限本地验证策略。",
      "related_finding_codes": [
        "DNSSEC_VALIDATION"
      ],
      "evidence_ids": [
        "E4",
        "E5",
        "E6",
        "E7",
        "E8"
      ],
      "validation_ids": [
        "V1",
        "V2",
        "V3",
        "V4",
        "V5",
        "V6",
        "V7"
      ],
      "instructions": [
        "只读查询并核对父区域发布的 DS 与子区域正在使用的 DNSKEY（含 key tag、算法和 digest）。",
        "核对密钥轮换时间、发布状态与管理权限，确认具体不匹配发生在哪个父子区域。"
      ],
      "expected_outcomes": [
        "缩小到所列异常环节或明确仍缺失的证据；不预设故障已修复。"
      ],
      "verification_method": "以同一信任锚、策略、时间范围和 QNAME/QTYPE 重验完整 DNSSEC 链与递归响应，保存新的 E/V；不能只看一次解析成功。",
      "prerequisites": [
        "有效的目标授权；配置变更另需管理权限与原因确认。"
      ],
      "safety_notes": [
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。"
      ],
      "executed": false
    },
    {
      "id": "D1-DNSSEC_VALIDATION-R2",
      "priority": 2,
      "title": "条件成立后的修复",
      "action_type": "POSSIBLE_FIX",
      "description": "只有确认父子 DS/DNSKEY 关联配置错误后，管理员才按正确密钥轮换流程修正对应记录；不直接删除 DS 或关闭 DNSSEC。",
      "target": ". DNSKEY via 127.0.0.10；test. DS via 127.0.0.10；test. DNSKEY via 127.0.0.11；example.test. DS via 127.0.0.11；example.test. DNSKEY via 127.0.0.12",
      "reason": "父区域 DS 与已取得子区域 DNSKEY 无法建立关联；阶段=child-ds-match，reason_code=DS_DIGEST_MISMATCH，范围={'qname': 'probe.example.test', 'qtype': 'A', 'validation_time': 1793604954.688389}；限本地验证策略。",
      "related_finding_codes": [
        "DNSSEC_VALIDATION"
      ],
      "evidence_ids": [
        "E4",
        "E5",
        "E6",
        "E7",
        "E8"
      ],
      "validation_ids": [
        "V1",
        "V2",
        "V3",
        "V4",
        "V5",
        "V6",
        "V7"
      ],
      "instructions": [
        "只有确认父子 DS/DNSKEY 关联配置错误后，管理员才按正确密钥轮换流程修正对应记录；不直接删除 DS 或关闭 DNSSEC。"
      ],
      "expected_outcomes": [
        "缩小到所列异常环节或明确仍缺失的证据；不预设故障已修复。"
      ],
      "verification_method": "以同一信任锚、策略、时间范围和 QNAME/QTYPE 重验完整 DNSSEC 链与递归响应，保存新的 E/V；不能只看一次解析成功。",
      "prerequisites": [
        "有效的目标授权；配置变更另需管理权限与原因确认。"
      ],
      "safety_notes": [
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。"
      ],
      "executed": false
    }
  ],
  "verification_steps": [
    {
      "id": "D1-DNSSEC_VALIDATION-R3",
      "priority": 3,
      "title": "复测并保留新证据",
      "action_type": "VERIFY",
      "description": "以同一信任锚、策略、时间范围和 QNAME/QTYPE 重验完整 DNSSEC 链与递归响应，保存新的 E/V；不能只看一次解析成功。",
      "target": ". DNSKEY via 127.0.0.10；test. DS via 127.0.0.10；test. DNSKEY via 127.0.0.11；example.test. DS via 127.0.0.11；example.test. DNSKEY via 127.0.0.12",
      "reason": "父区域 DS 与已取得子区域 DNSKEY 无法建立关联；阶段=child-ds-match，reason_code=DS_DIGEST_MISMATCH，范围={'qname': 'probe.example.test', 'qtype': 'A', 'validation_time': 1793604954.688389}；限本地验证策略。",
      "related_finding_codes": [
        "DNSSEC_VALIDATION"
      ],
      "evidence_ids": [
        "E4",
        "E5",
        "E6",
        "E7",
        "E8"
      ],
      "validation_ids": [
        "V1",
        "V2",
        "V3",
        "V4",
        "V5",
        "V6",
        "V7"
      ],
      "instructions": [
        "以同一信任锚、策略、时间范围和 QNAME/QTYPE 重验完整 DNSSEC 链与递归响应，保存新的 E/V；不能只看一次解析成功。"
      ],
      "expected_outcomes": [
        "缩小到所列异常环节或明确仍缺失的证据；不预设故障已修复。"
      ],
      "verification_method": "以同一信任锚、策略、时间范围和 QNAME/QTYPE 重验完整 DNSSEC 链与递归响应，保存新的 E/V；不能只看一次解析成功。",
      "prerequisites": [
        "有效的目标授权；配置变更另需管理权限与原因确认。"
      ],
      "safety_notes": [
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。"
      ],
      "executed": false
    }
  ]
}
```

## http-503

旧报告 diagnostic_assessment 实际输出：

```text
已取得 HTTP 层响应或请求错误，详情见事实表；这不直接证明 DNS 故障或客户端问题。
```

新报告高层实际输出：

```json
{
  "diagnosis_status": "FAULT_LOCALIZED",
  "summary": "HTTP 返回 503",
  "fault_location": "http://probe.example:55314/status",
  "cause": "本次 http://probe.example:55314/status 最终 http://probe.example:55314/status 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
  "cause_status": "OBSERVED_MECHANISM",
  "evidence_ids": [
    "E1"
  ],
  "validation_ids": [],
  "remediation_steps": [
    {
      "id": "D1-HTTP_503-R1",
      "priority": 1,
      "title": "优先核对与定位",
      "action_type": "CHECK",
      "description": "核对所列 URL、最终 URL、状态码、重定向与请求完成状态；结合服务日志和接口设计确认响应含义。",
      "target": "http://probe.example:55314/status",
      "reason": "本次 http://probe.example:55314/status 最终 http://probe.example:55314/status 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E1"
      ],
      "validation_ids": [],
      "instructions": [
        "核对所列 URL、最终 URL、状态码、重定向与请求完成状态；结合服务日志和接口设计确认响应含义。"
      ],
      "expected_outcomes": [
        "缩小到所列异常环节或明确仍缺失的证据；不预设故障已修复。"
      ],
      "verification_method": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
      "prerequisites": [
        "有效的目标授权；配置变更另需管理权限与原因确认。"
      ],
      "safety_notes": [
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。"
      ],
      "executed": false
    },
    {
      "id": "D1-HTTP_503-R2",
      "priority": 2,
      "title": "条件成立后的修复",
      "action_type": "POSSIBLE_FIX",
      "description": "仅在确认应用、权限或上游配置问题且有管理权限后修正对应设置；4xx/5xx 不要求修改 DNS。",
      "target": "http://probe.example:55314/status",
      "reason": "本次 http://probe.example:55314/status 最终 http://probe.example:55314/status 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E1"
      ],
      "validation_ids": [],
      "instructions": [
        "仅在确认应用、权限或上游配置问题且有管理权限后修正对应设置；4xx/5xx 不要求修改 DNS。"
      ],
      "expected_outcomes": [
        "缩小到所列异常环节或明确仍缺失的证据；不预设故障已修复。"
      ],
      "verification_method": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
      "prerequisites": [
        "有效的目标授权；配置变更另需管理权限与原因确认。"
      ],
      "safety_notes": [
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。"
      ],
      "executed": false
    }
  ],
  "verification_steps": [
    {
      "id": "D1-HTTP_503-R3",
      "priority": 3,
      "title": "复测并保留新证据",
      "action_type": "VERIFY",
      "description": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
      "target": "http://probe.example:55314/status",
      "reason": "本次 http://probe.example:55314/status 最终 http://probe.example:55314/status 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E1"
      ],
      "validation_ids": [],
      "instructions": [
        "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。"
      ],
      "expected_outcomes": [
        "缩小到所列异常环节或明确仍缺失的证据；不预设故障已修复。"
      ],
      "verification_method": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
      "prerequisites": [
        "有效的目标授权；配置变更另需管理权限与原因确认。"
      ],
      "safety_notes": [
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。"
      ],
      "executed": false
    }
  ]
}
```

## dns-normal

旧报告 diagnostic_assessment 实际输出：

```text
本次已测 DNS 查询取得记录，未发现该范围的解析状态异常；不能据此确认用户客户端原因。
```

新报告高层实际输出：

```json
{
  "diagnosis_status": "NO_FAULT_OBSERVED",
  "summary": "本次已测范围未发现明确异常。",
  "fault_location": "probe.example A via 127.0.0.1；probe.example A via 127.0.0.2；probe.example A via 127.0.0.3",
  "cause": "仅为本次已测路径的状态，不确认客户端原因。",
  "cause_status": "UNKNOWN",
  "evidence_ids": [
    "E1",
    "E2",
    "E3"
  ],
  "validation_ids": [],
  "remediation_steps": [
    {
      "id": "D1-MEASURED_NORMAL-R1",
      "priority": 1,
      "title": "优先核对与定位",
      "action_type": "CHECK",
      "description": "在故障设备记录具体错误、发生时间和当时网络；对照同一目标，先不修改配置。",
      "target": "probe.example A via 127.0.0.1；probe.example A via 127.0.0.2；probe.example A via 127.0.0.3",
      "reason": "仅为本次已测路径的状态，不确认客户端原因。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E1",
        "E2",
        "E3"
      ],
      "validation_ids": [],
      "instructions": [
        "在故障设备记录具体错误、发生时间和当时网络；对照同一目标，先不修改配置。"
      ],
      "expected_outcomes": [
        "缩小到所列异常环节或明确仍缺失的证据；不预设故障已修复。"
      ],
      "verification_method": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
      "prerequisites": [
        "有效的目标授权；配置变更另需管理权限与原因确认。"
      ],
      "safety_notes": [
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。"
      ],
      "executed": false
    }
  ],
  "verification_steps": [
    {
      "id": "D1-MEASURED_NORMAL-R2",
      "priority": 2,
      "title": "复测并保留新证据",
      "action_type": "VERIFY",
      "description": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
      "target": "probe.example A via 127.0.0.1；probe.example A via 127.0.0.2；probe.example A via 127.0.0.3",
      "reason": "仅为本次已测路径的状态，不确认客户端原因。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E1",
        "E2",
        "E3"
      ],
      "validation_ids": [],
      "instructions": [
        "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。"
      ],
      "expected_outcomes": [
        "缩小到所列异常环节或明确仍缺失的证据；不预设故障已修复。"
      ],
      "verification_method": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
      "prerequisites": [
        "有效的目标授权；配置变更另需管理权限与原因确认。"
      ],
      "safety_notes": [
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。"
      ],
      "executed": false
    }
  ]
}
```
