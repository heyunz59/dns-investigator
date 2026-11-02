# 同证据报告对照

历史回放与 constructed report input 分开标注；未执行公网或模型调用。完整输入及原始文件哈希见 expanded-baseline/before.json。

## dns-timeout

来源：historical_controlled_measurement_replay

修改前实际高层诊断：
```json
{
  "diagnosis_status": "FAULT_LOCALIZED",
  "fault_detected": true,
  "primary_issue": "RECURSIVE_QUERY_TIMEOUT",
  "summary": "所列递归查询路径本次未响应",
  "fault_layer": "Recursive DNS",
  "fault_location": "probe.example A via 127.0.0.1",
  "affected_scope": [
    {
      "evidence_id": "E3",
      "target": "probe.example",
      "record_type": "A",
      "resolver": "127.0.0.1",
      "resolver_role": "recursive",
      "measured_at": "2026-11-02T07:35:54.624000+00:00",
      "source_mode": "live",
      "result": "TIMEOUT",
      "cname_chain": []
    }
  ],
  "unaffected_or_comparison_scope": [
    {
      "evidence_id": "E1",
      "target": "probe.example",
      "record_type": "A",
      "resolver": "127.0.0.2",
      "resolver_role": "recursive",
      "measured_at": "2026-11-02T07:35:54.463532+00:00",
      "source_mode": "live",
      "result": "NOERROR",
      "canonical_name": "probe.example",
      "cname_chain": []
    },
    {
      "evidence_id": "E2",
      "target": "probe.example",
      "record_type": "A",
      "resolver": "127.0.0.3",
      "resolver_role": "recursive",
      "measured_at": "2026-11-02T07:35:54.463532+00:00",
      "source_mode": "live",
      "result": "NOERROR",
      "canonical_name": "probe.example",
      "cname_chain": []
    }
  ],
  "cause": "查询 probe.example A：127.0.0.1 对 probe.example 返回 TIMEOUT（E3）。不推断注册状态或服务器宕机。",
  "cause_status": "OBSERVED_MECHANISM",
  "alternative_causes": [
    "解析器服务状态",
    "网络路径或访问策略"
  ],
  "reason": "查询 probe.example A：127.0.0.1 对 probe.example 返回 TIMEOUT（E3）。不推断注册状态或服务器宕机。",
  "evidence_ids": [
    "E3",
    "E1",
    "E2"
  ],
  "validation_ids": [],
  "finding_codes": [
    "RECURSIVE_QUERY_TIMEOUT"
  ],
  "relevant_attempt_ids": [],
  "source_modes": [
    "live"
  ],
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
  ],
  "limitations": [
    "范围仅为所列来源、时间及已测组合；协议异常不确认具体运维操作或用户故障的唯一原因。",
    "单次观测不能区分缓存、策略、调度、网络路径或服务因素；未确认唯一根因。",
    "缺失时间/来源的旧日志保留未知；未执行 DNSSEC 验证或完整迭代解析。"
  ]
}
```

修改后实际高层诊断与并列观测：
```json
{
  "primary": {
    "status_code": null,
    "error_details": {},
    "location": [
      {
        "qname": "probe.example",
        "qtype": "A",
        "resolver": "127.0.0.1",
        "role": "recursive",
        "ip": null,
        "port": null,
        "url": null,
        "final_url": null,
        "measured_at": "2026-11-02T07:35:54.624000+00:00",
        "source_mode": "live"
      }
    ],
    "fault_component": "Recursive DNS",
    "failure_stage": null,
    "reason_code": "RECURSIVE_QUERY_TIMEOUT",
    "direct_evidence_ids": [
      "E3"
    ],
    "direct_validation_ids": [],
    "dependency_evidence_ids": [],
    "dependency_validation_ids": [],
    "relevance": "independent_observation",
    "selection_reason": "独立测量保留；缺少足够问题相关性或主次依据，不推断唯一主因。",
    "intent_source": "unknown",
    "diagnosis_status": "FAULT_LOCALIZED",
    "fault_detected": true,
    "primary_issue": "RECURSIVE_QUERY_TIMEOUT",
    "summary": "所列递归查询路径本次未响应",
    "fault_layer": "Recursive DNS",
    "fault_location": "probe.example A via 127.0.0.1",
    "affected_scope": [
      {
        "evidence_id": "E3",
        "target": "probe.example",
        "record_type": "A",
        "resolver": "127.0.0.1",
        "resolver_role": "recursive",
        "measured_at": "2026-11-02T07:35:54.624000+00:00",
        "source_mode": "live",
        "result": "TIMEOUT",
        "cname_chain": []
      }
    ],
    "unaffected_or_comparison_scope": [
      {
        "evidence_id": "E1",
        "target": "probe.example",
        "record_type": "A",
        "resolver": "127.0.0.2",
        "resolver_role": "recursive",
        "measured_at": "2026-11-02T07:35:54.463532+00:00",
        "source_mode": "live",
        "result": "NOERROR",
        "canonical_name": "probe.example",
        "cname_chain": []
      },
      {
        "evidence_id": "E2",
        "target": "probe.example",
        "record_type": "A",
        "resolver": "127.0.0.3",
        "resolver_role": "recursive",
        "measured_at": "2026-11-02T07:35:54.463532+00:00",
        "source_mode": "live",
        "result": "NOERROR",
        "canonical_name": "probe.example",
        "cname_chain": []
      }
    ],
    "cause": "probe.example A 经 127.0.0.1 查询未在时限内收到响应；未确认服务器宕机。",
    "cause_status": "OBSERVED_MECHANISM",
    "alternative_causes": [
      "解析器服务状态",
      "网络路径或访问策略"
    ],
    "reason": "probe.example A 经 127.0.0.1 查询未在时限内收到响应；未确认服务器宕机。",
    "evidence_ids": [
      "E3",
      "E1",
      "E2"
    ],
    "validation_ids": [],
    "finding_codes": [
      "RECURSIVE_QUERY_TIMEOUT"
    ],
    "relevant_attempt_ids": [],
    "source_modes": [
      "live"
    ],
    "remediation_steps": [
      {
        "method": {
          "kind": "current_tool",
          "tool_name": "query_dns",
          "supported_by_current_tools": true,
          "parameters": {
            "domain": "probe.example",
            "record_type": "A",
            "resolver": "127.0.0.1"
          },
          "description": "后续新的授权调查中的候选检查；仍须目标、解析器、时效和预算校验，尚未执行。"
        },
        "branches": [
          {
            "condition": "如果后续检查发现：原解析路径仍超时、对照正常",
            "interpretation": "范围集中于所列查询路径；服务与网络未区分",
            "next_action": "检查该解析器服务日志与受限网络可达性。",
            "change_prerequisites": []
          },
          {
            "condition": "如果后续检查发现：原路径恢复响应",
            "interpretation": "可能间歇性；不能确认已永久修复",
            "next_action": "记录复测时间，核对故障时刻和日志。",
            "change_prerequisites": []
          },
          {
            "condition": "如果后续检查发现：所有已授权对照路径均超时",
            "interpretation": "范围可能更广，未确认本机或运营商原因",
            "next_action": "核对测量工具及现场网络，不无界增加查询。",
            "change_prerequisites": []
          },
          {
            "condition": "如果后续检查发现：原路径收到 SERVFAIL",
            "interpretation": "已收到 DNS 错误响应，不再是超时",
            "next_action": "转入响应错误及上游/验证材料的调查。",
            "change_prerequisites": []
          }
        ],
        "id": "D1-RECURSIVE_QUERY_TIMEOUT-R1",
        "priority": 1,
        "title": "优先核对与定位",
        "action_type": "CHECK",
        "description": "从相同测量位置复测所列目标、记录类型和解析路径，记录真实复测时间；与已测对照路径比较。；核对该解析器/权威服务状态、网络可达性和查询访问策略，区分服务与路径因素。",
        "target": "probe.example A via 127.0.0.1",
        "reason": "probe.example A 经 127.0.0.1 查询未在时限内收到响应；未确认服务器宕机。",
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
          "如果后续检查发现：原解析路径仍超时、对照正常",
          "如果后续检查发现：原路径恢复响应",
          "如果后续检查发现：所有已授权对照路径均超时",
          "如果后续检查发现：原路径收到 SERVFAIL"
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
        "method": {
          "kind": "administrator_conditional_change",
          "supported_by_current_tools": false,
          "parameters": [
            {
              "qname": "probe.example",
              "qtype": "A",
              "resolver": "127.0.0.1",
              "role": "recursive",
              "ip": null,
              "port": null,
              "url": null,
              "final_url": null,
              "measured_at": "2026-11-02T07:35:54.624000+00:00",
              "source_mode": "live"
            }
          ],
          "description": "仅在分支条件和管理权限成立后人工变更；本程序不执行。"
        },
        "branches": [],
        "id": "D1-RECURSIVE_QUERY_TIMEOUT-R2",
        "priority": 2,
        "title": "条件成立后的修复",
        "action_type": "POSSIBLE_FIX",
        "description": "仅在对照确认具体缓存、服务或区域配置问题并具备管理权限后，修正对应配置；不要仅凭差异更换 DNS 或改记录。",
        "target": "probe.example A via 127.0.0.1",
        "reason": "probe.example A 经 127.0.0.1 查询未在时限内收到响应；未确认服务器宕机。",
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
        "method": {
          "kind": "current_tool",
          "tool_name": "query_dns",
          "supported_by_current_tools": true,
          "parameters": {
            "domain": "probe.example",
            "record_type": "A",
            "resolver": "127.0.0.1"
          },
          "description": "后续新的授权调查中的候选检查；仍须目标、解析器、时效和预算校验，尚未执行。"
        },
        "branches": [],
        "id": "D1-RECURSIVE_QUERY_TIMEOUT-R3",
        "priority": 3,
        "title": "复测并保留新证据",
        "action_type": "VERIFY",
        "description": "从相同位置、记录复测时间，重新检查相同目标/类型/解析器；比较原异常是否消失及对照是否稳定。",
        "target": "probe.example A via 127.0.0.1",
        "reason": "probe.example A 经 127.0.0.1 查询未在时限内收到响应；未确认服务器宕机。",
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
    ],
    "limitations": [
      "范围仅为所列来源、时间及已测组合；协议异常不确认具体运维操作或用户故障的唯一原因。",
      "单次观测不能区分缓存、策略、调度、网络路径或服务因素；未确认唯一根因。",
      "缺失时间/来源的旧日志保留未知；未执行 DNSSEC 验证或完整迭代解析。"
    ]
  },
  "secondary": []
}
```

## dnssec-ds_mismatch

来源：historical_controlled_measurement_replay

修改前实际高层诊断：
```json
{
  "diagnosis_status": "CONFIRMED_PROTOCOL_ISSUE",
  "fault_detected": true,
  "primary_issue": "DNSSEC_VALIDATION",
  "summary": "父区域 DS 与已取得子区域 DNSKEY 无法建立关联",
  "fault_layer": "DNSSEC",
  "fault_location": ". DNSKEY via 127.0.0.10；test. DS via 127.0.0.10；test. DNSKEY via 127.0.0.11；example.test. DS via 127.0.0.11；example.test. DNSKEY via 127.0.0.12",
  "affected_scope": [
    {
      "evidence_id": "E4",
      "target": ".",
      "record_type": "DNSKEY",
      "resolver": "127.0.0.10",
      "resolver_role": "authoritative",
      "measured_at": "2026-11-02T07:35:54.689721+00:00",
      "source_mode": "live",
      "result": "NOERROR",
      "canonical_name": "",
      "cname_chain": []
    },
    {
      "evidence_id": "E5",
      "target": "test.",
      "record_type": "DS",
      "resolver": "127.0.0.10",
      "resolver_role": "authoritative",
      "measured_at": "2026-11-02T07:35:54.691228+00:00",
      "source_mode": "live",
      "result": "NOERROR",
      "canonical_name": "test",
      "cname_chain": []
    },
    {
      "evidence_id": "E6",
      "target": "test.",
      "record_type": "DNSKEY",
      "resolver": "127.0.0.11",
      "resolver_role": "authoritative",
      "measured_at": "2026-11-02T07:35:54.692254+00:00",
      "source_mode": "live",
      "result": "NOERROR",
      "canonical_name": "test",
      "cname_chain": []
    },
    {
      "evidence_id": "E7",
      "target": "example.test.",
      "record_type": "DS",
      "resolver": "127.0.0.11",
      "resolver_role": "authoritative",
      "measured_at": "2026-11-02T07:35:54.693254+00:00",
      "source_mode": "live",
      "result": "NOERROR",
      "canonical_name": "example.test",
      "cname_chain": []
    },
    {
      "evidence_id": "E8",
      "target": "example.test.",
      "record_type": "DNSKEY",
      "resolver": "127.0.0.12",
      "resolver_role": "authoritative",
      "measured_at": "2026-11-02T07:35:54.695117+00:00",
      "source_mode": "live",
      "result": "NOERROR",
      "canonical_name": "example.test",
      "cname_chain": []
    }
  ],
  "unaffected_or_comparison_scope": [],
  "cause": "父区域 DS 与已取得子区域 DNSKEY 无法建立关联；阶段=child-ds-match，reason_code=DS_DIGEST_MISMATCH，范围={'qname': 'probe.example.test', 'qtype': 'A', 'validation_time': 1793604954.688389}；限本地验证策略。",
  "cause_status": "VERIFIED_PROTOCOL",
  "alternative_causes": [
    "密钥轮换、发布配置或签名材料问题仍需管理员核对"
  ],
  "reason": "父区域 DS 与已取得子区域 DNSKEY 无法建立关联；阶段=child-ds-match，reason_code=DS_DIGEST_MISMATCH，范围={'qname': 'probe.example.test', 'qtype': 'A', 'validation_time': 1793604954.688389}；限本地验证策略。",
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
  "finding_codes": [
    "DNSSEC_VALIDATION"
  ],
  "relevant_attempt_ids": [
    "A1"
  ],
  "source_modes": [
    "live"
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
  ],
  "limitations": [
    "范围仅为所列来源、时间及已测组合；协议异常不确认具体运维操作或用户故障的唯一原因。",
    "本工具有有限协议支持；否定证明等与独立验证器的历史分歧仍须复核。"
  ]
}
```

修改后实际高层诊断与并列观测：
```json
{
  "primary": {
    "status_code": null,
    "error_details": {},
    "location": [
      {
        "zone": "example.test.",
        "validation_id": "V7",
        "component": "ds_digest"
      }
    ],
    "fault_component": "ds_digest",
    "failure_stage": "child-ds-match",
    "reason_code": "DS_DIGEST_MISMATCH",
    "direct_evidence_ids": [
      "E7",
      "E8"
    ],
    "direct_validation_ids": [
      "V7"
    ],
    "dependency_evidence_ids": [
      "E4",
      "E5",
      "E6"
    ],
    "dependency_validation_ids": [
      "V1",
      "V2",
      "V3",
      "V4",
      "V5",
      "V6"
    ],
    "relevance": "independent_observation",
    "selection_reason": "独立测量保留；缺少足够问题相关性或主次依据，不推断唯一主因。 本地协议确认优先。",
    "intent_source": "unknown",
    "diagnosis_status": "CONFIRMED_PROTOCOL_ISSUE",
    "fault_detected": true,
    "primary_issue": "DNSSEC_VALIDATION",
    "summary": "父区域 DS 与已取得子区域 DNSKEY 无法建立关联",
    "fault_layer": "DNSSEC",
    "fault_location": "example.test. 父侧 DS 与子侧 DNSKEY 关联验证",
    "affected_scope": [
      {
        "evidence_id": "E7",
        "target": "example.test.",
        "record_type": "DS",
        "resolver": "127.0.0.11",
        "resolver_role": "authoritative",
        "measured_at": "2026-11-02T07:35:54.693254+00:00",
        "source_mode": "live",
        "result": "NOERROR",
        "canonical_name": "example.test",
        "cname_chain": []
      },
      {
        "evidence_id": "E8",
        "target": "example.test.",
        "record_type": "DNSKEY",
        "resolver": "127.0.0.12",
        "resolver_role": "authoritative",
        "measured_at": "2026-11-02T07:35:54.695117+00:00",
        "source_mode": "live",
        "result": "NOERROR",
        "canonical_name": "example.test",
        "cname_chain": []
      }
    ],
    "unaffected_or_comparison_scope": [],
    "cause": "父区域 DS 与已取得子区域 DNSKEY 无法建立关联；阶段=child-ds-match，reason_code=DS_DIGEST_MISMATCH，范围={'qname': 'probe.example.test', 'qtype': 'A', 'validation_time': 1793604954.688389}；限本地验证策略。",
    "cause_status": "VERIFIED_PROTOCOL",
    "alternative_causes": [
      "密钥轮换、发布配置或签名材料问题仍需管理员核对"
    ],
    "reason": "父区域 DS 与已取得子区域 DNSKEY 无法建立关联；阶段=child-ds-match，reason_code=DS_DIGEST_MISMATCH，范围={'qname': 'probe.example.test', 'qtype': 'A', 'validation_time': 1793604954.688389}；限本地验证策略。",
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
    "finding_codes": [
      "DNSSEC_VALIDATION"
    ],
    "relevant_attempt_ids": [
      "A1"
    ],
    "source_modes": [
      "live"
    ],
    "remediation_steps": [
      {
        "method": {
          "kind": "administrator_read_only",
          "supported_by_current_tools": false,
          "parameters": [
            {
              "zone": "example.test.",
              "validation_id": "V7",
              "component": "ds_digest"
            }
          ],
          "description": "人工只读核对或外部复核；不是自动工具调用。"
        },
        "branches": [
          {
            "condition": "如果后续检查发现：父侧 DS 与子侧 DNSKEY 的算法/digest 发布材料仍不匹配",
            "interpretation": "关联异常复现，但轮换或配置操作原因未定",
            "next_action": "管理员核对轮换状态后条件性修正对应发布材料，再重验完整链。",
            "change_prerequisites": [
              "管理权限、配置备份及已确认的具体配置问题；另行操作，不自动执行。"
            ]
          },
          {
            "condition": "如果后续检查发现：DS/DNSKEY 匹配但 RRSIG 验证失败",
            "interpretation": "当前阻断环节已变化",
            "next_action": "检查签名者、DNSKEY、RRSIG 和验证时间，不直接修改 DS。",
            "change_prerequisites": []
          },
          {
            "condition": "如果后续检查发现：材料缺失或算法/策略不支持",
            "interpretation": "仍无法确定",
            "next_action": "保持未知，按同一信任锚/时间与独立验证器只读复核。",
            "change_prerequisites": []
          }
        ],
        "id": "D1-DNSSEC_VALIDATION-R1",
        "priority": 1,
        "title": "优先核对与定位",
        "action_type": "CHECK",
        "description": "只读查询并核对父区域发布的 DS 与子区域正在使用的 DNSKEY（含 key tag、算法和 digest）。；核对密钥轮换时间、发布状态与管理权限，确认具体不匹配发生在哪个父子区域。",
        "target": "example.test. 父侧 DS 与子侧 DNSKEY 关联验证",
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
          "如果后续检查发现：父侧 DS 与子侧 DNSKEY 的算法/digest 发布材料仍不匹配",
          "如果后续检查发现：DS/DNSKEY 匹配但 RRSIG 验证失败",
          "如果后续检查发现：材料缺失或算法/策略不支持"
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
        "method": {
          "kind": "administrator_conditional_change",
          "supported_by_current_tools": false,
          "parameters": [
            {
              "zone": "example.test.",
              "validation_id": "V7",
              "component": "ds_digest"
            }
          ],
          "description": "仅在分支条件和管理权限成立后人工变更；本程序不执行。"
        },
        "branches": [],
        "id": "D1-DNSSEC_VALIDATION-R2",
        "priority": 2,
        "title": "条件成立后的修复",
        "action_type": "POSSIBLE_FIX",
        "description": "只有确认父子 DS/DNSKEY 关联配置错误后，管理员才按正确密钥轮换流程修正对应记录；不直接删除 DS 或关闭 DNSSEC。",
        "target": "example.test. 父侧 DS 与子侧 DNSKEY 关联验证",
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
        "method": {
          "kind": "external_read_only",
          "supported_by_current_tools": false,
          "parameters": [
            {
              "zone": "example.test.",
              "validation_id": "V7",
              "component": "ds_digest"
            }
          ],
          "description": "人工只读核对或外部复核；不是自动工具调用。"
        },
        "branches": [],
        "id": "D1-DNSSEC_VALIDATION-R3",
        "priority": 3,
        "title": "复测并保留新证据",
        "action_type": "VERIFY",
        "description": "以同一信任锚、策略、时间范围和 QNAME/QTYPE 重验完整 DNSSEC 链与递归响应，保存新的 E/V；不能只看一次解析成功。",
        "target": "example.test. 父侧 DS 与子侧 DNSKEY 关联验证",
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
    ],
    "limitations": [
      "范围仅为所列来源、时间及已测组合；协议异常不确认具体运维操作或用户故障的唯一原因。",
      "本工具有有限协议支持；否定证明等与独立验证器的历史分歧仍须复核。"
    ]
  },
  "secondary": []
}
```

## multi-TCP

来源：constructed_report_input_not_network_measurement

修改前实际高层诊断：
```json
{
  "diagnosis_status": "FAULT_LOCALIZED",
  "fault_detected": true,
  "primary_issue": "HTTP_503",
  "summary": "[fixture/synthetic 模拟数据] HTTP 返回 503",
  "fault_layer": "HTTP",
  "fault_location": "https://probe.example/",
  "affected_scope": [
    {
      "evidence_id": "E2",
      "target": "https://probe.example/",
      "measured_at": "2026-11-02T00:00:00+00:00",
      "source_mode": "synthetic",
      "result": 503
    }
  ],
  "unaffected_or_comparison_scope": [],
  "cause": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
  "cause_status": "OBSERVED_MECHANISM",
  "alternative_causes": [
    "访问权限或请求条件",
    "应用或上游服务行为"
  ],
  "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
  "evidence_ids": [
    "E2"
  ],
  "validation_ids": [],
  "finding_codes": [],
  "relevant_attempt_ids": [],
  "source_modes": [
    "synthetic"
  ],
  "remediation_steps": [
    {
      "id": "D1-HTTP_503-R1",
      "priority": 1,
      "title": "优先核对与定位",
      "action_type": "CHECK",
      "description": "核对所列 URL、最终 URL、状态码、重定向与请求完成状态；结合服务日志和接口设计确认响应含义。",
      "target": "https://probe.example/",
      "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E2"
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
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
        "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
      ],
      "executed": false
    },
    {
      "id": "D1-HTTP_503-R2",
      "priority": 2,
      "title": "条件成立后的修复",
      "action_type": "POSSIBLE_FIX",
      "description": "仅在确认应用、权限或上游配置问题且有管理权限后修正对应设置；4xx/5xx 不要求修改 DNS。",
      "target": "https://probe.example/",
      "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E2"
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
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
        "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
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
      "target": "https://probe.example/",
      "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E2"
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
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
        "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
      ],
      "executed": false
    }
  ],
  "limitations": [
    "范围仅为所列来源、时间及已测组合；协议异常不确认具体运维操作或用户故障的唯一原因。",
    "不得作为当前真实公网故障；真实检查前须重新 live 解析，不能直接探测模拟地址。",
    "还存在独立异常或未完成范围；排序仅用于展示，不确认主次因果关系。"
  ]
}
```

修改后实际高层诊断与并列观测：
```json
{
  "primary": {
    "status_code": null,
    "error_details": {},
    "location": [
      {
        "qname": null,
        "qtype": null,
        "resolver": null,
        "role": null,
        "ip": "192.0.2.10",
        "port": 443,
        "url": null,
        "final_url": null,
        "measured_at": "2026-11-02T00:00:00+00:00",
        "source_mode": "synthetic"
      }
    ],
    "fault_component": "TCP/Network Transport",
    "failure_stage": "tcp-connect",
    "reason_code": "REFUSED",
    "direct_evidence_ids": [
      "E1"
    ],
    "direct_validation_ids": [],
    "dependency_evidence_ids": [],
    "dependency_validation_ids": [],
    "relevance": "explicit_focus",
    "selection_reason": "明确关注层与本调查已测范围匹配；目标/端口按已有结构检查，未提供的时间/关联不补造；不改变确认等级。",
    "intent_source": "explicit_user_statement",
    "diagnosis_status": "FAULT_LOCALIZED",
    "fault_detected": true,
    "primary_issue": "TCP_REFUSED",
    "summary": "[fixture/synthetic 模拟数据] TCP：本次连接被拒绝",
    "fault_layer": "TCP/Network Transport",
    "fault_location": "192.0.2.10 port 443",
    "affected_scope": [
      {
        "evidence_id": "E1",
        "target": "192.0.2.10",
        "port": 443,
        "measured_at": "2026-11-02T00:00:00+00:00",
        "source_mode": "synthetic",
        "result": "REFUSED"
      }
    ],
    "unaffected_or_comparison_scope": [],
    "cause": "本次连接被拒绝（REFUSED）；详情=None。不证明 HTTP 使用相同后端。",
    "cause_status": "OBSERVED_MECHANISM",
    "alternative_causes": [
      "服务监听",
      "主机防火墙",
      "网络访问策略或路径"
    ],
    "reason": "本次连接被拒绝（REFUSED）；详情=None。不证明 HTTP 使用相同后端。",
    "evidence_ids": [
      "E1"
    ],
    "validation_ids": [],
    "finding_codes": [],
    "relevant_attempt_ids": [],
    "source_modes": [
      "synthetic"
    ],
    "remediation_steps": [
      {
        "method": {
          "kind": "simulation_review",
          "supported_by_current_tools": false,
          "parameters": [
            {
              "qname": null,
              "qtype": null,
              "resolver": null,
              "role": null,
              "ip": "192.0.2.10",
              "port": 443,
              "url": null,
              "final_url": null,
              "measured_at": "2026-11-02T00:00:00+00:00",
              "source_mode": "synthetic"
            }
          ],
          "description": "人工只读核对或外部复核；不是自动工具调用。"
        },
        "branches": [
          {
            "condition": "如果后续检查发现：同一 IP/端口仍为 连接拒绝",
            "interpretation": "复测仅确认连接结果，未确认服务未启动",
            "next_action": "对照服务监听、主机/网络访问日志，区分未监听、访问控制和路径。",
            "change_prerequisites": []
          },
          {
            "condition": "如果后续检查发现：确认监听或访问规则存在具体错误",
            "interpretation": "取得可操作的管理配置证据",
            "next_action": "管理员仅修正对应服务/规则，再复测同一端口。",
            "change_prerequisites": [
              "管理权限、配置备份及已确认的具体配置问题；另行操作，不自动执行。"
            ]
          },
          {
            "condition": "如果后续检查发现：复测成功或错误类别变化",
            "interpretation": "路径状态随时间变化，原原因仍未确认",
            "next_action": "保留新错误码和时间；不禁用 IPv6 或关闭整个防火墙。",
            "change_prerequisites": []
          }
        ],
        "id": "D1-TCP_REFUSED-R1",
        "priority": 1,
        "title": "优先核对与定位",
        "action_type": "CHECK",
        "description": "核对所列 IP/端口的服务监听及主机/网络放行规则；区分 REFUSED、TIMEOUT 和 NETWORK_ERROR。",
        "target": "192.0.2.10 port 443",
        "reason": "本次连接被拒绝（REFUSED）；详情=None。不证明 HTTP 使用相同后端。",
        "related_finding_codes": [],
        "evidence_ids": [
          "E1"
        ],
        "validation_ids": [],
        "instructions": [
          "核对所列 IP/端口的服务监听及主机/网络放行规则；区分 REFUSED、TIMEOUT 和 NETWORK_ERROR。"
        ],
        "expected_outcomes": [
          "如果后续检查发现：同一 IP/端口仍为 连接拒绝",
          "如果后续检查发现：确认监听或访问规则存在具体错误",
          "如果后续检查发现：复测成功或错误类别变化"
        ],
        "verification_method": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
        "prerequisites": [
          "有效的目标授权；配置变更另需管理权限与原因确认。"
        ],
        "safety_notes": [
          "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
          "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
        ],
        "executed": false
      },
      {
        "method": {
          "kind": "administrator_conditional_change",
          "supported_by_current_tools": false,
          "parameters": [
            {
              "qname": null,
              "qtype": null,
              "resolver": null,
              "role": null,
              "ip": "192.0.2.10",
              "port": 443,
              "url": null,
              "final_url": null,
              "measured_at": "2026-11-02T00:00:00+00:00",
              "source_mode": "synthetic"
            }
          ],
          "description": "仅在分支条件和管理权限成立后人工变更；本程序不执行。"
        },
        "branches": [],
        "id": "D1-TCP_REFUSED-R2",
        "priority": 2,
        "title": "条件成立后的修复",
        "action_type": "POSSIBLE_FIX",
        "description": "只有确认具体监听或访问规则错误后，由管理员修正对应服务/规则，不关闭全部防火墙或禁用 IPv6。",
        "target": "192.0.2.10 port 443",
        "reason": "本次连接被拒绝（REFUSED）；详情=None。不证明 HTTP 使用相同后端。",
        "related_finding_codes": [],
        "evidence_ids": [
          "E1"
        ],
        "validation_ids": [],
        "instructions": [
          "只有确认具体监听或访问规则错误后，由管理员修正对应服务/规则，不关闭全部防火墙或禁用 IPv6。"
        ],
        "expected_outcomes": [
          "缩小到所列异常环节或明确仍缺失的证据；不预设故障已修复。"
        ],
        "verification_method": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
        "prerequisites": [
          "有效的目标授权；配置变更另需管理权限与原因确认。"
        ],
        "safety_notes": [
          "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
          "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
        ],
        "executed": false
      }
    ],
    "verification_steps": [
      {
        "method": {
          "kind": "simulation_review",
          "supported_by_current_tools": false,
          "parameters": [
            {
              "qname": null,
              "qtype": null,
              "resolver": null,
              "role": null,
              "ip": "192.0.2.10",
              "port": 443,
              "url": null,
              "final_url": null,
              "measured_at": "2026-11-02T00:00:00+00:00",
              "source_mode": "synthetic"
            }
          ],
          "description": "人工只读核对或外部复核；不是自动工具调用。"
        },
        "branches": [],
        "id": "D1-TCP_REFUSED-R3",
        "priority": 3,
        "title": "复测并保留新证据",
        "action_type": "VERIFY",
        "description": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
        "target": "192.0.2.10 port 443",
        "reason": "本次连接被拒绝（REFUSED）；详情=None。不证明 HTTP 使用相同后端。",
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
          "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
          "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
        ],
        "executed": false
      }
    ],
    "limitations": [
      "范围仅为所列来源、时间及已测组合；协议异常不确认具体运维操作或用户故障的唯一原因。",
      "不得作为当前真实公网故障；真实检查前须重新 live 解析，不能直接探测模拟地址。",
      "其他独立异常的关联未验证；同时发生不证明因果关系。"
    ]
  },
  "secondary": [
    {
      "status_code": 503,
      "error_details": {},
      "location": [
        {
          "qname": null,
          "qtype": null,
          "resolver": null,
          "role": null,
          "ip": null,
          "port": 443,
          "url": "https://probe.example/",
          "final_url": "https://probe.example/",
          "measured_at": "2026-11-02T00:00:00+00:00",
          "source_mode": "synthetic",
          "original_host": "probe.example",
          "final_host": "probe.example",
          "expected_sni": "probe.example"
        }
      ],
      "fault_component": "HTTP",
      "failure_stage": "http-request",
      "reason_code": "503",
      "direct_evidence_ids": [
        "E2"
      ],
      "direct_validation_ids": [],
      "dependency_evidence_ids": [],
      "dependency_validation_ids": [],
      "relevance": "independent_observation",
      "selection_reason": "独立测量保留；缺少足够问题相关性或主次依据，不推断唯一主因。",
      "intent_source": "explicit_user_statement",
      "diagnosis_status": "FAULT_LOCALIZED",
      "fault_detected": true,
      "primary_issue": "HTTP_503",
      "summary": "[fixture/synthetic 模拟数据] HTTP 返回 503",
      "fault_layer": "HTTP",
      "fault_location": "https://probe.example/",
      "affected_scope": [
        {
          "evidence_id": "E2",
          "target": "https://probe.example/",
          "measured_at": "2026-11-02T00:00:00+00:00",
          "source_mode": "synthetic",
          "result": 503
        }
      ],
      "unaffected_or_comparison_scope": [],
      "cause": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
      "cause_status": "OBSERVED_MECHANISM",
      "alternative_causes": [
        "访问权限或请求条件",
        "应用或上游服务行为"
      ],
      "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
      "evidence_ids": [
        "E2"
      ],
      "validation_ids": [],
      "finding_codes": [],
      "relevant_attempt_ids": [],
      "source_modes": [
        "synthetic"
      ],
      "remediation_steps": [
        {
          "method": {
            "kind": "simulation_review",
            "supported_by_current_tools": false,
            "parameters": [
              {
                "qname": null,
                "qtype": null,
                "resolver": null,
                "role": null,
                "ip": null,
                "port": 443,
                "url": "https://probe.example/",
                "final_url": "https://probe.example/",
                "measured_at": "2026-11-02T00:00:00+00:00",
                "source_mode": "synthetic",
                "original_host": "probe.example",
                "final_host": "probe.example",
                "expected_sni": "probe.example"
              }
            ],
            "description": "人工只读核对或外部复核；不是自动工具调用。"
          },
          "branches": [
            {
              "condition": "如果后续检查发现：同一请求仍返回 503",
              "interpretation": "状态码是现象，不能证明具体原因",
              "next_action": "只读核对 服务健康与维护状态 及端点设计；最多一次已授权对照重试，未采集 Retry-After 不编造等待值。",
              "change_prerequisites": []
            },
            {
              "condition": "如果后续检查发现：管理员确认具体 服务健康与维护状态 配置错误",
              "interpretation": "有条件的配置修复依据成立",
              "next_action": "仅修正对应设置，不因 HTTP 错误修改 DNS。",
              "change_prerequisites": [
                "管理权限、配置备份及已确认的具体配置问题；另行操作，不自动执行。"
              ]
            },
            {
              "condition": "如果后续检查发现：响应符合设计或复测恢复",
              "interpretation": "该响应不一定是故障或可能间歇性",
              "next_action": "保留请求条件和时间，再核对用户现场错误。",
              "change_prerequisites": []
            }
          ],
          "id": "D2-HTTP_503-R1",
          "priority": 1,
          "title": "优先核对与定位",
          "action_type": "CHECK",
          "description": "核对所列 URL、最终 URL、状态码、重定向与请求完成状态；结合服务日志和接口设计确认响应含义。",
          "target": "https://probe.example/",
          "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
          "related_finding_codes": [],
          "evidence_ids": [
            "E2"
          ],
          "validation_ids": [],
          "instructions": [
            "核对所列 URL、最终 URL、状态码、重定向与请求完成状态；结合服务日志和接口设计确认响应含义。"
          ],
          "expected_outcomes": [
            "如果后续检查发现：同一请求仍返回 503",
            "如果后续检查发现：管理员确认具体 服务健康与维护状态 配置错误",
            "如果后续检查发现：响应符合设计或复测恢复"
          ],
          "verification_method": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
          "prerequisites": [
            "有效的目标授权；配置变更另需管理权限与原因确认。"
          ],
          "safety_notes": [
            "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
            "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
          ],
          "executed": false
        },
        {
          "method": {
            "kind": "administrator_conditional_change",
            "supported_by_current_tools": false,
            "parameters": [
              {
                "qname": null,
                "qtype": null,
                "resolver": null,
                "role": null,
                "ip": null,
                "port": 443,
                "url": "https://probe.example/",
                "final_url": "https://probe.example/",
                "measured_at": "2026-11-02T00:00:00+00:00",
                "source_mode": "synthetic",
                "original_host": "probe.example",
                "final_host": "probe.example",
                "expected_sni": "probe.example"
              }
            ],
            "description": "仅在分支条件和管理权限成立后人工变更；本程序不执行。"
          },
          "branches": [],
          "id": "D2-HTTP_503-R2",
          "priority": 2,
          "title": "条件成立后的修复",
          "action_type": "POSSIBLE_FIX",
          "description": "仅在确认应用、权限或上游配置问题且有管理权限后修正对应设置；4xx/5xx 不要求修改 DNS。",
          "target": "https://probe.example/",
          "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
          "related_finding_codes": [],
          "evidence_ids": [
            "E2"
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
            "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
            "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
          ],
          "executed": false
        }
      ],
      "verification_steps": [
        {
          "method": {
            "kind": "simulation_review",
            "supported_by_current_tools": false,
            "parameters": [
              {
                "qname": null,
                "qtype": null,
                "resolver": null,
                "role": null,
                "ip": null,
                "port": 443,
                "url": "https://probe.example/",
                "final_url": "https://probe.example/",
                "measured_at": "2026-11-02T00:00:00+00:00",
                "source_mode": "synthetic",
                "original_host": "probe.example",
                "final_host": "probe.example",
                "expected_sni": "probe.example"
              }
            ],
            "description": "人工只读核对或外部复核；不是自动工具调用。"
          },
          "branches": [],
          "id": "D2-HTTP_503-R3",
          "priority": 3,
          "title": "复测并保留新证据",
          "action_type": "VERIFY",
          "description": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
          "target": "https://probe.example/",
          "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
          "related_finding_codes": [],
          "evidence_ids": [
            "E2"
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
            "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
            "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
          ],
          "executed": false
        }
      ],
      "limitations": [
        "范围仅为所列来源、时间及已测组合；协议异常不确认具体运维操作或用户故障的唯一原因。",
        "不得作为当前真实公网故障；真实检查前须重新 live 解析，不能直接探测模拟地址。",
        "其他独立异常的关联未验证；同时发生不证明因果关系。"
      ]
    }
  ]
}
```

## multi-ambiguous

来源：constructed_report_input_not_network_measurement

修改前实际高层诊断：
```json
{
  "diagnosis_status": "FAULT_LOCALIZED",
  "fault_detected": true,
  "primary_issue": "HTTP_503",
  "summary": "[fixture/synthetic 模拟数据] HTTP 返回 503",
  "fault_layer": "HTTP",
  "fault_location": "https://probe.example/",
  "affected_scope": [
    {
      "evidence_id": "E2",
      "target": "https://probe.example/",
      "measured_at": "2026-11-02T00:00:00+00:00",
      "source_mode": "synthetic",
      "result": 503
    }
  ],
  "unaffected_or_comparison_scope": [],
  "cause": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
  "cause_status": "OBSERVED_MECHANISM",
  "alternative_causes": [
    "访问权限或请求条件",
    "应用或上游服务行为"
  ],
  "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
  "evidence_ids": [
    "E2"
  ],
  "validation_ids": [],
  "finding_codes": [],
  "relevant_attempt_ids": [],
  "source_modes": [
    "synthetic"
  ],
  "remediation_steps": [
    {
      "id": "D1-HTTP_503-R1",
      "priority": 1,
      "title": "优先核对与定位",
      "action_type": "CHECK",
      "description": "核对所列 URL、最终 URL、状态码、重定向与请求完成状态；结合服务日志和接口设计确认响应含义。",
      "target": "https://probe.example/",
      "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E2"
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
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
        "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
      ],
      "executed": false
    },
    {
      "id": "D1-HTTP_503-R2",
      "priority": 2,
      "title": "条件成立后的修复",
      "action_type": "POSSIBLE_FIX",
      "description": "仅在确认应用、权限或上游配置问题且有管理权限后修正对应设置；4xx/5xx 不要求修改 DNS。",
      "target": "https://probe.example/",
      "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E2"
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
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
        "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
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
      "target": "https://probe.example/",
      "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E2"
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
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
        "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
      ],
      "executed": false
    }
  ],
  "limitations": [
    "范围仅为所列来源、时间及已测组合；协议异常不确认具体运维操作或用户故障的唯一原因。",
    "不得作为当前真实公网故障；真实检查前须重新 live 解析，不能直接探测模拟地址。",
    "还存在独立异常或未完成范围；排序仅用于展示，不确认主次因果关系。"
  ]
}
```

修改后实际高层诊断与并列观测：
```json
{
  "primary": null,
  "secondary": [
    {
      "status_code": 503,
      "error_details": {},
      "location": [
        {
          "qname": null,
          "qtype": null,
          "resolver": null,
          "role": null,
          "ip": null,
          "port": 443,
          "url": "https://probe.example/",
          "final_url": "https://probe.example/",
          "measured_at": "2026-11-02T00:00:00+00:00",
          "source_mode": "synthetic",
          "original_host": "probe.example",
          "final_host": "probe.example",
          "expected_sni": "probe.example"
        }
      ],
      "fault_component": "HTTP",
      "failure_stage": "http-request",
      "reason_code": "503",
      "direct_evidence_ids": [
        "E2"
      ],
      "direct_validation_ids": [],
      "dependency_evidence_ids": [],
      "dependency_validation_ids": [],
      "relevance": "independent_observation",
      "selection_reason": "独立测量保留；缺少足够问题相关性或主次依据，不推断唯一主因。",
      "intent_source": "unknown",
      "diagnosis_status": "FAULT_LOCALIZED",
      "fault_detected": true,
      "primary_issue": "HTTP_503",
      "summary": "[fixture/synthetic 模拟数据] HTTP 返回 503",
      "fault_layer": "HTTP",
      "fault_location": "https://probe.example/",
      "affected_scope": [
        {
          "evidence_id": "E2",
          "target": "https://probe.example/",
          "measured_at": "2026-11-02T00:00:00+00:00",
          "source_mode": "synthetic",
          "result": 503
        }
      ],
      "unaffected_or_comparison_scope": [],
      "cause": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
      "cause_status": "OBSERVED_MECHANISM",
      "alternative_causes": [
        "访问权限或请求条件",
        "应用或上游服务行为"
      ],
      "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
      "evidence_ids": [
        "E2"
      ],
      "validation_ids": [],
      "finding_codes": [],
      "relevant_attempt_ids": [],
      "source_modes": [
        "synthetic"
      ],
      "remediation_steps": [
        {
          "method": {
            "kind": "simulation_review",
            "supported_by_current_tools": false,
            "parameters": [
              {
                "qname": null,
                "qtype": null,
                "resolver": null,
                "role": null,
                "ip": null,
                "port": 443,
                "url": "https://probe.example/",
                "final_url": "https://probe.example/",
                "measured_at": "2026-11-02T00:00:00+00:00",
                "source_mode": "synthetic",
                "original_host": "probe.example",
                "final_host": "probe.example",
                "expected_sni": "probe.example"
              }
            ],
            "description": "人工只读核对或外部复核；不是自动工具调用。"
          },
          "branches": [
            {
              "condition": "如果后续检查发现：同一请求仍返回 503",
              "interpretation": "状态码是现象，不能证明具体原因",
              "next_action": "只读核对 服务健康与维护状态 及端点设计；最多一次已授权对照重试，未采集 Retry-After 不编造等待值。",
              "change_prerequisites": []
            },
            {
              "condition": "如果后续检查发现：管理员确认具体 服务健康与维护状态 配置错误",
              "interpretation": "有条件的配置修复依据成立",
              "next_action": "仅修正对应设置，不因 HTTP 错误修改 DNS。",
              "change_prerequisites": [
                "管理权限、配置备份及已确认的具体配置问题；另行操作，不自动执行。"
              ]
            },
            {
              "condition": "如果后续检查发现：响应符合设计或复测恢复",
              "interpretation": "该响应不一定是故障或可能间歇性",
              "next_action": "保留请求条件和时间，再核对用户现场错误。",
              "change_prerequisites": []
            }
          ],
          "id": "D2-HTTP_503-R1",
          "priority": 1,
          "title": "优先核对与定位",
          "action_type": "CHECK",
          "description": "核对所列 URL、最终 URL、状态码、重定向与请求完成状态；结合服务日志和接口设计确认响应含义。",
          "target": "https://probe.example/",
          "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
          "related_finding_codes": [],
          "evidence_ids": [
            "E2"
          ],
          "validation_ids": [],
          "instructions": [
            "核对所列 URL、最终 URL、状态码、重定向与请求完成状态；结合服务日志和接口设计确认响应含义。"
          ],
          "expected_outcomes": [
            "如果后续检查发现：同一请求仍返回 503",
            "如果后续检查发现：管理员确认具体 服务健康与维护状态 配置错误",
            "如果后续检查发现：响应符合设计或复测恢复"
          ],
          "verification_method": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
          "prerequisites": [
            "有效的目标授权；配置变更另需管理权限与原因确认。"
          ],
          "safety_notes": [
            "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
            "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
          ],
          "executed": false
        },
        {
          "method": {
            "kind": "administrator_conditional_change",
            "supported_by_current_tools": false,
            "parameters": [
              {
                "qname": null,
                "qtype": null,
                "resolver": null,
                "role": null,
                "ip": null,
                "port": 443,
                "url": "https://probe.example/",
                "final_url": "https://probe.example/",
                "measured_at": "2026-11-02T00:00:00+00:00",
                "source_mode": "synthetic",
                "original_host": "probe.example",
                "final_host": "probe.example",
                "expected_sni": "probe.example"
              }
            ],
            "description": "仅在分支条件和管理权限成立后人工变更；本程序不执行。"
          },
          "branches": [],
          "id": "D2-HTTP_503-R2",
          "priority": 2,
          "title": "条件成立后的修复",
          "action_type": "POSSIBLE_FIX",
          "description": "仅在确认应用、权限或上游配置问题且有管理权限后修正对应设置；4xx/5xx 不要求修改 DNS。",
          "target": "https://probe.example/",
          "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
          "related_finding_codes": [],
          "evidence_ids": [
            "E2"
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
            "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
            "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
          ],
          "executed": false
        }
      ],
      "verification_steps": [
        {
          "method": {
            "kind": "simulation_review",
            "supported_by_current_tools": false,
            "parameters": [
              {
                "qname": null,
                "qtype": null,
                "resolver": null,
                "role": null,
                "ip": null,
                "port": 443,
                "url": "https://probe.example/",
                "final_url": "https://probe.example/",
                "measured_at": "2026-11-02T00:00:00+00:00",
                "source_mode": "synthetic",
                "original_host": "probe.example",
                "final_host": "probe.example",
                "expected_sni": "probe.example"
              }
            ],
            "description": "人工只读核对或外部复核；不是自动工具调用。"
          },
          "branches": [],
          "id": "D2-HTTP_503-R3",
          "priority": 3,
          "title": "复测并保留新证据",
          "action_type": "VERIFY",
          "description": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
          "target": "https://probe.example/",
          "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 503；不证明 DNS 故障或该响应是否符合端点设计。",
          "related_finding_codes": [],
          "evidence_ids": [
            "E2"
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
            "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
            "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
          ],
          "executed": false
        }
      ],
      "limitations": [
        "范围仅为所列来源、时间及已测组合；协议异常不确认具体运维操作或用户故障的唯一原因。",
        "不得作为当前真实公网故障；真实检查前须重新 live 解析，不能直接探测模拟地址。",
        "其他独立异常的关联未验证；同时发生不证明因果关系。"
      ]
    },
    {
      "status_code": null,
      "error_details": {},
      "location": [
        {
          "qname": null,
          "qtype": null,
          "resolver": null,
          "role": null,
          "ip": "192.0.2.10",
          "port": 443,
          "url": null,
          "final_url": null,
          "measured_at": "2026-11-02T00:00:00+00:00",
          "source_mode": "synthetic"
        }
      ],
      "fault_component": "TCP/Network Transport",
      "failure_stage": "tcp-connect",
      "reason_code": "REFUSED",
      "direct_evidence_ids": [
        "E1"
      ],
      "direct_validation_ids": [],
      "dependency_evidence_ids": [],
      "dependency_validation_ids": [],
      "relevance": "independent_observation",
      "selection_reason": "独立测量保留；缺少足够问题相关性或主次依据，不推断唯一主因。",
      "intent_source": "unknown",
      "diagnosis_status": "FAULT_LOCALIZED",
      "fault_detected": true,
      "primary_issue": "TCP_REFUSED",
      "summary": "[fixture/synthetic 模拟数据] TCP：本次连接被拒绝",
      "fault_layer": "TCP/Network Transport",
      "fault_location": "192.0.2.10 port 443",
      "affected_scope": [
        {
          "evidence_id": "E1",
          "target": "192.0.2.10",
          "port": 443,
          "measured_at": "2026-11-02T00:00:00+00:00",
          "source_mode": "synthetic",
          "result": "REFUSED"
        }
      ],
      "unaffected_or_comparison_scope": [],
      "cause": "本次连接被拒绝（REFUSED）；详情=None。不证明 HTTP 使用相同后端。",
      "cause_status": "OBSERVED_MECHANISM",
      "alternative_causes": [
        "服务监听",
        "主机防火墙",
        "网络访问策略或路径"
      ],
      "reason": "本次连接被拒绝（REFUSED）；详情=None。不证明 HTTP 使用相同后端。",
      "evidence_ids": [
        "E1"
      ],
      "validation_ids": [],
      "finding_codes": [],
      "relevant_attempt_ids": [],
      "source_modes": [
        "synthetic"
      ],
      "remediation_steps": [
        {
          "method": {
            "kind": "simulation_review",
            "supported_by_current_tools": false,
            "parameters": [
              {
                "qname": null,
                "qtype": null,
                "resolver": null,
                "role": null,
                "ip": "192.0.2.10",
                "port": 443,
                "url": null,
                "final_url": null,
                "measured_at": "2026-11-02T00:00:00+00:00",
                "source_mode": "synthetic"
              }
            ],
            "description": "人工只读核对或外部复核；不是自动工具调用。"
          },
          "branches": [
            {
              "condition": "如果后续检查发现：同一 IP/端口仍为 连接拒绝",
              "interpretation": "复测仅确认连接结果，未确认服务未启动",
              "next_action": "对照服务监听、主机/网络访问日志，区分未监听、访问控制和路径。",
              "change_prerequisites": []
            },
            {
              "condition": "如果后续检查发现：确认监听或访问规则存在具体错误",
              "interpretation": "取得可操作的管理配置证据",
              "next_action": "管理员仅修正对应服务/规则，再复测同一端口。",
              "change_prerequisites": [
                "管理权限、配置备份及已确认的具体配置问题；另行操作，不自动执行。"
              ]
            },
            {
              "condition": "如果后续检查发现：复测成功或错误类别变化",
              "interpretation": "路径状态随时间变化，原原因仍未确认",
              "next_action": "保留新错误码和时间；不禁用 IPv6 或关闭整个防火墙。",
              "change_prerequisites": []
            }
          ],
          "id": "D3-TCP_REFUSED-R1",
          "priority": 1,
          "title": "优先核对与定位",
          "action_type": "CHECK",
          "description": "核对所列 IP/端口的服务监听及主机/网络放行规则；区分 REFUSED、TIMEOUT 和 NETWORK_ERROR。",
          "target": "192.0.2.10 port 443",
          "reason": "本次连接被拒绝（REFUSED）；详情=None。不证明 HTTP 使用相同后端。",
          "related_finding_codes": [],
          "evidence_ids": [
            "E1"
          ],
          "validation_ids": [],
          "instructions": [
            "核对所列 IP/端口的服务监听及主机/网络放行规则；区分 REFUSED、TIMEOUT 和 NETWORK_ERROR。"
          ],
          "expected_outcomes": [
            "如果后续检查发现：同一 IP/端口仍为 连接拒绝",
            "如果后续检查发现：确认监听或访问规则存在具体错误",
            "如果后续检查发现：复测成功或错误类别变化"
          ],
          "verification_method": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
          "prerequisites": [
            "有效的目标授权；配置变更另需管理权限与原因确认。"
          ],
          "safety_notes": [
            "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
            "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
          ],
          "executed": false
        },
        {
          "method": {
            "kind": "administrator_conditional_change",
            "supported_by_current_tools": false,
            "parameters": [
              {
                "qname": null,
                "qtype": null,
                "resolver": null,
                "role": null,
                "ip": "192.0.2.10",
                "port": 443,
                "url": null,
                "final_url": null,
                "measured_at": "2026-11-02T00:00:00+00:00",
                "source_mode": "synthetic"
              }
            ],
            "description": "仅在分支条件和管理权限成立后人工变更；本程序不执行。"
          },
          "branches": [],
          "id": "D3-TCP_REFUSED-R2",
          "priority": 2,
          "title": "条件成立后的修复",
          "action_type": "POSSIBLE_FIX",
          "description": "只有确认具体监听或访问规则错误后，由管理员修正对应服务/规则，不关闭全部防火墙或禁用 IPv6。",
          "target": "192.0.2.10 port 443",
          "reason": "本次连接被拒绝（REFUSED）；详情=None。不证明 HTTP 使用相同后端。",
          "related_finding_codes": [],
          "evidence_ids": [
            "E1"
          ],
          "validation_ids": [],
          "instructions": [
            "只有确认具体监听或访问规则错误后，由管理员修正对应服务/规则，不关闭全部防火墙或禁用 IPv6。"
          ],
          "expected_outcomes": [
            "缩小到所列异常环节或明确仍缺失的证据；不预设故障已修复。"
          ],
          "verification_method": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
          "prerequisites": [
            "有效的目标授权；配置变更另需管理权限与原因确认。"
          ],
          "safety_notes": [
            "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
            "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
          ],
          "executed": false
        }
      ],
      "verification_steps": [
        {
          "method": {
            "kind": "simulation_review",
            "supported_by_current_tools": false,
            "parameters": [
              {
                "qname": null,
                "qtype": null,
                "resolver": null,
                "role": null,
                "ip": "192.0.2.10",
                "port": 443,
                "url": null,
                "final_url": null,
                "measured_at": "2026-11-02T00:00:00+00:00",
                "source_mode": "synthetic"
              }
            ],
            "description": "人工只读核对或外部复核；不是自动工具调用。"
          },
          "branches": [],
          "id": "D3-TCP_REFUSED-R3",
          "priority": 3,
          "title": "复测并保留新证据",
          "action_type": "VERIFY",
          "description": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
          "target": "192.0.2.10 port 443",
          "reason": "本次连接被拒绝（REFUSED）；详情=None。不证明 HTTP 使用相同后端。",
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
            "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
            "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
          ],
          "executed": false
        }
      ],
      "limitations": [
        "范围仅为所列来源、时间及已测组合；协议异常不确认具体运维操作或用户故障的唯一原因。",
        "不得作为当前真实公网故障；真实检查前须重新 live 解析，不能直接探测模拟地址。",
        "其他独立异常的关联未验证；同时发生不证明因果关系。"
      ]
    }
  ]
}
```

## http-403

来源：constructed_report_input_not_network_measurement

修改前实际高层诊断：
```json
{
  "diagnosis_status": "FAULT_LOCALIZED",
  "fault_detected": true,
  "primary_issue": "HTTP_403",
  "summary": "[fixture/synthetic 模拟数据] HTTP 返回 403",
  "fault_layer": "HTTP",
  "fault_location": "https://probe.example/",
  "affected_scope": [
    {
      "evidence_id": "E2",
      "target": "https://probe.example/",
      "measured_at": "2026-11-02T00:00:00+00:00",
      "source_mode": "synthetic",
      "result": 403
    }
  ],
  "unaffected_or_comparison_scope": [],
  "cause": "本次 https://probe.example/ 最终 https://probe.example/ 返回 403；不证明 DNS 故障或该响应是否符合端点设计。",
  "cause_status": "OBSERVED_MECHANISM",
  "alternative_causes": [
    "访问权限或请求条件",
    "应用或上游服务行为"
  ],
  "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 403；不证明 DNS 故障或该响应是否符合端点设计。",
  "evidence_ids": [
    "E2"
  ],
  "validation_ids": [],
  "finding_codes": [],
  "relevant_attempt_ids": [],
  "source_modes": [
    "synthetic"
  ],
  "remediation_steps": [
    {
      "id": "D1-HTTP_403-R1",
      "priority": 1,
      "title": "优先核对与定位",
      "action_type": "CHECK",
      "description": "核对所列 URL、最终 URL、状态码、重定向与请求完成状态；结合服务日志和接口设计确认响应含义。",
      "target": "https://probe.example/",
      "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 403；不证明 DNS 故障或该响应是否符合端点设计。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E2"
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
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
        "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
      ],
      "executed": false
    },
    {
      "id": "D1-HTTP_403-R2",
      "priority": 2,
      "title": "条件成立后的修复",
      "action_type": "POSSIBLE_FIX",
      "description": "仅在确认应用、权限或上游配置问题且有管理权限后修正对应设置；4xx/5xx 不要求修改 DNS。",
      "target": "https://probe.example/",
      "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 403；不证明 DNS 故障或该响应是否符合端点设计。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E2"
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
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
        "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
      ],
      "executed": false
    }
  ],
  "verification_steps": [
    {
      "id": "D1-HTTP_403-R3",
      "priority": 3,
      "title": "复测并保留新证据",
      "action_type": "VERIFY",
      "description": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
      "target": "https://probe.example/",
      "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 403；不证明 DNS 故障或该响应是否符合端点设计。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E2"
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
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
        "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
      ],
      "executed": false
    }
  ],
  "limitations": [
    "范围仅为所列来源、时间及已测组合；协议异常不确认具体运维操作或用户故障的唯一原因。",
    "不得作为当前真实公网故障；真实检查前须重新 live 解析，不能直接探测模拟地址。"
  ]
}
```

修改后实际高层诊断与并列观测：
```json
{
  "primary": {
    "status_code": 403,
    "error_details": {},
    "location": [
      {
        "qname": null,
        "qtype": null,
        "resolver": null,
        "role": null,
        "ip": null,
        "port": 443,
        "url": "https://probe.example/",
        "final_url": "https://probe.example/",
        "measured_at": "2026-11-02T00:00:00+00:00",
        "source_mode": "synthetic",
        "original_host": "probe.example",
        "final_host": "probe.example",
        "expected_sni": "probe.example"
      }
    ],
    "fault_component": "HTTP",
    "failure_stage": "http-request",
    "reason_code": "403",
    "direct_evidence_ids": [
      "E2"
    ],
    "direct_validation_ids": [],
    "dependency_evidence_ids": [],
    "dependency_validation_ids": [],
    "relevance": "independent_observation",
    "selection_reason": "独立测量保留；缺少足够问题相关性或主次依据，不推断唯一主因。",
    "intent_source": "unknown",
    "diagnosis_status": "FAULT_LOCALIZED",
    "fault_detected": true,
    "primary_issue": "HTTP_403",
    "summary": "[fixture/synthetic 模拟数据] HTTP 返回 403",
    "fault_layer": "HTTP",
    "fault_location": "https://probe.example/",
    "affected_scope": [
      {
        "evidence_id": "E2",
        "target": "https://probe.example/",
        "measured_at": "2026-11-02T00:00:00+00:00",
        "source_mode": "synthetic",
        "result": 403
      }
    ],
    "unaffected_or_comparison_scope": [],
    "cause": "本次 https://probe.example/ 最终 https://probe.example/ 返回 403；不证明 DNS 故障或该响应是否符合端点设计。",
    "cause_status": "OBSERVED_MECHANISM",
    "alternative_causes": [
      "访问权限或请求条件",
      "应用或上游服务行为"
    ],
    "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 403；不证明 DNS 故障或该响应是否符合端点设计。",
    "evidence_ids": [
      "E2"
    ],
    "validation_ids": [],
    "finding_codes": [],
    "relevant_attempt_ids": [],
    "source_modes": [
      "synthetic"
    ],
    "remediation_steps": [
      {
        "method": {
          "kind": "simulation_review",
          "supported_by_current_tools": false,
          "parameters": [
            {
              "qname": null,
              "qtype": null,
              "resolver": null,
              "role": null,
              "ip": null,
              "port": 443,
              "url": "https://probe.example/",
              "final_url": "https://probe.example/",
              "measured_at": "2026-11-02T00:00:00+00:00",
              "source_mode": "synthetic",
              "original_host": "probe.example",
              "final_host": "probe.example",
              "expected_sni": "probe.example"
            }
          ],
          "description": "人工只读核对或外部复核；不是自动工具调用。"
        },
        "branches": [
          {
            "condition": "如果后续检查发现：同一请求仍返回 403",
            "interpretation": "状态码是现象，不能证明具体原因",
            "next_action": "只读核对 授权/访问策略 及端点设计；最多一次已授权对照重试，未采集 Retry-After 不编造等待值。",
            "change_prerequisites": []
          },
          {
            "condition": "如果后续检查发现：管理员确认具体 授权/访问策略 配置错误",
            "interpretation": "有条件的配置修复依据成立",
            "next_action": "仅修正对应设置，不因 HTTP 错误修改 DNS。",
            "change_prerequisites": [
              "管理权限、配置备份及已确认的具体配置问题；另行操作，不自动执行。"
            ]
          },
          {
            "condition": "如果后续检查发现：响应符合设计或复测恢复",
            "interpretation": "该响应不一定是故障或可能间歇性",
            "next_action": "保留请求条件和时间，再核对用户现场错误。",
            "change_prerequisites": []
          }
        ],
        "id": "D1-HTTP_403-R1",
        "priority": 1,
        "title": "优先核对与定位",
        "action_type": "CHECK",
        "description": "核对所列 URL、最终 URL、状态码、重定向与请求完成状态；结合服务日志和接口设计确认响应含义。",
        "target": "https://probe.example/",
        "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 403；不证明 DNS 故障或该响应是否符合端点设计。",
        "related_finding_codes": [],
        "evidence_ids": [
          "E2"
        ],
        "validation_ids": [],
        "instructions": [
          "核对所列 URL、最终 URL、状态码、重定向与请求完成状态；结合服务日志和接口设计确认响应含义。"
        ],
        "expected_outcomes": [
          "如果后续检查发现：同一请求仍返回 403",
          "如果后续检查发现：管理员确认具体 授权/访问策略 配置错误",
          "如果后续检查发现：响应符合设计或复测恢复"
        ],
        "verification_method": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
        "prerequisites": [
          "有效的目标授权；配置变更另需管理权限与原因确认。"
        ],
        "safety_notes": [
          "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
          "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
        ],
        "executed": false
      },
      {
        "method": {
          "kind": "administrator_conditional_change",
          "supported_by_current_tools": false,
          "parameters": [
            {
              "qname": null,
              "qtype": null,
              "resolver": null,
              "role": null,
              "ip": null,
              "port": 443,
              "url": "https://probe.example/",
              "final_url": "https://probe.example/",
              "measured_at": "2026-11-02T00:00:00+00:00",
              "source_mode": "synthetic",
              "original_host": "probe.example",
              "final_host": "probe.example",
              "expected_sni": "probe.example"
            }
          ],
          "description": "仅在分支条件和管理权限成立后人工变更；本程序不执行。"
        },
        "branches": [],
        "id": "D1-HTTP_403-R2",
        "priority": 2,
        "title": "条件成立后的修复",
        "action_type": "POSSIBLE_FIX",
        "description": "仅在确认应用、权限或上游配置问题且有管理权限后修正对应设置；4xx/5xx 不要求修改 DNS。",
        "target": "https://probe.example/",
        "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 403；不证明 DNS 故障或该响应是否符合端点设计。",
        "related_finding_codes": [],
        "evidence_ids": [
          "E2"
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
          "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
          "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
        ],
        "executed": false
      }
    ],
    "verification_steps": [
      {
        "method": {
          "kind": "simulation_review",
          "supported_by_current_tools": false,
          "parameters": [
            {
              "qname": null,
              "qtype": null,
              "resolver": null,
              "role": null,
              "ip": null,
              "port": 443,
              "url": "https://probe.example/",
              "final_url": "https://probe.example/",
              "measured_at": "2026-11-02T00:00:00+00:00",
              "source_mode": "synthetic",
              "original_host": "probe.example",
              "final_host": "probe.example",
              "expected_sni": "probe.example"
            }
          ],
          "description": "人工只读核对或外部复核；不是自动工具调用。"
        },
        "branches": [],
        "id": "D1-HTTP_403-R3",
        "priority": 3,
        "title": "复测并保留新证据",
        "action_type": "VERIFY",
        "description": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
        "target": "https://probe.example/",
        "reason": "本次 https://probe.example/ 最终 https://probe.example/ 返回 403；不证明 DNS 故障或该响应是否符合端点设计。",
        "related_finding_codes": [],
        "evidence_ids": [
          "E2"
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
          "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
          "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
        ],
        "executed": false
      }
    ],
    "limitations": [
      "范围仅为所列来源、时间及已测组合；协议异常不确认具体运维操作或用户故障的唯一原因。",
      "不得作为当前真实公网故障；真实检查前须重新 live 解析，不能直接探测模拟地址。"
    ]
  },
  "secondary": []
}
```

## tls-None

来源：constructed_report_input_not_network_measurement

修改前实际高层诊断：
```json
{
  "diagnosis_status": "FAULT_LOCALIZED",
  "fault_detected": true,
  "primary_issue": "TLS_CERTIFICATE_VERIFY_FAILED",
  "summary": "[fixture/synthetic 模拟数据] TLS 证书验证失败",
  "fault_layer": "TLS",
  "fault_location": "https://probe.example/",
  "affected_scope": [
    {
      "evidence_id": "E2",
      "target": "https://probe.example/",
      "measured_at": "2026-11-02T00:00:00+00:00",
      "source_mode": "synthetic",
      "result": "TLS_ERROR"
    }
  ],
  "unaffected_or_comparison_scope": [],
  "cause": "该连接的证书校验明确失败；错误详情={'code': 'CERTIFICATE_VERIFY_FAILED', 'certificate': {'verify_code': None}}。",
  "cause_status": "OBSERVED_MECHANISM",
  "alternative_causes": [
    "证书有效期、名称或信任链问题需按实际错误核对"
  ],
  "reason": "该连接的证书校验明确失败；错误详情={'code': 'CERTIFICATE_VERIFY_FAILED', 'certificate': {'verify_code': None}}。",
  "evidence_ids": [
    "E2"
  ],
  "validation_ids": [],
  "finding_codes": [],
  "relevant_attempt_ids": [],
  "source_modes": [
    "synthetic"
  ],
  "remediation_steps": [
    {
      "id": "D1-TLS_CERTIFICATE_VERIFY_FAILED-R1",
      "priority": 1,
      "title": "优先核对与定位",
      "action_type": "CHECK",
      "description": "核对实际证书错误码、证书有效期、目标名称、证书链与系统时间，保留原域名的 Host/SNI 和证书校验。",
      "target": "https://probe.example/",
      "reason": "该连接的证书校验明确失败；错误详情={'code': 'CERTIFICATE_VERIFY_FAILED', 'certificate': {'verify_code': None}}。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E2"
      ],
      "validation_ids": [],
      "instructions": [
        "核对实际证书错误码、证书有效期、目标名称、证书链与系统时间，保留原域名的 Host/SNI 和证书校验。"
      ],
      "expected_outcomes": [
        "缩小到所列异常环节或明确仍缺失的证据；不预设故障已修复。"
      ],
      "verification_method": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
      "prerequisites": [
        "有效的目标授权；配置变更另需管理权限与原因确认。"
      ],
      "safety_notes": [
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
        "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
      ],
      "executed": false
    },
    {
      "id": "D1-TLS_CERTIFICATE_VERIFY_FAILED-R2",
      "priority": 2,
      "title": "条件成立后的修复",
      "action_type": "POSSIBLE_FIX",
      "description": "仅在证实证书或信任链配置问题后更新对应证书/链；不得关闭证书验证或用 IP 替换 HTTPS 域名。",
      "target": "https://probe.example/",
      "reason": "该连接的证书校验明确失败；错误详情={'code': 'CERTIFICATE_VERIFY_FAILED', 'certificate': {'verify_code': None}}。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E2"
      ],
      "validation_ids": [],
      "instructions": [
        "仅在证实证书或信任链配置问题后更新对应证书/链；不得关闭证书验证或用 IP 替换 HTTPS 域名。"
      ],
      "expected_outcomes": [
        "缩小到所列异常环节或明确仍缺失的证据；不预设故障已修复。"
      ],
      "verification_method": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
      "prerequisites": [
        "有效的目标授权；配置变更另需管理权限与原因确认。"
      ],
      "safety_notes": [
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
        "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
      ],
      "executed": false
    }
  ],
  "verification_steps": [
    {
      "id": "D1-TLS_CERTIFICATE_VERIFY_FAILED-R3",
      "priority": 3,
      "title": "复测并保留新证据",
      "action_type": "VERIFY",
      "description": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
      "target": "https://probe.example/",
      "reason": "该连接的证书校验明确失败；错误详情={'code': 'CERTIFICATE_VERIFY_FAILED', 'certificate': {'verify_code': None}}。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E2"
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
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
        "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
      ],
      "executed": false
    }
  ],
  "limitations": [
    "范围仅为所列来源、时间及已测组合；协议异常不确认具体运维操作或用户故障的唯一原因。",
    "不得作为当前真实公网故障；真实检查前须重新 live 解析，不能直接探测模拟地址。"
  ]
}
```

修改后实际高层诊断与并列观测：
```json
{
  "primary": {
    "status_code": null,
    "error_details": {
      "code": "CERTIFICATE_VERIFY_FAILED",
      "certificate": {
        "verify_code": null
      }
    },
    "location": [
      {
        "qname": null,
        "qtype": null,
        "resolver": null,
        "role": null,
        "ip": null,
        "port": 443,
        "url": "https://probe.example/",
        "final_url": "https://probe.example/",
        "measured_at": "2026-11-02T00:00:00+00:00",
        "source_mode": "synthetic",
        "original_host": "probe.example",
        "final_host": "probe.example",
        "expected_sni": "probe.example"
      }
    ],
    "fault_component": "TLS",
    "failure_stage": "tls-validation",
    "reason_code": "CERTIFICATE_VERIFY_FAILED",
    "direct_evidence_ids": [
      "E2"
    ],
    "direct_validation_ids": [],
    "dependency_evidence_ids": [],
    "dependency_validation_ids": [],
    "relevance": "independent_observation",
    "selection_reason": "独立测量保留；缺少足够问题相关性或主次依据，不推断唯一主因。",
    "intent_source": "unknown",
    "diagnosis_status": "FAULT_LOCALIZED",
    "fault_detected": true,
    "primary_issue": "TLS_CERTIFICATE_VERIFY_FAILED",
    "summary": "[fixture/synthetic 模拟数据] TLS 证书验证失败",
    "fault_layer": "TLS",
    "fault_location": "https://probe.example/",
    "affected_scope": [
      {
        "evidence_id": "E2",
        "target": "https://probe.example/",
        "measured_at": "2026-11-02T00:00:00+00:00",
        "source_mode": "synthetic",
        "result": "TLS_ERROR"
      }
    ],
    "unaffected_or_comparison_scope": [],
    "cause": "该连接的证书校验明确失败；错误详情={'code': 'CERTIFICATE_VERIFY_FAILED', 'certificate': {'verify_code': None}}。",
    "cause_status": "OBSERVED_MECHANISM",
    "alternative_causes": [
      "证书有效期、名称或信任链问题需按实际错误核对"
    ],
    "reason": "该连接的证书校验明确失败；错误详情={'code': 'CERTIFICATE_VERIFY_FAILED', 'certificate': {'verify_code': None}}。",
    "evidence_ids": [
      "E2"
    ],
    "validation_ids": [],
    "finding_codes": [],
    "relevant_attempt_ids": [],
    "source_modes": [
      "synthetic"
    ],
    "remediation_steps": [
      {
        "method": {
          "kind": "simulation_review",
          "supported_by_current_tools": false,
          "parameters": [
            {
              "qname": null,
              "qtype": null,
              "resolver": null,
              "role": null,
              "ip": null,
              "port": 443,
              "url": "https://probe.example/",
              "final_url": "https://probe.example/",
              "measured_at": "2026-11-02T00:00:00+00:00",
              "source_mode": "synthetic",
              "original_host": "probe.example",
              "final_host": "probe.example",
              "expected_sni": "probe.example"
            }
          ],
          "description": "人工只读核对或外部复核；不是自动工具调用。"
        },
        "branches": [
          {
            "condition": "如果后续检查发现：只读核对后确认 实际错误类别、证书链、名称与时钟；未知不等于过期 存在问题",
            "interpretation": "错误码提供方向，不自动确定运维根因",
            "next_action": "有权限者修正已确认的证书/链/时间配置，保留 Host/SNI 和证书验证。",
            "change_prerequisites": [
              "管理权限、配置备份及已确认的具体配置问题；另行操作，不自动执行。"
            ]
          },
          {
            "condition": "如果后续检查发现：证书材料正常或只有一般连接错误",
            "interpretation": "尚未定位证书根因",
            "next_action": "核对相同域名与路径的 TLS 日志，不依据域名猜测过期，不用 IP 替换 URL。",
            "change_prerequisites": []
          }
        ],
        "id": "D1-TLS_CERTIFICATE_VERIFY_FAILED-R1",
        "priority": 1,
        "title": "优先核对与定位",
        "action_type": "CHECK",
        "description": "核对实际证书错误码、证书有效期、目标名称、证书链与系统时间，保留原域名的 Host/SNI 和证书校验。",
        "target": "https://probe.example/",
        "reason": "该连接的证书校验明确失败；错误详情={'code': 'CERTIFICATE_VERIFY_FAILED', 'certificate': {'verify_code': None}}。",
        "related_finding_codes": [],
        "evidence_ids": [
          "E2"
        ],
        "validation_ids": [],
        "instructions": [
          "核对实际证书错误码、证书有效期、目标名称、证书链与系统时间，保留原域名的 Host/SNI 和证书校验。"
        ],
        "expected_outcomes": [
          "如果后续检查发现：只读核对后确认 实际错误类别、证书链、名称与时钟；未知不等于过期 存在问题",
          "如果后续检查发现：证书材料正常或只有一般连接错误"
        ],
        "verification_method": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
        "prerequisites": [
          "有效的目标授权；配置变更另需管理权限与原因确认。"
        ],
        "safety_notes": [
          "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
          "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
        ],
        "executed": false
      },
      {
        "method": {
          "kind": "administrator_conditional_change",
          "supported_by_current_tools": false,
          "parameters": [
            {
              "qname": null,
              "qtype": null,
              "resolver": null,
              "role": null,
              "ip": null,
              "port": 443,
              "url": "https://probe.example/",
              "final_url": "https://probe.example/",
              "measured_at": "2026-11-02T00:00:00+00:00",
              "source_mode": "synthetic",
              "original_host": "probe.example",
              "final_host": "probe.example",
              "expected_sni": "probe.example"
            }
          ],
          "description": "仅在分支条件和管理权限成立后人工变更；本程序不执行。"
        },
        "branches": [],
        "id": "D1-TLS_CERTIFICATE_VERIFY_FAILED-R2",
        "priority": 2,
        "title": "条件成立后的修复",
        "action_type": "POSSIBLE_FIX",
        "description": "仅在证实证书或信任链配置问题后更新对应证书/链；不得关闭证书验证或用 IP 替换 HTTPS 域名。",
        "target": "https://probe.example/",
        "reason": "该连接的证书校验明确失败；错误详情={'code': 'CERTIFICATE_VERIFY_FAILED', 'certificate': {'verify_code': None}}。",
        "related_finding_codes": [],
        "evidence_ids": [
          "E2"
        ],
        "validation_ids": [],
        "instructions": [
          "仅在证实证书或信任链配置问题后更新对应证书/链；不得关闭证书验证或用 IP 替换 HTTPS 域名。"
        ],
        "expected_outcomes": [
          "缩小到所列异常环节或明确仍缺失的证据；不预设故障已修复。"
        ],
        "verification_method": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
        "prerequisites": [
          "有效的目标授权；配置变更另需管理权限与原因确认。"
        ],
        "safety_notes": [
          "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
          "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
        ],
        "executed": false
      }
    ],
    "verification_steps": [
      {
        "method": {
          "kind": "simulation_review",
          "supported_by_current_tools": false,
          "parameters": [
            {
              "qname": null,
              "qtype": null,
              "resolver": null,
              "role": null,
              "ip": null,
              "port": 443,
              "url": "https://probe.example/",
              "final_url": "https://probe.example/",
              "measured_at": "2026-11-02T00:00:00+00:00",
              "source_mode": "synthetic",
              "original_host": "probe.example",
              "final_host": "probe.example",
              "expected_sni": "probe.example"
            }
          ],
          "description": "人工只读核对或外部复核；不是自动工具调用。"
        },
        "branches": [],
        "id": "D1-TLS_CERTIFICATE_VERIFY_FAILED-R3",
        "priority": 3,
        "title": "复测并保留新证据",
        "action_type": "VERIFY",
        "description": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
        "target": "https://probe.example/",
        "reason": "该连接的证书校验明确失败；错误详情={'code': 'CERTIFICATE_VERIFY_FAILED', 'certificate': {'verify_code': None}}。",
        "related_finding_codes": [],
        "evidence_ids": [
          "E2"
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
          "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
          "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
        ],
        "executed": false
      }
    ],
    "limitations": [
      "范围仅为所列来源、时间及已测组合；协议异常不确认具体运维操作或用户故障的唯一原因。",
      "不得作为当前真实公网故障；真实检查前须重新 live 解析，不能直接探测模拟地址。"
    ]
  },
  "secondary": []
}
```

## body-timeout

来源：constructed_report_input_not_network_measurement

修改前实际高层诊断：
```json
{
  "diagnosis_status": "FAULT_LOCALIZED",
  "fault_detected": true,
  "primary_issue": "HTTP_REQUEST_TIMEOUT",
  "summary": "[fixture/synthetic 模拟数据] HTTP 请求未完成",
  "fault_layer": "HTTP",
  "fault_location": "https://probe.example/",
  "affected_scope": [
    {
      "evidence_id": "E2",
      "target": "https://probe.example/",
      "measured_at": "2026-11-02T00:00:00+00:00",
      "source_mode": "synthetic",
      "result": 200
    }
  ],
  "unaffected_or_comparison_scope": [],
  "cause": "状态码=200；请求错误=TIMEOUT；正文状态=read_error；错误详情={}。不能由已收响应头断言完整成功。",
  "cause_status": "OBSERVED_MECHANISM",
  "alternative_causes": [],
  "reason": "状态码=200；请求错误=TIMEOUT；正文状态=read_error；错误详情={}。不能由已收响应头断言完整成功。",
  "evidence_ids": [
    "E2"
  ],
  "validation_ids": [],
  "finding_codes": [],
  "relevant_attempt_ids": [],
  "source_modes": [
    "synthetic"
  ],
  "remediation_steps": [
    {
      "id": "D1-HTTP_REQUEST_TIMEOUT-R1",
      "priority": 1,
      "title": "优先核对与定位",
      "action_type": "CHECK",
      "description": "核对所列 URL、最终 URL、状态码、重定向与请求完成状态；结合服务日志和接口设计确认响应含义。",
      "target": "https://probe.example/",
      "reason": "状态码=200；请求错误=TIMEOUT；正文状态=read_error；错误详情={}。不能由已收响应头断言完整成功。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E2"
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
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
        "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
      ],
      "executed": false
    },
    {
      "id": "D1-HTTP_REQUEST_TIMEOUT-R2",
      "priority": 2,
      "title": "条件成立后的修复",
      "action_type": "POSSIBLE_FIX",
      "description": "仅在确认应用、权限或上游配置问题且有管理权限后修正对应设置；4xx/5xx 不要求修改 DNS。",
      "target": "https://probe.example/",
      "reason": "状态码=200；请求错误=TIMEOUT；正文状态=read_error；错误详情={}。不能由已收响应头断言完整成功。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E2"
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
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
        "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
      ],
      "executed": false
    }
  ],
  "verification_steps": [
    {
      "id": "D1-HTTP_REQUEST_TIMEOUT-R3",
      "priority": 3,
      "title": "复测并保留新证据",
      "action_type": "VERIFY",
      "description": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
      "target": "https://probe.example/",
      "reason": "状态码=200；请求错误=TIMEOUT；正文状态=read_error；错误详情={}。不能由已收响应头断言完整成功。",
      "related_finding_codes": [],
      "evidence_ids": [
        "E2"
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
        "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
        "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
      ],
      "executed": false
    }
  ],
  "limitations": [
    "范围仅为所列来源、时间及已测组合；协议异常不确认具体运维操作或用户故障的唯一原因。",
    "不得作为当前真实公网故障；真实检查前须重新 live 解析，不能直接探测模拟地址。"
  ]
}
```

修改后实际高层诊断与并列观测：
```json
{
  "primary": {
    "status_code": 200,
    "error_details": {},
    "location": [
      {
        "qname": null,
        "qtype": null,
        "resolver": null,
        "role": null,
        "ip": null,
        "port": 443,
        "url": "https://probe.example/",
        "final_url": "https://probe.example/",
        "measured_at": "2026-11-02T00:00:00+00:00",
        "source_mode": "synthetic",
        "original_host": "probe.example",
        "final_host": "probe.example",
        "expected_sni": "probe.example"
      }
    ],
    "fault_component": "HTTP",
    "failure_stage": "http-request",
    "reason_code": "TIMEOUT",
    "direct_evidence_ids": [
      "E2"
    ],
    "direct_validation_ids": [],
    "dependency_evidence_ids": [],
    "dependency_validation_ids": [],
    "relevance": "independent_observation",
    "selection_reason": "独立测量保留；缺少足够问题相关性或主次依据，不推断唯一主因。",
    "intent_source": "unknown",
    "diagnosis_status": "FAULT_LOCALIZED",
    "fault_detected": true,
    "primary_issue": "HTTP_REQUEST_TIMEOUT",
    "summary": "[fixture/synthetic 模拟数据] HTTP 请求未完成",
    "fault_layer": "HTTP",
    "fault_location": "https://probe.example/",
    "affected_scope": [
      {
        "evidence_id": "E2",
        "target": "https://probe.example/",
        "measured_at": "2026-11-02T00:00:00+00:00",
        "source_mode": "synthetic",
        "result": 200
      }
    ],
    "unaffected_or_comparison_scope": [],
    "cause": "状态码=200；请求错误=TIMEOUT；正文状态=read_error；错误详情={}。不能由已收响应头断言完整成功。",
    "cause_status": "OBSERVED_MECHANISM",
    "alternative_causes": [],
    "reason": "状态码=200；请求错误=TIMEOUT；正文状态=read_error；错误详情={}。不能由已收响应头断言完整成功。",
    "evidence_ids": [
      "E2"
    ],
    "validation_ids": [],
    "finding_codes": [],
    "relevant_attempt_ids": [],
    "source_modes": [
      "synthetic"
    ],
    "remediation_steps": [
      {
        "method": {
          "kind": "simulation_review",
          "supported_by_current_tools": false,
          "parameters": [
            {
              "qname": null,
              "qtype": null,
              "resolver": null,
              "role": null,
              "ip": null,
              "port": 443,
              "url": "https://probe.example/",
              "final_url": "https://probe.example/",
              "measured_at": "2026-11-02T00:00:00+00:00",
              "source_mode": "synthetic",
              "original_host": "probe.example",
              "final_host": "probe.example",
              "expected_sni": "probe.example"
            }
          ],
          "description": "人工只读核对或外部复核；不是自动工具调用。"
        },
        "branches": [
          {
            "condition": "如果后续检查发现：收到状态码但正文读取仍未完成",
            "interpretation": "响应头存在不等于完整请求成功",
            "next_action": "核对正文/上游日志和传输中断；最多一次已授权对照重试。",
            "change_prerequisites": []
          },
          {
            "condition": "如果后续检查发现：完整完成或错误变化",
            "interpretation": "原异常未持续复现",
            "next_action": "记录状态码、最终 URL、正文状态与时间；不据此认定用户现场已修复。",
            "change_prerequisites": []
          }
        ],
        "id": "D1-HTTP_REQUEST_TIMEOUT-R1",
        "priority": 1,
        "title": "优先核对与定位",
        "action_type": "CHECK",
        "description": "核对所列 URL、最终 URL、状态码、重定向与请求完成状态；结合服务日志和接口设计确认响应含义。",
        "target": "https://probe.example/",
        "reason": "状态码=200；请求错误=TIMEOUT；正文状态=read_error；错误详情={}。不能由已收响应头断言完整成功。",
        "related_finding_codes": [],
        "evidence_ids": [
          "E2"
        ],
        "validation_ids": [],
        "instructions": [
          "核对所列 URL、最终 URL、状态码、重定向与请求完成状态；结合服务日志和接口设计确认响应含义。"
        ],
        "expected_outcomes": [
          "如果后续检查发现：收到状态码但正文读取仍未完成",
          "如果后续检查发现：完整完成或错误变化"
        ],
        "verification_method": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
        "prerequisites": [
          "有效的目标授权；配置变更另需管理权限与原因确认。"
        ],
        "safety_notes": [
          "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
          "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
        ],
        "executed": false
      },
      {
        "method": {
          "kind": "administrator_conditional_change",
          "supported_by_current_tools": false,
          "parameters": [
            {
              "qname": null,
              "qtype": null,
              "resolver": null,
              "role": null,
              "ip": null,
              "port": 443,
              "url": "https://probe.example/",
              "final_url": "https://probe.example/",
              "measured_at": "2026-11-02T00:00:00+00:00",
              "source_mode": "synthetic",
              "original_host": "probe.example",
              "final_host": "probe.example",
              "expected_sni": "probe.example"
            }
          ],
          "description": "仅在分支条件和管理权限成立后人工变更；本程序不执行。"
        },
        "branches": [],
        "id": "D1-HTTP_REQUEST_TIMEOUT-R2",
        "priority": 2,
        "title": "条件成立后的修复",
        "action_type": "POSSIBLE_FIX",
        "description": "仅在确认应用、权限或上游配置问题且有管理权限后修正对应设置；4xx/5xx 不要求修改 DNS。",
        "target": "https://probe.example/",
        "reason": "状态码=200；请求错误=TIMEOUT；正文状态=read_error；错误详情={}。不能由已收响应头断言完整成功。",
        "related_finding_codes": [],
        "evidence_ids": [
          "E2"
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
          "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
          "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
        ],
        "executed": false
      }
    ],
    "verification_steps": [
      {
        "method": {
          "kind": "simulation_review",
          "supported_by_current_tools": false,
          "parameters": [
            {
              "qname": null,
              "qtype": null,
              "resolver": null,
              "role": null,
              "ip": null,
              "port": 443,
              "url": "https://probe.example/",
              "final_url": "https://probe.example/",
              "measured_at": "2026-11-02T00:00:00+00:00",
              "source_mode": "synthetic",
              "original_host": "probe.example",
              "final_host": "probe.example",
              "expected_sni": "probe.example"
            }
          ],
          "description": "人工只读核对或外部复核；不是自动工具调用。"
        },
        "branches": [],
        "id": "D1-HTTP_REQUEST_TIMEOUT-R3",
        "priority": 3,
        "title": "复测并保留新证据",
        "action_type": "VERIFY",
        "description": "以相同目标和端口/URL重新检查，记录时间、状态与请求完整性；成功仅代表复测路径，不等于用户现场已修复。",
        "target": "https://probe.example/",
        "reason": "状态码=200；请求错误=TIMEOUT；正文状态=read_error；错误详情={}。不能由已收响应头断言完整成功。",
        "related_finding_codes": [],
        "evidence_ids": [
          "E2"
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
          "尚未执行；仅限已授权目标，不自动修改配置或扩大网络访问范围。",
          "fixture/synthetic 仅用于模拟复核；真实检查前重新 live 解析，不直接探测模拟地址。"
        ],
        "executed": false
      }
    ],
    "limitations": [
      "范围仅为所列来源、时间及已测组合；协议异常不确认具体运维操作或用户故障的唯一原因。",
      "不得作为当前真实公网故障；真实检查前须重新 live 解析，不能直接探测模拟地址。"
    ]
  },
  "secondary": []
}
```
