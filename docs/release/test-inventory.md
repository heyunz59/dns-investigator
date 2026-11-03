# Test inventory

All existing test functions retained. Parameter expansion produced 604 baseline cases; fixture migration changes input paths, not expectations. Tests use synthetic facts, scripted models or controlled loopback services, not paid/public services. IPv6 may skip only when the host cannot bind loopback; actual results record skips.

|Module|Test functions|Purpose / controlled scope|
|---|---:|---|
| test_accounting_v2.py | 4 | Controlled behavior regression; domain indicated by module name. |
| test_agent.py | 2 | Controlled behavior regression; domain indicated by module name. |
| test_agent_draft.py | 7 | Controlled behavior regression; domain indicated by module name. |
| test_alias_scope.py | 9 | Bounded, source-isolated CNAME authorization without extra Agent tools. |
| test_authority_states.py | 3 | Controlled behavior regression; domain indicated by module name. |
| test_authority_v3.py | 4 | Controlled behavior regression; domain indicated by module name. |
| test_cli.py | 2 | Controlled behavior regression; domain indicated by module name. |
| test_controlled_accuracy.py | 1 | Real DNS datagrams to local controlled services, not fixture or public tests. |
| test_dns_accuracy.py | 14 | Acceptance counterexamples: expectations stay outside Agent input. |
| test_dns_time.py | 4 | Controlled behavior regression; domain indicated by module name. |
| test_dns_v3.py | 11 | Controlled behavior regression; domain indicated by module name. |
| test_dnssec_boundaries.py | 9 | Adversarial material, process lifetime and authenticated-import regressions. |
| test_dnssec_proof_edges.py | 2 | Authenticated but malformed denial content must not establish absence. |
| test_fcd_acceptance.py | 7 | Acceptance regressions across tools, ledger, findings and visible report. |
| test_final_agent_context.py | 7 | Controlled behavior regression; domain indicated by module name. |
| test_final_verification.py | 10 | Independent behavior checks against final-verification requirements. |
| test_http_security.py | 10 | Controlled behavior regression; domain indicated by module name. |
| test_manual_review_fixes.py | 10 | Controlled behavior regression; domain indicated by module name. |
| test_nsec3_audit.py | 2 | Controlled behavior regression; domain indicated by module name. |
| test_nsec3_followup.py | 2 | Controlled behavior regression; domain indicated by module name. |
| test_path_groups.py | 14 | Historical real-log replay and constructed counterexamples; never new public probes. |
| test_protocol_dnssec.py | 2 | Controlled behavior regression; domain indicated by module name. |
| test_protocol_edns.py | 6 | Controlled behavior regression; domain indicated by module name. |
| test_protocol_reporting.py | 2 | Controlled behavior regression; domain indicated by module name. |
| test_protocol_trace.py | 4 | Controlled behavior regression; domain indicated by module name. |
| test_reliability.py | 6 | Controlled behavior regression; domain indicated by module name. |
| test_reliability_v2.py | 12 | Scripted models test orchestration only; these are not DeepSeek acceptance runs. |
| test_report_acceptance.py | 10 | Report-level counterexamples; no public-network or paid-model assumptions. |
| test_report_quality.py | 23 | Report replay / constructed inputs / scripted model tests, not public-network acceptance. |
| test_review_rules.py | 2 | Controlled behavior regression; domain indicated by module name. |
| test_tcp_policy.py | 8 | Controlled behavior regression; domain indicated by module name. |
| test_tools.py | 9 | Controlled behavior regression; domain indicated by module name. |
| test_v05_closure.py | 8 | Finalization tests: constructed provenance, unchanged admission, CLI allocation. |
| test_v05_reasoning.py | 13 | Outcome/scope/causal-level tests, not natural-language accuracy scoring. |
| test_v05_schema.py | 2 | Controlled behavior regression; domain indicated by module name. |
| test_v06_final_review.py | 6 | Mixed report and offline replay regression; no fresh public/model tests. |
| test_v3_targeted_fixes.py | 10 | Deterministic reproductions: no public network or model needed. |
| test_web.py | 7 | Web presentation contract and loopback boundary tests; no public probes. |
| test_web_product.py | 13 | Product presentation, cancellation, offline export and ownership boundaries. |

Legacy result compatibility preserves all 48 + 4 previously validated objects. Complete original result fields remain in aggregated fixtures; no-result files previously skipped by loops are archived. Source-string guards remain where relevant to frozen configuration constraints; behavior tests remain the principal evidence. No test modules were merged or removed to reduce counts.
