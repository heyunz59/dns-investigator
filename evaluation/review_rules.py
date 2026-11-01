"""Reproducible mechanical screening; not a human or complete semantic assessment."""
import re
from dns_investigator.accounting import statistics, call_reviews


def screen(log, case):
    result = log.get("result", {})
    text = result.get("conclusion", "") + "\n" + "\n".join(result.get("limitations", []))
    measured = log.get("evidence", [])
    stats = statistics(log, case)
    calls = call_reviews(log, case)
    model_result = log.get("result_origin") in {"model","model_with_evidence_bound_report"} and log.get("execution_status") == "ended"
    enough = not stats["missing_required_measurements"]
    checks = {"model_returned_validated_output": model_result,
              "required_measurements_present": enough}
    if case["id"] == "C1":
        checks["acknowledges_not_reproduced"] = bool(re.search(r"未.{0,5}复现|无法复现|不能复现", text))
    elif case["id"] == "C2":
        checks["mentions_nxdomain"] = "NXDOMAIN" in text
        checks["no_tcp_attempt"] = not any(a["tool_name"] == "check_tcp" for a in log.get("attempts", []))
    elif case["id"] == "C3":
        checks["mentions_resolver_comparison"] = "1.1.1.1" in text and ("超时" in text or "TIMEOUT" in text)
    elif case["id"] in {"C4", "C6c"}:
        checks["mentions_timeout_and_uncertainty"] = ("超时" in text or "TIMEOUT" in text) and bool(re.search(r"不能|无法|未知|待验证|不确定|未确认", text))
    elif case["id"] == "C5":
        checks["mentions_http503"] = "503" in text
    elif case["id"] == "Q1":
        checks["returns_address_ttl"] = "192.0.2.10" in text and "60" in text
        checks["only_a_query"] = all(a["tool_name"] == "query_dns" and a["input"].get("record_type", "A") == "A" for a in log.get("attempts", []))
    elif case["id"] == "MISSING":
        checks["acknowledges_missing_fact"] = bool(re.search(r"未提供|没有提供|缺少|未知|未覆盖|信息不足|缺失", text))
        checks["no_nonretryable_duplicates"] = not any((a.get("error") or {}).get("code") == "NON_RETRYABLE_DUPLICATE" for a in log.get("attempts", []))
        if log.get("mode") != "baseline":
            checks["requested_missing_aaaa"] = any(a["tool_name"] == "query_dns" and a["input"].get("record_type") == "AAAA" and
                (a.get("error") or {}).get("code") == "FIXTURE_NOT_COVERED" for a in log.get("attempts", []))
    return dict(success=int(all(checks.values())), correct_calls=sum(c["suggested_correct"] for c in calls),
                hypothesis_count_observed=len(result.get("hypotheses",[])),scoring_policy="scoped_v2_no_count_gate",
                checks=checks, note="仅结构/执行/关键词规则筛查，不验证全部语义；待独立人工复核")
