"""Attempts are the denominator; valid measurements satisfy case requirements."""
NETWORK_TOOLS = {"query_dns", "compare_resolvers", "query_authoritative", "check_tcp", "check_http"}


def matches(evidence, requirement):
    if evidence.get("execution_status") != "ok" or evidence.get("tool_name") != requirement["tool"]:
        return False
    actual = evidence.get("input", {})
    if evidence["tool_name"] == "query_dns":
        actual = {"record_type": "A", "resolver": None, **actual}
    return all(actual.get(k) == v for k, v in requirement.get("input", {}).items())


def statistics(log, case):
    baseline = log.get("mode") == "baseline"
    complete = log.get("schema_version", 0) >= 2 and log.get("attempt_accounting") == "complete" and "attempts" in log
    attempts = [a for a in log.get("attempts", []) if a["tool_name"] in NETWORK_TOOLS]
    requirements = case.get("required_measurements", [{"tool": t} for t in case.get("required_tools", [])])
    missing = [r for r in requirements if not any(matches(e, r) for e in log.get("evidence", []))]
    return dict(attempt_accounting="complete" if complete else "incomplete",
                dns_network_attempts=len(log.get("dns_attempts",[])) if log.get("schema_version",0)>=3 else None,
                measurements=len(log.get("evidence",[])),
                total_calls=len(attempts) if complete else 0 if baseline else None,
                missing_required_measurements=missing,
                tool_ms=sum(a.get("duration_ms", 0) for a in attempts))


def call_reviews(log, case):
    """Mechanical suggestions, explicitly subject to human review."""
    result = []
    for attempt in log.get("attempts", []):
        if attempt["tool_name"] not in NETWORK_TOOLS:
            continue
        error = (attempt.get("error") or {}).get("code")
        valid = attempt["status"] in {"measured", "unavailable", "execution_error"}
        reason = "参数有效且属于调查范围；执行失败不自动说明选择错误"
        if error in {"INVALID_INPUT", "FRAMEWORK_ARGUMENT_REJECTED", "NON_RETRYABLE_DUPLICATE", "BUDGET_EXHAUSTED", "NOT_EXECUTED", "CANCELLED"}:
            valid, reason = False, error
        args = attempt.get("input", {})
        if case["id"] == "Q1" and (attempt["tool_name"] != "query_dns" or args.get("record_type", "A") != "A"):
            valid, reason = False, "超出只查 A 的任务"
        if case["id"] == "C2" and attempt["tool_name"] != "query_dns":
            valid, reason = False, "已有 NXDOMAIN，缺少合理的后续连接依据"
        result.append(dict(attempt_id=attempt["attempt_id"], tool=attempt["tool_name"],
                           input=args, status=attempt["status"], error_code=error,
                           suggested_correct=int(valid), reason=reason))
    return result
