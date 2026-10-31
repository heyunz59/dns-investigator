"""Pure comparisons: differences are observations, never a pollution verdict."""
from .dns_wire import comparable_response


def compare(rows):
    usable = [r for r in rows if r.get("execution_status", "ok") == "ok"]
    if any(not comparable_response(r) for r in usable):
        return ["COMPARISON_INCONCLUSIVE"]
    codes = []
    if len(usable) < 2:
        return ["COMPARISON_INCONCLUSIVE"]
    def values(key):
        return {str(r.get(key)) for r in usable}
    if len(values("rcode")) > 1:
        codes.append("RCODE_DISAGREEMENT")
    if len({bool(r.get("records")) for r in usable}) > 1:
        codes.append("RECORD_PRESENCE_DISAGREEMENT")
    if len({tuple(sorted(x["value"] for x in r.get("records", []))) for r in usable}) > 1:
        codes.append("ADDRESS_SET_DIFFERENCE")
    def chain(r):
        return tuple((x.get("name"),x.get("target")) if isinstance(x,dict) else str(x) for x in r.get("cname_chain",[]))
    if len({chain(r) for r in usable}) > 1:
        codes.append("CNAME_DIFFERENCE")
    if any(r.get("rcode") == "TIMEOUT" for r in usable) and any(r.get("rcode") != "TIMEOUT" for r in usable):
        codes.append("RESOLVER_TIMEOUT_DIFFERENCE")
    if len({tuple(x.get("ttl") for x in r.get("records", [])) for r in usable}) > 1:
        codes.append("TTL_DIFFERENCE")
    if len(values("duration_ms")) > 1:
        codes.append("LATENCY_DIFFERENCE")
    return codes or ["NO_SIGNIFICANT_DIFFERENCE"]
