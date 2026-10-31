"""Sanitize selected run. Only publish after manual review of all text fields."""
import argparse
import json
from pathlib import Path
from dns_investigator.privacy import redact


def export(source, destination):
    log = json.loads(source.read_text(encoding="utf-8"))
    local_resolvers = set()
    for evidence in log.get("evidence", []):
        if evidence["source_mode"] == "live" and evidence["tool_name"] == "query_dns":
            data = evidence.get("data", {})
            local_resolvers.update(data.get("resolvers", []))
            if data.get("responding_resolver"):
                local_resolvers.add(data["responding_resolver"])
    text = json.dumps(redact(log), ensure_ascii=False, indent=2)
    for resolver in sorted(local_resolvers, key=len, reverse=True):
        text = text.replace(resolver, "[resolver redacted]")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("source", type=Path)
    p.add_argument("destination", type=Path)
    a = p.parse_args()
    export(a.source, a.destination)
