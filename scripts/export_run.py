"""Sanitize selected run. Only publish after manual review of all text fields."""
import argparse
import json
from pathlib import Path
from dns_investigator.privacy import redact


def export(source, destination):
    log = json.loads(source.read_text(encoding="utf-8"))
    local_resolvers = set()
    def collect(value):
        if isinstance(value,dict):
            for key,item in value.items():
                if key in {"resolvers","system_resolver_configuration"} and isinstance(item,list):
                    local_resolvers.update(str(x) for x in item)
                if key in {"resolver","responding_resolver"} and isinstance(item,str):
                    local_resolvers.add(item)
                collect(item)
        elif isinstance(value,list):
            for item in value: collect(item)
    for evidence in log.get("evidence", []):
        if evidence["source_mode"] == "live" and evidence["tool_name"] == "query_dns":
            data = evidence.get("data", {})
            local_resolvers.update(data.get("resolvers", []))
            if data.get("responding_resolver"):
                local_resolvers.add(data["responding_resolver"])
    if any(e.get("source_mode")=="live" for e in log.get("evidence",[])):
        collect(log)
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
