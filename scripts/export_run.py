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
    evidence_rows=log.get("evidence",[]) if isinstance(log,dict) else []
    for evidence in evidence_rows:
        if evidence["source_mode"] == "live" and evidence["tool_name"] == "query_dns":
            data = evidence.get("data", {})
            local_resolvers.update(data.get("resolvers", []))
            if data.get("responding_resolver"):
                local_resolvers.add(data["responding_resolver"])
    if any(e.get("source_mode")=="live" for e in evidence_rows):
        collect(log)
    text = json.dumps(redact(log), ensure_ascii=False, indent=2)
    index=0
    for resolver in sorted(local_resolvers, key=lambda x:(-len(x),x)):
        if resolver in {"1.1.1.1","8.8.8.8"}:continue
        index+=1
        text = text.replace(resolver, f"[local-resolver-{index}]")
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(text, encoding="utf-8")


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("source", type=Path)
    p.add_argument("destination", type=Path)
    a = p.parse_args()
    export(a.source, a.destination)
