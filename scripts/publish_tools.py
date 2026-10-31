"""Export explicitly reviewed tool-only measurements, removing local DNS configuration."""
import argparse
import json
from pathlib import Path
from dns_investigator.privacy import redact


def publish(source, destination):
    rows = json.loads(source.read_text(encoding="utf-8"))
    for row in rows:
        data = row.get("data", {})
        if "resolvers" in data:
            data["resolvers"] = ["REDACTED: local DNS configuration"]
        if "responding_resolver" in data:
            data["responding_resolver"] = "REDACTED"
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(redact(rows), ensure_ascii=False, indent=2), encoding="utf-8")


if __name__ == "__main__":
    p = argparse.ArgumentParser(description="仅用于已人工检查的工具日志；其他输入信息仍须自行脱敏")
    p.add_argument("source", type=Path)
    p.add_argument("destination", type=Path)
    args = p.parse_args()
    publish(args.source, args.destination)
