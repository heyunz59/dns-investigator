"""Conservative logging: strip ALL query values, fragments and credentials."""
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode


def safe_url(value: str) -> str:
    p = urlsplit(value)
    host = p.hostname or ""
    if ":" in host:
        host = f"[{host}]"
    if p.port:
        host += f":{p.port}"
    return urlunsplit((p.scheme, host, p.path,
                      urlencode([(k, "REDACTED") for k, _ in parse_qsl(p.query, keep_blank_values=True)]), ""))


def redact(value, secrets=()):
    if isinstance(value, dict):
        return {k: redact(v, secrets) for k, v in value.items()
                if k.lower() not in {"api_key", "authorization", "cookie", "reasoning_content"}}
    if isinstance(value, list):
        return [redact(v, secrets) for v in value]
    if isinstance(value, str):
        for secret in secrets:
            if secret:
                value = value.replace(secret, "REDACTED")
        value = re.sub(r"sk-[A-Za-z0-9_-]{8,}", "REDACTED", value)
        def clean(match):
            try:
                return safe_url(match.group())
            except ValueError:
                return "[invalid URL]"
        return re.sub(r"https?://[^\s<>\"']+", clean, value)
    return value
