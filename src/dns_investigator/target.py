import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit


def domain(value: str) -> str:
    value = value.rstrip(".").encode("idna").decode("ascii").lower()
    if len(value) > 253 or not all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", p) for p in value.split(".")):
        raise ValueError("域名格式无效")
    return value


@dataclass
class Target:
    domain: str
    url: str
    port: int
    default_https: bool


def parse_target(value: str) -> Target:
    value = value.strip()
    if not value or any(c.isspace() or ord(c) < 32 for c in value) or "\\" in value:
        raise ValueError("请输入单个有效域名或 HTTP/HTTPS URL")
    default = "://" not in value
    p = urlsplit("https://" + value if default else value)
    if p.scheme not in ("http", "https") or not p.hostname or p.username is not None or p.password is not None:
        raise ValueError("仅支持无用户名密码的 HTTP/HTTPS URL")
    host = domain(p.hostname)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("调查目标应为域名；TCP 工具单独接受 IP")
    port = p.port if p.port is not None else (443 if p.scheme == "https" else 80)
    if not 1 <= port <= 65535:
        raise ValueError("端口必须在 1–65535 范围")
    authority = host + (f":{p.port}" if p.port is not None else "")
    return Target(host, urlunsplit((p.scheme, authority, p.path or "/", p.query, "")), port, default)


def extract_target(text: str) -> str | None:
    match = re.search(r"https?://[^\s，。；！？<>]+|(?<![\w@])(?:[A-Za-z0-9-]+\.)+[A-Za-z]{2,63}(?::\d+)?(?:/[^\s，。；！？<>]*)?", text)
    return match.group().rstrip(".,;!?）)") if match else None
