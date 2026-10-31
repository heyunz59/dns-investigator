import asyncio
import ipaddress
import json
import socket
import ssl
import time
from datetime import datetime, timezone
from pathlib import Path
import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
from .privacy import redact, safe_url
from .target import domain, parse_target


def now():
    return datetime.now(timezone.utc).isoformat()


class ToolBackend:
    """Per-investigation evidence ledger. Fixture backend never falls through to live."""
    def __init__(self, target, fixture: Path | None = None, max_calls=10, on_evidence=None):
        self.target = target
        self.fixture = json.loads(fixture.read_text(encoding="utf-8")) if fixture else None
        self.max_calls = max_calls
        self.calls = []
        self.on_evidence = on_evidence

    async def call(self, name, **args):
        if len(self.calls) >= self.max_calls:
            raise RuntimeError("工具调用上限已达到")
        self._validate(name, args)
        started = time.monotonic()
        row = dict(id=f"E{len(self.calls)+1}", tool_call_id=f"T{len(self.calls)+1}",
                   tool_name=name, input=redact(args), started_at=now(),
                   source_mode="fixture" if self.fixture else "live",
                   measurement_location="synthetic" if self.fixture else "program-host",
                   execution_status="ok", data={}, error=None)
        # Reserve the slot before awaiting: parallel model calls cannot bypass budget.
        self.calls.append(row)
        try:
            if self.fixture is not None:
                matches = [item for item in self.fixture if item["tool"] == name and
                           all(args.get(k) == v for k, v in item["match"].items())]
                if not matches:
                    raise ValueError("fixture 没有匹配此参数的原始事实")
                row["data"] = matches[0]["data"].copy()
            else:
                if name == "check_http" and safe_url(args["url"]) == safe_url(self.target.url):
                    args = {**args, "url": self.target.url}
                row["data"] = await getattr(self, name)(**args)
        except asyncio.CancelledError:
            row.update(execution_status="cancelled", error={"category": "cancelled"})
            raise
        except Exception as exc:
            row.update(execution_status="error", error={"category": type(exc).__name__})
        finally:
            row["duration_ms"] = round((time.monotonic()-started)*1000, 2)
            if self.on_evidence:
                self.on_evidence(row)
        return row

    def _validate(self, name, args):
        timeout = args.get("timeout", 5)
        if not 0 < timeout <= (15 if name == "check_http" else 5):
            raise ValueError("工具超时参数越界")
        if name == "query_dns":
            if domain(args["domain"]) != self.target.domain:
                raise ValueError("DNS 查询仅限本次调查域名")
            if args.get("record_type", "A") not in ("A", "AAAA"):
                raise ValueError("只支持 A/AAAA")
            if args.get("resolver"):
                ipaddress.ip_address(args["resolver"])
        elif name == "check_tcp":
            ipaddress.ip_address(args["ip"])
            if args["port"] not in {80, 443, self.target.port}:
                raise ValueError("不允许扫描无关端口")
            known = {r["value"] for c in self.calls if c["tool_name"] == "query_dns"
                     for r in c["data"].get("records", [])}
            if args["ip"] not in known:
                raise ValueError("TCP 地址必须来自已有 DNS 证据")
        elif name == "check_http":
            t = parse_target(args["url"])
            if t.domain != self.target.domain or t.port not in {80, 443, self.target.port}:
                raise ValueError("HTTP 初始目标必须属于本次调查")
        else:
            raise ValueError("未知工具")

    async def query_dns(self, domain, record_type="A", resolver=None, timeout=5):
        r = dns.asyncresolver.Resolver()
        if resolver:
            r.nameservers = [resolver]
        data = dict(resolvers=[str(x) for x in r.nameservers], record_type=record_type,
                    records=[], cname_chain=[], rcode=None,
                    scope="DNS query only; browser cache/hosts/proxy/DoH not reproduced")
        try:
            answer = await r.resolve(domain, record_type, lifetime=timeout, raise_on_no_answer=False)
            data["rcode"] = dns.rcode.to_text(answer.response.rcode())
            data["responding_resolver"] = str(answer.nameserver)
            data["records"] = [{"value": x.to_text(), "ttl": answer.rrset.ttl} for x in answer] if answer.rrset else []
            data["cname_chain"] = [rr.to_text() for rr in answer.response.answer if rr.rdtype == dns.rdatatype.CNAME]
        except dns.resolver.NXDOMAIN:
            data["rcode"] = "NXDOMAIN"
        except dns.exception.Timeout:
            data["rcode"] = "TIMEOUT"
        except dns.resolver.NoNameservers as exc:
            # Preserve individual response codes rather than conflating them with NXDOMAIN.
            codes = []
            for entry in exc.kwargs.get("errors", []):
                response = entry[4] if len(entry) > 4 else None
                if isinstance(response, dns.message.Message):
                    codes.append(dns.rcode.to_text(response.rcode()))
            data.update(rcode=codes[0] if codes and len(set(codes)) == 1 else "NO_NAMESERVERS",
                        response_codes=codes)
        return data

    async def check_tcp(self, ip, port, timeout=5):
        sock = socket.socket(socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET,
                             socket.SOCK_STREAM)
        sock.setblocking(False)
        try:
            async with asyncio.timeout(timeout):
                await asyncio.get_running_loop().sock_connect(sock, (ip, port))
            status = "CONNECTED"
        except ConnectionRefusedError:
            status = "REFUSED"
        except TimeoutError:
            status = "TIMEOUT"
        except OSError:
            status = "NETWORK_ERROR"
        finally:
            sock.close()
        return dict(ip=ip, port=port, status=status)

    async def check_http(self, url, timeout=15):
        data = dict(status_code=None, final_url=safe_url(url), redirects=[], peer_ip=None,
                    proxy_mode="disabled (trust_env=False)", bytes_read=0, error=None)
        try:
            # Outer deadline includes all redirects, DNS, TLS and body reads.
            async with asyncio.timeout(timeout):
                async with httpx.AsyncClient(trust_env=False, verify=True, follow_redirects=False) as client:
                    for hop in range(6):
                        async with client.stream("GET", url, timeout=timeout, headers={"User-Agent": "dns-investigator/0.1"}) as response:
                            data.update(status_code=response.status_code, final_url=safe_url(str(response.url)))
                            stream = response.extensions.get("network_stream")
                            peer = stream.get_extra_info("server_addr") if stream else None
                            data["peer_ip"] = str(peer[0]) if peer else None
                            if response.is_redirect and "location" in response.headers:
                                next_url = str(response.url.join(response.headers["location"]))
                                parsed = httpx.URL(next_url)
                                if parsed.scheme not in ("http", "https") or parsed.username or parsed.password:
                                    data["error"] = "UNSUPPORTED_REDIRECT"
                                    break
                                data["redirects"].append(dict(status=response.status_code, url=safe_url(next_url)))
                                if hop == 5:
                                    data["error"] = "TOO_MANY_REDIRECTS"
                                    break
                                url = next_url
                                continue
                            async for chunk in response.aiter_raw(chunk_size=4096):
                                data["bytes_read"] += len(chunk)
                                if data["bytes_read"] >= 65536:
                                    break
                            break
        except (TimeoutError, httpx.TimeoutException):
            data["error"] = "TIMEOUT"
        except httpx.RequestError as exc:
            cause = exc
            tls = False
            while cause:
                tls |= isinstance(cause, ssl.SSLError)
                cause = cause.__cause__
            data["error"] = "TLS_ERROR" if tls else type(exc).__name__
        return data
