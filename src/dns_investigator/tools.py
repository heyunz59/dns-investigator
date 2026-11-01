import asyncio
import ipaddress
import json
import socket
import ssl
import time
import contextvars
import copy
import itertools
from datetime import datetime, timezone
from pathlib import Path
import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx
from .privacy import redact, safe_url
from .target import domain, parse_target
from .dns_wire import DNSClient, TYPES
from .dns_compare import compare,compare_details,evidence_rows
from .dns_diagnosis import diagnose
from .authority import investigate_authority
from .network_errors import describe
from .alias_scope import alias_paths,already_resolved

PARENT = contextvars.ContextVar("dns_parent", default=None)


def now():
    return datetime.now(timezone.utc).isoformat()


class ToolBackend:
    """Per-investigation evidence ledger. Fixture backend never falls through to live."""
    def __init__(self, target, fixture: Path | None = None, max_calls=10, on_evidence=None):
        self.target = target
        self.fixture = json.loads(fixture.read_text(encoding="utf-8")) if fixture else None
        self.max_calls = max_calls
        self.calls = []  # Valid measurements only; never a call counter.
        self._evidence_ids = itertools.count(1)
        self._evidence_by_call = {}
        self.attempts = []
        self.request_kind = "investigation"
        self.blocked = set()
        self.on_evidence = on_evidence
        self.dns = DNSClient(self)
        self.dns_tool_timeout = 20
        self.max_auth_servers = 2
        self.resolvers = (None,"1.1.1.1","8.8.8.8")

    def owned_evidence(self, call_id):
        return list(self._evidence_by_call.get(call_id, ()))

    def save_evidence(self, row):
        # Synchronous allocation + append, with no await: atomic within this event loop.
        # Imported baseline facts may already occupy an E id.
        existing={e["id"] for e in self.calls}
        identifier=f"E{next(self._evidence_ids)}"
        while identifier in existing:
            identifier=f"E{next(self._evidence_ids)}"
        row=copy.deepcopy({**row,"id":identifier,"parent_tool_call_id":row["tool_call_id"]})
        self.calls.append(row)
        self._evidence_by_call.setdefault(row["tool_call_id"],[]).append(row)
        self.emit("evidence",row)
        return row

    def add_dns_evidence(self, data, parent, query_id=None):
        row=dict(tool_call_id=parent,parent_tool_call_id=parent,
                 query_attempt_id=query_id,tool_name="query_dns",input=dict(domain=data.get("qname"),record_type=data.get("qtype"),resolver=data.get("resolver")),
                 started_at=now(),duration_ms=data.get("duration_ms",0),execution_status="ok",data=data,
                 source_mode="fixture" if self.fixture is not None else "live",measurement_location="synthetic" if self.fixture is not None else "program-host",error=None)
        self.attach_alias_scope(row)
        return self.save_evidence(row)

    def attach_alias_scope(self,row):
        name=row.get("data",{}).get("qname")
        if name and name!=self.target.domain:
            authorization=alias_paths(self).get(name)
            if authorization:row["target_authorization"]=authorization

    @property
    def finish_now(self):
        return len(self.attempts) >= max(1, self.max_calls - 2)

    def emit(self, kind, row):
        if self.on_evidence:
            self.on_evidence({"event": kind, **row})

    def register(self, name, args, provider_id=None):
        row = dict(attempt_id=f"A{len(self.attempts)+1}", tool_name=name,
                   provider_call_id=provider_id, input=redact(args), started_at=now(),
                   status="pending", evidence_id=None, error=None, duration_ms=0)
        self.attempts.append(row)
        self.emit("attempt_started", row)
        return row

    def reject(self, row, code, message, retryable=False, status="rejected", emit=True):
        row.update(status=status, error=dict(code=code, message=message, retryable=retryable))
        if emit:
            self.emit("attempt_finished", row)
        return dict(attempt_id=row["attempt_id"], execution_status="error", data={},
                    partial_evidence=self.owned_evidence(row["attempt_id"]),
                    findings=diagnose(self.calls),
                    error=row["error"], source_mode="fixture" if self.fixture is not None else "live",
                    budget={"remaining": max(0, self.max_calls-len(self.attempts)),
                            "finish_now": self.finish_now})

    def settle_pending(self, messages, final=False):
        retries = {getattr(p, "tool_call_id", None) for m in messages for p in m.parts
                   if getattr(p, "part_kind", "") == "retry-prompt" or getattr(p, "outcome", None) == "retried"}
        for row in self.attempts:
            if row["status"] == "pending" and (final or row["provider_call_id"] in retries):
                schema = row["provider_call_id"] in retries
                self.reject(row, "FRAMEWORK_ARGUMENT_REJECTED" if schema else "NOT_EXECUTED",
                            "框架拒绝参数或工具不可用；未进行测量。" if schema else "运行结束前未执行该尝试。",
                            status="schema_rejected" if schema else "not_executed")

    async def call(self, name, provider_id=None, **args):
        attempt = next((a for a in self.attempts if provider_id and a["provider_call_id"] == provider_id
                        and a["status"] == "pending"), None)
        if attempt is None:
            attempt = self.register(name, args, provider_id)
        started = time.monotonic()
        if int(attempt["attempt_id"][1:]) > self.max_calls:
            return self.reject(attempt, "BUDGET_EXHAUSTED", "硬性调用预算已用尽；请使用已有事实结束调查。")
        fingerprint = json.dumps([name, {k: v for k, v in args.items() if k != "timeout"}], sort_keys=True)
        if fingerprint in self.blocked:
            return self.reject(attempt, "NON_RETRYABLE_DUPLICATE", "相同请求已明确不可重试；未重复执行，无新增事实。")
        if name=="query_dns" and args.get("resolver") is None and any(
            a is not attempt and a["tool_name"]=="compare_resolvers" and a["status"] in {"pending","running"}
            and a["input"].get("domain")==args.get("domain") and a["input"].get("record_type","A")==args.get("record_type","A")
            for a in self.attempts):
            return self.reject(attempt,"REDUNDANT_QUERY","同轮 compare_resolvers 将提供相同系统解析器查询；本次未重复执行。")
        upper=15 if name=="check_http" else 5
        if isinstance(args.get("timeout"),(int,float)) and not 0<args["timeout"]<=upper:
            return self.reject(attempt,"INVALID_INPUT",f"timeout 必须大于0且不超过{upper}秒；此次未执行。")
        try:
            self._validate(name, args)
        except (ValueError, KeyError, TypeError, UnicodeError):
            self.blocked.add(fingerprint)
            return self.reject(attempt, "INVALID_INPUT", "参数非法或不在本次调查范围；检查目标、端口、类型和已有 DNS 证据。")
        if name=="query_dns" and domain(args["domain"])!=self.target.domain:
            prior=already_resolved(self,domain(args["domain"]),args.get("record_type","A"))
            if prior:
                return self.reject(attempt,"ALIAS_ALREADY_RESOLVED",f"已有 {prior} 提供相同类型末端记录；本次不重复跟进。")
        attempt["status"] = "running"
        token=PARENT.set(attempt["attempt_id"])
        row = dict(tool_call_id=attempt["attempt_id"],
                   tool_name=name, input=redact(args), started_at=now(),
                   source_mode="fixture" if self.fixture is not None else "live",
                   measurement_location="synthetic" if self.fixture is not None else "program-host",
                   execution_status="ok", data={}, error=None)
        try:
            if self.fixture is not None:
                def matching(item):
                    expected = item["match"]
                    if name == "query_dns":
                        expected = {"record_type": "A", "resolver": None, **expected}
                    actual = {"record_type": "A", "resolver": None, **args} if name == "query_dns" else args
                    return item["tool"] == name and all(actual.get(k) == v for k, v in expected.items())
                matches = [item for item in self.fixture if matching(item)]
                if not matches:
                    self.blocked.add(fingerprint)
                    return self.reject(attempt, "FIXTURE_NOT_COVERED",
                        "测试数据没有提供该项事实；不是 DNS 无记录/NXDOMAIN 或真实网络失败。不可重试；请保留未知并结束或选择其他有用检查。",
                        status="unavailable", emit=False)
                row["data"] = copy.deepcopy(matches[0]["data"])
            else:
                if name == "check_http" and safe_url(args["url"]) == safe_url(self.target.url):
                    args = {**args, "url": self.target.url}
                async with asyncio.timeout(self.dns_tool_timeout if name in {"compare_resolvers","query_authoritative"} else 16):
                    row["data"] = await getattr(self, name)(**args)
            if self.fixture is not None and name == "query_dns":
                row["data"]={"qname":args["domain"],"qtype":args.get("record_type","A"),"resolver_role":"recursive",**row["data"]}
            if name in {"compare_resolvers","query_authoritative"}:
                # Fixture composites contain raw sub-responses, not conclusions.
                if self.fixture is not None:
                    for data in row["data"].get("responses",[]):
                        if data.get("execution_status","ok")=="ok":
                            evidence=self.add_dns_evidence(data,attempt["attempt_id"])
                            data["evidence_id"]=evidence["id"]
                ids=[e["id"] for e in self.owned_evidence(attempt["attempt_id"])]
                measured=evidence_rows(self.owned_evidence(attempt["attempt_id"]))
                failures=[{**r,"source_mode":row["source_mode"],"parent_tool_call_id":attempt["attempt_id"]}
                          for r in row["data"].get("responses",[]) if r.get("execution_status")=="error"]
                row["data"]["comparison"]=compare_details(measured+failures)
                row["data"]["differences"]=row["data"]["comparison"]["differences"]
                attempt.update(status="measured" if ids else "unavailable",evidence_ids=ids)
                row["data"]["findings"]=diagnose(self.calls)
                row["data"]["evidence_ids"]=ids
                return row
            if row["data"].get("execution_status")=="error":
                return self.reject(attempt,(row["data"].get("error") or {}).get("code","DNS_EXECUTION_ERROR"),"DNS 查询没有取得响应；已有子查询证据保留。",emit=False)
            identifier=row["data"].get("evidence_id") if name=="query_dns" else None
            if identifier is not None:
                if identifier not in {e["id"] for e in self.owned_evidence(attempt["attempt_id"])}:
                    raise ValueError("DNS returned evidence owned by another call")
                attempt.update(status="measured",evidence_id=identifier)
                return {**row,"id":identifier,"findings":diagnose(self.calls)}
            # Only an actually returned measurement earns an E identifier.
            row["duration_ms"]=round((time.monotonic()-started)*1000,2)
            self.attach_alias_scope(row)
            row=self.save_evidence(row)
            attempt.update(status="measured", evidence_id=row["id"])
        except asyncio.CancelledError:
            self.reject(attempt, "CANCELLED", "测量被取消；没有取得有效事实。", status="cancelled", emit=False)
            raise
        except TimeoutError:
            return self.reject(attempt,"DNS_TOOL_TIMEOUT","复合 DNS 工具整体时间预算已用尽；已取得的证据仍保留。",status="execution_error",emit=False)
        except Exception:
            self.blocked.add(fingerprint)
            return self.reject(attempt, "INTERNAL_EXECUTION_ERROR", "工具内部执行失败；没有取得有效测量，不能据此判断目标故障。", status="execution_error", emit=False)
        finally:
            PARENT.reset(token)
            attempt["evidence_ids"]=[e["id"] for e in self.owned_evidence(attempt["attempt_id"])]
            attempt["duration_ms"] = round((time.monotonic()-started)*1000, 2)
            self.emit("attempt_finished", attempt)
        row = {**row, "findings":diagnose(self.calls), "budget": {"remaining": max(0, self.max_calls-len(self.attempts)),
                                 "finish_now": self.finish_now}}
        return row

    def _validate(self, name, args):
        timeout = args.get("timeout", 5)
        if not 0 < timeout <= (15 if name == "check_http" else 5):
            raise ValueError("工具超时参数越界")
        if name in {"query_dns","compare_resolvers","query_authoritative"}:
            requested=domain(args["domain"])
            if requested != self.target.domain and (name!="query_dns" or requested not in alias_paths(self)):
                raise ValueError("DNS 查询仅限本次调查域名")
            if args.get("record_type", "A") not in TYPES:
                raise ValueError("不支持该 DNS 类型")
            if args.get("resolver"):
                ipaddress.ip_address(args["resolver"])
                if self.fixture is None and not self.dns.permitted(args["resolver"]):
                    raise ValueError("未经配置授权的私有 DNS 地址")
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
        from .target import domain as normalize_domain
        domain=normalize_domain(domain)
        return await self.dns.query(domain,record_type,resolver,timeout,PARENT.get())

    async def compare_resolvers(self, domain, record_type="A", timeout=5):
        rows=await asyncio.gather(*(self.dns.query(domain,record_type,r,timeout,PARENT.get()) for r in self.resolvers))
        return dict(responses=rows,differences=compare(rows),limitations=["CDN, GeoDNS, TTL, cache and policy can explain differences."])

    async def query_authoritative(self, domain, record_type="A", timeout=5):
        return await investigate_authority(self,domain,record_type,timeout,PARENT.get())

    async def check_tcp(self, ip, port, timeout=5):
        sock = socket.socket(socket.AF_INET6 if ipaddress.ip_address(ip).version == 6 else socket.AF_INET,
                             socket.SOCK_STREAM)
        sock.setblocking(False)
        detail=None
        try:
            async with asyncio.timeout(timeout):
                # Windows Proactor sock_connect needs a numeric IPv6 4-tuple;
                # resolve locally with AI_NUMERICHOST (no network DNS lookup).
                address=socket.getaddrinfo(ip,port,sock.family,socket.SOCK_STREAM,0,socket.AI_NUMERICHOST)[0][4]
                await asyncio.get_running_loop().sock_connect(sock, address)
            status = "CONNECTED"
        except ConnectionRefusedError as exc:
            status = "REFUSED"
            detail=describe(exc)
        except TimeoutError as exc:
            status = "TIMEOUT"
            detail=describe(exc)
        except OSError as exc:
            status = "NETWORK_ERROR"
            detail=describe(exc)
        finally:
            sock.close()
        return dict(ip=ip, port=port, status=status,error_detail=detail,
                    event_loop=type(asyncio.get_running_loop()).__name__,family="IPv6" if ":" in ip else "IPv4")

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
        except (TimeoutError, httpx.TimeoutException) as exc:
            data["error"] = "TIMEOUT"
            data["error_detail"]=describe(exc)
        except httpx.RequestError as exc:
            data["error_detail"]=describe(exc)
            data["error"] = "TLS_ERROR" if data["error_detail"]["code"] in {"TLS_ERROR","CERTIFICATE_VERIFY_FAILED"} else type(exc).__name__
        return data
