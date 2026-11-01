import asyncio
import json
import socket
from pathlib import Path
import dns.resolver
import dns.message
import dns.rcode
import httpx
import pytest
from dns_investigator.tools import ToolBackend
from dns_investigator.target import parse_target, extract_target
from dns_investigator.privacy import redact

FIXTURES = Path(__file__).resolve().parents[1] / "data/fixtures"


@pytest.mark.parametrize("value", ["", "ftp://example.com", "https://u:p@example.com", "a b.com", "https://example.com:0", "https://example.com:99999", "-bad.com", "https://127.0.0.1", "https://example.com\\@evil.com"])
def test_invalid_target(value):
    with pytest.raises(ValueError):
        parse_target(value)


def test_target_and_redaction():
    t = parse_target("example.com/path?token=secret")
    assert t.default_https and t.url == "https://example.com/path?token=secret"
    assert "secret" not in redact(t.url)
    assert extract_target("请查询 example.com 的 A 记录") == "example.com"


@pytest.mark.parametrize("case,rcode", [("C1", "NOERROR"), ("C2", "NXDOMAIN"), ("C3", "TIMEOUT"), ("C4", "NOERROR"), ("C5", "NOERROR"), ("C6c", "NOERROR"), ("Q1", "NOERROR")])
async def test_fixture_cases(case, rcode):
    b = ToolBackend(parse_target("example.com"), FIXTURES / f"{case}.json")
    result = await b.call("query_dns", domain="example.com", record_type="A", resolver=None)
    assert result["data"]["rcode"] == rcode
    assert result["source_mode"] == "fixture"
    if case == "C3":
        other = await b.call("query_dns", domain="example.com", record_type="A", resolver="1.1.1.1")
        assert other["data"]["rcode"] == "NOERROR" and len(b.calls) == 2
    if case in {"C1", "C4", "C5"}:
        tcp = await b.call("check_tcp", ip="192.0.2.10", port=443)
        assert tcp["data"]["status"] == ("TIMEOUT" if case == "C4" else "CONNECTED")
    if case in {"C1", "C5", "C6c"}:
        http = await b.call("check_http", url="https://example.com/")
        assert http["data"]["status_code"] == ({"C1": 200, "C5": 503, "C6c": None}[case])


async def test_budget_and_scope():
    b = ToolBackend(parse_target("example.com"), FIXTURES / "C2.json", max_calls=1)
    rejected = await b.call("check_tcp", ip="192.0.2.10", port=443)
    assert rejected["error"]["code"] == "INVALID_INPUT"
    exhausted = await b.call("query_dns", domain="example.com")
    assert exhausted["error"]["code"] == "BUDGET_EXHAUSTED"
    assert len(b.attempts) == 2 and not b.calls


@pytest.mark.parametrize("rcode", ["SERVFAIL", "REFUSED"])
async def test_dns_response_codes(monkeypatch, rcode):
    response = dns.message.make_response(dns.message.make_query("example.com", "A"))
    response.set_rcode(dns.rcode.from_text(rcode))
    async def fail(*a, **kw):
        return response
    monkeypatch.setattr(dns.asyncquery, "udp", fail)
    data = await ToolBackend(parse_target("example.com")).query_dns("example.com")
    assert data["rcode"] == rcode


async def test_dns_no_answer(monkeypatch):
    class Answer:
        response = dns.message.make_response(dns.message.make_query("example.com", "AAAA"))
        rrset = None
        nameserver = "192.0.2.53"
    async def resolve(*a, **kw):
        return Answer.response
    monkeypatch.setattr(dns.asyncquery, "udp", resolve)
    data = await ToolBackend(parse_target("example.com")).query_dns("example.com", "AAAA")
    assert data["rcode"] == "NOERROR" and data["records"] == []


async def test_real_loopback_tcp():
    server = await asyncio.start_server(lambda r, w: w.close(), "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    b = ToolBackend(parse_target("example.com"))
    try:
        assert (await b.check_tcp("127.0.0.1", port))["status"] == "CONNECTED"
    finally:
        server.close()
        await server.wait_closed()
    assert (await b.check_tcp("127.0.0.1", port))["status"] == "REFUSED"


async def test_http_real_redirect_and_body_bound():
    async def handler(reader, writer):
        line = await reader.readline()
        while await reader.readline() not in (b"\r\n", b""):
            pass
        if b"/start " in line:
            writer.write(b"HTTP/1.1 302 Found\r\nLocation: /end\r\nContent-Length: 0\r\n\r\n")
        else:
            writer.write(b"HTTP/1.1 503 Unavailable\r\nContent-Length: 100000\r\n\r\n" + b"x" * 100000)
        await writer.drain()
        writer.close()
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        from dns_investigator.http_safety import HTTPPolicy
        backend=ToolBackend(parse_target("example.com"));url=f"http://127.0.0.1:{port}/start"
        backend.http_policy=HTTPPolicy(url,allowed_networks=("127.0.0.1/32",))
        result = await backend.check_http(url)
        assert result["status_code"] == 503 and len(result["redirects"]) == 1
        assert result["bytes_read"] <= 65536
    finally:
        server.close()
        await server.wait_closed()


async def test_http_deadline():
    async def handler(reader, writer):
        await reader.read()
        writer.close()
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    try:
        port = server.sockets[0].getsockname()[1]
        from dns_investigator.http_safety import HTTPPolicy
        backend=ToolBackend(parse_target("example.com"));url=f"http://127.0.0.1:{port}/"
        backend.http_policy=HTTPPolicy(url,allowed_networks=("127.0.0.1/32",))
        result = await backend.check_http(url, timeout=0.1)
        assert result["error"] == "TIMEOUT"
    finally:
        server.close()
        await server.wait_closed()
