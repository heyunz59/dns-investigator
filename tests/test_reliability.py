import asyncio
import json
import ssl
from pathlib import Path
import dns.exception
import dns.resolver
import httpx
import pytest
from pydantic_ai.models.function import FunctionModel
from dns_investigator.tools import ToolBackend
from dns_investigator.agent import investigate
from dns_investigator.config import Config
from dns_investigator.target import parse_target


@pytest.mark.parametrize("exc,expected", [(dns.resolver.NXDOMAIN(), "NXDOMAIN"), (dns.exception.Timeout(), "TIMEOUT")])
async def test_dns_exception_categories(monkeypatch, exc, expected):
    async def fail(*a, **k):
        if expected == "TIMEOUT":
            raise exc
        import dns.message, dns.rcode
        response=dns.message.make_response(dns.message.make_query("example.com","A"))
        response.set_rcode(dns.rcode.NXDOMAIN)
        return response
    monkeypatch.setattr(dns.asyncquery, "udp", fail)
    b = ToolBackend(parse_target("example.com"))
    r = await b.call("query_dns", domain="example.com")
    assert r["execution_status"] == "ok" and r["data"]["rcode"] == expected


async def test_missing_fixture_no_live_fallback():
    fixture = Path(__file__).resolve().parents[1] / "data/fixtures/MISSING.json"
    b = ToolBackend(parse_target("example.com"), fixture)
    r = await b.call("check_http", url="https://example.com/")
    assert r["execution_status"] == "error" and r["source_mode"] == "fixture"
    assert r["error"]["code"] == "FIXTURE_NOT_COVERED"


@pytest.mark.parametrize("extra", [{"record_type": "AAAA"}, {"resolver": "1.1.1.1"}])
async def test_fixture_dns_parameters_are_exact(extra):
    fixture = Path(__file__).resolve().parents[1] / "data/fixtures/MISSING.json"
    b = ToolBackend(parse_target("example.com"), fixture)
    r = await b.call("query_dns", domain="example.com", **extra)
    assert r["execution_status"] == "error" and r["data"] == {}


async def test_parallel_budget(monkeypatch):
    b = ToolBackend(parse_target("example.com"), max_calls=1)
    async def slow(**kwargs):
        await asyncio.sleep(0.01)
        return {"rcode": "TIMEOUT"}
    monkeypatch.setattr(b, "query_dns", slow)
    r = await asyncio.gather(b.call("query_dns", domain="example.com"),
                             b.call("query_dns", domain="example.com"), return_exceptions=True)
    assert len(b.calls) == 1 and len(b.attempts) == 2
    assert sum(isinstance(x, dict) and x.get("error", {}).get("code") == "BUDGET_EXHAUSTED" for x in r if x.get("error")) == 1


async def test_tls_error(monkeypatch):
    class BadClient:
        async def __aenter__(self):
            raise httpx.ConnectError("TLS") from ssl.SSLCertVerificationError("test")
        async def __aexit__(self, *a):
            pass
    monkeypatch.setattr(httpx, "AsyncClient", lambda **kw: BadClient())
    r = await ToolBackend(parse_target("example.com")).check_http("https://example.com/")
    assert r["error"] == "TLS_ERROR"


async def test_model_failure_log_saved(tmp_path):
    def fail(*a):
        raise RuntimeError("secret-details-that-must-not-be-logged")
    log, path = await investigate("调查 example.com", parse_target("example.com"), Config("test"),
                                  model=FunctionModel(fail), log_dir=tmp_path)
    assert log["status"] == "failed"
    assert "secret-details" not in path.read_text(encoding="utf-8")
