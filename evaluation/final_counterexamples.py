"""Bounded external-behavior counterexamples; no model or public network."""
import argparse
import asyncio
from contextlib import asynccontextmanager
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch
from dns_investigator.http_safety import HTTPPolicy,PinnedTransport,AuthorizedBackend
from dns_investigator.target import parse_target
from dns_investigator.tools import ToolBackend
from .controlled_dns import controlled, Server
from .fcd_acceptance import followed_alias, report
from .accuracy_cases import cases


@asynccontextmanager
async def http_body(mode):
    async def handler(reader, writer):
        try:
            await reader.readuntil(b"\r\n\r\n")
            body = b"OK" if mode == "complete" else b"x" * 70000 if mode == "limit" else b""
            size = len(body) if mode != "timeout" else 10
            writer.write(f"HTTP/1.1 200 OK\r\nContent-Length: {size}\r\n\r\n".encode() + body)
            await writer.drain()
            if mode == "timeout":
                await reader.read()  # Only client deadline/disconnect releases this, no timing sleep.
        finally:
            writer.close()
            await writer.wait_closed()
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]
    backend = ToolBackend(parse_target(f"http://localhost:{port}/"))
    backend.http_policy = HTTPPolicy(backend.target.url, allowed_networks=("127.0.0.1/32",))
    async def resolver(host, port):return ["127.0.0.1"]
    backend.http_transport_factory=lambda policy:PinnedTransport(policy,AuthorizedBackend(policy,resolver))
    try:
        yield backend
    finally:
        server.close()
        await server.wait_closed()


async def interrupted_authority(ending):
    entered = asyncio.Event()
    packets = []
    original = Server.datagram_received
    def receive(server, wire, addr):
        import dns.message, dns.rdatatype
        question = dns.message.from_wire(wire).question[0]
        if server.index >= 3 and question.rdtype == dns.rdatatype.A:
            packets.append(server.index)
            if len(packets) == 2:
                entered.set()
                return  # Actual second target UDP datagram arrived; no answer sent.
        original(server, wire, addr)
    async with controlled("normal"), _patched_receive(receive):
        backend = ToolBackend(parse_target("probe.example"))
        if ending == "timeout":
            backend.dns_tool_timeout = .2
        task = asyncio.create_task(backend.call("query_authoritative", domain="probe.example"))
        await asyncio.wait_for(entered.wait(), 3)
        if ending == "cancel":
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
        else:
            await task
    return backend, packets


@asynccontextmanager
async def _patched_receive(receive):
    with patch.object(Server, "datagram_received", receive):
        yield


async def capture(out):
    if out.exists():
        raise FileExistsError("Preserve previous snapshots")
    examples = {}
    for mode in ("complete", "limit", "timeout"):
        async with http_body(mode) as backend:
            await backend.call("check_http", url=backend.target.url, timeout=.25)
        examples["http_" + mode] = dict(evidence=backend.calls, attempts=backend.attempts, report=report(backend).model_dump())
    with tempfile.TemporaryDirectory() as directory:
        backend = await followed_alias(Path(directory))
    for e in backend.calls:
        e["started_at"] = "2026-11-01T00:00:00"  # deliberately no timezone
    examples["naive_alias"] = dict(evidence=backend.calls, report=report(backend).model_dump())
    backend = ToolBackend(parse_target("probe.example"))
    backend.calls = cases()["timeout"]
    for e in backend.calls:
        e["started_at"] = None
    examples["unknown_time_timeout"] = dict(evidence=backend.calls, report=report(backend).model_dump())
    for ending in ("cancel", "timeout"):
        backend, received = await interrupted_authority(ending)
        examples["authority_" + ending] = dict(received_target_datagrams=received, attempts=backend.attempts,
            dns_attempts=backend.dns.attempts, evidence=backend.calls, report=report(backend).model_dump())
    import dns_investigator
    source = Path(dns_investigator.__file__).parent
    snapshot = dict(source_ref=subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        source_hashes={p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in source.glob("*.py")},
        model_invoked=False, public_network_invoked=False,
        review="controlled_network_and_fixed_replay_not_semantic_accuracy", cases=examples)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
    print("saved", len(examples), "counterexamples:", out.as_posix())


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    asyncio.run(capture(parser.parse_args().output))
