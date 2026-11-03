# DNS Investigator

**Evidence-Based DNS Troubleshooting with an AI Agent**

[English](README.md) · [简体中文](README.zh-CN.md)

![Tests](https://github.com/heyunz59/dns-investigator/actions/workflows/tests.yml/badge.svg?branch=chore%2Fopen-source-release-prep)
![Python](https://img.shields.io/badge/Python-3.11%2B-blue)
![License](https://img.shields.io/badge/License-MIT-green)

DNS Investigator combines a DeepSeek/PydanticAI agent, controlled network diagnostics and traceable evidence to investigate DNS resolution failures and related connectivity issues. It helps locate the **observed failing scope**, distinguish facts from candidate explanations, and choose the next safe check. It does not promise a unique root cause.

> **Release candidate: 0.6.0rc1.** v0.6 is on `chore/open-source-release-prep`; main is not yet synchronized. No GitHub Release or PyPI package was published by this preparation. Use the branch-specific clone below.

![Historical DNS path replay](docs/images/diagnosis.png)
*Actual local Web rendering of a redacted historical Baidu investigation. The system resolver identity uses a documentation address; this is not a current network measurement.*

## When to use it

|Problem|What the tool can establish|
|---|---|
|A domain fails to resolve|Observed response/transport state: NXDOMAIN, NODATA, SERVFAIL, REFUSED or timeout|
|Resolvers disagree|Which measured paths differ, without treating one public resolver timeout as domain failure|
|DNSSEC blocks resolution|Supported local DS/DNSKEY/signature/denial checks, or an explicit INDETERMINATE boundary|
|DNS succeeds but access fails|Separate TCP, TLS and bounded HTTP observations; headers do not prove a complete page|
|Several anomalies coexist|Preserved primary/parallel observations and uncertainty about their causal relationship|

## Capabilities and engineering choices

- **One Agent, five tools:** query_dns, compare_resolvers, query_authoritative, check_tcp, check_http. Selection is dynamic, not a fixed all-tools pipeline.
- **Multiple DNS paths:** A/AAAA/CNAME/NS/SOA, recursive comparison, selected authority checks, bounded delegation trace, EDNS/EDE and limited local DNSSEC.
- **Traceable A/Q/E/V ledgers:** tool attempts, DNS requests, measurements and local validation results. Invalid attempts count; composite child requests retain ownership.
- **Evidence-bound reporting:** deterministic findings and scoped conclusions separate observed facts, unverified model candidates, direct proof and prerequisite material.
- **Path-level aggregation:** compatible resolver/mechanism/source/location/time observations can be grouped without losing individual queries or inventing root causes.
- **Read-only troubleshooting:** CHECK / conditional POSSIBLE_FIX / VERIFY branches; no automatic configuration changes. Authorization, budgets and fixture/live isolation remain outside model control.
- **Local Web:** progress/cancellation, history, evidence, troubleshooting, timeline, JSON and standalone offline HTML.

### How it works

User → one DeepSeek Agent → five tools → authorized/budgeted ToolBackend → A/Q/E + local V → deterministic findings/report → Agent continues or stops → CLI/JSON/Web.

DNSSEC, diagnosis and reporting are ordinary Python modules, not extra Agents or tools. A valid reference or JSON object does not guarantee semantic correctness. [Architecture](docs/architecture.md) · [support matrix and limitations](docs/limitations.md).

## Quick start

Requirements: Git, Python 3.11+ (CI targets 3.11/3.12), an authorized network and a modern browser. Agent investigations require your own DeepSeek API key and can incur API charges.

```bash
git clone --branch chore/open-source-release-prep --single-branch --depth 1 https://github.com/heyunz59/dns-investigator.git
cd dns-investigator
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\python.exe -m pip install -e ".[web]"
Copy-Item .env.example .env
.\.venv\Scripts\Activate.ps1
```

Linux/macOS:

```bash
.venv/bin/python -m pip install -e ".[web]"
cp .env.example .env
source .venv/bin/activate
```

If PowerShell activation is restricted, invoke `.\.venv\Scripts\python.exe -m ...` directly; no policy change is required. In .env set DEEPSEEK_API_KEY locally. Never paste or commit it. Defaults: deepseek-flash, https://api.deepseek.com, thinking disabled. Model/account availability is external. CLI-only users can install with `python -m pip install -e .`.

### Web

```bash
python -m dns_investigator.web
# Or: dns-investigator-web
```

Open http://127.0.0.1:8765 . Enter a domain or HTTP(S) URL and optional question. Review the result, evidence and conditional suggestions; export JSON/HTML if useful. The server is loopback-only, not a public multi-user service. [Configuration](docs/configuration.md).

### CLI

```bash
dns-investigator "Investigate DNS resolution failures for example.com"
dns-investigator "Query example.com A records"
dns-investigator --target example.com --format json
```

Default commands call DeepSeek and may perform real authorized network measurements. --target supplies the target; --format json is noninteractive with exactly one JSON object on stdout and progress on stderr. Exit codes: 0 completed, 3 limited, 1 execution failure, 2 invalid input/configuration. completed is not an accuracy score. --verbose expands text reports and cannot be combined with JSON.

### No-key, no-public-network demo

```bash
python -m dns_investigator.main --target example.com --tools-only --fixture data/fixtures/C1.json --format json
```

This uses synthetic DNS/TCP/HTTP facts and no model. Missing fixture facts never trigger live fallback. **--tools-only without --fixture can access the real network** and follows a fixed tool-test sequence; it is not Agent acceptance. Running an Agent with a fixture still requires a model key.

To view controlled reports without a key: `python -m scripts.prepare_web_demos`, then open the local Web history. Those reports are explicitly marked as examples.

## A sourced diagnostic example

The redacted [Baidu replay](data/regressions/baidu-investigation.json) contains 19 E, 17 Q, 6 A and zero V. Seven timeouts form two recursive path groups (five and two); successful DNS/TCP plus an HTTP 301 with a policy-refused redirect remain visible. It does not prove that the final page loaded or that the domain is globally unavailable. Source/redaction hashes are recorded in data_provenance. [Method and provenance](docs/evaluation.md).

![Controlled DNSSEC example](docs/images/dnssec.png)
*Actual Web rendering of controlled signed-DNS evidence: a DS/DNSKEY mismatch. This is a fixture/controlled example, not a public-domain diagnosis.*

![Investigation timeline](docs/images/timeline.png)
*Actual timeline rendered from the same redacted historical replay; no new tools were run.*

## Validation

The pre-cleanup candidate passed **604 tests** on Windows/Linux. This preparation preserves all test functions and migrates fixed data out of historical output directories; [current verification](docs/release/verification.json) records the new run and CI. Tests cover controlled DNS wire exchanges, DNSSEC/NSEC3, authorization, accounting/concurrency, Agent behavior, reports, Web and installed CLI entry points.

```bash
python -m pip install -e ".[web,dev]"
python -m pytest -q
python scripts/check_repository.py
```

Fixture tests, real loopback integration, scripted models, paid model runs and independent semantic review are distinct. No independent root-cause accuracy percentage is available. [Evaluation](docs/evaluation.md) · [test inventory](docs/release/test-inventory.md).

## Safety and limitations

Use authorized targets only. HTTP/TCP policies are independent; preserve certificate checks and Host/SNI. A public resolver timeout does not establish a dead DNS server. CDN/cache/TTL differences are not automatically faults. NSEC3 is limited to supported zero-iteration, empty-salt, non-Opt-Out proofs; unsupported/incomplete cases stay unknown. Historical replay does not grant current authorization. Browser proxies/DoH/cache may differ from program measurements.

Logs can contain network information even after redaction. Do not publish unreviewed transcripts. No automatic repairs, public Web deployment, universal DNSSEC coverage or guaranteed root-cause diagnosis are provided. [Security](SECURITY.md) · [limitations](docs/limitations.md).

## Documentation and contribution

[Architecture](docs/architecture.md) · [Configuration](docs/configuration.md) · [Security boundaries](docs/security.md) · [Evaluation](docs/evaluation.md) · [Development](docs/development.md) · [Changelog](CHANGELOG.md) · [Historical archive](docs/archive/README.md)

See [CONTRIBUTING.md](CONTRIBUTING.md) for reproduction and regression requirements. Original project code/documentation is MIT licensed with owner approval; [LICENSE](LICENSE) and [third-party notices](THIRD_PARTY_NOTICES.md) distinguish bundled upstream resources. No formal release is created by this branch.
