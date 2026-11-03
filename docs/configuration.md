# Configuration guide

Configuration is read from environment variables and the project's local `.env` file. Start with `.env.example`, run from the repository root, and keep `.env` out of Git. The README places the virtual environment inside the checkout; for installations elsewhere, set process environment variables explicitly rather than relying on discovery of an unrelated `.env`.

## Model connection

| Variable | Default | Purpose |
| --- | --- | --- |
| `DEEPSEEK_API_KEY` | Empty | Your local API credential |
| `DEEPSEEK_MODEL` | `deepseek-flash` | Model identifier |
| `DEEPSEEK_BASE_URL` | `https://api.deepseek.com` | Model endpoint |
| `MODEL_TIMEOUT` | `60` | Timeout for an individual model request, seconds |

A key is required for agent investigations, including agent runs over fixtures. Tools-only checks, saved-report browsing and example preparation do not call the model. Thinking is disabled and temperature is zero in the agent configuration. Model availability, authentication and billing depend on the service account.

HTTP measurement deliberately does not use environment proxies. The model SDK can have separate connection settings, so model access does not establish that public DNS/HTTP measurement paths are reachable. Keep proxy credentials out of shared examples and reports.

## Budgets and deadlines

| Variable | Default | Meaning |
| --- | --- | --- |
| `MAX_TOOL_CALLS` | `10` | Observed tool-attempt budget, including refusals and repeated calls |
| `DNS_QUERY_BUDGET` | `32` | Actual DNS request budget; accepted range 1–128 |
| `DNS_TOOL_TIMEOUT` | `20` | Composite DNS deadline, seconds; accepted range 1–60 |
| `MAX_AUTH_SERVERS` | `2` | Selected authority limit; environment input is clamped to 1–3 |

One composite call can consume several DNS requests; UDP/TCP fallback also consumes separate request attempts. Increasing one budget does not increase the other. The agent receives a stopping opportunity near the tool limit, while hard limits remain enforced.

Single DNS/TCP tool timeout parameters must be greater than zero and at most five seconds. HTTP is limited to 15 seconds overall, at most five redirects and 64 KiB of body reading. The size limit does not establish that a page was completely read. Deep-protocol depth, dependencies, records, signatures and computation have additional software-controlled limits. Use recorded stop reasons to distinguish execution limits from remote responses.

## Recursive resolvers

```dotenv
DNS_RESOLVERS=system,1.1.1.1,8.8.8.8
```

The comma-separated list accepts one to four identities. `system` uses the configured system DNS path; other entries must be numeric IP addresses. To test only the system path, use `DNS_RESOLVERS=system`; for an explicit public comparison, use `DNS_RESOLVERS=1.1.1.1,8.8.8.8`.

System configuration can contain several upstreams and a legitimate private resolver. Records identify the configuration and actual measurement as available. Explicit resolvers still pass tool admission rules; the configuration is not unrestricted network access. Authoritative checks have separate discovery/address policies. An unreachable public resolver is a path outcome to compare with the other measurements, not proof of domain-wide failure.

## HTTP and TCP authorization

All additional permissions are empty by default:

```dotenv
HTTP_ALLOWED_ORIGINS=
HTTP_ALLOWED_NETWORKS=
TCP_ALLOWED_NETWORKS=
```

| Variable | Format | Scope |
| --- | --- | --- |
| `HTTP_ALLOWED_ORIGINS` | Comma-separated `scheme://host:port` origins | Additional HTTP origins, including authorized redirects |
| `HTTP_ALLOWED_NETWORKS` | Comma-separated strict CIDRs | Explicit HTTP permissions for non-public addresses |
| `TCP_ALLOWED_NETWORKS` | Comma-separated strict CIDRs | Independent TCP address permissions |

The original HTTP origin is authorized for the investigation. An ordinary HTTP port-80 target can upgrade to HTTPS port 443 at the same host. Other redirects need an authorized origin. HTTP checks the full resolved address set before choosing a destination, retaining the original Host/SNI and certificate checks.

For an internal service you administer, the following illustrates syntax. Substitute only destinations you are entitled to investigate:

```dotenv
HTTP_ALLOWED_ORIGINS=https://service.example.org:8443
HTTP_ALLOWED_NETWORKS=10.20.30.40/32
TCP_ALLOWED_NETWORKS=10.20.30.40/32
```

These permissions remain protocol-specific. They do not remove target, DNS-evidence, port, redirect or budget checks. TCP requires usable target DNS evidence; eligible ports are 80, 443 and the explicit target port. Special prohibited destinations remain blocked by TCP policy even with a broad network configured. Prefer an individual endpoint or the smallest required CIDR. A suggested check does not authorize the application to widen configuration.

## Root hints and trust anchors

Root hints and trust resources are under `src/dns_investigator/assets/`. `sources.json` records URLs/hashes; `anchor-authentication.json` records software-snapshot authentication.

Maintainers update trust resources using `scripts/import_root_anchor.py` and `scripts/verify_anchor_cms.ps1`, with separate downloaded input and an authenticated import. There is no background RFC5011 updater. Runtime rejects authentication receipts older than 180 days. See [third-party notices](../THIRD_PARTY_NOTICES.md) and the [DNSSEC support profile](limitations.md).

## Verify safely

After installation, verify import and the offline tools first:

```bash
python -c "from importlib.metadata import version; print(version('dns-investigator'))"
python -m dns_investigator.main --target example.com --tools-only --fixture data/fixtures/C1.json --format json
```

Then run an agent investigation when the model key and permissions are ready. Offline tool execution does not validate the API key or establish a public-network root cause.
