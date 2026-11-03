# User guide

This guide covers an installed CLI/Web application. See the [English](../README.md) or [Chinese](../README.zh-CN.md) README for installation and [configuration](configuration.md) for settings.

## Choosing a workflow

| Goal | Entry point | Model required | Measurement source |
| --- | --- | --- | --- |
| Ask a DNS/connectivity question | CLI question or Web Start | Yes | Live network by default |
| Investigate fixed test facts | CLI question with `--fixture` | Yes | Fixture, with no live fallback |
| Check independent tool execution | `--tools-only` | No | Live unless a fixture is supplied |
| Inspect a saved report | Web import/history | No | Saved historical evidence |
| Explore example reports | `python -m scripts.prepare_web_demos` then Web History | No | Labeled controlled examples |

Use the smallest question that describes the problem. A lookup asks for records; an investigation describes a symptom or comparison. If only DNS matters, state that explicitly. The agent can end an investigation when the evidence already answers the question.

## Targets and questions

Targets are domain names or HTTP/HTTPS URLs. Bare domains use HTTPS by default. URLs retain their path and query; include an explicit port when that is the endpoint you are investigating. Credentials inside URLs and invalid ports are rejected. The target parser is in [target.py](../src/dns_investigator/target.py).

```bash
dns-investigator "lookup example.com A records"
dns-investigator "Compare DNS resolver paths" --target example.com
dns-investigator "Investigate this endpoint" --target https://example.com/status
dns-investigator "Trace delegation and check DNSSEC" --target example.com
```

`--target` is authoritative for target selection. Interactive text mode asks for a missing target. Piped input and JSON mode should include a target in the question or supply `--target`.

Protocol modes such as `trace` and `dnssec` are parameters of the agent's `query_authoritative` tool, not CLI flags. Ask for the relevant investigation in the question. Resolver sets are configured with `DNS_RESOLVERS`; there is no CLI `--resolver` option.

## CLI output and automation

```bash
dns-investigator "Investigate DNS resolution" --target example.com --format json > investigation.json
```

stdout contains one JSON object. Progress is written to stderr, so a normal stdout redirect preserves valid JSON. Combining stderr into the same file can mix progress text with JSON. `--verbose` expands the text report and cannot be used with JSON mode.

Exit codes are `0` for local completion, `3` for a limited investigation, `1` for execution failure and `2` for input/configuration errors. Tools-only mode returns `0` when its independent verification sequence ends; inspect its attempts/evidence for individual outcomes. For shell automation, handle limited results explicitly instead of discarding their evidence.

## Understanding saved JSON

The complete output model is defined in [schemas.py](../src/dns_investigator/schemas.py). Useful fields include:

| Field | Meaning |
| --- | --- |
| `status` | Overall execution outcome: completed, limited, failed or cancellation state |
| `result` | Structured report, when available |
| `result.diagnostic_conclusion` | Selected primary diagnosis, or null when none is established |
| `result.secondary_diagnoses` | Secondary or parallel observations |
| `result.measured_facts` | Scoped facts derived from measurements |
| `result.remediation_plan` | Complete CHECK/POSSIBLE_FIX/VERIFY actions and branches |
| `result.execution_issues` | Attempt-linked refusals or execution problems |
| `attempts` | Tool-call attempts, including rejected calls |
| `dns_attempts` | Actual DNS query attempts |
| `evidence` | Recorded measurements with scope, source and call ownership |
| `validation_results` | Local protocol-verification records and dependencies |

An E can record a timeout without containing a DNS response. A V is local verification, not another network measurement. An A failure is not an E proving a remote fault. Legacy logs may lack newer fields; the reader preserves unknowns rather than guessing.

The CLI also prints the local log path. Keep raw logs local unless reviewed. JSON exports may contain network identifiers even after automatic redaction.

## Using the Web application

Start `python -m dns_investigator.web` or `dns-investigator-web`, then open `http://127.0.0.1:8765`.

### Start and monitor

Enter a target, add an optional symptom/question, and select Start. Progress shows actual evidence callbacks and recorded calls. While work is pending, lack of a new event does not establish a network fault. The interface runs one investigation at a time.

### Inspect

The home summary shows the selected observation(s), fault scope, resolver paths and priority actions. Resolution & Evidence lists query details and original records. Troubleshooting contains full conclusions and conditional branches. Timeline exposes actual operations, execution errors and E/Q/A/V associations.

### Cancel

Cancel asks the active task to stop and save obtained evidence. Cancellation cannot withdraw packets already sent; the UI can remain in a stopping state while cleanup completes. Cancellation is restricted to the owning browser session. Reloading the same browser session can reconnect to an active job; server restarts do not restore an in-memory job queue.

### History and import

History reads saved JSON in `results/runs/`, supports target filtering and uses recorded measurement times. Import accepts a JSON report up to 16 MB, creates a local copy with a generated identifier and never runs the imported text as instructions or commands. Historical replay uses saved context and ledgers, keeps the original result and does not reuse historical authorization as permission for new checks.

### Export

JSON is suitable for automation and source-level review. HTML includes the report, branches, timeline and embedded styles; it runs without scripts or network access and can be printed from a browser. Review exports before sharing, especially real targets, URL parameters, resolver identities and model text.

## Offline tools and examples

```bash
python -m dns_investigator.main --target example.com --tools-only --fixture data/fixtures/C1.json --format json
python -m scripts.prepare_web_demos
```

The first command exercises a fixed DNS/TCP/HTTP tool sequence on synthetic facts. The second prepares labeled example reports for Web History. Neither needs a model key or makes public measurements. Fixture misses are explicit unavailable facts and do not fall back to live networking.

An agent run with `--fixture` still calls DeepSeek. Live tools-only execution without `--fixture` still makes network requests. These modes answer different verification questions; [evaluation](evaluation.md) describes the distinctions.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `No module named dns_investigator` or command not found | Install the project into the same virtual environment used by the command. Use `python -m dns_investigator.main --help` to check the module entry. |
| Missing API key | Edit the local `.env` from `.env.example` and run from the repository root, or set the process environment explicitly. Tools-only fixtures and historical browsing need no key. |
| Model authentication, model-name or quota error | Check the account, endpoint, configured model and service limits. Preserve any recorded evidence; do not treat the API error as a DNS result. |
| Public resolver timeouts | Check whether that resolver path is reachable from the measuring network. Compare the recorded working paths before drawing a domain-wide conclusion. |
| Redirect or private-address refusal | Inspect the actual origin/address and policy. Grant additional access only when you control and authorize that destination. |
| `FIXTURE_NOT_COVERED` | The test did not supply that fact. Choose another covered check or preserve the unknown; repeated timeouts do not create a missing fixture entry. |
| DNSSEC policy limit / INDETERMINATE | Inspect the reason, material, algorithm profile and remaining budget in [limitations](limitations.md). |
| Web port already in use | Check which local process owns port 8765. Avoid starting a second server on the same port. |

For an unresolved bug, follow [CONTRIBUTING](../CONTRIBUTING.md) and attach a minimal sanitized reproduction. Report security issues [privately](https://github.com/heyunz59/dns-investigator/security/advisories/new).
