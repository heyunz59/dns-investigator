# Contributing

Install Python 3.11 or 3.12, then `python -m pip install -e ".[web,dev]"`. Run `python -m pytest -q`, `python scripts/check_repository.py` and `python scripts/check_public.py`. See [development](docs/development.md).

Report sanitized reproduction commands, version, OS, expected behavior and actual errors. Never attach an unreviewed .env, raw model transcript or private network topology. Security issues follow [SECURITY.md](SECURITY.md).

Keep PRs focused. DNS changes need controlled wire counterexamples; DNSSEC changes need trusted positive/negative and policy-limit tests. Network changes need authorization, redirect/rebinding, cancellation, budget and concurrent A/Q/E regressions. Reports need scope, reference, certainty and unknown-context tests. Do not weaken assertions to obtain a green build.

New measurements must identify source, target, type, time and parent call. Adding tools requires a separate design and safety review; the current architecture has five. Do not silently broaden CIDRs or targets. Fixture mode must remain isolated. Keep generated data outside Git, preserve failures and label automatic scoring as pending human review. Fixtures contain measurements, not prewritten root causes.

Explain behavior, rationale, validation and limitations in PRs. Public PR jobs receive no maintainer API key. Contribute only material you may license under the root MIT license; upstream notices remain applicable.
