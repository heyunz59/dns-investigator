# Reproducible evaluation

See [methods](../docs/evaluation.md) and [development](../docs/development.md). Generated data stays ignored under results/runs or results/evaluation-raw.

- report_quality: thirteen frozen controlled report inputs.
- v06_final_review: mixed faults, legacy context, local browser/offline HTML.
- protocol_lab / signed_protocol_lab / controlled_dns: loopback servers used in CI.
- accuracy_cases + accuracy_expectations: fixed facts/expectations, never sent to Agent.
- run_eval + cases.json: paid same-model A/B fixture experiment, three repeats by default.
- dns_v3 + dns_v3_metrics: real-model DNS fixtures and mechanical accounting.
- nsec3_divergence: optional external Unbound comparison, no bundled verifier.
- review_rules / summarize: mechanical screening and explicit reviewed metrics, not independent accuracy.

Superseded captures remain in [the archive](../docs/archive/README.md). Missing results are not success, completed is not accuracy, and fixtures do not establish public-network causes.
