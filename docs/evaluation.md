# Evaluation and reproducibility

The pre-cleanup a8fd689 candidate passed 604 tests on Windows/Linux: https://github.com/heyunz59/dns-investigator/actions/runs/41457651962 . Later packaging results are recorded separately in release/verification.json; old CI is not claimed as validation of new packaging.

`python -m pytest -q` uses fixtures, scripted models and controlled loopback DNS/HTTP/TCP, including IPv6 when supported. No DeepSeek key or public DNS is required. Local protocol integration differs from fixture returns; scripted models do not validate DeepSeek. See [test inventory](release/test-inventory.md).

`python -m evaluation.report_quality results/runs/report-replay-new` replays frozen evidence into a new directory. `python -m evaluation.v06_final_review results/runs/mixed-review-new` adds actual local browser/offline HTML checks and needs Playwright with Chrome/Edge or Chromium. Neither calls a model/public target.

`python -m evaluation.run_eval --repeats 3` is a paid same-model A/B experiment (facts-only versus Agent+fixture), recording actual model, source, configuration and failed runs. Criteria never enter the Agent. `python -m evaluation.dns_v3` uses a real model with ten DNS fixtures, not public measurements. Automatic structure/execution/keyword scores remain pending human review, not root-cause accuracy. Summarization needs explicit reviewers and complete attempt counts; A without tools is N/A.

The optional Unbound harness needs a separately obtained 1.26.2 Windows library and controlled loopback port-53 permissions. It is not a runtime validator. Historical inputs, results and disagreements remain in [the archive](archive/README.md). No new Unbound/model/public experiment is claimed during cleanup.

## Historical real example

The redacted Baidu replay has 19 E, 17 Q, 6 A, zero V. Seven timeouts form two measured paths (five and two); normal DNS/TCP and HTTP 301 with a refused redirect remain visible. It proves neither current availability nor a unique root cause. The private resolver was replaced consistently with documentation address 192.0.2.53. Provenance records original/transformed hashes; it is not byte-identical. No independent semantic accuracy estimate is available.
