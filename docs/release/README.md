# v0.6 release preparation

Candidate: 0.6.0rc1, chore/open-source-release-prep, based on a8fd689. Runtime changes are limited to __init__.__version__; all other runtime modules/assets retain their baseline content. No diagnosis, network, cryptography or interface algorithm was changed.

Before inventory: [before-summary.json](audit/before-summary.json); [after inventory](audit/after-summary.json), [cleanup mapping](audit/cleanup-map.csv), [archive receipt](audit/archive-receipt.json), [test inventory](test-inventory.md), [verification](verification.json), [Windows installation](windows-installation.json), [screenshots](../images/README.md.png).

All 604 existing parametrized cases remain. Migration initially omitted accuracy_expectations.json; it was restored from the verified archive with assertions intact. Initial stdin-based audit could not spawn Windows validation workers; corrected file-based baseline passed 604 tests in 43.23s. Final migrated full suite passed 604 in 42.20s. These harness/migration failures are not presented as successful runs.

Source-only fixture migration retains 48 legacy model result objects, four legacy controlled formal results, thirteen report-quality cases and seven mixed scenarios. Originals and old intermediate failures remain at the immutable archive commit. Redaction is explicit, not claimed byte-identical. Historical Git size was not reduced.

MIT owner approval was obtained. CONTRIBUTING, SECURITY, CHANGELOG and Issue/PR templates are present. CODE_OF_CONDUCT is intentionally deferred until a maintainer commits to an enforcement/contact process. Private vulnerability reporting was observed disabled; no security contact was invented. Formal release, PyPI publication, tag, main merge and visibility changes are not performed. Upstream root-resource provenance is retained; a formal distribution should resolve any remaining third-party redistribution interpretation.

README preview screenshots are local Markdown renders, not screenshots of GitHub's website. Product screenshots come from actual local Web replay; captions distinguish redacted live history from controlled DNSSEC material. No paid model/public diagnostic experiment was performed during cleanup.
