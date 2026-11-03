# Historical archive

Immutable source: [a8fd689](https://github.com/heyunz59/dns-investigator/tree/a8fd68983c11c5841275f0a4423e2110525ff278). Retired results/published, stage documents and one-time harnesses remain there. No Git history or other branch was rewritten/deleted.

Before removal, all 6,536 tracked files were stored in sibling archive ../dns-investigator-archives/dns-investigator-a8fd689-pre-release.zip. Every entry was decompressed and SHA256-checked. The local ZIP was not uploaded as a Release asset. [Receipt](../release/audit/archive-receipt.json). Public recovery uses Git, not access to the maintainer's machine:

```bash
git fetch origin a8fd68983c11c5841275f0a4423e2110525ff278
git archive --format=zip --output=historical-a8fd689.zip a8fd68983c11c5841275f0a4423e2110525ff278
```

Git archive reconstructs committed bytes; the local ZIP preserves original working-tree line endings, so archive hashes can differ. Tree cleanup does not reduce full historical clone size.

Audit: [full inventory](../release/audit/before-tracked-files.csv), [directory sizes](../release/audit/before-directory-stats.json), [largest files](../release/audit/before-largest-30.json), [binaries](../release/audit/before-binary-files.json), [duplicates](../release/audit/before-identical-content.json), [references](../release/audit/reference-candidates.json), [actual test reads](../release/audit/baseline-test-file-reads.json), [per-file cleanup map](../release/audit/cleanup-map.csv).

Stable fixtures retain all 48 formerly validated legacy results and four controlled legacy reports. Logs/metadata skipped by old compatibility loops were archived. No test function was removed. Original paths in fixture provenance identify archived sources, not current file dependencies.

Privacy flags are candidates, not proven leaks; many address/credential-like strings are intentional refusal tests. Baidu was redacted, but old Git content remains unchanged. Review old raw logs before redistribution. Scanning does not certify historical privacy.
