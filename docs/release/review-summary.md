# Cleanup decisions and remaining release gates

|Area|Observed purpose and dependency|Decision|Risk|
|---|---|---|---|
|src: 43 files|Installed runtime + 11 bundled assets|Retain; only __version__ changes|High: core behavior and authenticated bytes|
|tests: 40 Python files|Behavior/safety/protocol/compatibility/CLI regressions|Retain every test function; migrate input paths only|High|
|data: 19 files|Controlled tool fixtures, historical replay|Retain; redact private resolver in replay with provenance|High|
|results: 6,307 files|Historical runs, raw wires, model logs, intermediate HTML/screenshots|Extract actual test requirements; archive all originals; keep only README|Medium: data loss/privacy|
|docs: 53 original files|Stage-specific acceptance history and screenshots|Archive 51 old files; replace architecture/validation with maintained docs|Medium: links/provenance|
|evaluation: 48 original files|Harnesses plus one-time captures|Retain 20 reusable programs/definitions, archive 28|High: reproducibility|
|scripts: 16 original files|Maintenance + old acceptance captures|Retain 6 relevant scripts, archive 10; add repository checker|Medium|

6,396 original tracked paths were retired after backup verification. The complete pre-cleanup archive includes all 6,536 files, including overwritten README and packaging files. 56 historical source files feed five extracted report inputs/aggregates; provenance.json is the sixth JSON file. All 52 previously validated legacy results remain, not just a selected success subset. Superseded no-result metadata was not exercising the old validation assertion.

Original audit used real file reads plus import/path reference analysis. The discovered accuracy_expectations.json omission was corrected from the archive; final migration passes all original cases. Duplicate-hash candidates were reviewed as historical outputs, not deleted blindly by filename. Raw matched values are not reproduced in privacy findings; selected examples were reviewed contextually and screenshots re-rendered after redaction.

## Release gates

- Owner approved MIT for original material; third-party resources remain separately attributed. Their exact bytes/authentication provenance are preserved. Confirm any additional resource redistribution interpretation before formal distribution; MIT does not relicense them.
- main remains behind the candidate by design. Maintainer must separately authorize merge, tagging, Release/PyPI publication and update clone/badge refs if the stable ref changes. None is automatic.
- GitHub private vulnerability reporting was disabled at audit time. Enable a private route or establish a verified private contact before soliciting sensitive reports; no mailbox or SLA was invented.
- No independent root-cause accuracy figure is available. Completed/JSON/CI results remain distinct from semantic accuracy.
- Full historical clone size remains; shallow cloning the candidate avoids most historic blobs. Old history can still contain private network identifiers; current redaction does not erase history.
- CODE_OF_CONDUCT remains optional/deferred until the maintainer commits to enforcement. No new Agent/model/public-network experiment was performed in preparation.
