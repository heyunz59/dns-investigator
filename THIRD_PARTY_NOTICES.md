# Third-party notices

MIT covers original project material, as approved by the owner. It does not relicense dependencies, upstream resources, trademarks or model services.

## Bundled DNS resources

`src/dns_investigator/assets/sources.json` records URLs, dates and SHA256 for `named.root`, `root-anchors.xml`, `root-anchors.p7s` and `icannbundle.pem`. All bytes are preserved. The CA bundle is public certificate material. `anchor-authentication.json` records CMS authentication, not copyright permission or online revocation checks.

IANA describes vendor distribution of root anchors: https://www.iana.org/dnssec/files . Root hints: https://www.internic.net/domain/named.root . No separate SPDX identifier was established for these snapshots. The CC0 statement https://www.iana.org/help/licensing-terms is limited to protocol registries, not every IANA resource. Preserve upstream provenance; maintainers should confirm any additional redistribution terms before formal publication. No ownership of these resources is claimed.

## Separately installed dependencies

PydanticAI: MIT; dnspython: ISC; HTTPX/HTTPcore: BSD-3-Clause; python-dotenv: BSD-3-Clause; cryptography: Apache-2.0 OR BSD-3-Clause; FastAPI: MIT; Starlette: BSD-3-Clause; Uvicorn: BSD-3-Clause; Jinja2: BSD-3-Clause. Installed distribution metadata and upstream notices remain authoritative. These packages are not vendored. DeepSeek is a separate service governed by its service terms.

No Unbound binaries, DLLs or external verifier source are redistributed. The optional comparison harness requires a separately obtained Unbound installation. Synthetic signing keys are generated for controlled tests, not production use.

## Examples

The Baidu sample is redacted historical live evidence, not a current measurement or byte-identical copy. Documentation/loopback addresses in controlled samples are test inputs. Screenshots identify replay/fixture provenance; no third-party endorsement is implied.
