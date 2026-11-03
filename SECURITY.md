# Security policy

This application actively probes networks. Use authorized targets only. Web is designed for loopback on one machine, not public or multi-user hosting. Do not expose it through a public reverse proxy.

HTTP/TCP have separate address and origin policies. Model drafts are not measurements. Suggestions are never automatically executed. Logs can contain domains, URLs, resolver addresses and model text: inspect and redact before sharing. Pattern scans do not certify privacy. Rotate exposed credentials at their issuer; deleting the latest file does not erase Git history. See [security boundaries](docs/security.md).

## Reporting

Private vulnerability reporting was **disabled** when checked through GitHub's API during release preparation. No dedicated security email is published. Do not put exploit details, credentials or private logs in a public Issue. Ask the maintainer through a sanitized contact request to establish a private channel, or use GitHub private reporting if subsequently enabled. No response SLA or bounty is promised.

0.6.0rc1 is a release candidate, not a supported stable release. No older-version maintenance commitment is made. Formal publication requires maintainer approval and review of remaining redistribution/privacy notes.
