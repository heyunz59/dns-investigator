# Security policy

## Reporting a vulnerability

Use [GitHub private vulnerability reporting](https://github.com/heyunz59/dns-investigator/security/advisories/new) to report a vulnerability privately. Private reporting is enabled for this repository. Include the affected commit/version, platform, a minimal reproduction, expected impact and any relevant authorization or evidence behavior. Replace real credentials, private targets and personal paths with controlled examples.

Do not publish exploit details or sensitive logs in public Issues. For ordinary bugs that do not disclose a vulnerability, use the bug-report template. The project does not currently offer a response-time SLA or a bug bounty.

## Supported versions

Security fixes are developed on main. The current package version is 0.6.0rc1; there is no separate long-term support branch. Include your exact version/commit when reporting an issue and test with the current main revision when practical.

## Operational security

DNS Investigator performs active network checks. Run it only against authorized targets. The Web interface is designed for loopback, single-machine use; exposing it to the internet is outside its deployment model.

HTTP and TCP have independent authorization controls. HTTP checks the resolved address set and each redirect, preserves Host/SNI and validates certificates. The Agent cannot change network permissions, trust anchors or query budgets. Remediation suggestions are informational and do not execute configuration changes.

Model text is separate from measured evidence. Logs can contain domains, URLs, resolver addresses and model responses; inspect exports before sharing. Redaction and pattern scans cannot establish that every sensitive detail has been removed. Rotate exposed credentials at their issuer: removing a file from the current tree does not remove Git history.

See [network security design](docs/security.md), [configuration](docs/configuration.md) and [support limitations](docs/limitations.md) for the application boundaries.
