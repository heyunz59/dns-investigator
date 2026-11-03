# Security boundaries

Use authorized targets only. Web binds to 127.0.0.1:8765, checks local hosts/request tokens and limits cancellation to the owning browser session. It is not an internet-facing service.

Resolver configuration is trusted local input. Private system resolvers can be legitimate. Discovered authorities receive separate checks, fixed DNS ports and bounded selection. Trace uses software root hints, RD=0, bailiwick checks and bounded dependencies, not arbitrary scanning.

TCP needs valid target DNS evidence and an allowed port; internal access requires trusted configuration. HTTP independently checks origin, complete resolved address sets and redirects, pins numeric destinations, preserves Host/SNI and verifies certificates. Mixed public/private answers fail closed. DNS/TCP/HTTP can reach different endpoints and do not automatically prove the same backend.

Fixture mode never falls back to live networking. Missing data is an execution issue, not NXDOMAIN. Rejected parameters/nonretryable repeats remain in accounting. Soft stopping and hard limits coexist; cancellation retains evidence but cannot recall packets.

Model drafts are unverified candidates. Structural reference validation cannot guarantee semantic correctness. HTTP bodies are not sent to the model. Exports can still contain network identifiers; redaction/pattern scanning is not exhaustive privacy certification. Git history remains accessible after tree cleanup.

See [SECURITY.md](../SECURITY.md) and [third-party notices](../THIRD_PARTY_NOTICES.md).
