# Support and limitations

DNS types: A/AAAA/CNAME/NS/SOA. NODATA is a supported negative interpretation of NOERROR, not a distinct RCODE. TIMEOUT means no timely response, not a server RCODE. Incomplete aliases/referrals are not automatically NODATA. CDN/TTL differences alone do not prove corruption.

basic authority discovery can depend on recursive DNS. trace is independently rooted but bounded, not a complete general resolver. DNSSEC uses authenticated software-distributed root anchors and isolated bounded local cryptography. Signature algorithms: 8/13/14/15; DS digests: 2/4; RSA policy: 2048–4096. NSEC supports selected authenticated negative/delegation/wildcard proofs. NSEC3 supports SHA1 hashing, zero iterations, empty salt, no Opt-Out and selected exact/closest-encloser/next-closer/wildcard proofs.

Nonzero iterations, nonempty salt, Opt-Out, unsupported structures/algorithms, DNAME, Compact Denial and exhausted budgets may remain INDETERMINATE/policy-limited. Unsupported is not automatically BOGUS, INSECURE or SECURE. Signatures alone do not prove denial semantics. There is no full DNSSEC conformance certification, ongoing RFC5011 daemon or universal public-zone coverage.

One host does not reproduce browser caches, hosts, DoH, proxies or historical connectivity. DNS success, TCP success, TLS validation, HTTP headers and a complete page are separate. Timeout does not establish a dead server. Valid JSON is not diagnosis accuracy.

completed means local output requirements were met, not independent correctness. limited preserves insufficient evidence; failed preserves execution/model failure even with a deterministic fallback report. Unknown historical context stays unknown, and historical permissions are not current authorization. Suggestions are never executed.

Web has no durable multi-user queue. Cancellation cannot undo sent requests. 0.6.0rc1 is a candidate, with no new public Release or PyPI upload.
