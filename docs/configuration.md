# Configuration

Copy .env.example to .env where you start the app. Never commit real keys. Ordinary users should retain conservative defaults.

|Variable|Default|Meaning|
|---|---|---|
|DEEPSEEK_API_KEY|empty|Required for Agent calls, including Agent+fixture; may incur charges|
|DEEPSEEK_MODEL|deepseek-flash|Actual account availability is external|
|DEEPSEEK_BASE_URL|https://api.deepseek.com|Model endpoint|
|MODEL_TIMEOUT|60|Per-model request timeout, seconds|
|MAX_TOOL_CALLS|10|Observed tool attempts, including refusals|
|DNS_QUERY_BUDGET|32|Actual DNS requests; range 1–128|
|DNS_TOOL_TIMEOUT|20|Composite DNS deadline, seconds; range 1–60|
|MAX_AUTH_SERVERS|2|Selected authority limit, clamped to 1–3|
|DNS_RESOLVERS|system,1.1.1.1,8.8.8.8|1–4 identities; system may have multiple upstreams|
|HTTP_ALLOWED_ORIGINS|empty|Additional trusted origins|
|HTTP_ALLOWED_NETWORKS|empty|Explicit HTTP internal CIDRs|
|TCP_ALLOWED_NETWORKS|empty|Explicit TCP internal CIDRs|

Single DNS/TCP requests are bounded separately. HTTP has a 15-second total limit, at most five redirects and 64 KiB body reading. Suggestions never authorize broader configuration. Public resolver timeout does not prove target failure.

HTTP uses direct connections without environment proxies. Model SDK/browser routes may differ. Do not commit proxy credentials. Deep-protocol policies are not model-adjustable. Root snapshots require authenticated maintainer import; no RFC5011 background updater exists.
