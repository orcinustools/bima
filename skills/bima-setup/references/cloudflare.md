# Cloudflare

Three independent, opt-in pieces. None of them changes Bima's own rules or defaults.

| Situation | Use |
|---|---|
| HAProxy + Bima at the origin, Cloudflare proxying in front | `bima init --cloudflare` (+ `--cloudflare-only`) → `cloudflare.trust_edge: true` |
| Ban attackers at the edge too | `cloudflare.ban_sync` + rule `ip.src in $bima_blocklist` |
| A zone where Bima cannot run at the origin, or a first layer in front | `bima cloudflare rules` / `apply` |

## 1. Origin behind Cloudflare

Without this, every client looks like a Cloudflare edge address. Bima would then score
and ban the edge, which blocks everyone behind that edge.

```
bima init --cloudflare [--cloudflare-only] ...
```

It generates:
- `bima-cloudflare.lst`: the Cloudflare edge ranges, installed next to the blocklist map.
- In the frontend, **before** the blocklist deny lines:
  ```
  acl bima_cf_edge src -f /etc/haproxy/bima-cloudflare.lst
  http-request deny deny_status 403 if !bima_cf_edge      # only with --cloudflare-only
  http-request set-src req.hdr_ip(cf-connecting-ip) if bima_cf_edge { req.hdr(cf-connecting-ip) -m found }
  ```
- In `config.yaml`: `cloudflare.trust_edge: true`. Bima adds the edge ranges to
  `trusted_proxies`, never bans an edge address, and ignores the edge's JA3 and `cf-*`
  headers when fingerprinting clients.

Rules:
- `CF-Connecting-IP` is trusted **only** from edge addresses. A client hitting the origin
  directly can forge it, which is why the `if bima_cf_edge` condition is mandatory.
- `--cloudflare-only` (origin lockdown) also refuses direct hits. Before enabling it, ask
  the user whether anything reaches the origin without Cloudflare: health checks,
  payment-provider webhooks, internal clients. Allow those first.
- Refresh the ranges monthly, then reload HAProxy:
  `bima cloudflare ips -fetch -o /etc/haproxy/bima-cloudflare.lst`. If you also set
  `cloudflare.edge_ips_file` to that file, restart Bima.
- TLS: the edge terminates the client's TLS. JA3 at the origin is Cloudflare's, so group
  detection by fingerprint relies on header order and User-Agent only.

## 2. Ban sync to the edge

```yaml
cloudflare:
  ban_sync: {enabled: true, account_id: "<account id>", list_name: bima_blocklist, interval: 30s}
```
- Put `BIMA_CLOUDFLARE_API_TOKEN` in `bima.env`. The token needs
  **Account > Account Filter Lists > Edit**.
- The agent creates the IP list if it is missing. It pushes new bans within about 2 s,
  removes lifted or expired ones, and reconciles every `interval`.
- Only items whose comment starts with `bima` are managed. Entries added by hand are left
  alone. Private addresses are never sent, and IPv6 bans are sent as their /64.
- Detect mode never bans, so nothing is synced.
- Several agents (Redis) can sync concurrently; the operations are idempotent.
- The list blocks nothing by itself. It needs the custom rule `ip.src in $bima_blocklist`,
  which is rule 1 of `bima cloudflare rules`.
- Verify: `bima check` shows `cloudflare pass`, and the metric
  `bima_cloudflare_sync_errors_total` stays at 0.

## 3. Cloudflare WAF custom rules

```
bima cloudflare rules [-format text|json|terraform] [flags]
BIMA_CLOUDFLARE_API_TOKEN=… bima cloudflare apply -zone ZONE -account ACCOUNT          # plan only
BIMA_CLOUDFLARE_API_TOKEN=… bima cloudflare apply -zone ZONE -account ACCOUNT -yes     # apply
```
- The token needs **Zone > Zone WAF > Edit**, plus Account Filter Lists Edit when
  `-account` should create the list.
- Default set: 5 rules, which is the Free plan's limit. Each expression is ≤ 4096 chars.
  1. `bima_blocklist`: Bima bans (`ip.src in $bima_blocklist`).
  2. `bima_sensitive`: dotfiles, keys, dumps, configs, build artifacts, and PHP/ASP/WordPress
     paths.
  3. `bima_injection_1` and `bima_injection_2`: RCE, Log4Shell, PHP wrappers, SSRF, SSTI,
     SQLi, NoSQL, XSS and traversal in the URI. Also checks payloads in any header value
     and the `x-middleware-subrequest` header.
  4. `bima_clients`: scanner User-Agents, and search-crawler UAs that Cloudflare did not
     verify (`not cf.client.bot`).
- Options:

  | Flag | Effect |
  |---|---|
  | `-script-hosts a,b` | Hosts that legitimately serve `.php` or WordPress |
  | `-exempt-path /x/` | Path prefixes skipped by the injection rules |
  | `-ai-bots` | Also block AI crawlers |
  | `-cloud-asn 396982` | Block unverified bot UAs from these ASNs |
  | `-block-empty-ua` with `-empty-ua-allow api.host` | Block an empty User-Agent, except on these hosts |
  | `-action managed_challenge` | Challenge instead of block |
  | `-list ""` | No blocklist rule |
- `apply` reads the zone's custom rules and updates the `bima_*` rules in place. It keeps
  every other rule unless `-replace-existing` is given. Always show the plan (run without
  `-yes`) to the user first.
- More than 5 rules on the Free plan fails, for example when older hand-written copies of
  the same checks exist. Ask the user before using `-replace-existing`: it deletes their
  rules.
- Coverage: the rules are tested against Bima's scenario corpus, with 0 false positives on
  benign traffic. About 76% of the URI/header attacks are stopped at the edge. The rest, and
  everything in request bodies (invisible to custom rules below Enterprise), needs Bima at
  the origin.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Everyone gets 403 after enabling `--cloudflare-only` | The edge list is missing or empty, or the zone's DNS record is not proxied (grey cloud) → refresh the list and check the orange cloud |
| Bima logs show Cloudflare addresses as clients | The `set-src` line is missing or placed after the deny lines, or `trust_edge` is false |
| `refusing to ban a trusted proxy address` in logs | The client IP was not restored for that request → fix the `set-src` order |
| `apply`: `unknown list $bima_blocklist` | The list does not exist yet → pass `-account` or enable ban sync first, or use `-list ""` |
| `apply`: rule limit exceeded | Free plan allows 5 custom rules → remove older duplicates or use `-replace-existing` with consent |
| `bima_cloudflare_sync_errors_total` rising | Token permission or account id → `bima check -config …` |
