# Bima config reference (`config.yaml`)

`bima init` generates a working file; `bima check` validates it. Durations use Go
syntax (`10m`, `1h`). Secrets are env-only.

| Key | Default | Notes |
|---|---|---|
| `listen` | `:12345` | SPOP address HAProxy connects to (`be_bima_agents`). Prefer `127.0.0.1:12345`. |
| `metrics_addr` | `:9101` | `/healthz`, `/metrics`, `/bans`, `/report`. Keep private. |
| `mode` | `enforce` | `detect` = shadow (alerts as `would-*`, never blocks). Env `BIMA_MODE` overrides. |
| `host` | `bima` | Label shown in alerts. |
| `allowlist` | `[]` | CIDRs never inspected (office, monitoring, payment-provider webhooks). |
| `trusted_proxies` | `[]` | CDN/LB CIDRs allowed to set the client IP via X-Forwarded-For — **same list as `set-src` in haproxy.cfg**. If HAProxy takes the IP from a header sent by anyone else, Bima holds the TCP peer accountable instead (forged headers cannot frame or impersonate clients, nor buy an allowlisted identity). |
| `bots.verify` / `bots.timeout` | `true` / `2s` | Reverse-DNS + forward-confirm check of UAs claiming Googlebot, Bingbot, Applebot, YandexBot, Baiduspider, PetalBot, Amazonbot (async, cached). Fake → `BIMA-BOT-301`; any crawler UA probing secrets → `BIMA-BOT-302`; verified crawlers are not scored for 404s. |
| `max_body_inspect` | `65536` | Bytes of body inspected. ≤ HAProxy `tune.bufsize`. |
| `crs.enabled` / `paranoia` / `inbound_threshold` | `true` / `1` / `5` | OWASP CRS v4 via Coraza. Raise paranoia only with thorough tuning. |
| `crs.allowed_methods` | `GET HEAD POST OPTIONS PUT PATCH DELETE` | |
| `crs.fast_path` | `true` | Skip CRS when every input is plain; Bima signatures always run. |
| `crs.timeout` | `50ms` | CRS deadline; on expiry the verdict comes from signatures/virtual patches (`bima_crs_timeouts_total`). Keep < SPOE `timeout processing`. |
| `crs.extra_directives` | `""` | Raw SecLang appended after CRS. |
| `score.tarpit` / `score.ban` | `50` / `80` | Per-IP thresholds. |
| `score.half_life` / `score.window` | `5m` / `1m` | Score decay; counting window for enumeration signals. |
| `group.by` | `[asn, fingerprint]` | Distributed-enumeration grouping. `asn` needs `geoip.asn_db`. |
| `group.distinct_404` / `min_ips` / `member_404` / `penalty` / `flag_ttl` | `60/3/3/80/10m` | Raise `distinct_404` for sites with many broken links; behind big NAT/CGNAT consider `by: [asn]` only. |
| `state.backend` | `memory` | `memory` (single agent; bans persisted to `ban_file`) or `redis` (multiple agents / nodes). |
| `state.ban_file` | `""` | e.g. `/var/lib/bima/bans.json` (memory backend). |
| `state.redis.addr` / `prefix` | `""` / `bima:` | Password via `BIMA_REDIS_PASSWORD`. |
| `geoip.country_db` / `asn_db` | `""` | MMDB files (GeoLite2 or DB-IP Lite). Adds `ASxxx ORG, CC` to alerts. |
| `ban.enabled` | `true` | |
| `ban.runtime_apis` | — | One per HAProxy node: `unix:/path` or `tcp:host:port`. |
| `ban.map_file` | — | Must equal the path in the HAProxy `map_ip(...)` rule. |
| `ban.durations` | `[10m, 1h, 24h]` | Escalation ladder (48 h memory). |
| `ban.reconcile_interval` | `2s` | Store → HAProxy maps sync period. |
| `alert.dedup_window` / `digest_interval` | `5m` / `5m` | |
| `alert.telegram.enabled` / `api_base` | | Secrets: `BIMA_TELEGRAM_TOKEN`, `BIMA_TELEGRAM_CHAT_ID`. |
| `alert.discord.enabled` | | Webhook (`BIMA_DISCORD_WEBHOOK`) **or** bot (`BIMA_DISCORD_BOT_TOKEN` + `BIMA_DISCORD_CHANNEL_ID`). Webhook wins if both set. |
| `exclusions` | `[]` | See `tuning.md`. |

## Locations (used by exclusions and `/report`)
`path`, `query:<name>`, `query-name`, `body` (raw JSON/text), `body:<name>` (form or
JSON key, e.g. `body:json.description`), `header:<name>`, `cookie:<name>`.

## HA checklist
- `state.backend: redis`, same `redis.addr` on all agents, Redis reachable < 5 ms.
- `ban.runtime_apis` lists every HAProxy node.
- Redis down → circuit breaker: scoring skipped for 5 s windows, signatures/CRS still block (metric `bima_store_errors_total`).
