# Examples

Every config here loads with `bima check` (they are tested by `go test ./internal/config`),
and the HAProxy files pass `haproxy -c`. Secrets are never in these files: they come from
the env file (`/etc/bima/bima.env`).

## Bima configs (`config/`)

| File | Situation |
|---|---|
| `01-minimal.yaml` | Smallest working setup: one node, shadow mode, no alerts |
| `02-single-node.yaml` | One server, HAProxy terminates TLS, Telegram alerts, GeoIP |
| `03-ha-redis.yaml` | Two HAProxy nodes, an agent per node, shared Redis state, Discord bot |
| `04-behind-load-balancer.yaml` | Behind a cloud LB / reverse proxy that sets X-Forwarded-For |
| `05-behind-cloudflare.yaml` | Origin behind Cloudflare: CF-Connecting-IP, edge never banned, ban sync to the edge |
| `06-shadow-mode-tuning.yaml` | Detect mode with narrow exclusions (GraphQL, PostHog cookie, WYSIWYG, payment API, tickets) |
| `07-strict.yaml` | Admin panel: paranoia 2, faster and longer bans |
| `08-public-api.yaml` | JSON API with CGNAT mobile clients and partner webhooks |
| `09-wordpress.yaml` | WordPress: editor endpoints excluded narrowly |
| `10-kubernetes.yaml` | Ingress pods + Bima Deployment, Runtime APIs over TCP, Redis |
| `11-high-traffic.yaml` | Busy site: tighter CRS deadline, smaller body window, Redis |
| `12-alerts-only.yaml` | Watch only: never blocks or bans, alerts to Telegram + Discord |

## HAProxy (`haproxy/`)

| File | Situation |
|---|---|
| `behind-cloudflare.cfg` | Output of `bima init --cloudflare-only`: client IP from CF-Connecting-IP (edge only), origin lockdown |
| `tls-sni-split.cfg` | Port 443 passthrough for most hostnames, selected hostnames terminated, inspected by Bima and re-encrypted upstream |

`bima init` writes the full reference config for the other cases (`--trusted-proxies`,
`--tls-crt-dir`, `--state redis`, …).

## Cloudflare (`cloudflare/`)

| File | What |
|---|---|
| `rules.sh` | `bima cloudflare rules` variants: defaults, no ban list, site policy, challenge, JSON, Terraform |
| `apply.sh` | Plan, then apply the rules to a zone with the API |
| `edge-ips-cron.sh` | Monthly refresh of the Cloudflare edge ranges for HAProxy and Bima |
