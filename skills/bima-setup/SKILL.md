---
name: bima-setup
description: Install, configure, verify and tune Bima, a WAF that runs as an HAProxy SPOE agent (blocks RCE/injection, detects enumeration, bans IPs via the HAProxy Runtime API, alerts to Telegram/Discord). Use when asked to set up, deploy, upgrade, troubleshoot, tune false positives of, or switch modes of Bima / "WAF di HAProxy".
---

# Bima setup

Bima is a single binary. Every step below uses its own subcommands, which are
non-interactive and print machine-readable output with `--json`:

| Command | Purpose |
|---|---|
| `bima init [flags]` | Generate config.yaml, HAProxy snippet + full example, SPOE file, empty blocklist map, systemd unit, env template |
| `bima check -config F [--json] [--send]` | Validate config and live wiring (CRS, Runtime API, map, SPOE backend, agent, Redis, GeoIP, notifiers) |
| `bima run -config F` | Run the agent (what systemd starts) |
| `bima test-alert -config F` | Send one test alert to every notifier |
| `bima relay -config F` | Alertmanager webhook → Bima notifiers (separate service; delivers agent-down alerts) |
| `bima unban -config F IP...` | Lift bans on every HAProxy node and reset the score (false positive / support request) |
| `bima skills show bima-setup <file>` | Print a reference file of this skill |

## Ground rules (production safety)

1. **Ask before touching production HAProxy.** Show the user the diff of `haproxy.cfg` and get a yes before any reload. Always run `haproxy -c -f <cfg>` first; never reload a config that fails the check.
2. **Start in `mode: detect`** (shadow mode: alerts only, never blocks). Switch to `enforce` only after the user has reviewed `/report` (see `references/tuning.md`).
3. **Secrets never go into config.yaml** — use the env file (`BIMA_TELEGRAM_TOKEN`, `BIMA_TELEGRAM_CHAT_ID`, `BIMA_DISCORD_WEBHOOK` or `BIMA_DISCORD_BOT_TOKEN` + `BIMA_DISCORD_CHANNEL_ID`, `BIMA_REDIS_PASSWORD`), mode 0600, owned by the bima user.
4. **The Runtime API socket and Bima's metrics port must stay private** (unix socket or internal network; metrics on 127.0.0.1 or a monitoring VLAN).
5. Bima fails open: if the agent is down HAProxy keeps serving (uninspected). That is intended — don't "fix" it by failing closed without the user's explicit decision.

## Workflow

### 1. Discover the host
Collect before generating anything (ask the user only for what you cannot find):
- `haproxy -vv` — need **≥ 2.8** (3.0 LTS recommended); note if built with OpenSSL (for JA3).
- Path of the active config (`systemctl cat haproxy`, usually `/etc/haproxy/haproxy.cfg`) and the frontend(s) serving the app.
- Whether port 443 is `mode tcp` (TLS passthrough): then HTTPS can't be inspected until TLS is terminated in HAProxy for the protected hostnames (see `references/haproxy.md`, "HTTPS behind mode tcp").
- Existing `stats socket` line (reuse it if it has `level admin`; otherwise one must be added).
- Is HAProxy behind a CDN/LB? If yes, the trusted proxy CIDRs (needed to restore the client IP).
- One node or several HAProxy nodes? Several → Redis is required (`--state redis`).
- Alert channels the user wants (Telegram, Discord webhook, Discord bot).

### 2. Install the binary
Put `bima` in `/usr/local/bin`, create the user and state dir:
```
useradd --system --no-create-home --shell /usr/sbin/nologin bima
usermod -aG haproxy bima            # access to the admin socket (mode 660)
install -d -o bima -g bima /var/lib/bima /etc/bima
```

### 3. Generate files
```
bima init --dir /tmp/bima-setup --mode detect --host <public-hostname> \
  --runtime-api unix:/var/run/haproxy/admin.sock --backend <app ip:port> \
  [--trusted-proxies 10.0.0.0/8,...] [--state redis --redis <addr>] \
  [--telegram] [--discord|--discord-bot] [--json]
```
Read `/tmp/bima-setup/NEXT_STEPS.md` — it is generated for these exact flags.

### 4. Wire HAProxy
Merge `haproxy-bima.cfg` into the user's config (do not replace their file):
- the `global` lines (socket, `tune.bufsize`, `tune.ssl.capture-buffer-size`),
- the frontend lines **in order** into each frontend that serves the app — the blocklist `deny` before the SPOE call, `set-var` before `send-spoe-group`, `http-response send-spoe-group` last,
- the `be_bima_agents` backend.
Copy `bima-spoe.conf` and `bima-blocklist.map` to the paths used in the snippet.
Details and pitfalls: `references/haproxy.md`.
Then: `haproxy -c -f /etc/haproxy/haproxy.cfg` → show diff → user approves → `systemctl reload haproxy`.

### 5. Start Bima
Install `config.yaml` to `/etc/bima/`, `bima.env` (filled with secrets) to `/etc/bima/bima.env` (0600), `bima.service` to `/etc/systemd/system/`, then `systemctl daemon-reload && systemctl enable --now bima`.

### 6. Verify
```
bima check -config /etc/bima/config.yaml --json
```
Every check must be `pass` (a `warn` is acceptable only if you can explain it). Then prove it end to end:
- `curl -s -o /dev/null -w '%{http_code}' 'https://<host>/?x=;id'` → **200** in detect mode, and a `would-block` alert arrives.
- `bima test-alert -config /etc/bima/config.yaml` → every notifier `✔`.
If anything fails, use `references/troubleshooting.md`.

### 7. Tune, then enforce
Let real traffic run in detect mode (ideally days), review `GET http://127.0.0.1:9101/report`, add narrow `exclusions` (procedure in `references/tuning.md`), and only with the user's go-ahead set `mode: enforce` and `systemctl restart bima`. Re-run step 6 (the `;id` probe must now return 403).

### 8. Monitoring (recommended)
Prometheus scrape targets, alert rules (agent down, HAProxy without agent, Redis errors, alert delivery failing) and a Grafana dashboard: `references/monitoring.md`.

## Reference files
Read with `bima skills show bima-setup <file>` (or from the installed skill dir):
- `references/haproxy.md` — snippet anatomy, ordering, TLS/JA3, trusted proxies, multi-node
- `references/config.md` — every config key, defaults, HA with Redis
- `references/tuning.md` — shadow mode, `/report`, writing exclusions safely
- `references/troubleshooting.md` — symptom → cause → fix table
- `references/monitoring.md` — Prometheus/Alertmanager/Grafana wiring
