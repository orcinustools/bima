# Troubleshooting

Start with `bima check -config /etc/bima/config.yaml --json`; each failing check has a `hint`.

| Symptom | Likely cause | Fix |
|---|---|---|
| Every response has `txn.bima.error` / attacks pass in enforce mode | HAProxy can't reach the agent, or agent exceeds 100 ms | `systemctl status bima`; `listen` matches `be_bima_agents` server address; check `bima_inspect_duration_seconds` p99 |
| `check runtime_api: fail ... permission denied` | bima user not in socket group | `usermod -aG haproxy bima`, socket `mode 660`, restart bima |
| `check blocklist_map: fail Unknown map identifier` | map path in config ≠ path in HAProxy rule, or rule missing | make `ban.map_file` identical to `map_ip(<path>)`; ensure the file exists; reload HAProxy |
| `check spoe_backend: fail` | `be_bima_agents` backend missing or named differently | add the backend from `haproxy-bima.cfg` |
| Bans placed (`/bans`) but IP still served | client IP is the LB/CDN address | configure trusted proxies + `set-src` (see haproxy.md) |
| All users banned at once | `set-src` trusts X-Forwarded-For from everyone, or allowlist missing for LB health checks | restrict `set-src` to trusted CIDRs; allowlist monitoring IPs |
| Access log shows random 10.x / 192.168.x / 172.16-31.x / 100.64.x client IPs, one per request, with "bot" UAs probing `.env`/`.next` | A scanner forging `X-Forwarded-For` and the proxy that wrote the log trusts it from anyone | Trust forwarding headers only from your CDN/LB (`set-src ... if from_trusted`, Traefik `forwardedHeaders.trustedIPs`, nginx `set_real_ip_from`); set Bima `trusted_proxies`. Bima keys on `fc_src` and flags rotation (`BIMA-SPOOF-202`) |
| Many `would_block` on one endpoint | false positive | follow tuning.md |
| Alerts missing | notifier secrets not in env, or 4xx from API | `bima test-alert`; metric `bima_alerts_sent_total{status="error"}`; Telegram bot must be a member of the chat; Discord bot needs *Send Messages* + *Embed Links* in the channel |
| `bima_store_errors_total` rising | Redis unreachable/slow | check Redis; breaker keeps blocking signatures but skips scoring |
| HAProxy reload fails after merge | see "Validate" in haproxy.md | `haproxy -c` output names the line |
| High latency | CRS on large bodies | lower `max_body_inspect`, keep `crs.fast_path: true`, add agents |

Useful commands:
```
echo "show map /etc/haproxy/bima-blocklist.map" | socat stdio /var/run/haproxy/admin.sock
curl -s 127.0.0.1:9101/bans | jq
curl -s 127.0.0.1:9101/metrics | grep -E 'bima_(verdicts|bans|store_errors|alerts_sent)'
journalctl -u bima -f | jq -c 'select(.msg=="detection")'
```
Unban manually: `bima unban -config /etc/bima/config.yaml <ip>` (store + every HAProxy map, score reset).
Don't edit `ban_file` while bima runs: it is rewritten from memory on shutdown.
