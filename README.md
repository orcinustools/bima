# Bima — WAF agent for HAProxy (SPOE)

Bima runs as an **HAProxy SPOE agent**. It blocks malicious payloads (RCE, Log4Shell,
Spring4Shell/OGNL, SSTI, LFI, SSRF, SQLi/NoSQLi, XSS, XXE, prototype pollution, webshell
uploads), detects enumeration behaviour (directory brute force, IDOR/ID enumeration,
scanners, credential brute force, and **distributed** enumeration per ASN or client
fingerprint), bans abusive IPs through the HAProxy Runtime API, and sends alerts to
**Telegram** and **Discord**.

```
Client ─► HAProxy ─(L0: stick-table, blocklist map)─► SPOE ─► Bima agent(s) ─► allow / tarpit / block
                                                               ├─ signatures BIMA-* (always on, ~25µs)
                                                               ├─ virtual patches BIMA-VP-* (CVE-specific)
                                                               ├─ OWASP CRS v4 / Coraza (fast path for plain inputs, own deadline)
                                                               ├─ per-IP + group scoring (ASN, JA3 + header order + UA)
                                                               ├─ state: memory + file │ Redis (multiple agents)
                                                               ├─ bans ► reconcile ► every HAProxy (Runtime API)
                                                               └─ alerts ► dedup/digest ► Telegram, Discord
Prometheus ◄─ /metrics (bima, haproxy) ─► Alertmanager ─► Telegram, Discord (agent down, …)
Grafana ◄─ "Bima WAF" dashboard
```

## Detection layers

| Layer | What | Action |
|---|---|---|
| L0 HAProxy | blocklist map (maintained by Bima), 300 req/10s rate limit | 403 / 429 |
| Signatures `BIMA-*` | RCE-001..004 (shell, PHP, Node/Python), L4J-004, JAVA-005..007 (Spring, deserialization, OGNL), SSTI-007, LFI-008, UPL-009, SSRF-010, XXE-011, PROTO-012, PHP-013 — after normalisation (repeated URL-decoding, overlong UTF-8, NFKC, `c''at`, `${IFS}`, base64, Log4j lookup de-obfuscation) | block, score +30/+50 |
| Virtual patches `BIMA-VP-*` | VP-001..010 + SQLI-014: request-level rules for specific CVEs (Next.js middleware bypass, SharePoint ToolShell, Tomcat partial PUT, TeamCity `;.jsp`, malformed Host, CrushFTP, PHP-CGI, dot-segments, abusive multipart, SAP NetWeaver, SQLi in auth headers) | block |
| OWASP CRS v4 | Coraza, paranoia 1. Protocol-only hits (920/911/922) are logged only. Skipped for trivially plain requests (fast path) and capped by its own deadline | block, score +30/+50 |
| Behaviour `BIMA-ENUM-*` | 101 scanner UA, 102 sensitive path, 103 ID enumeration, 104 ≥20 distinct 404s, 105 auth brute force, 106 error ratio | score |
| Identity `BIMA-SPOOF-*` | Client identity from the TCP peer (`fc_src`) when a forwarding header is forged: untrusted forwarder, internal address claimed by a public peer, header rotation across networks (202), allowlist bypass attempt (203) | identity / block |
| Crawlers `BIMA-BOT-*` | Claimed Googlebot/Bingbot/Applebot/… verified by reverse DNS (301 fake); crawler UA probing secrets (302); verified crawlers spared from 404 scoring | score |
| Groups `BIMA-ENUM-107` | ≥60 distinct 404s from ≥3 IPs sharing an ASN **or** a client fingerprint; every contributing IP is penalised | group ban |

Per-IP scores decay (half-life 5 min). **≥50 → tarpit**, **≥80 → ban** with an escalation
ladder `10m → 1h → 24h`.

## Modes and tuning
1. Deploy with `mode: detect` (shadow): everything is detected and alerted as `would-*`, nothing is blocked.
2. Read `GET /report` on the metrics port: hits per rule, top paths/locations, samples,
   `likely_false_positive` and a ready-to-paste **`suggested_exclusion`**.
3. Add narrow `exclusions:` (rule + path + location), repeat until false positives are gone.
4. Switch to `mode: enforce`.

Locations share one scheme across signatures and CRS: `path`, `query:<k>`,
`body[:<k>]` (JSON: `body:json.a.b`), `header:<h>`, `cookie:<c>`.

## Alerts
- CRITICAL/HIGH and ban events are sent immediately; MEDIUM events go into a **digest**.
  Dedup per `IP + category`; escalations are always sent, with the **evidence** (all rules that fired).
  Alerts include **ASN/country** (MMDB: GeoLite2 or DB-IP Lite). Delivery is ordered per notifier.
- Retries honour 429 `retry_after`. Payloads are escaped. Secrets come from the environment only:
  `BIMA_TELEGRAM_TOKEN`, `BIMA_TELEGRAM_CHAT_ID`, `BIMA_DISCORD_WEBHOOK` **or**
  `BIMA_DISCORD_BOT_TOKEN` + `BIMA_DISCORD_CHANNEL_ID`, `BIMA_REDIS_PASSWORD`.
- Verify real credentials with `bima test-alert -config config.yaml`.
- Problems with Bima itself (agent down, HAProxy without an agent, Redis errors, alert
  delivery failures, high latency) are alerted by **Prometheus + Alertmanager** — see `deploy/monitoring/`.

## CLI and agent skill
```
bima run        -config FILE                     # run the agent (default command)
bima init       [--json] [flags]                 # generate config, HAProxy snippet, SPOE, systemd unit, env, monitoring
bima check      -config FILE [--json] [--send]   # validate live wiring, with a hint for every failure
bima test-alert -config FILE
bima unban      -config FILE IP...               # lift bans everywhere, reset score
bima relay      -config FILE                     # Alertmanager → Discord bot / Telegram
bima skills     list | show [NAME [FILE]] | install [--dir ~/.claude/skills]
bima version
```
The `bima-setup` skill (SKILL.md + 5 references) is **embedded in the binary**. After
`bima skills install`, coding agents such as Claude Code can install, verify and tune
Bima on their own, following safe defaults: start in `detect`, ask before reloading
HAProxy, keep secrets in the environment.

## Deployment
| File | Purpose |
|---|---|
| `deploy/haproxy.cfg` | Production HAProxy (TLS + JA3 capture, Runtime API unix socket, exporter :8404) |
| `deploy/bima-spoe.conf` | SPOE config (identical for every environment) |
| `config.example.yaml` | Production Bima config (starts in `mode: detect`) |
| `deploy/monitoring/` | Prometheus rules, Alertmanager template, Grafana dashboard |
| `Dockerfile` target `runtime` | Production image (agent only) |

**HA:** `state.backend: redis` and list every HAProxy node in `ban.runtime_apis`. Bans
live in Redis (sorted set); each agent reconciles them into every map every 2 s.
**Single node:** `state.backend: memory` with `ban_file`, so bans survive restarts.

## Fail-open and latency budget
- SPOE timeout is 100 ms. If the agent is down or times out the request passes and
  HAProxy sets `txn.bima.error` (alert `BimaNoAgentInHAProxy`).
- CRS runs under its own 50 ms deadline and a concurrency cap, so CRS-expensive bodies
  cannot push the agent past the SPOE budget; the verdict then comes from signatures.
- Every Redis call is bounded to 25 ms. **Circuit breaker:** after 3 errors Redis is
  bypassed for 5 s; signatures and CRS keep blocking, only scoring is skipped.
- Bodies are inspected up to 64 KB (`tune.bufsize` / `max-frame-size`); cap larger bodies
  per endpoint in HAProxy.

## Scenario corpus
`test/scenarios/*.yaml` holds 376 single-request scenarios in 25 categories:
- attacks: RCE, Log4Shell, Java/OGNL, SSTI, LFI, SSRF, SQLi/NoSQLi, XSS, uploads, XXE, CRLF, prototype pollution, evasion;
- **CVEs 2023–2026**: React2Shell, Next.js middleware bypass, SharePoint ToolShell, SAP NetWeaver, Tomcat, CrushFTP,
  Craft CMS, Roundcube, Langflow, FortiWeb, PAN-OS, Ivanti, GeoServer, TeamCity, Confluence, Struts, Check Point,
  Citrix Bleed, Magento, PHP-CGI, PHP CVE-2026-109618/9, Starlette CVE-2026-48710, …;
- benign traffic, including a benign counterpart for every virtual patch.

Plus 14 multi-request behaviour flows (`test/e2e/scenariorun`).
- `go test ./internal/engine -run TestScenarios -v` runs the corpus against the engine in two
  profiles: *untuned* (false positives reported) and *tuned* (zero tolerance).
- E2E phase `S` sends the same corpus through a real HAProxy as raw HTTP, so malformed Host
  headers and un-normalised paths arrive as is.
- Known gaps carry a `gap:` note with the reason; they are reported, never silently skipped.

## Tests
```bash
go test ./...                                    # unit tests + scenario corpus
bash test/e2e/setup.sh                           # HA stack: 2×HAProxy, 2×Bima, Redis, Prometheus, Alertmanager, Grafana, mock Telegram/Discord
cd deploy/e2e && bash ../../test/e2e/run.sh      # every phase (or e.g. run.sh 4 5 S)
bash test/e2e/run-prod.sh                        # deploy/haproxy.cfg + runtime image, unmodified
bash test/e2e/run-skill.sh                       # skill workflow: plain HAProxy → init → merge → check → detect → enforce
```

## License
MIT © 2026 Eka Tresna Irawan — see [LICENSE](LICENSE).
