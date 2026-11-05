# Wiring HAProxy for Bima

`bima init` writes `haproxy-bima.cfg` (lines to merge) and `haproxy.cfg` (a complete
reference config). Merge — never overwrite the user's file.

## global
```
stats socket /var/run/haproxy/admin.sock mode 660 level admin   # Bima adds/removes bans here
tune.bufsize 65536                  # largest request body Bima can inspect (req.body)
tune.ssl.capture-buffer-size 128    # keep TLS ClientHello → JA3 fingerprint
```
- Changing an existing `stats socket` line (mode/group/level) needs a **restart**,
  not a reload: in master-worker mode the socket is inherited across reloads with
  its old permissions (`bima check` reports `permission denied`).
- If a `stats socket` with `level admin` already exists, reuse it and pass its path to `--runtime-api`. Don't add a second admin socket on a TCP port reachable from outside.
- `tune.bufsize` raises memory per connection (2 × bufsize). 65536 is fine for typical
  hosts; with very high connection counts consider 32768 and `max_body_inspect: 32768`.

## frontend (each frontend that serves the app) — order matters
```
option http-buffer-request                 # make the body available to SPOE
unique-id-format %{+X}o\ %ci:%cp_%fi:%fp_%Ts_%rt:%pid
unique-id-header X-Request-ID
# (behind CDN/LB only) restore client IP from trusted proxies:
acl from_trusted src -f /etc/haproxy/bima-trusted.lst
http-request set-src hdr_ip(x-forwarded-for,-1) if from_trusted
# L0: banned IPs never reach the agent
http-request deny deny_status 403 if { src,map_ip(/etc/haproxy/bima-blocklist.map) -m found }
# L1-2: Bima
http-request set-var(txn.path) path
http-request set-var(txn.method) method
filter spoe engine bima config /etc/haproxy/bima-spoe.conf
http-request send-spoe-group bima check-request
http-request deny deny_status 403 if { var(txn.bima.action) -m str block }
http-request tarpit deny_status 429 if { var(txn.bima.action) -m str tarpit }
http-response send-spoe-group bima check-response
```
Ordering rules:
1. `set-src` (real client IP) **before** anything that uses `src`.
2. Blocklist `deny` **before** `send-spoe-group` (saves agent work for banned IPs).
3. `set-var(txn.path/method)` **before** `send-spoe-group` (the response message reads them).
4. Existing user rules that must win (e.g. health-check `return`, ACME challenge) go **before** the Bima block.
5. If the frontend already has `http-request` rules that redirect/deny, keep them; insert the Bima block after authentication-free routing rules but before `use_backend`.
- `timeout tarpit` in `defaults` controls how long tarpitted clients wait (e.g. `5s`).
- Optional `http-request deny deny_status 429 if { sc_http_req_rate(0) gt 300 }` with a stick-table is a cheap L0 rate limit; only add it if the user wants rate limiting.

## HTTPS behind `mode tcp` (TLS passthrough)
A frontend in `mode tcp` only sees encrypted bytes: Bima cannot inspect it, and the
backend loses the client IP (it sees HAProxy). Terminate TLS in HAProxy only for
the hostnames you protect and keep passthrough for everything else:
```
frontend https-in
    mode tcp
    bind *:443
    tcp-request inspect-delay 2s          # on timeout: plain passthrough (served, not inspected)
    tcp-request content accept if { req.ssl_hello_type 1 }
    use_backend be_bima_tls if { req.ssl_sni -i app.example.com api.example.com }
    default_backend be_passthrough       # unchanged

backend be_bima_tls
    mode tcp
    server local abns@bima-tls send-proxy-v2

frontend fe_bima_tls
    mode http
    bind abns@bima-tls accept-proxy ssl crt /etc/haproxy/certs/app.pem alpn h2,http/1.1
    # ... the Bima frontend block from haproxy-bima.cfg ...
    http-request del-header X-Forwarded-For   # after send-spoe-group: client values are untrusted
    http-request set-header X-Real-IP %[src]
    option forwardfor                          # backend now sees the real client IP
    default_backend be_reencrypt

backend be_reencrypt
    mode http
    server app1 10.0.0.10:443 ssl verify none sni ssl_fc_sni alpn http/1.1
```
Certificates: Let's Encrypt with `certbot certonly --standalone --http-01-address 127.0.0.1
--http-01-port 8888` and, in the port-80 frontend, an ACME route that only exists while
certbot listens (so a backend doing its own ACME is not disturbed):
```
use_backend be_acme if { path_beg /.well-known/acme-challenge/ } { nbsrv(be_acme) gt 0 } { hdr(host),field(1,:) -i app.example.com }
backend be_acme
    server certbot 127.0.0.1:8888 check inter 300ms rise 1 fall 1
```
plus a deploy hook that writes `fullchain+privkey` to `/etc/haproxy/certs/<name>.pem` and
reloads HAProxy.

## backend
```
backend be_bima_agents
    mode tcp
    balance roundrobin
    timeout connect 1s
    timeout server 3m
    server bima1 127.0.0.1:12345 check inter 2s
```
Several agents → several `server` lines (requires `state.backend: redis`).

## SPOE file
`bima-spoe.conf` is identical for every environment; copy it as is. Its
`timeout processing 100ms` is the latency budget: on timeout HAProxy fails open
and sets `txn.bima.error`. Bima keeps CRS under its own 50 ms deadline so a
CRS-expensive body cannot push the agent past that budget.
`max-frame-size 65532` requires `tune.bufsize 65536`; with HAProxy's default frame
size (16384) bodies reach the agent truncated to ~16 KB.

## Body size (inspection window)
Bima sees at most `tune.bufsize` (64 KB) of a body; anything after it is not
inspected. Cap bodies on endpoints that never need more, e.g.
```
http-request deny deny_status 413 if { req.body_size gt 65536 } !{ path_beg /upload /api/import }
```
Truncated JSON/XML is not treated as an attack (no false positives on large
legitimate bodies).

## Multi-node
Each HAProxy node: same snippet. Bima config: `state.backend: redis` and
`ban.runtime_apis` listing **every** node's Runtime API (unix socket for the local
node, `tcp:<internal-ip>:9999` for remote nodes bound to an internal interface only).
Bans are reconciled into all maps every 2 s.

## Validate
`haproxy -c -f /etc/haproxy/haproxy.cfg` must print `Configuration file is valid`.
Common errors:
- `No Private Key found in '...crt.key'` → the `crt` directory contains separate
  `.crt`/`.key` files; it must contain combined cert+key PEMs only.
- `unable to find map file` → create the empty map file at the referenced path.
- `SPOE: ... unknown keyword` → HAProxy too old (< 2.8) or typo in the spoe file path.
