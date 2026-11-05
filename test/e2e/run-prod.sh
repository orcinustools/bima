#!/usr/bin/env bash
# E2E for the production HAProxy config (deploy/haproxy.cfg) + production image.
# No X-Forwarded-For trust here: every request comes from one client IP.
set -uo pipefail
cd "$(dirname "$0")/../../deploy/e2e-prod"
PASS=0; FAIL=0; FAILED=()
ok()  { PASS=$((PASS+1)); printf "  \033[32m✔\033[0m %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); FAILED+=("$1"); printf "  \033[31m✘ %s\033[0m\n" "$1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
code() { curl -sk -o /dev/null -w '%{http_code}' --max-time 10 "$@"; }
M=http://127.0.0.1:28101
wait_until() { local t=$1; shift; for _ in $(seq 1 "$t"); do eval "$*" && return 0; sleep 1; done; return 1; }

: > bima-blocklist.map
mkdir -p certs && cp ../e2e/certs/site.pem certs/site.pem   # crt dir must hold only cert+key PEMs
docker compose down -v >/dev/null 2>&1
docker compose build bima >/dev/null 2>&1 && docker compose up -d >/dev/null 2>&1
wait_until 60 '[[ $(code $M/healthz) == 200 ]]'
printf "\n\033[36m━━━━ PRODUCTION CONFIG (deploy/haproxy.cfg, image target=runtime) ━━━━\033[0m\n"
check "haproxy started with production config" '[[ $(docker compose ps haproxy --format "{{.State}}") == running ]]'
check "image is the slim runtime target (no mocks inside)" '! docker compose exec -T bima test -e /usr/local/bin/mocknotify'
check "HTTP  :80  → app (200)"  '[[ $(code http://127.0.0.1:28080/) == 200 ]]'
check "HTTPS :443 → app (200)"  '[[ $(code https://127.0.0.1:28443/) == 200 ]]'
check "HAProxy Prometheus exporter :8404" 'curl -s http://127.0.0.1:28404/metrics | grep -q haproxy_frontend_http_requests_total'
check "blocklist map loaded via unix socket (reconcile ok)" "wait_until 10 'docker compose logs bima 2>&1 | grep -q \"runtime api\" || ! docker compose logs bima 2>&1 | grep -q \"unreachable\"'"
check "attack over TLS blocked (403)" '[[ $(code "https://127.0.0.1:28443/api/ping?host=;id") == 403 ]]'
sleep 1
check "JA3 recorded for TLS client" "docker compose logs bima 2>&1 | grep -q '\"ja3\":\"[0-9a-f]\{32\}\"'"
code "https://127.0.0.1:28443/api/ping?host=|uname" >/dev/null
sleep 1
IP=$(curl -s $M/bans | jq -r 'keys[0]')
check "client banned after repeat attack (ip=$IP)" '[[ -n $IP && $IP != null ]]'
check "clean request from banned client rejected by HAProxy map" '[[ $(code https://127.0.0.1:28443/) == 403 ]]'
check "ban persisted to /var/lib/bima/bans.json" "docker compose exec -T bima cat /var/lib/bima/bans.json | grep -q '$IP'"
docker compose restart bima >/dev/null 2>&1; wait_until 30 '[[ $(code $M/healthz) == 200 ]]'
check "ban restored after agent restart" "curl -s $M/bans | jq -e 'has(\"$IP\")' >/dev/null"
docker compose restart haproxy >/dev/null 2>&1; sleep 1; wait_until 30 '[[ $(code $M/healthz) == 200 ]]'
check "ban re-applied to fresh HAProxy map via unix socket" "wait_until 15 '[[ \$(code https://127.0.0.1:28443/) == 403 ]]'"
check "alerts delivered (telegram+discord)" '[[ $(curl -s http://127.0.0.1:28090/messages | jq "[.messages[].channel]|unique|length") == 2 ]]'
check "Bima metrics exposed" 'curl -s $M/metrics | grep -q bima_bans_total'
printf "\n════════ PROD RESULT: %d passed, %d failed ════════\n" $PASS $FAIL
for f in "${FAILED[@]}"; do printf "  - %s\n" "$f"; done
docker compose down -v >/dev/null 2>&1
(( FAIL == 0 ))
