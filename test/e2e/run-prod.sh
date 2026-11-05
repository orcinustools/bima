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

printf "\n\033[36m━━━━ REAL LOG REPLAY: forged internal X-Forwarded-For + fake crawler UAs ━━━━\033[0m\n"
curl -s -X DELETE http://127.0.0.1:28090/messages >/dev/null
for b in $(curl -s $M/bans | jq -r 'keys[]'); do docker compose exec -T bima bima unban -config /etc/bima/config.yaml "$b"; done
check "bima unban lifted every ban" "[[ \$(curl -s $M/bans | jq length) == 0 ]] && wait_until 10 '[[ \$(code https://127.0.0.1:28443/) == 200 ]]'"
codes=()
while IFS='|' read -r xff path ua; do
  codes+=("$(code -H "X-Forwarded-For: $xff" -A "$ua" "https://127.0.0.1:28443$path")")
done <<'LOG'
192.168.60.245|/.vercel/project.json|Mozilla/5.0 (compatible; cohere-ai; +https://cohere.com/crawler)
10.100.20.99|/.next/prerender-manifest.json|Mozilla/5.0 (compatible; ChatGLM-Spider/1.0; +https://zhipuai.cn/)
192.168.121.22|/.next/routes-manifest.json|Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)
10.184.8.39|/.netlify/state.json|Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)
192.168.120.248|/.next/required-server-files.json|Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; ClaudeBot/1.0; +claudebot@anthropic.com)
10.169.175.104|/prisma/schema.prisma|Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-User/1.0; +claudebot@anthropic.com)
192.168.224.109|/.env.shared|CCBot/2.0 (https://commoncrawl.org/faq/)
172.26.54.205|/packages/api/.env|Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)
10.160.196.240|/.env.monorepo|Mozilla/5.0 (compatible; Amazonbot/0.1; +https://developer.amazon.com/support/amazonbot)
LOG
check "scanner stopped at its first probe, everything after refused (${codes[*]})" '[[ ${codes[0]} == 403 || ${codes[0]} == 429 ]] && [[ ! " ${codes[*]:1} " =~ " 200 " ]]'
check "forged X-Forwarded-For ignored: the TCP client is the banned identity" "curl -s $M/bans | jq -e 'keys|length==1' >/dev/null && ! curl -s $M/bans | jq -e 'has(\"192.168.60.245\")' >/dev/null"
sleep 6
curl -s http://127.0.0.1:28090/messages | jq -r '.messages[].text' > /tmp/bima-prod-alerts.txt
for kw in BIMA-ENUM-102 BIMA-BOT-301; do
  check "alert explains it ($kw)" "grep -q $kw /tmp/bima-prod-alerts.txt"
done
# same IP + category (fake-crawler) is deduplicated into one alert; the report keeps every rule
check "report records the crawler probing secrets (BIMA-BOT-302)" "curl -s $M/report | jq -e '.rules[]|select(.rule==\"BIMA-BOT-302\")' >/dev/null"
printf "\n════════ PROD RESULT: %d passed, %d failed ════════\n" $PASS $FAIL
for f in "${FAILED[@]}"; do printf "  - %s\n" "$f"; done
docker compose down -v >/dev/null 2>&1
(( FAIL == 0 ))
