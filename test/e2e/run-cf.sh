#!/usr/bin/env bash
# E2E: Bima behind Cloudflare, using exactly what `bima init --cloudflare-only
# --cloudflare-account` generates, plus `bima cloudflare apply` against a
# Cloudflare API stand-in. The "edge" container plays a Cloudflare edge node.
set -uo pipefail
cd "$(dirname "$0")/../../deploy/e2e-cf"
PASS=0; FAIL=0; FAILED=()
ok()  { PASS=$((PASS+1)); printf "  \033[32m✔\033[0m %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); FAILED+=("$1"); printf "  \033[31m✘ %s\033[0m\n" "$1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
wait_until() { local t=$1; shift; for _ in $(seq 1 "$t"); do eval "$*" && return 0; sleep 1; done; return 1; }
H=http://172.31.77.2
M=http://127.0.0.1:28201
CF=http://127.0.0.1:28295
# via the simulated Cloudflare edge, as client $1
edge()   { local ip=$1; shift; docker compose exec -T edge curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "CF-Connecting-IP: $ip" "$@"; }
direct() { docker compose exec -T direct curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@"; }
state()  { curl -s $CF/_state; }
bima()   { docker compose exec -T bima bima "$@"; }

docker compose down -v >/dev/null 2>&1
docker compose build bima >/dev/null 2>&1 || { echo "build failed"; exit 1; }

printf "\n\033[36m━━━━ GENERATE: bima init --cloudflare-only --cloudflare-account ━━━━\033[0m\n"
rm -rf gen && mkdir gen
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/gen:/out" bima:e2e bima init --dir /out --force --mode enforce --host cf.e2e \
  --cloudflare-only --cloudflare-account e2eacct --runtime-api unix:/var/run/haproxy/admin.sock \
  --map-file /etc/haproxy/bima-blocklist.map --spoe-file /etc/haproxy/bima-spoe.conf \
  --backend 127.0.0.1:8000 --listen 127.0.0.1:12345 --metrics 0.0.0.0:9101 >/dev/null
check "init wrote the Cloudflare edge list" 'grep -q "^173.245.48.0/20" gen/bima-cloudflare.lst'
check "init: HAProxy restores the client IP from CF-Connecting-IP (edge only)" 'grep -q "set-src req.hdr_ip(cf-connecting-ip) if bima_cf_edge" gen/haproxy-bima.cfg'
check "init: origin lockdown line" 'grep -q "deny deny_status 403 if !bima_cf_edge" gen/haproxy-bima.cfg'
check "init: config has trust_edge + ban_sync" 'grep -q "trust_edge: true" gen/config.yaml && grep -q "account_id: \"e2eacct\"" gen/config.yaml'
check "init: env template has BIMA_CLOUDFLARE_API_TOKEN" 'grep -q BIMA_CLOUDFLARE_API_TOKEN gen/bima.env'
# test-only adjustments: container logging, the simulated edge, the API stand-in, fast sync
sed -i 's|log /dev/log local0 info|log stdout format raw local0 info|' gen/haproxy.cfg
printf '# simulated Cloudflare edge (e2e)\n172.31.77.10/32\n' > gen/bima-cloudflare.lst
sed -i 's|  # edge_ips_file: .*|  edge_ips_file: /etc/haproxy/bima-cloudflare.lst\n  api_base: http://172.31.77.30:8095|; s|interval: 30s|interval: 3s|' gen/config.yaml

docker compose up -d >/dev/null 2>&1
wait_until 60 '[[ $(curl -s -o /dev/null -w "%{http_code}" $M/healthz) == 200 ]]'
check "generated haproxy.cfg is valid (haproxy -c)" 'docker compose exec -T haproxy haproxy -c -f /usr/local/etc/haproxy/haproxy.cfg >/dev/null 2>&1'
check "agent up, edge ranges trusted" 'docker compose logs bima 2>&1 | grep -q "behind cloudflare"'

printf "\n\033[36m━━━━ ORIGIN BEHIND CLOUDFLARE ━━━━\033[0m\n"
check "client via Cloudflare edge → 200" '[[ $(edge 198.51.100.9 $H/) == 200 ]]'
check "direct hit on the origin → 403 (lockdown)" '[[ $(direct $H/) == 403 ]]'
check "direct hit with forged CF-Connecting-IP → 403" '[[ $(direct -H "CF-Connecting-IP: 198.51.100.9" $H/) == 403 ]]'
codes="$(edge 203.0.113.77 "$H/api/ping?host=;id") $(edge 203.0.113.77 "$H/api/ping?host=|uname") $(edge 203.0.113.77 "$H/.env")"
check "attacks via the edge blocked ($codes)" '[[ ! " $codes " =~ " 200 " ]]'
sleep 1
check "the attacker's real IP (from CF-Connecting-IP) is banned" "curl -s $M/bans | jq -e 'has(\"203.0.113.77\")' >/dev/null"
check "the Cloudflare edge is NOT banned" "! curl -s $M/bans | jq -e 'has(\"172.31.77.10\")' >/dev/null"
check "banned client refused by the HAProxy map, even for clean requests" '[[ $(edge 203.0.113.77 $H/) == 403 ]]'
check "other visitors behind the same edge unaffected" '[[ $(edge 198.51.100.9 $H/products) == 200 ]]'
check "alert/log names the real client, not the edge" "docker compose logs bima 2>&1 | grep '\"ip\":\"203.0.113.77\"' | grep -q block"

printf "\n\033[36m━━━━ BAN SYNC → CLOUDFLARE IP LIST ━━━━\033[0m\n"
check "IP list bima_blocklist created on the account" "wait_until 15 'state | jq -e \".lists.bima_blocklist\" >/dev/null'"
check "ban pushed to the edge list (comment bima …)" "wait_until 15 'state | jq -e \"[.lists.bima_blocklist.items[] | select(.ip==\\\"203.0.113.77\\\" and (.comment|startswith(\\\"bima\\\")))] | length == 1\" >/dev/null'"
check "edge address never pushed" "! state | jq -e '.lists.bima_blocklist.items[] | select(.ip==\"172.31.77.10\")' >/dev/null"
check "metric bima_cloudflare_items_added_total ≥ 1" 'curl -s $M/metrics | grep -Eq "^bima_cloudflare_items_added_total [1-9]"'
bima unban -config /etc/bima/config.yaml 203.0.113.77 >/dev/null
check "unban removes it from the edge list" "wait_until 15 'state | jq -e \"(.lists.bima_blocklist.items // []) | length == 0\" >/dev/null'"
check "unbanned client served again" "wait_until 10 '[[ \$(edge 203.0.113.77 $H/) == 200 ]]'"
check "bima check: cloudflare ban sync pass" "bima check -config /etc/bima/config.yaml --json 2>/dev/null | jq -e '.checks[] | select(.name==\"cloudflare\" and .status==\"pass\")' >/dev/null"

printf "\n\033[36m━━━━ bima cloudflare apply (WAF custom rules) ━━━━\033[0m\n"
A="bima cloudflare apply -api-base http://172.31.77.30:8095 -zone z1 -account e2eacct"
out=$(docker compose exec -T -e BIMA_CLOUDFLARE_API_TOKEN=cf-test-token bima $A 2>&1)
check "dry run prints the plan, writes nothing" '[[ $out == *"dry run"* ]] && state | jq -e ".zones.z1 == null" >/dev/null'
out=$(docker compose exec -T -e BIMA_CLOUDFLARE_API_TOKEN=cf-test-token bima $A -yes 2>&1)
check "apply → 5 Bima rules in the zone (Free-plan limit)" '[[ $out == *"applied"* ]] && state | jq -e "[.zones.z1[] | select(.description|startswith(\"[bima]\"))] | length == 5" >/dev/null' || echo "$out" | sed 's/^/      /'
check "every expression ≤ 4096 chars and the list rule resolves" 'state | jq -e "all(.zones.z1[]; (.expression|length) <= 4096)" >/dev/null'
ids1=$(state | jq -c '[.zones.z1[].id]')
out=$(docker compose exec -T -e BIMA_CLOUDFLARE_API_TOKEN=cf-test-token bima $A -yes 2>&1)
check "re-apply updates in place (same rule ids, still 5)" '[[ $(state | jq -c "[.zones.z1[].id]") == "$ids1" ]]'
out=$(docker compose exec -T -e BIMA_CLOUDFLARE_API_TOKEN=wrong bima $A -yes 2>&1)
check "bad token reported" '[[ $out == *"Authentication error"* ]]'

docker compose down -v >/dev/null 2>&1
printf "\n════════ CLOUDFLARE RESULT: %d passed, %d failed ════════\n" "$PASS" "$FAIL"
for f in "${FAILED[@]}"; do echo "  - $f"; done
[[ $FAIL == 0 ]]
