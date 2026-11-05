#!/usr/bin/env bash
# E2E for the embedded agent skill: follow skills/bima-setup/SKILL.md on a fresh
# host that already runs HAProxy with its own config, using only bima subcommands.
set -uo pipefail
cd "$(dirname "$0")/../.."
PASS=0; FAIL=0; FAILED=()
ok()  { PASS=$((PASS+1)); printf "  \033[32m✔\033[0m %s\n" "$1"; }
bad() { FAIL=$((FAIL+1)); FAILED+=("$1"); printf "  \033[31m✘ %s\033[0m\n" "$1"; }
check() { if eval "$2"; then ok "$1"; else bad "$1"; fi; }
sect() { printf "\033[33m▶ %s\033[0m\n" "$1"; }
X="docker exec bima-skilltest"
wait_until() { local t=$1; shift; for _ in $(seq 1 "$t"); do eval "$*" && return 0; sleep 1; done; return 1; }

docker build -q --target skilltest -t bima:skilltest . >/dev/null || { echo "build failed"; exit 1; }
docker rm -f bima-skilltest >/dev/null 2>&1
docker run -d --name bima-skilltest --entrypoint sleep bima:skilltest infinity >/dev/null
printf "\n\033[36m━━━━ SKILL WORKFLOW (fresh host, existing HAProxy config) ━━━━\033[0m\n"

sect "0. Existing host: the user's own HAProxy config + app"
$X sh -c 'mkdir -p /etc/haproxy /var/run/haproxy && cat > /etc/haproxy/haproxy.cfg <<CFG
global
    log stdout format raw local0 info
    maxconn 4096

defaults
    mode http
    log global
    option httplog
    timeout connect 5s
    timeout client 30s
    timeout server 30s

frontend fe_shop
    bind :80
    http-request return status 200 content-type text/plain string "ok" if { path /healthz }
    default_backend be_shop

backend be_shop
    server shop1 127.0.0.1:8000 check
CFG
(mockapp >/tmp/app.log 2>&1 &) ; (mocknotify >/tmp/notify.log 2>&1 &)
haproxy -D -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid'
sleep 1
check "original site works" '[[ $($X curl -s -o /dev/null -w %{http_code} http://127.0.0.1/) == 200 ]]'
check "HAProxy version ≥ 2.8 (skill step 1)" '$X haproxy -v | grep -qE "version (2\.(8|9)|3\.)"'

sect "1. Skill is embedded in the binary"
check "bima skills list shows bima-setup" '$X bima skills list | grep -q "^bima-setup"'
$X bima skills install --dir /root/.claude/skills >/dev/null
check "skills install writes SKILL.md + 5 references" '[[ $($X find /root/.claude/skills/bima-setup -type f | wc -l) == 6 ]]'
check "installed SKILL.md has front matter name" '$X head -3 /root/.claude/skills/bima-setup/SKILL.md | grep -q "^name: bima-setup"'
check "skills show prints a reference" '$X bima skills show bima-setup references/haproxy.md | grep -q "order matters"'
check "skills install refuses to overwrite without --force" '! $X bima skills install --dir /root/.claude/skills 2>/dev/null'

sect "2. bima init (step 3)"
out=$($X bima init --dir /tmp/setup --mode detect --host shop.local --runtime-api unix:/var/run/haproxy/admin.sock \
      --backend 127.0.0.1:8000 --discord-bot --json)
check "init --json lists generated files" "echo '$out' | jq -e '.files|length >= 10' >/dev/null"
check "bima.env created with mode 600" '[[ $($X stat -c %a /tmp/setup/bima.env) == 600 ]]'
cj=$($X sh -c "BIMA_DISCORD_BOT_TOKEN=x BIMA_DISCORD_CHANNEL_ID=1 bima check -config /tmp/setup/config.yaml --json")
check "generated config is valid for bima" "echo '$cj' | jq -e '.checks[]|select(.name==\"config\" and .status==\"pass\")' >/dev/null"
check "full example haproxy.cfg passes haproxy -c" '$X sh -c "cp /tmp/setup/bima-spoe.conf /etc/haproxy/ && touch /etc/haproxy/bima-blocklist.map && haproxy -c -f /tmp/setup/haproxy.cfg" >/dev/null 2>&1'

sect "3. Merge snippet into the EXISTING config (step 4)"
$X sh -c 'cd /tmp/setup && cp /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.orig &&
  awk "/^### \[global\]/{f=1;next} /^###/{f=0} f&&NF" haproxy-bima.cfg > g.txt &&
  awk "/^### \[defaults\]/{f=1;next} /^###/{f=0} f&&NF" haproxy-bima.cfg > d.txt &&
  awk "/^### \[frontend/{f=1;next} /^###/{f=0} f&&NF" haproxy-bima.cfg > fe.txt &&
  awk "/^### new section/{f=1;next} f" haproxy-bima.cfg > be.txt &&
  awk -v G=g.txt -v D=d.txt -v F=fe.txt "
    /^global/{print; while((getline l<G)>0) print l; next}
    /^defaults/{print; while((getline l<D)>0) print l; next}
    /^ *default_backend be_shop/{while((getline l<F)>0) print l}
    {print}" /etc/haproxy/haproxy.cfg.orig > /etc/haproxy/haproxy.cfg &&
  echo >> /etc/haproxy/haproxy.cfg && cat be.txt >> /etc/haproxy/haproxy.cfg &&
  cp bima-spoe.conf /etc/haproxy/bima-spoe.conf && cp bima-blocklist.map /etc/haproxy/bima-blocklist.map'
check "user rules kept (healthz return still before Bima block)" '$X awk "/healthz/{h=NR} /send-spoe-group bima check-request/{s=NR} END{exit !(h && s && h<s)}" /etc/haproxy/haproxy.cfg'
check "merged config passes haproxy -c (exit 0)" '$X haproxy -c -q -f /etc/haproxy/haproxy.cfg'
$X sh -c 'haproxy -D -f /etc/haproxy/haproxy.cfg -p /run/haproxy.pid -sf $(cat /run/haproxy.pid)'; sleep 1
check "site still serves after reload (agent not started yet → fail-open)" '[[ $($X curl -s -o /dev/null -w %{http_code} http://127.0.0.1/) == 200 ]]'

ENV="BIMA_DISCORD_BOT_TOKEN=test-bot BIMA_DISCORD_CHANNEL_ID=42 BIMA_DISCORD_API_BASE=http://127.0.0.1:8090/api/v10"
sect "4. bima check before the agent runs"
pre=$($X sh -c "$ENV bima check -config /tmp/setup/config.yaml --json")
st() { echo "$pre" | jq -r --arg n "$1" '[.checks[]|select(.name==$n)|.status]|first'; }
check "runtime_api pass (HAProxy reachable over unix socket)" '[[ $(st runtime_api) == pass ]]'
check "blocklist_map pass (map referenced by merged config)" '[[ $(st blocklist_map) == pass ]]'
check "spoe_backend warn: 0 agents UP (with hint)" '[[ $(st spoe_backend) == warn ]]'
check "agent warn: not started yet" '[[ $(st agent) == warn ]]'
check "state fail: /var/lib/bima missing (hint tells the fix)" "[[ \$(st state) == fail ]] && echo '$pre' | jq -e '.checks[]|select(.name==\"state\")|.hint|test(\"install -d\")' >/dev/null"

sect "5. Install + start (steps 5–6)"
$X sh -c "mkdir -p /var/lib/bima /etc/bima && cp /tmp/setup/config.yaml /etc/bima/ && ($ENV nohup bima run -config /etc/bima/config.yaml >/tmp/bima.log 2>&1 &)"
wait_until 20 '[[ $($X curl -s -o /dev/null -w %{http_code} http://127.0.0.1:9101/healthz) == 200 ]]'
sleep 3
post=$($X sh -c "$ENV bima check -config /etc/bima/config.yaml --json --send")
check "bima check --send: ok=true" "echo '$post' | jq -e '.ok' >/dev/null"
check "all checks pass except mode=detect warn & geoip skip" "[[ \$(echo '$post' | jq -r '[.checks[]|select(.status!=\"pass\")|.name]|sort|join(\",\")') == geoip,mode ]]"
check "test alert delivered via Discord bot API" '$X curl -s http://127.0.0.1:8090/messages | jq -e "[.messages[]|select(.channel==\"discord-bot\")]|length>0" >/dev/null'
check "probe ;id in detect mode → 200" '[[ $($X curl -s -o /dev/null -w %{http_code} "http://127.0.0.1/?x=;id") == 200 ]]'
check "would-block alert sent" "wait_until 10 '$X curl -s http://127.0.0.1:8090/messages | grep -q WOULD-BLOCK'"

sect "6. Switch to enforce (step 7)"
$X sh -c "sed -i 's/^mode: detect/mode: enforce/' /etc/bima/config.yaml && kill \$(pidof bima); sleep 1; ($ENV nohup bima run -config /etc/bima/config.yaml >>/tmp/bima.log 2>&1 &)"
wait_until 20 '[[ $($X curl -s -o /dev/null -w %{http_code} http://127.0.0.1:9101/healthz) == 200 ]]'; sleep 3
check "legit request 200 in enforce mode" '[[ $($X curl -s -o /dev/null -w %{http_code} "http://127.0.0.1/products?page=2") == 200 ]]'
check "probe ;id in enforce mode → 403" '[[ $($X curl -s -o /dev/null -w %{http_code} "http://127.0.0.1/?x=;id") == 403 ]]'
check "same client now tarpitted (score ≥ 50) → 429" '[[ $($X curl -s -o /dev/null -w %{http_code} --max-time 10 "http://127.0.0.1/products") == 429 ]]'
check "bima check mode now pass" "$X sh -c \"$ENV bima check -config /etc/bima/config.yaml --json\" | jq -e '.checks[]|select(.name==\"mode\" and .status==\"pass\")' >/dev/null"
check "bima version prints" '$X bima version | grep -q "^bima "'

printf "\n════════ SKILL RESULT: %d passed, %d failed ════════\n" $PASS $FAIL
for f in "${FAILED[@]}"; do printf "  - %s\n" "$f"; done
docker rm -f bima-skilltest >/dev/null 2>&1
(( FAIL == 0 ))
