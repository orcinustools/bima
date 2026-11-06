#!/usr/bin/env bash
# Install / update Bima's custom rules in a zone. Other custom rules are kept;
# the bima_* rules are updated in place on every run.
# Token: Zone > Zone WAF > Edit (+ Account > Account Filter Lists > Edit for -account).
set -euo pipefail
: "${BIMA_CLOUDFLARE_API_TOKEN:?set the API token}"
ZONE=${ZONE:?zone id}          # domain Overview page, right column
ACCOUNT=${ACCOUNT:?account id}

# plan only (nothing is written)
bima cloudflare apply -zone "$ZONE" -account "$ACCOUNT" -ai-bots

# apply after reviewing the plan
read -rp "apply? [y/N] " a
[[ $a == y ]] && bima cloudflare apply -zone "$ZONE" -account "$ACCOUNT" -ai-bots -yes

# The Free plan allows 5 custom rules. If older hand-written copies of these
# checks exist, delete them in the dashboard, or (dropping ALL non-Bima rules):
#   bima cloudflare apply -zone "$ZONE" -account "$ACCOUNT" -replace-existing -yes
