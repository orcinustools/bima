#!/usr/bin/env bash
# Cloudflare WAF custom rules generated from Bima's signatures — common variants.
# Print only; paste into Security > WAF > Custom rules, or use apply.sh.
set -euo pipefail

# 1. Defaults: 5 rules (Free plan), ban list + sensitive files + injection + scanners/fake crawlers
bima cloudflare rules

# 2. Without the ban list rule (no ban sync configured)
bima cloudflare rules -list ""

# 3. Site policy: a WordPress newsletter host, AI crawlers blocked, unverified
#    bots from Google Cloud blocked, empty User-Agent blocked except on the API host
bima cloudflare rules \
  -script-hosts newsletter.example.com \
  -ai-bots \
  -cloud-asn 396982 \
  -block-empty-ua -empty-ua-allow api.example.com

# 4. Challenge instead of block, skip injection checks on a webhook receiver
bima cloudflare rules -action managed_challenge -exempt-path /webhooks/

# 5. API payload (PUT .../rulesets/phases/http_request_firewall_custom/entrypoint)
bima cloudflare rules -format json > bima-cf-rules.json

# 6. Terraform (cloudflare/cloudflare v5)
bima cloudflare rules -format terraform > bima-cf-rules.tf
