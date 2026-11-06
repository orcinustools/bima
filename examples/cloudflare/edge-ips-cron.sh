#!/usr/bin/env bash
# /etc/cron.monthly/bima-cloudflare-ips — keep the Cloudflare edge list fresh
# (origin behind Cloudflare: haproxy acl + cloudflare.edge_ips_file).
set -euo pipefail
f=/etc/haproxy/bima-cloudflare.lst
bima cloudflare ips -fetch -o "$f.new"
if ! cmp -s "$f" "$f.new"; then
  mv "$f.new" "$f"
  haproxy -c -f /etc/haproxy/haproxy.cfg && systemctl reload haproxy && systemctl restart bima
else
  rm -f "$f.new"
fi
