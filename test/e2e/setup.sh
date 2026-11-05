#!/usr/bin/env bash
# Prepare e2e assets (self-signed TLS cert) and start the stack.
set -euo pipefail
cd "$(dirname "$0")/../../deploy/e2e"
mkdir -p certs
if [[ ! -f certs/site.pem ]]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 30 -subj "/CN=e2e.bima.local" \
    -keyout certs/site.key -out certs/site.crt >/dev/null 2>&1
  cat certs/site.crt certs/site.key > certs/site.pem && chmod 644 certs/site.pem
fi
: > bima-blocklist.map
docker compose build bima
docker compose up -d
