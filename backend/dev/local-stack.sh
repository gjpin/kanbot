#!/bin/sh
# Starts the local stack of backend/AGENTS.md: auth.kanbot.internal in
# /etc/hosts (with sudo, once), the certificates and secrets of
# dev/auth-setup.sh, then the compose services named (all of them when none
# is: Postgres, Authelia and Keycloak), waiting until they are healthy.
# Development and CI only.
#
#   sh dev/local-stack.sh                    (from backend/)
#   sh dev/local-stack.sh postgres authelia
set -eu
cd "$(dirname "$0")/.."
# Only an active entry for loopback counts, not a comment or another address.
if ! grep -Eq '^[[:space:]]*127\.0\.0\.1[[:space:]]([^#]*[[:space:]])?auth\.kanbot\.internal([[:space:]]|$)' /etc/hosts; then
  echo "127.0.0.1 auth.kanbot.internal" | sudo tee -a /etc/hosts >/dev/null
fi
sh dev/auth-setup.sh
docker compose up -d --wait "$@"
