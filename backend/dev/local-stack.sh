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
if ! grep -q '[[:space:]]auth\.kanbot\.internal\([[:space:]]\|$\)' /etc/hosts; then
  echo "127.0.0.1 auth.kanbot.internal" | sudo tee -a /etc/hosts >/dev/null
fi
sh dev/auth-setup.sh
docker compose up -d --wait "$@"
