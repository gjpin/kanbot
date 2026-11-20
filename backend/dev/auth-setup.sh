#!/bin/sh
# Generates the local Authelia's certificates and secrets into
# dev/.generated/ (git-ignored). Development only: nothing here may be used
# in a deployment.
#
#   sh dev/auth-setup.sh      (from backend/)
#
# Idempotent: existing files are kept, so running it again changes nothing.
# Delete dev/.generated/ to start over.
set -eu

dir="$(cd "$(dirname "$0")" && pwd)/.generated"
mkdir -p "$dir"
cd "$dir"

host="auth.kanbot.internal"

# A file is generated only if it does not exist yet.
missing() { [ ! -s "$1" ]; }

# Local certificate authority, trusted by the backend (OIDC_CA_FILE) and
# the tests.
if missing ca.key || missing ca.crt; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out ca.key
  openssl req -x509 -new -key ca.key -out ca.crt -days 3650 -sha256 \
    -subj "/CN=kanbot local development CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
  rm -f "$host.crt"
fi

# Authelia's TLS certificate, signed by the CA.
if missing "$host.key" || missing "$host.crt"; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$host.key"
  openssl req -new -key "$host.key" -out "$host.csr" -subj "/CN=$host"
  printf '%s\n' \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=serverAuth" \
    "subjectAltName=DNS:$host" > "$host.ext"
  openssl x509 -req -in "$host.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "$host.crt" -days 825 -sha256 -extfile "$host.ext"
  rm -f "$host.csr" "$host.ext" ca.srl
fi

# Authelia's secrets, read through its *_FILE environment variables.
for secret in jwt_secret session_secret storage_encryption_key oidc_hmac_secret; do
  if missing "$secret"; then
    openssl rand -hex 32 > "$secret"
  fi
done

# The OIDC provider's token signing key.
if missing oidc_jwks_rsa.pem; then
  openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out oidc_jwks_rsa.pem
fi

# The container reads these as another user. Development secrets only.
chmod 644 ./*
echo "dev/.generated is ready"
