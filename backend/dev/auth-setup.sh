#!/bin/sh
# Generates the local identity providers' (Authelia, Keycloak) certificate
# and secrets into dev/.generated/, which compose mounts into their
# containers, and the local CA's key into dev/.generated-ca/, which it does
# not (both git-ignored). Development only: nothing here may be used in a
# deployment.
#
#   sh dev/auth-setup.sh      (from backend/)
#
# Idempotent: existing files are kept, so running it again changes nothing,
# except certificates that expire within a day, which are renewed. Delete
# both directories to start over.
set -eu

dev="$(cd "$(dirname "$0")" && pwd)"
dir="$dev/.generated"
ca_dir="$dev/.generated-ca"
mkdir -p "$dir"
# The CA key can sign certificates for any name: only its owner reads it.
(umask 077 && mkdir -p "$ca_dir")
chmod 700 "$ca_dir"
ca_key="$ca_dir/ca.key"
cd "$dir"
# Where older versions of this script kept it.
if [ -s ca.key ] && [ ! -s "$ca_key" ]; then
  mv ca.key "$ca_key"
fi
rm -f ca.key

host="auth.kanbot.internal"
# Temporary files, removed however the script ends.
trap 'rm -f "$host.csr" "$host.ext" ca.srl' EXIT

# A file is generated only if it does not exist yet.
missing() { [ ! -s "$1" ]; }

# A certificate is renewed when it is missing or expires within a day.
expiring() { missing "$1" || ! openssl x509 -checkend 86400 -noout -in "$1" >/dev/null; }

# Local certificate authority, trusted by the backend (OIDC_CA_FILE) and
# the tests.
if missing "$ca_key" || expiring ca.crt; then
  (umask 077 && openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$ca_key")
  openssl req -x509 -new -key "$ca_key" -out ca.crt -days 3650 -sha256 \
    -subj "/CN=kanbot local development CA" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"
  rm -f "$host.crt"
fi

# The identity providers' TLS certificate, signed by the CA.
if missing "$host.key" || expiring "$host.crt"; then
  openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$host.key"
  openssl req -new -key "$host.key" -out "$host.csr" -subj "/CN=$host"
  printf '%s\n' \
    "basicConstraints=critical,CA:FALSE" \
    "keyUsage=critical,digitalSignature" \
    "extendedKeyUsage=serverAuth" \
    "subjectAltName=DNS:$host" > "$host.ext"
  openssl x509 -req -in "$host.csr" -CA ca.crt -CAkey "$ca_key" -CAcreateserial \
    -out "$host.crt" -days 825 -sha256 -extfile "$host.ext"
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

# The containers read these as another user. Development secrets only;
# the CA key is not among them.
chmod 644 ./*
chmod 600 "$ca_key"
echo "dev/.generated is ready"
