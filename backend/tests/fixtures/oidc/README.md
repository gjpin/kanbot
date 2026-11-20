# OIDC test fixtures: test-only

**Everything in this folder is for tests only.** The keys and certificates
here are public, committed on purpose, and must never be used for anything
else: no deployment, no development stack, no signing of real tokens. A
secret scanner needs an allowlist for this folder.

They were generated with OpenSSL. Regenerating a file breaks nothing as long
as the tests that use it still pass.

| File | What | Used by |
|---|---|---|
| `rsa-a.pem`, `rsa-a.jwk.json` | RSA-2048 signing key A and its public JWK | the default key of `tests/common/idp.rs` |
| `rsa-b.pem`, `rsa-b.jwk.json` | RSA-2048 signing key B | key rotation, forged signatures |
| `rsa-1024.pem`, `rsa-1024.jwk.json` | RSA-1024 key, too weak: must be ignored | key filtering |
| `p256.pem`, `p256.jwk.json` | EC P-256 key (ES256) | algorithms |
| `p384.pem`, `p384.jwk.json` | EC P-384 key (ES384) | algorithms |
| `ed25519.pem`, `ed25519.jwk.json` | Ed25519 key (EdDSA) | algorithms |
| `ca.crt` | Self-signed P-256 CA certificate, valid 100 years | `auth::config` tests (`OIDC_CA_FILE`) |

Each JWK has `kid` = its file name and `use: sig`, and no `alg`, so tests
check that kanbot derives the algorithm from the key type.

```sh
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa-a.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa-b.pem
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out rsa-1024.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out p256.pem
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384 -out p384.pem
openssl genpkey -algorithm ED25519 -out ed25519.pem
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout /dev/null -out ca.crt -days 36500 -subj "/CN=kanbot test CA (test-only)"
```

The JWKs were derived from the public keys (`openssl pkey -pubout -outform
DER`): for RSA, `n` is the modulus (`openssl rsa -pubin -modulus`) and `e` is
`AQAB` (65537); for EC, `x` and `y` are the two halves of the uncompressed
point at the end of the DER; for Ed25519, `x` is its last 32 bytes. All
values are unpadded base64url.
