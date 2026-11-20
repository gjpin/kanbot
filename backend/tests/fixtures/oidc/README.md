# OIDC test fixtures: test-only

**Everything in this folder is for tests only.** The keys and certificates
here are public, committed on purpose, and must never be used for anything
else: no deployment, no development stack, no signing of real tokens. A
secret scanner needs an allowlist for this folder.

They were generated with OpenSSL. Regenerating a file breaks nothing as long
as the tests that use it still pass.

| File | What | Used by |
|---|---|---|
| `ca.crt` | Self-signed P-256 CA certificate, valid 100 years | `auth::config` tests (`OIDC_CA_FILE`) |

```sh
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -keyout /dev/null -out ca.crt -days 36500 -subj "/CN=kanbot test CA (test-only)"
```
