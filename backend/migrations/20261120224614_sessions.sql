-- The login flow through the backend (docs/oidc.md) and the sessions it
-- creates. Secrets are never stored in plain form: tokens, codes, states and
-- nonces kanbot issues are stored as SHA-256 hashes; IdP tokens and the PKCE
-- verifier are encrypted (XChaCha20-Poly1305, with the key ID in the blob).

-- One sign-in in progress, between /auth/login and /auth/callback.
CREATE TABLE login_attempts (
  id                 uuid PRIMARY KEY,
  state_hash         bytea NOT NULL UNIQUE,
  nonce_hash         bytea NOT NULL,
  pkce_verifier      bytea NOT NULL,
  platform           text NOT NULL CHECK (platform IN ('web', 'native')),
  -- web: the hash of the __Host-kanbot_login cookie that binds the attempt
  -- to the browser that started it.
  browser_binding_hash bytea,
  -- native: where the app receives its one-time code, and its PKCE challenge.
  app_redirect_uri   text,
  app_code_challenge text,
  created_at         timestamptz NOT NULL DEFAULT now(),
  expires_at         timestamptz NOT NULL,
  used_at            timestamptz,
  CHECK (
    (platform = 'web' AND browser_binding_hash IS NOT NULL
      AND app_redirect_uri IS NULL AND app_code_challenge IS NULL)
    OR (platform = 'native' AND browser_binding_hash IS NULL
      AND app_redirect_uri IS NOT NULL AND app_code_challenge IS NOT NULL)
  )
);
CREATE INDEX login_attempts_expires_at ON login_attempts (expires_at);

-- A kanbot session of a web or native app.
CREATE TABLE sessions (
  id                  uuid PRIMARY KEY,
  -- NULL for a native session until the app redeems its one-time code.
  token_hash          bytea UNIQUE,
  user_id             uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
  kind                text NOT NULL CHECK (kind IN ('web', 'native')),
  idp_access_token    bytea NOT NULL,
  idp_refresh_token   bytea,
  idp_id_token        bytea,
  access_expires_at   timestamptz NOT NULL,
  created_at          timestamptz NOT NULL DEFAULT now(),
  last_used_at        timestamptz NOT NULL DEFAULT now(),
  idle_expires_at     timestamptz NOT NULL,
  absolute_expires_at timestamptz NOT NULL,
  CHECK (kind = 'native' OR token_hash IS NOT NULL)
);
CREATE INDEX sessions_user_id ON sessions (user_id);
CREATE INDEX sessions_idle_expires_at ON sessions (idle_expires_at);
CREATE INDEX sessions_absolute_expires_at ON sessions (absolute_expires_at);

-- One-time codes that hand a native session to the app (60 seconds).
CREATE TABLE login_codes (
  code_hash          bytea PRIMARY KEY,
  session_id         uuid NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
  app_code_challenge text NOT NULL,
  expires_at         timestamptz NOT NULL,
  used_at            timestamptz
);
CREATE INDEX login_codes_expires_at ON login_codes (expires_at);
CREATE INDEX login_codes_session_id ON login_codes (session_id);
