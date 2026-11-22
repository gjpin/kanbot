//! Access-token validation (`auth::token`) against tokens signed with the
//! fixture keys: what is accepted, and why everything else is refused.

pub mod common;

use common::idp::{self, DEFAULT_KEYS, base64url, encoding_key, jwk, sign, sign_with_header};
use jsonwebtoken::{Algorithm, EncodingKey};
use kanbot_backend::auth::{
    config::OidcConfig,
    keys::KeySet,
    token::{MAX_TOKEN_BYTES, PlatformRole, Principal, Rejection, UnverifiedToken},
};
use serde_json::{Value, json};

const ISSUER: &str = "https://auth.example.com";
const NOW: u64 = 1_800_000_000;

fn config(extra: &[(&'static str, &str)]) -> OidcConfig {
    let mut vars = vec![("OIDC_ISSUER", ISSUER)];
    vars.extend_from_slice(extra);
    idp::config(ISSUER, &vars)
}

fn keys(extra: &[Value]) -> KeySet {
    let mut keys: Vec<Value> = DEFAULT_KEYS.iter().map(|name| jwk(name)).collect();
    keys.extend_from_slice(extra);
    KeySet::from_jwks(&keys)
}

fn claims() -> Value {
    json!({
        "iss": ISSUER,
        "aud": "kanbot-api",
        "sub": "user-1",
        "exp": 1_800_000_300_u64,
        "iat": NOW,
        "groups": ["kanbot-user", "staff"],
        "azp": "kanbot-cli",
        "name": "Alice",
    })
}

fn with(mut claims: Value, field: &str, value: Value) -> Value {
    claims[field] = value;
    claims
}

fn without(mut claims: Value, field: &str) -> Value {
    claims.as_object_mut().unwrap().remove(field);
    claims
}

fn validate_with(token: &str, config: &OidcConfig, keys: &KeySet) -> Result<Principal, Rejection> {
    let token = UnverifiedToken::parse(token)?;
    let key = keys.get(token.kid()).ok_or(Rejection::UnknownKey)?;
    token.verify(&key, config, NOW)
}

fn validate(token: &str) -> Result<Principal, Rejection> {
    validate_with(token, &config(&[]), &keys(&[]))
}

#[test]
fn accepts_a_valid_token() {
    let principal = validate(&sign("rsa-a", &claims())).unwrap();
    assert_eq!(
        principal,
        Principal {
            issuer: ISSUER.to_owned(),
            subject: "user-1".to_owned(),
            role: PlatformRole::User,
            client_id: Some("kanbot-cli".to_owned()),
            display_name: Some("Alice".to_owned()),
            groups: Some(vec!["kanbot-user".to_owned(), "staff".to_owned()]),
            expires_at: 1_800_000_300,
        }
    );
}

#[test]
fn accepts_each_supported_algorithm() {
    for name in ["rsa-a", "p256", "p384", "ed25519"] {
        assert!(validate(&sign(name, &claims())).is_ok(), "{name}");
    }
    for alg in [
        Algorithm::RS256,
        Algorithm::RS384,
        Algorithm::RS512,
        Algorithm::PS256,
        Algorithm::PS384,
        Algorithm::PS512,
    ] {
        let kid = format!("rsa-{alg:?}");
        let mut key = jwk("rsa-b");
        key["kid"] = json!(kid);
        key["alg"] = json!(alg);
        let token = sign_with_header(
            &json!({ "alg": alg, "kid": kid }),
            &encoding_key("rsa-b"),
            alg,
            &claims(),
        );
        assert!(
            validate_with(&token, &config(&[]), &keys(&[key])).is_ok(),
            "{alg:?}"
        );
    }
}

#[test]
fn time_claims() {
    // Within the 60 s leeway.
    assert!(
        validate(&sign(
            "rsa-a",
            &with(claims(), "exp", json!(1_799_999_940_u64))
        ))
        .is_ok()
    );
    assert_eq!(
        validate(&sign(
            "rsa-a",
            &with(claims(), "exp", json!(1_799_999_939_u64))
        )),
        Err(Rejection::Expired)
    );
    assert_eq!(
        validate(&sign(
            "rsa-a",
            &with(claims(), "nbf", json!(1_800_000_061_u64))
        )),
        Err(Rejection::NotYetValid)
    );
    assert!(
        validate(&sign(
            "rsa-a",
            &with(claims(), "nbf", json!(1_800_000_060_u64))
        ))
        .is_ok()
    );
    assert_eq!(
        validate(&sign(
            "rsa-a",
            &with(claims(), "iat", json!(1_800_000_061_u64))
        )),
        Err(Rejection::NotYetValid)
    );
    assert!(validate(&sign("rsa-a", &without(claims(), "iat"))).is_ok());
}

#[test]
fn each_required_claim_is_required() {
    for claim in ["exp", "iss", "aud", "sub"] {
        assert_eq!(
            validate(&sign("rsa-a", &without(claims(), claim))),
            Err(Rejection::MissingClaim),
            "{claim}"
        );
    }
}

#[test]
fn issuer_must_match_exactly() {
    for iss in [
        json!(format!("{ISSUER}/")),
        json!("https://AUTH.example.com"),
        json!("https://evil.example.com"),
        json!([ISSUER]),
    ] {
        assert_eq!(
            validate(&sign("rsa-a", &with(claims(), "iss", iss.clone()))),
            Err(Rejection::WrongIssuer),
            "{iss}"
        );
    }
}

#[test]
fn audience_may_be_a_string_or_an_array_containing_ours() {
    assert!(validate(&sign("rsa-a", &with(claims(), "aud", json!("kanbot-api")))).is_ok());
    assert!(
        validate(&sign(
            "rsa-a",
            &with(claims(), "aud", json!(["openshell-gateway", "kanbot-api"]))
        ))
        .is_ok()
    );
    for aud in [
        json!("openshell-gateway"),
        json!(["openshell-gateway"]),
        json!([]),
    ] {
        assert_eq!(
            validate(&sign("rsa-a", &with(claims(), "aud", aud.clone()))),
            Err(Rejection::WrongAudience),
            "{aud}"
        );
    }
}

#[test]
fn issuer_and_audience_of_the_wrong_type_count_as_missing() {
    for claim in ["iss", "aud"] {
        assert_eq!(
            validate(&sign("rsa-a", &with(claims(), claim, json!(42)))),
            Err(Rejection::MissingClaim),
            "{claim}"
        );
    }
}

#[test]
fn an_id_token_is_not_an_access_token() {
    // An ID token's audience is the client it was issued to.
    let id_token = with(with(claims(), "aud", json!("kanbot")), "nonce", json!("n"));
    assert_eq!(
        validate(&sign("rsa-a", &id_token)),
        Err(Rejection::WrongAudience)
    );
}

#[test]
fn alg_none_is_refused() {
    let token = format!(
        "{}.{}.",
        base64url(
            json!({ "alg": "none", "kid": "rsa-a" })
                .to_string()
                .as_bytes()
        ),
        base64url(claims().to_string().as_bytes())
    );
    assert_eq!(validate(&token), Err(Rejection::Malformed));
    let with_signature = format!("{token}c2ln");
    assert_eq!(validate(&with_signature), Err(Rejection::Malformed));
}

#[test]
fn hmac_signed_with_the_public_key_is_refused() {
    let public_key = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/oidc/rsa-a.jwk.json"
    ))
    .unwrap();
    for alg in [Algorithm::HS256, Algorithm::HS384, Algorithm::HS512] {
        let token = sign_with_header(
            &json!({ "alg": alg, "kid": "rsa-a" }),
            &EncodingKey::from_secret(&public_key).unwrap(),
            alg,
            &claims(),
        );
        assert_eq!(validate(&token), Err(Rejection::BadAlgorithm), "{alg:?}");
    }
}

#[test]
fn an_rsa_key_without_alg_verifies_any_rsa_algorithm() {
    // As Entra ID publishes them: `alg` is optional (RFC 7517).
    for alg in [Algorithm::RS384, Algorithm::PS256, Algorithm::PS512] {
        let token = sign_with_header(
            &json!({ "alg": alg, "kid": "rsa-a" }),
            &encoding_key("rsa-a"),
            alg,
            &claims(),
        );
        assert!(validate(&token).is_ok(), "{alg:?}");
    }
}

#[test]
fn header_alg_must_match_the_key() {
    // A real RS384 signature with the right key, but the key says RS256.
    let mut key = jwk("rsa-a");
    key["alg"] = json!("RS256");
    key["kid"] = json!("rsa-rs256");
    let token = sign_with_header(
        &json!({ "alg": "RS384", "kid": "rsa-rs256" }),
        &encoding_key("rsa-a"),
        Algorithm::RS384,
        &claims(),
    );
    assert_eq!(
        validate_with(&token, &config(&[]), &keys(&[key])),
        Err(Rejection::BadAlgorithm)
    );
    // An EC signature presented under an RSA kid.
    let token = sign_with_header(
        &json!({ "alg": "ES256", "kid": "rsa-a" }),
        &encoding_key("p256"),
        Algorithm::ES256,
        &claims(),
    );
    assert_eq!(validate(&token), Err(Rejection::BadAlgorithm));
}

#[test]
fn signature_must_verify() {
    let forged = sign_with_header(
        &json!({ "alg": "RS256", "kid": "rsa-a" }),
        &encoding_key("rsa-b"),
        Algorithm::RS256,
        &claims(),
    );
    assert_eq!(validate(&forged), Err(Rejection::BadSignature));

    // A valid signature over other claims.
    let token = sign("rsa-a", &claims());
    let (rest, signature) = token.rsplit_once('.').unwrap();
    let (header, _) = rest.split_once('.').unwrap();
    let admin = with(claims(), "groups", json!(["kanbot-admin"]));
    let tampered = format!(
        "{header}.{}.{signature}",
        base64url(admin.to_string().as_bytes())
    );
    assert_eq!(validate(&tampered), Err(Rejection::BadSignature));
}

#[test]
fn kid_is_required_and_must_be_known() {
    let token = sign_with_header(
        &json!({ "alg": "RS256" }),
        &encoding_key("rsa-a"),
        Algorithm::RS256,
        &claims(),
    );
    assert_eq!(validate(&token), Err(Rejection::Malformed));
    // Not served: rsa-b is not in the set, and rsa-1024 is too weak.
    for name in ["rsa-b", "rsa-1024"] {
        assert_eq!(
            validate_with(
                &sign(name, &claims()),
                &config(&[]),
                &keys(&[jwk("rsa-1024")])
            ),
            Err(Rejection::UnknownKey),
            "{name}"
        );
    }
}

#[test]
fn crit_headers_are_refused() {
    for crit in [json!(["exp"]), json!(["b64"]), json!([])] {
        let token = sign_with_header(
            &json!({ "alg": "RS256", "kid": "rsa-a", "crit": crit, "b64": true }),
            &encoding_key("rsa-a"),
            Algorithm::RS256,
            &claims(),
        );
        assert_eq!(validate(&token), Err(Rejection::Malformed), "{crit}");
    }
}

#[test]
fn tokens_up_to_16_kib_are_read() {
    // A real, large token (big claims are common with many groups).
    let large = with(claims(), "pad", json!("x".repeat(10_000)));
    assert!(validate(&sign("rsa-a", &large)).is_ok());
    // Exactly at the limit: refused for its shape, not its size.
    assert_eq!(
        validate(&"a".repeat(MAX_TOKEN_BYTES)),
        Err(Rejection::Malformed)
    );
    assert_eq!(
        validate(&"a".repeat(MAX_TOKEN_BYTES + 1)),
        Err(Rejection::TooLarge)
    );
}

#[test]
fn an_empty_signature_is_malformed() {
    let valid = sign("rsa-a", &claims());
    let (unsigned, _) = valid.rsplit_once('.').unwrap();
    assert_eq!(validate(&format!("{unsigned}.")), Err(Rejection::Malformed));
}

#[test]
fn malformed_input_is_refused() {
    let valid = sign("rsa-a", &claims());
    let oversized = with(claims(), "pad", json!("x".repeat(MAX_TOKEN_BYTES)));
    assert_eq!(
        validate(&sign("rsa-a", &oversized)),
        Err(Rejection::TooLarge)
    );
    for token in [
        String::new(),
        "opaque-access-token-1234".to_owned(),
        "a.b".to_owned(),
        "a.b.c.d".to_owned(),
        format!("{valid}.extra"),
        valid.replacen('.', "..", 1),
        valid.replace('-', "+"),
        format!("{valid}="),
        format!(" {valid}"),
        "e30.e30.e30".to_owned(),
        "!!!.e30.e30".to_owned(),
    ] {
        if token == valid {
            continue;
        }
        assert_eq!(validate(&token), Err(Rejection::Malformed), "{token}");
    }
}

#[test]
fn roles_claim() {
    let role = |groups: Value| validate(&sign("rsa-a", &with(claims(), "groups", groups)));
    assert_eq!(
        role(json!(["kanbot-user"])).unwrap().role,
        PlatformRole::User
    );
    assert_eq!(
        role(json!(["kanbot-admin"])).unwrap().role,
        PlatformRole::Admin
    );
    assert_eq!(
        role(json!(["kanbot-user", "kanbot-admin"])).unwrap().role,
        PlatformRole::Admin
    );
    // Non-string items are ignored.
    let principal = role(json!([1, null, {"x": 1}, "kanbot-user"])).unwrap();
    assert_eq!(principal.role, PlatformRole::User);
    assert_eq!(principal.groups.unwrap(), ["kanbot-user"]);

    for groups in [
        json!(["staff"]),
        json!([]),
        json!("kanbot-user"),
        json!({ "kanbot-user": true }),
        json!(["Kanbot-User"]),
    ] {
        assert_eq!(role(groups.clone()), Err(Rejection::NoRole), "{groups}");
    }
    assert_eq!(
        validate(&sign("rsa-a", &without(claims(), "groups"))),
        Err(Rejection::NoRole)
    );
}

#[test]
fn nested_roles_claim() {
    let config = config(&[("OIDC_ROLES_CLAIM", "realm_access.roles")]);
    let claims = with(
        without(claims(), "groups"),
        "realm_access",
        json!({ "roles": ["kanbot-admin"] }),
    );
    let principal = validate_with(&sign("rsa-a", &claims), &config, &keys(&[])).unwrap();
    assert_eq!(principal.role, PlatformRole::Admin);

    let flat = with(claims, "realm_access", json!(["kanbot-admin"]));
    assert_eq!(
        validate_with(&sign("rsa-a", &flat), &config, &keys(&[])),
        Err(Rejection::NoRole)
    );
}

#[test]
fn groups_come_from_the_groups_claim() {
    let config = config(&[("OIDC_GROUPS_CLAIM", "teams")]);
    let claims = with(claims(), "teams", json!(["platform", 7, "ops"]));
    let principal = validate_with(&sign("rsa-a", &claims), &config, &keys(&[])).unwrap();
    assert_eq!(principal.groups.unwrap(), ["platform", "ops"]);
    assert_eq!(principal.role, PlatformRole::User);

    // An empty claim is known to be empty.
    let empty = with(claims.clone(), "teams", json!([]));
    let principal = validate_with(&sign("rsa-a", &empty), &config, &keys(&[])).unwrap();
    assert_eq!(principal.groups, Some(Vec::new()));

    // No groups claim, or not an array: unknown, still signed in.
    for claims in [
        without(claims.clone(), "teams"),
        with(claims, "teams", json!("platform")),
    ] {
        let principal = validate_with(&sign("rsa-a", &claims), &config, &keys(&[])).unwrap();
        assert_eq!(principal.groups, None);
    }
}

#[test]
fn values_the_database_cannot_store_are_dropped() {
    let principal = validate(&sign(
        "rsa-a",
        &with(
            with(claims(), "groups", json!(["kanbot-user", "bad\u{0}group"])),
            "name",
            json!("Al\u{0}ice"),
        ),
    ))
    .unwrap();
    assert_eq!(principal.groups.unwrap(), ["kanbot-user"]);
    assert_eq!(principal.display_name, None);
}

#[test]
fn long_display_names_are_cut() {
    let name = "é".repeat(500);
    let principal = validate(&sign("rsa-a", &with(claims(), "name", json!(name)))).unwrap();
    assert_eq!(principal.display_name.unwrap().chars().count(), 200);
}

#[test]
fn an_empty_client_claim_falls_through_to_the_next() {
    let claims = with(
        with(claims(), "azp", json!("")),
        "client_id",
        json!("kanbot-cli"),
    );
    assert_eq!(
        validate(&sign("rsa-a", &claims))
            .unwrap()
            .client_id
            .as_deref(),
        Some("kanbot-cli")
    );
}

#[test]
fn debug_output_leaves_out_personal_data() {
    let principal = validate(&sign("rsa-a", &claims())).unwrap();
    let debug = format!("{principal:?}");
    assert!(
        !debug.contains("Alice") && !debug.contains("user-1") && !debug.contains("staff"),
        "{debug}"
    );
    assert!(debug.contains("kanbot-cli"), "{debug}");
}

#[test]
fn only_jwt_access_and_id_token_types_are_accepted() {
    let token = |typ: Value| {
        sign_with_header(
            &json!({ "alg": "RS256", "kid": "rsa-a", "typ": typ }),
            &encoding_key("rsa-a"),
            Algorithm::RS256,
            &claims(),
        )
    };
    for typ in [
        "JWT",
        "jwt",
        "at+jwt",
        "application/at+JWT",
        "application/jwt",
    ] {
        assert!(validate(&token(json!(typ))).is_ok(), "{typ}");
    }
    for typ in ["logout+jwt", "dpop+jwt", "secevent+jwt", "JOSE", ""] {
        assert_eq!(
            validate(&token(json!(typ))),
            Err(Rejection::Malformed),
            "{typ}"
        );
    }
}

#[test]
fn foreign_tokens_are_verified_for_their_own_audience() {
    let config = config(&[]);
    let keys = keys(&[]);
    let verify = |claims: &Value| {
        let token = sign("rsa-a", claims);
        let token = UnverifiedToken::parse(&token)?;
        let key = keys.get(token.kid()).ok_or(Rejection::UnknownKey)?;
        token.verify_foreign(&key, &config, "openshell-gateway", NOW)
    };
    let gateway = with(claims(), "aud", json!(["openshell-gateway", "other"]));
    let verified = verify(&gateway).unwrap();
    assert_eq!(verified.audiences, ["openshell-gateway", "other"]);
    assert_eq!(verified.subject.as_deref(), Some("user-1"));
    assert_eq!(verified.expires_at, 1_800_000_300);
    // No role needed; the subject is optional.
    assert!(verify(&without(without(gateway.clone(), "groups"), "sub")).is_ok());
    assert_eq!(verify(&claims()), Err(Rejection::WrongAudience));
    assert_eq!(
        verify(&with(
            gateway.clone(),
            "iss",
            json!("https://other.example.com")
        )),
        Err(Rejection::WrongIssuer)
    );
    assert_eq!(
        verify(&with(gateway.clone(), "exp", json!(NOW - 61))),
        Err(Rejection::Expired)
    );
    let forged = sign_with_header(
        &json!({ "alg": "RS256", "kid": "rsa-a" }),
        &encoding_key("rsa-b"),
        Algorithm::RS256,
        &gateway,
    );
    let parsed = UnverifiedToken::parse(&forged).unwrap();
    assert_eq!(
        parsed.verify_foreign(
            &keys.get("rsa-a").unwrap(),
            &config,
            "openshell-gateway",
            NOW
        ),
        Err(Rejection::BadSignature)
    );
}

#[test]
fn subject_claim_is_configurable() {
    let config = config(&[("OIDC_SUBJECT_CLAIM", "oid")]);
    let claims = with(claims(), "oid", json!("object-id"));
    let principal = validate_with(&sign("rsa-a", &claims), &config, &keys(&[])).unwrap();
    assert_eq!(principal.subject, "object-id");

    for oid in [Value::Null, json!(""), json!(5)] {
        let claims = with(claims.clone(), "oid", oid.clone());
        assert_eq!(
            validate_with(&sign("rsa-a", &claims), &config, &keys(&[])),
            Err(Rejection::MissingClaim),
            "{oid}"
        );
    }
}

#[test]
fn client_allowlist_reads_azp_then_client_id_then_cid() {
    let config = config(&[("OIDC_ALLOWED_CLIENTS", "kanbot-cli")]);
    let check = |claims: &Value| validate_with(&sign("rsa-a", claims), &config, &keys(&[]));
    let base = without(claims(), "azp");

    for claim in ["azp", "client_id", "cid"] {
        let allowed = with(base.clone(), claim, json!("kanbot-cli"));
        assert_eq!(
            check(&allowed).unwrap().client_id.as_deref(),
            Some("kanbot-cli"),
            "{claim}"
        );
        let other = with(base.clone(), claim, json!("other"));
        assert_eq!(check(&other), Err(Rejection::ClientNotAllowed), "{claim}");
    }
    assert_eq!(check(&base), Err(Rejection::ClientNotAllowed));
    // azp comes first.
    let both = with(
        with(base.clone(), "azp", json!("other")),
        "client_id",
        json!("kanbot-cli"),
    );
    assert_eq!(check(&both), Err(Rejection::ClientNotAllowed));
    let both = with(
        with(base, "client_id", json!("other")),
        "cid",
        json!("kanbot-cli"),
    );
    assert_eq!(check(&both), Err(Rejection::ClientNotAllowed));
}

#[test]
fn any_client_is_accepted_without_an_allowlist() {
    let principal = validate(&sign("rsa-a", &without(claims(), "azp"))).unwrap();
    assert_eq!(principal.client_id, None);
}

#[test]
fn display_name_is_name_then_preferred_username() {
    let display = |claims: Value| validate(&sign("rsa-a", &claims)).unwrap().display_name;
    assert_eq!(display(claims()).as_deref(), Some("Alice"));
    let username = with(
        without(claims(), "name"),
        "preferred_username",
        json!("alice"),
    );
    assert_eq!(display(username).as_deref(), Some("alice"));
    assert_eq!(display(without(claims(), "name")), None);
    assert_eq!(display(with(claims(), "name", json!(""))), None);
}
