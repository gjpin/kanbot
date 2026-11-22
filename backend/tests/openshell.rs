//! The `OpenShell` integration against a fake gateway (`common/openshell.rs`).

pub mod common;

use std::collections::HashMap;

use common::openshell::{FakeGateway, Paging};
use kanbot_backend::openshell::{
    config::OpenShellConfig,
    gateway::{Added, Gateway, GatewayError, Member},
    model::{MemberRole, WorkspaceName},
};
use secrecy::SecretString;
use tonic::Code;

fn config(gateway: &str) -> OpenShellConfig {
    config_with(&[
        ("OPENSHELL_GATEWAY_URL", gateway),
        ("OPENSHELL_DANGEROUSLY_ALLOW_INSECURE_HTTP", "true"),
    ])
}

/// The configuration with `vars` besides the client's.
fn config_with(vars: &[(&'static str, &str)]) -> OpenShellConfig {
    let vars: HashMap<&'static str, String> = [
        ("OPENSHELL_AUDIENCE", "openshell-gateway"),
        ("OPENSHELL_CLIENT_ID", "kanbot-openshell"),
        ("OPENSHELL_CLIENT_SECRET", "openshell-test-secret"),
    ]
    .iter()
    .chain(vars)
    .map(|(name, value)| (*name, (*value).to_owned()))
    .collect();
    OpenShellConfig::from_lookup(
        &move |name| {
            vars.get(name)
                .cloned()
                .ok_or(std::env::VarError::NotPresent)
        },
        "kanbot-api",
    )
    .unwrap()
    .unwrap()
}

fn workspace(name: &str) -> WorkspaceName {
    WorkspaceName::parse(name).unwrap()
}

#[tokio::test]
async fn the_gateway_client_manages_members_with_its_token() {
    let fake = FakeGateway::default();
    fake.workspace("research");
    fake.accept("gw-token");
    let gateway = Gateway::new(&config(&fake.start().await)).unwrap();
    let token = SecretString::from("gw-token");

    assert!(
        gateway
            .workspace_exists(&token, &workspace("research"))
            .await
            .unwrap()
    );
    assert!(
        !gateway
            .workspace_exists(&token, &workspace("nope"))
            .await
            .unwrap()
    );

    for (subject, role) in [
        ("a", MemberRole::Admin),
        ("b", MemberRole::User),
        ("c", MemberRole::User),
    ] {
        assert_eq!(
            gateway
                .add_member(&token, &workspace("research"), subject, role)
                .await
                .unwrap(),
            Added::Added
        );
    }
    // Adding a member already there is no failure, but says so.
    assert_eq!(
        gateway
            .add_member(&token, &workspace("research"), "a", MemberRole::User)
            .await
            .unwrap(),
        Added::AlreadyMember
    );
    // Three members over two pages.
    let members = gateway
        .members(&token, &workspace("research"))
        .await
        .unwrap();
    assert_eq!(
        members,
        [
            Member {
                subject: "a".to_owned(),
                role: Some(MemberRole::Admin)
            },
            Member {
                subject: "b".to_owned(),
                role: Some(MemberRole::User)
            },
            Member {
                subject: "c".to_owned(),
                role: Some(MemberRole::User)
            },
        ]
    );

    gateway
        .remove_member(&token, &workspace("research"), "b")
        .await
        .unwrap();
    // Already absent is fine.
    gateway
        .remove_member(&token, &workspace("research"), "b")
        .await
        .unwrap();
    assert_eq!(
        gateway
            .members(&token, &workspace("research"))
            .await
            .unwrap()
            .len(),
        2
    );

    let state = fake.state.lock().unwrap();
    assert!(
        state
            .tokens
            .iter()
            .all(|header| header == "Bearer gw-token")
    );
    assert_eq!(
        state.changes,
        [
            "add research a 2",
            "add research b 1",
            "add research c 1",
            "remove research b",
            "remove research b",
        ]
    );
}

#[tokio::test]
async fn gateway_failures_are_typed() {
    let fake = FakeGateway::default();
    fake.workspace("research");
    let gateway = Gateway::new(&config(&fake.start().await)).unwrap();
    let wrong = SecretString::from("not-accepted");
    assert!(matches!(
        gateway
            .workspace_exists(&wrong, &workspace("research"))
            .await,
        Err(GatewayError::Refused)
    ));
    assert!(matches!(
        gateway.members(&wrong, &workspace("research")).await,
        Err(GatewayError::Refused)
    ));

    // Nothing listens there.
    let closed = Gateway::new(&config("http://127.0.0.1:1")).unwrap();
    assert!(matches!(
        closed
            .workspace_exists(&wrong, &workspace("research"))
            .await,
        Err(GatewayError::Unavailable)
    ));
}

#[tokio::test]
async fn odd_member_lists_are_refused() {
    let fake = FakeGateway::default();
    fake.workspace("research");
    fake.accept("gw-token");
    let gateway = Gateway::new(&config(&fake.start().await)).unwrap();
    let token = SecretString::from("gw-token");
    let list = async || gateway.members(&token, &workspace("research")).await;

    fake.state.lock().unwrap().paging = Paging::Repeat;
    assert!(matches!(list().await, Err(GatewayError::RepeatedPage)));
    assert_eq!(
        fake.lists_of("research"),
        2,
        "the repeat is noticed at once"
    );

    fake.state.lock().unwrap().paging = Paging::Endless;
    assert!(matches!(list().await, Err(GatewayError::TooManyMembers)));
    assert_eq!(fake.lists_of("research"), 2 + 100, "at most 100 pages");
}

#[tokio::test]
async fn messages_over_a_mebibyte_are_refused() {
    let fake = FakeGateway::default();
    fake.accept("gw-token");
    let gateway = Gateway::new(&config(&fake.start().await)).unwrap();
    let token = SecretString::from("gw-token");
    for (name, subject_bytes) in [("large", 1000 * 1024), ("too-large", 1024 * 1024)] {
        fake.workspace(name);
        fake.state
            .lock()
            .unwrap()
            .workspaces
            .get_mut(name)
            .unwrap()
            .insert("s".repeat(subject_bytes), 1);
    }
    assert_eq!(
        gateway
            .members(&token, &workspace("large"))
            .await
            .unwrap()
            .len(),
        1
    );
    assert!(matches!(
        gateway.members(&token, &workspace("too-large")).await,
        Err(GatewayError::Other(Code::OutOfRange))
    ));
}

mod tls {
    use super::*;

    const CERTIFICATE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/dev/.generated/auth.kanbot.internal.crt"
    );
    const KEY: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/dev/.generated/auth.kanbot.internal.key"
    );

    /// A fake gateway over TLS, with the local stack's certificate for
    /// `auth.kanbot.internal` (dev/auth-setup.sh), which resolves to
    /// loopback; its port.
    async fn serve(fake: &FakeGateway) -> u16 {
        fake.workspace("research");
        fake.accept("gw-token");
        let certificate = std::fs::read(CERTIFICATE).expect("run dev/auth-setup.sh");
        let key = std::fs::read(KEY).expect("run dev/auth-setup.sh");
        fake.start_tls(&certificate, &key).await
    }

    async fn reach(url: &str, ca_file: Option<&str>) -> Result<bool, GatewayError> {
        let mut vars = vec![("OPENSHELL_GATEWAY_URL", url)];
        vars.extend(ca_file.map(|path| ("OPENSHELL_CA_FILE", path)));
        Gateway::new(&config_with(&vars))
            .unwrap()
            .workspace_exists(&SecretString::from("gw-token"), &workspace("research"))
            .await
    }

    #[tokio::test]
    async fn the_gateway_is_reached_over_tls_trusting_the_ca_file() {
        let fake = FakeGateway::default();
        let port = serve(&fake).await;
        let url = format!("https://auth.kanbot.internal:{port}");
        assert!(reach(&url, Some(common::authelia::CA_FILE)).await.unwrap());
        assert_eq!(fake.state.lock().unwrap().tokens, ["Bearer gw-token"]);
    }

    #[tokio::test]
    async fn an_untrusted_certificate_is_refused() {
        let fake = FakeGateway::default();
        let port = serve(&fake).await;
        let url = format!("https://auth.kanbot.internal:{port}");
        // The local CA is not among the system's roots.
        assert!(matches!(
            reach(&url, None).await,
            Err(GatewayError::Unavailable)
        ));
        assert!(fake.state.lock().unwrap().tokens.is_empty(), "never sent");
    }

    #[tokio::test]
    async fn a_certificate_for_another_name_is_refused() {
        let fake = FakeGateway::default();
        let port = serve(&fake).await;
        // The same server, by an address its certificate does not name.
        let url = format!("https://127.0.0.1:{port}");
        assert!(matches!(
            reach(&url, Some(common::authelia::CA_FILE)).await,
            Err(GatewayError::Unavailable)
        ));
        assert!(fake.state.lock().unwrap().tokens.is_empty(), "never sent");
    }
}

mod credentials {
    use std::sync::Arc;

    use common::idp::{Reply, TestIdp, issued_claims, now, sign};
    use kanbot_backend::openshell::credentials::{CredentialError, Credentials};
    use secrecy::{ExposeSecret, SecretString};
    use serde_json::{Value, json};

    use super::*;

    /// A token from `idp` for `aud`, about `sub`, expiring at `exp`.
    fn token(idp: &TestIdp, aud: &Value, exp: u64, sub: &str) -> String {
        sign(
            "rsa-a",
            &json!({ "iss": idp.issuer, "sub": sub, "aud": aud, "exp": exp }),
        )
    }

    fn gateway(idp: &TestIdp, exp: u64) -> String {
        token(idp, &json!("openshell-gateway"), exp, "svc")
    }

    fn reply(access_token: &str) -> Reply {
        Reply::Json(
            json!({ "access_token": access_token, "token_type": "Bearer", "expires_in": 300 }),
        )
    }

    async fn credentials(idp: &TestIdp, extra: &[(&'static str, &str)]) -> Credentials {
        let mut openshell = config("http://127.0.0.1:1");
        for (name, value) in extra {
            match *name {
                "OPENSHELL_TOKEN_EXCHANGE" => openshell.token_exchange = *value == "true",
                "OPENSHELL_TOKEN_SCOPE" => openshell.token_scope = Some((*value).to_owned()),
                other => panic!("unknown setting {other}"),
            }
        }
        Credentials::new(Arc::new(openshell), idp.loaded_key_cache(&[]).await)
    }

    #[tokio::test]
    async fn the_service_token_comes_from_client_credentials_and_is_cached() {
        let idp = TestIdp::start().await;
        let issued = gateway(&idp, now() + 300);
        idp.set_token(reply(&issued));
        let credentials = credentials(&idp, &[("OPENSHELL_TOKEN_SCOPE", "gw/.default")]).await;

        let first = credentials.service_token().await.unwrap();
        let second = credentials.service_token().await.unwrap();
        assert_eq!(first.expose_secret(), issued);
        assert_eq!(second.expose_secret(), issued);

        let requests = idp.token_requests();
        assert_eq!(requests.len(), 1, "cached");
        let request = &requests[0];
        assert_eq!(request.form["grant_type"], "client_credentials");
        assert_eq!(request.form["scope"], "gw/.default");
        assert!(!request.form.contains_key("audience"));
        // client_secret_basic with kanbot's OpenShell client.
        assert_eq!(
            request.authorization.as_deref(),
            Some("Basic a2FuYm90LW9wZW5zaGVsbDpvcGVuc2hlbGwtdGVzdC1zZWNyZXQ=")
        );
    }

    #[tokio::test]
    async fn large_token_responses_are_read() {
        let idp = TestIdp::start().await;
        let issued = gateway(&idp, now().saturating_add(300));
        idp.set_token(Reply::Json(json!({
            "access_token": issued,
            "token_type": "Bearer",
            // Identity providers add fields of their own: well over 1 KiB.
            "padding": "x".repeat(8 * 1024),
        })));
        let credentials = credentials(&idp, &[]).await;
        assert_eq!(
            credentials.service_token().await.unwrap().expose_secret(),
            issued
        );
    }

    #[tokio::test]
    async fn a_token_expiring_within_the_margin_is_replaced() {
        let idp = TestIdp::start().await;
        // Exactly at the 30 s margin: replaced.
        idp.set_token(reply(&gateway(&idp, now().saturating_add(30))));
        let credentials = credentials(&idp, &[]).await;
        credentials.service_token().await.unwrap();
        credentials.service_token().await.unwrap();
        assert_eq!(idp.token_requests().len(), 2);
    }

    #[tokio::test]
    async fn an_expiring_service_token_is_replaced() {
        let idp = TestIdp::start().await;
        idp.set_token(reply(&gateway(&idp, now() + 10)));
        let credentials = credentials(&idp, &[]).await;
        credentials.service_token().await.unwrap();
        credentials.service_token().await.unwrap();
        assert_eq!(idp.token_requests().len(), 2);
    }

    #[tokio::test]
    async fn only_verified_tokens_for_the_gateway_alone_are_used() {
        let idp = TestIdp::start().await;
        let credentials = credentials(&idp, &[]).await;
        for (aud, expected) in [
            (json!(["openshell-gateway", "kanbot-api"]), "shared"),
            (json!("kanbot-api"), "wrong"),
            (json!("someone-else"), "wrong"),
        ] {
            idp.set_token(reply(&token(&idp, &aud, now() + 300, "svc")));
            let error = credentials.service_token().await.unwrap_err();
            let kind = match error {
                CredentialError::SharedAudience => "shared",
                CredentialError::WrongAudience => "wrong",
                other => panic!("{other}"),
            };
            assert_eq!(kind, expected, "{aud}");
        }
        // Expired, from another issuer, or not signed by the identity
        // provider: refused like any token.
        let expired = gateway(&idp, now() - 120);
        let elsewhere = sign(
            "rsa-a",
            &json!({ "iss": "https://elsewhere.example", "sub": "svc", "aud": "openshell-gateway", "exp": now() + 300 }),
        );
        let forged = common::idp::sign_with_header(
            &json!({ "alg": "RS256", "kid": "rsa-a" }),
            &common::idp::encoding_key("rsa-b"),
            jsonwebtoken::Algorithm::RS256,
            &json!({ "iss": idp.issuer, "sub": "svc", "aud": "openshell-gateway", "exp": now() + 300 }),
        );
        for bad in [expired, elsewhere, forged, "opaque-token".to_owned()] {
            idp.set_token(reply(&bad));
            assert!(
                matches!(
                    credentials.service_token().await,
                    Err(CredentialError::Invalid(_))
                ),
                "{bad}"
            );
        }
        idp.set_token(Reply::Error(
            axum::http::StatusCode::UNAUTHORIZED,
            json!({ "error": "invalid_client" }),
        ));
        let refused = credentials.service_token().await.unwrap_err();
        assert!(refused.is_refusal(), "{refused}");
    }

    #[tokio::test]
    async fn user_calls_exchange_the_users_token() {
        let idp = TestIdp::start().await;
        let exchanged = token(&idp, &json!("openshell-gateway"), now() + 300, "alice");
        idp.set_token(reply(&exchanged));
        let credentials = credentials(&idp, &[("OPENSHELL_TOKEN_EXCHANGE", "true")]).await;

        let user = sign(
            "rsa-a",
            &issued_claims(&idp.issuer, "alice", &["kanbot-user"]),
        );
        let result = credentials
            .on_behalf_of(&SecretString::from(user.clone()))
            .await
            .unwrap();
        assert_eq!(result.token.expose_secret(), exchanged);
        assert_eq!(result.subject, "alice");
        let form = &idp.token_requests()[0].form;
        assert_eq!(
            form["grant_type"],
            "urn:ietf:params:oauth:grant-type:token-exchange"
        );
        assert_eq!(form["subject_token"], user);
        assert_eq!(
            form["subject_token_type"],
            "urn:ietf:params:oauth:token-type:access_token"
        );
        assert_eq!(
            form["requested_token_type"],
            "urn:ietf:params:oauth:token-type:access_token"
        );
        assert_eq!(form["audience"], "openshell-gateway");

        // An exchange that keeps kanbot's audience is never used.
        idp.set_token(reply(&token(
            &idp,
            &json!(["kanbot-api", "openshell-gateway"]),
            now() + 300,
            "alice",
        )));
        assert!(matches!(
            credentials
                .on_behalf_of(&SecretString::from(user.clone()))
                .await,
            Err(CredentialError::SharedAudience)
        ));
        // Nor one for somebody else.
        idp.set_token(reply(&token(
            &idp,
            &json!("openshell-gateway"),
            now() + 300,
            "mallory",
        )));
        assert!(matches!(
            credentials.on_behalf_of(&SecretString::from(user)).await,
            Err(CredentialError::WrongSubject)
        ));
        // A user token that is no valid kanbot token is not exchanged.
        let requests = idp.token_requests().len();
        assert!(matches!(
            credentials
                .on_behalf_of(&SecretString::from("the-users-access-token"))
                .await,
            Err(CredentialError::Invalid(_))
        ));
        assert_eq!(idp.token_requests().len(), requests);
    }

    #[tokio::test]
    async fn a_forgotten_service_token_is_requested_again() {
        let idp = TestIdp::start().await;
        idp.set_token(reply(&gateway(&idp, now() + 300)));
        let credentials = credentials(&idp, &[]).await;
        credentials.service_token().await.unwrap();
        credentials.forget_service_token().await;
        credentials.service_token().await.unwrap();
        credentials.service_token().await.unwrap();
        assert_eq!(idp.token_requests().len(), 2);
    }
}

mod link_and_sync {
    use std::sync::Arc;

    use axum::http::StatusCode;
    use common::{
        api::Api,
        idp::{Reply, TestIdp, issued_claims, now, sign},
    };
    use kanbot_backend::{
        authz::policies::Policies,
        db,
        http::HttpSettings,
        openshell::{OpenShell, sync},
        state::AppState,
    };
    use serde_json::{Value, json};
    use sqlx::PgPool;
    use uuid::Uuid;

    use super::*;

    const ORG: Uuid = Uuid::from_u128(0x0a);

    struct Setup {
        api: Api,
        fake: FakeGateway,
        idp: TestIdp,
        openshell: Arc<OpenShell>,
        policies: Arc<Policies>,
    }

    /// A gateway token about `subject` that the fake accepts; the identity
    /// provider answers every token request with it from now on.
    fn issue_gateway_token(idp: &TestIdp, fake: &FakeGateway, subject: &str) -> String {
        let token = sign(
            "rsa-a",
            &json!({ "iss": idp.issuer, "sub": subject, "aud": "openshell-gateway", "exp": now().saturating_add(300) }),
        );
        idp.set_token(Reply::Json(json!({ "access_token": token })));
        fake.accept(&token);
        token
    }

    async fn sync_once(pool: &PgPool, setup: &Setup) -> sync::Changes {
        sync::sync_all(pool, &setup.policies, &setup.openshell, &setup.idp.issuer)
            .await
            .unwrap()
            .expect("no other sync holds the lock")
    }

    async fn setup(pool: &PgPool, exchange: bool) -> Setup {
        setup_with(pool, exchange, common::policies()).await
    }

    /// The app with the integration on, against the fake gateway; the
    /// identity provider issues gateway tokens the fake accepts.
    async fn setup_with(pool: &PgPool, exchange: bool, policies: Arc<Policies>) -> Setup {
        let idp = TestIdp::start().await;
        let fake = FakeGateway::default();
        issue_gateway_token(&idp, &fake, "svc");
        let mut openshell_config = config(&fake.start().await);
        openshell_config.token_exchange = exchange;
        let keys = idp.loaded_key_cache(&[]).await;
        let openshell = Arc::new(OpenShell::new(openshell_config, Arc::clone(&keys)).unwrap());
        let app = common::serve(
            AppState {
                db: pool.clone(),
                migrator: &db::MIGRATOR,
                keys,
                sessions: common::session_config(),
                authz: Arc::clone(&policies),
                openshell: Some(Arc::clone(&openshell)),
            },
            HttpSettings::new(),
            None,
        );
        sqlx::query!(
            "INSERT INTO organizations (id, slug, name) VALUES ($1, 'acme', 'Acme')",
            ORG
        )
        .execute(pool)
        .await
        .unwrap();
        Setup {
            api: Api::of(app),
            fake,
            idp,
            openshell,
            policies,
        }
    }

    impl Setup {
        fn token(&self, subject: &str, groups: &[&str]) -> String {
            sign("rsa-a", &issued_claims(&self.idp.issuer, subject, groups))
        }
    }

    #[sqlx::test]
    async fn platform_admins_link_existing_workspaces(pool: PgPool) {
        let setup = setup(&pool, false).await;
        setup.fake.workspace("research");
        let root = setup.token("root", &["kanbot-admin"]);
        let carol = setup.token("carol", &["kanbot-user"]);
        let carol_id = setup.api.user_id(&carol).await;
        let uri = format!("/organizations/{ORG}/openshell_workspace");
        setup
            .api
            .put(
                &format!("/organizations/{ORG}/admins/{carol_id}"),
                &root,
                None,
            )
            .await;

        // An organization admin may not link it.
        let (status, _) = setup
            .api
            .put(&uri, &carol, Some(json!({ "workspace": "research" })))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN);
        let (_, org) = setup
            .api
            .get(&format!("/organizations/{ORG}"), &carol)
            .await;
        assert!(
            !org["permissions"]
                .as_array()
                .unwrap()
                .contains(&json!("link_openshell_workspace"))
        );

        let (status, body) = setup
            .api
            .put(&uri, &root, Some(json!({ "workspace": "missing" })))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
        assert_eq!(
            body["errors"],
            json!([{ "pointer": "/workspace", "code": "not_found" }])
        );
        let (status, _) = setup
            .api
            .put(&uri, &root, Some(json!({ "workspace": "a b" })))
            .await;
        assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

        let (status, body) = setup
            .api
            .put(&uri, &root, Some(json!({ "workspace": "research" })))
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["openshell_workspace"], "research");
        assert!(
            body["permissions"]
                .as_array()
                .unwrap()
                .contains(&json!("link_openshell_workspace"))
        );

        // One organization per workspace.
        let other = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO organizations (id, slug, name) VALUES ($1, 'other', 'Other')",
            other
        )
        .execute(&pool)
        .await
        .unwrap();
        let (status, _) = setup
            .api
            .put(
                &format!("/organizations/{other}/openshell_workspace"),
                &root,
                Some(json!({ "workspace": "research" })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);

        // Linking again, or unlinking twice, changes and records nothing:
        // the workspace is not even checked again.
        setup
            .fake
            .state
            .lock()
            .unwrap()
            .workspaces
            .remove("research");
        let (status, _) = setup
            .api
            .put(&uri, &root, Some(json!({ "workspace": "research" })))
            .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = setup.api.delete(&uri, &root).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["openshell_workspace"], Value::Null);
        let (status, _) = setup.api.delete(&uri, &root).await;
        assert_eq!(status, StatusCode::OK);

        let actions = sqlx::query_scalar!(
            "SELECT action FROM audit_log WHERE action LIKE 'organization.openshell%' ORDER BY id"
        )
        .fetch_all(&pool)
        .await
        .unwrap();
        assert_eq!(
            actions,
            [
                "organization.openshell_linked",
                "organization.openshell_unlinked"
            ]
        );
        // The workspace was checked with the service account (no exchange),
        // and the user's token went nowhere.
        let requests = setup.idp.token_requests();
        assert!(!requests.is_empty());
        for request in requests {
            assert_eq!(request.form["grant_type"], "client_credentials");
            assert!(!request.form.values().any(|value| *value == root));
        }
    }

    #[sqlx::test]
    async fn linking_checks_the_workspace_as_the_user_with_token_exchange(pool: PgPool) {
        let setup = setup(&pool, true).await;
        setup.fake.workspace("research");
        let root = setup.token("root", &["kanbot-admin"]);
        issue_gateway_token(&setup.idp, &setup.fake, "root");
        let uri = format!("/organizations/{ORG}/openshell_workspace");
        let workspace_role = |role: i32| {
            setup
                .fake
                .state
                .lock()
                .unwrap()
                .workspaces
                .get_mut("research")
                .unwrap()
                .insert("root".to_owned(), role);
        };
        // Seeing the workspace is not enough: the sync would make the
        // organization's admins workspace admins.
        let (status, _) = setup
            .api
            .put(&uri, &root, Some(json!({ "workspace": "research" })))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "not a member");
        workspace_role(1);
        let (status, _) = setup
            .api
            .put(&uri, &root, Some(json!({ "workspace": "research" })))
            .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "a plain user of it");
        workspace_role(2);
        let (status, body) = setup
            .api
            .put(
                &format!("/organizations/{ORG}/openshell_workspace"),
                &root,
                Some(json!({ "workspace": "research" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let exchange = setup
            .idp
            .token_requests()
            .into_iter()
            .find(|request| request.form["grant_type"].ends_with("token-exchange"))
            .expect("a token exchange");
        assert_eq!(exchange.form["subject_token"], root);
    }

    /// A native session for `subject` (a user already), holding `access_token`
    /// as its identity provider token. Returns the session token.
    async fn native_session(pool: &PgPool, subject: &str, access_token: &str) -> String {
        use kanbot_backend::sessions::{
            crypto::{self, Field},
            secrets,
        };
        let id = Uuid::new_v4();
        let issued = secrets::issue(secrets::SESSION_TOKEN).unwrap();
        let sealed = crypto::seal(
            &common::session_config().keys,
            id,
            Field::AccessToken,
            &secrecy::SecretString::from(access_token.to_owned()),
        )
        .unwrap();
        sqlx::query!(
            "INSERT INTO sessions
               (id, token_hash, user_id, kind, idp_access_token, access_expires_at,
                idle_expires_at, absolute_expires_at)
             SELECT $1, $2, id, 'native', $3, now() + interval '1 hour',
                    now() + interval '1 hour', now() + interval '1 day'
             FROM users WHERE subject = $4",
            id,
            &issued.hash[..],
            sealed,
            subject,
        )
        .execute(pool)
        .await
        .unwrap();
        secrecy::ExposeSecret::expose_secret(&issued.value).to_owned()
    }

    #[sqlx::test]
    async fn a_session_exchanges_its_stored_identity_provider_token(pool: PgPool) {
        let setup = setup(&pool, true).await;
        setup.fake.workspace("research");
        issue_gateway_token(&setup.idp, &setup.fake, "root");
        setup
            .fake
            .state
            .lock()
            .unwrap()
            .workspaces
            .get_mut("research")
            .unwrap()
            .insert("root".to_owned(), 2);
        let root = setup.token("root", &["kanbot-admin"]);
        setup.api.user_id(&root).await;
        let session = native_session(&pool, "root", &root).await;
        assert!(session.starts_with("kbs_"));

        let (status, body) = setup
            .api
            .put(
                &format!("/organizations/{ORG}/openshell_workspace"),
                &session,
                Some(json!({ "workspace": "research" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        let exchange = &setup.idp.token_requests()[0];
        // The identity provider's token, never kanbot's session token.
        assert_eq!(exchange.form["subject_token"], root);
    }

    #[sqlx::test]
    async fn without_the_integration_linking_is_a_conflict(pool: PgPool) {
        let api = Api::new(pool.clone());
        let root = common::api::admin("root");
        let (_, org) = api
            .get("/organizations/00000000-0000-0000-0000-000000000001", &root)
            .await;
        assert_eq!(org["openshell_workspace"], Value::Null);
        assert!(
            !org["permissions"]
                .as_array()
                .unwrap()
                .contains(&json!("link_openshell_workspace"))
        );
        let (status, _) = api
            .put(
                "/organizations/00000000-0000-0000-0000-000000000001/openshell_workspace",
                &root,
                Some(json!({ "workspace": "research" })),
            )
            .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }

    async fn user(pool: &PgPool, issuer: &str, subject: &str, disabled: bool) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query!(
            r#"INSERT INTO users (id, issuer, subject, platform_role, disabled_at)
               VALUES ($1, $2, $3, 'user', CASE WHEN $4 THEN now() END)"#,
            id,
            issuer,
            subject,
            disabled
        )
        .execute(pool)
        .await
        .unwrap();
        id
    }

    async fn team(pool: &PgPool, slug: &str, access: &str, members: &[Uuid]) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO teams (id, slug, name) VALUES ($1, $2, 'T')",
            id,
            slug
        )
        .execute(pool)
        .await
        .unwrap();
        sqlx::query!(
            "INSERT INTO organization_teams (organization_id, team_id, access) VALUES ($1, $2, $3)",
            ORG,
            id,
            access
        )
        .execute(pool)
        .await
        .unwrap();
        for member in members {
            sqlx::query!(
                "INSERT INTO team_members (team_id, user_id, role, source) VALUES ($1, $2, 'member', 'manual')",
                id,
                member
            )
            .execute(pool)
            .await
            .unwrap();
        }
        id
    }

    fn members(fake: &FakeGateway) -> Vec<(String, i32)> {
        fake.state.lock().unwrap().workspaces["research"]
            .iter()
            .map(|(subject, role)| (subject.clone(), *role))
            .collect()
    }

    #[sqlx::test]
    async fn sync_keeps_the_workspace_in_line_with_the_organization(pool: PgPool) {
        let setup = setup(&pool, false).await;
        let issuer = setup.idp.issuer.clone();
        setup.fake.workspace("research");
        // Added in OpenShell by someone else: never touched.
        setup
            .fake
            .state
            .lock()
            .unwrap()
            .workspaces
            .get_mut("research")
            .unwrap()
            .insert("eve".to_owned(), 1);

        let alice = user(&pool, &issuer, "alice", false).await;
        let bob = user(&pool, &issuer, "bob", false).await;
        let carol = user(&pool, &issuer, "carol", false).await;
        let dave = user(&pool, &issuer, "dave", true).await;
        let eve = user(&pool, &issuer, "eve", false).await;
        let stranger = user(&pool, "https://other-issuer", "zed", false).await;
        for admin in [alice, dave] {
            sqlx::query!(
                "INSERT INTO organization_admins (organization_id, user_id) VALUES ($1, $2)",
                ORG,
                admin
            )
            .execute(&pool)
            .await
            .unwrap();
        }
        let writers = team(&pool, "writers", "write", &[bob, eve, stranger]).await;
        let readers = team(&pool, "readers", "read", &[carol]).await;

        // Not linked yet: nothing happens, not even a token request.
        let changes = sync_once(&pool, &setup).await;
        assert_eq!(changes, sync::Changes::default());
        assert!(setup.idp.token_requests().is_empty());

        sqlx::query!(
            "UPDATE organizations SET openshell_workspace = 'research' WHERE id = $1",
            ORG
        )
        .execute(&pool)
        .await
        .unwrap();
        let changes = sync_once(&pool, &setup).await;
        assert_eq!((changes.added, changes.removed, changes.skipped), (2, 0, 1));
        // Admins as admins (2), writers as users (1); not the reader, the
        // disabled admin or the other issuer's user; eve left as she was.
        assert_eq!(
            members(&setup.fake),
            [
                ("alice".to_owned(), 2),
                ("bob".to_owned(), 1),
                ("eve".to_owned(), 1),
            ]
        );

        // Nothing changed: nothing written.
        let before = setup.fake.state.lock().unwrap().changes.len();
        sync_once(&pool, &setup).await;
        assert_eq!(setup.fake.state.lock().unwrap().changes.len(), before);

        // Someone changes a member kanbot added in OpenShell: put back.
        setup
            .fake
            .state
            .lock()
            .unwrap()
            .workspaces
            .get_mut("research")
            .unwrap()
            .insert("alice".to_owned(), 1);
        sync_once(&pool, &setup).await;
        assert_eq!(members(&setup.fake)[0], ("alice".to_owned(), 2));

        // Bob becomes an admin, the readers get write access, eve leaves.
        sqlx::query!(
            "INSERT INTO organization_admins (organization_id, user_id) VALUES ($1, $2)",
            ORG,
            bob
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query!(
            "UPDATE organization_teams SET access = 'write' WHERE team_id = $1",
            readers
        )
        .execute(&pool)
        .await
        .unwrap();
        sqlx::query!(
            "DELETE FROM team_members WHERE team_id = $1 AND user_id = $2",
            writers,
            eve
        )
        .execute(&pool)
        .await
        .unwrap();
        sync_once(&pool, &setup).await;
        assert_eq!(
            members(&setup.fake),
            [
                ("alice".to_owned(), 2),
                ("bob".to_owned(), 2),
                ("carol".to_owned(), 1),
                ("eve".to_owned(), 1),
            ]
        );

        // Unlinked: kanbot removes what it added, and only that.
        sqlx::query!(
            "UPDATE organizations SET openshell_workspace = NULL WHERE id = $1",
            ORG
        )
        .execute(&pool)
        .await
        .unwrap();
        let changes = sync_once(&pool, &setup).await;
        assert_eq!(changes.removed, 3);
        assert_eq!(members(&setup.fake), [("eve".to_owned(), 1)]);
        let recorded = sqlx::query_scalar!(r#"SELECT count(*) AS "count!" FROM openshell_members"#)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(recorded, 0);
        // Every call used the service account's token.
        let state = setup.fake.state.lock().unwrap();
        assert!(
            state
                .tokens
                .iter()
                .all(|header| state.accepted.contains(header))
        );
        assert!(
            state.changes.contains(&"remove research bob".to_owned()),
            "role change replaces"
        );
    }

    #[sqlx::test]
    async fn linking_wakes_the_background_sync(pool: PgPool) {
        let setup = setup(&pool, false).await;
        setup.fake.workspace("research");
        let root = setup.token("root", &["kanbot-admin"]);
        let alice = setup.token("alice", &["kanbot-user"]);
        let alice_id = setup.api.user_id(&alice).await;
        setup
            .api
            .put(
                &format!("/organizations/{ORG}/admins/{alice_id}"),
                &root,
                None,
            )
            .await;
        // The interval's first run happens now, with nothing linked; only the
        // database's change notification can sync before the next one,
        // minutes away (after the minimum gap between runs).
        sync::spawn_sync(
            pool.clone(),
            Arc::clone(&setup.policies),
            Arc::clone(&setup.openshell),
            setup.idp.issuer.clone(),
        );
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        let (status, _) = setup
            .api
            .put(
                &format!("/organizations/{ORG}/openshell_workspace"),
                &root,
                Some(json!({ "workspace": "research" })),
            )
            .await;
        assert_eq!(status, StatusCode::OK);
        for _ in 0..300 {
            if !members(&setup.fake).is_empty() {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert_eq!(members(&setup.fake), [("alice".to_owned(), 2)]);
    }

    #[sqlx::test]
    async fn a_refused_service_token_stops_the_sync(pool: PgPool) {
        let setup = setup(&pool, false).await;
        sqlx::query!(
            "UPDATE organizations SET openshell_workspace = 'research' WHERE id = $1",
            ORG
        )
        .execute(&pool)
        .await
        .unwrap();
        setup.fake.workspace("research");
        setup.idp.set_token(Reply::Status(StatusCode::UNAUTHORIZED));
        let result =
            sync::sync_all(&pool, &setup.policies, &setup.openshell, &setup.idp.issuer).await;
        assert!(matches!(result, Err(sync::SyncError::Credentials(_))));
    }

    async fn admin_of(pool: &PgPool, organization: Uuid, user: Uuid) {
        sqlx::query!(
            "INSERT INTO organization_admins (organization_id, user_id) VALUES ($1, $2)",
            organization,
            user
        )
        .execute(pool)
        .await
        .unwrap();
    }

    async fn link(pool: &PgPool, organization: Uuid, workspace: &str) {
        sqlx::query!(
            "UPDATE organizations SET openshell_workspace = $2 WHERE id = $1",
            organization,
            workspace
        )
        .execute(pool)
        .await
        .unwrap();
    }

    #[sqlx::test]
    async fn deployer_policies_apply_to_the_sync(pool: PgPool) {
        // Contractors may not write; nobody manages the organization from
        // outside the office network, which the sync is not in.
        let policies = Policies::with_deployer(
            r#"
            @id("contractors-read-only")
            forbid (principal, action == Kanbot::Action::"write", resource)
            when { principal.groups.contains("contractors") };
            @id("office-only")
            forbid (principal, action == Kanbot::Action::"manageOrganization", resource)
            unless { context.ip.isInRange(ip("10.0.0.0/8")) };
            "#,
        )
        .unwrap();
        let setup = setup_with(&pool, false, Arc::new(policies)).await;
        let issuer = setup.idp.issuer.clone();
        setup.fake.workspace("research");
        let alice = user(&pool, &issuer, "alice", false).await;
        let dave = user(&pool, &issuer, "dave", false).await;
        sqlx::query!(
            "UPDATE users SET groups = '{contractors}' WHERE id = $1",
            dave
        )
        .execute(&pool)
        .await
        .unwrap();
        admin_of(&pool, ORG, alice).await;
        team(&pool, "writers", "write", &[dave]).await;
        link(&pool, ORG, "research").await;

        sync_once(&pool, &setup).await;
        // Dave is left out; Alice is an admin of the organization, but may
        // not manage it here: a plain user of the workspace.
        assert_eq!(members(&setup.fake), [("alice".to_owned(), 1)]);
    }

    #[sqlx::test]
    async fn one_failing_workspace_does_not_stop_the_others(pool: PgPool) {
        let setup = setup(&pool, false).await;
        let issuer = setup.idp.issuer.clone();
        let alice = user(&pool, &issuer, "alice", false).await;
        // "alpha" sorts first and fails; "beta" must still be synced.
        let beta = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO organizations (id, slug, name) VALUES ($1, 'beta', 'Beta')",
            beta
        )
        .execute(&pool)
        .await
        .unwrap();
        for (organization, workspace) in [(ORG, "alpha"), (beta, "beta")] {
            setup.fake.workspace(workspace);
            admin_of(&pool, organization, alice).await;
            link(&pool, organization, workspace).await;
        }
        setup
            .fake
            .state
            .lock()
            .unwrap()
            .failing_adds
            .insert("alpha".to_owned());

        let changes = sync_once(&pool, &setup).await;
        assert_eq!((changes.added, changes.failed), (1, 1));
        {
            let state = setup.fake.state.lock().unwrap();
            assert_eq!(state.workspaces["beta"].len(), 1);
            assert!(state.workspaces["alpha"].is_empty());
        }
        // The failed add was recorded first: kanbot still knows the member
        // is its own, and adds them when the gateway works again.
        let recorded =
            sqlx::query_scalar!("SELECT subject FROM openshell_members WHERE workspace = 'alpha'")
                .fetch_all(&pool)
                .await
                .unwrap();
        assert_eq!(recorded, ["alice"]);
        setup.fake.state.lock().unwrap().failing_adds.clear();
        let changes = sync_once(&pool, &setup).await;
        assert_eq!((changes.added, changes.failed), (1, 0));
    }

    #[sqlx::test]
    async fn a_workspace_deleted_in_openshell_is_forgotten_once_unlinked(pool: PgPool) {
        let setup = setup(&pool, false).await;
        let issuer = setup.idp.issuer.clone();
        let alice = user(&pool, &issuer, "alice", false).await;
        setup.fake.workspace("research");
        admin_of(&pool, ORG, alice).await;
        link(&pool, ORG, "research").await;
        sync_once(&pool, &setup).await;

        // Deleted in OpenShell, then unlinked in kanbot.
        setup
            .fake
            .state
            .lock()
            .unwrap()
            .workspaces
            .remove("research");
        sqlx::query!("UPDATE organizations SET openshell_workspace = NULL")
            .execute(&pool)
            .await
            .unwrap();
        let changes = sync_once(&pool, &setup).await;
        assert_eq!((changes.removed, changes.failed), (1, 0));
        let left = sqlx::query_scalar!(r#"SELECT count(*) AS "n!" FROM openshell_members"#)
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(left, 0, "nothing wedges the next runs");
    }

    #[sqlx::test]
    async fn one_instance_syncs_at_a_time(pool: PgPool) {
        let setup = setup(&pool, false).await;
        // Another instance holds the lock.
        let mut other = pool.begin().await.unwrap();
        sqlx::query!("SELECT pg_advisory_xact_lock(7737587003854966611)")
            .execute(&mut *other)
            .await
            .unwrap();
        let outcome = sync::sync_all(&pool, &setup.policies, &setup.openshell, &setup.idp.issuer)
            .await
            .unwrap();
        assert_eq!(outcome, None);
        other.rollback().await.unwrap();
        assert_eq!(sync_once(&pool, &setup).await, sync::Changes::default());
        // Released once the run is over.
        assert_eq!(lock_holders(&pool).await, 0);
    }

    /// The sync's advisory lock key, "kanbotOS" in ASCII.
    const SYNC_LOCK: i64 = 0x6b61_6e62_6f74_4f53;

    /// How many sessions hold the sync's lock in this test's database
    /// (`pg_locks` lists every database's).
    async fn lock_holders(pool: &PgPool) -> i64 {
        sqlx::query_scalar!(
            r#"SELECT count(*) AS "n!" FROM pg_locks
               WHERE locktype = 'advisory' AND granted
                 AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
                 AND ((classid::bigint << 32) | objid::bigint) = $1"#,
            SYNC_LOCK
        )
        .fetch_one(pool)
        .await
        .unwrap()
    }

    async fn organization(pool: &PgPool, slug: &str) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query!(
            "INSERT INTO organizations (id, slug, name) VALUES ($1, $2, 'O')",
            id,
            slug
        )
        .execute(pool)
        .await
        .unwrap();
        id
    }

    fn members_of(fake: &FakeGateway, workspace: &str) -> Vec<(String, i32)> {
        fake.state.lock().unwrap().workspaces[workspace]
            .iter()
            .map(|(subject, role)| (subject.clone(), *role))
            .collect()
    }

    /// Kanbot's records for `workspace`: subject and role.
    async fn recorded(pool: &PgPool, workspace: &str) -> Vec<(String, String)> {
        sqlx::query!(
            "SELECT subject, role FROM openshell_members WHERE workspace = $1 ORDER BY subject",
            workspace
        )
        .fetch_all(pool)
        .await
        .unwrap()
        .into_iter()
        .map(|row| (row.subject, row.role))
        .collect()
    }

    fn pair(subject: &str, role: &str) -> (String, String) {
        (subject.to_owned(), role.to_owned())
    }

    /// Starts a run in the background.
    fn spawn_run(
        pool: &PgPool,
        setup: &Setup,
    ) -> tokio::task::JoinHandle<Result<Option<sync::Changes>, sync::SyncError>> {
        let (pool, policies, openshell, issuer) = (
            pool.clone(),
            Arc::clone(&setup.policies),
            Arc::clone(&setup.openshell),
            setup.idp.issuer.clone(),
        );
        tokio::spawn(async move { sync::sync_all(&pool, &policies, &openshell, &issuer).await })
    }

    /// Waits up to 10 s for `done`.
    async fn eventually(what: &str, done: impl Fn() -> bool) {
        for _ in 0..200 {
            if done() {
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        panic!("never: {what}");
    }

    /// Timings for background sync tests: no timer run after the first,
    /// no gap between runs.
    fn fast(retry_ms: u64) -> sync::Timing {
        sync::Timing {
            interval: std::time::Duration::from_secs(3600),
            retry: std::time::Duration::from_millis(retry_ms),
            min_gap: std::time::Duration::ZERO,
            listen_retry: std::time::Duration::from_millis(100),
            listen_retry_max: std::time::Duration::from_millis(200),
        }
    }

    #[sqlx::test]
    async fn a_stale_record_is_corrected_without_a_gateway_call(pool: PgPool) {
        let setup = setup(&pool, false).await;
        let issuer = setup.idp.issuer.clone();
        let alice = user(&pool, &issuer, "alice", false).await;
        setup.fake.workspace("research");
        admin_of(&pool, ORG, alice).await;
        link(&pool, ORG, "research").await;
        sync_once(&pool, &setup).await;
        sqlx::query!("UPDATE openshell_members SET role = 'user'")
            .execute(&pool)
            .await
            .unwrap();
        let before = setup.fake.state.lock().unwrap().changes.len();
        let changes = sync_once(&pool, &setup).await;
        assert_eq!(changes, sync::Changes::default());
        assert_eq!(setup.fake.state.lock().unwrap().changes.len(), before);
        assert_eq!(recorded(&pool, "research").await, [pair("alice", "admin")]);
    }

    #[sqlx::test]
    async fn a_member_someone_else_adds_meanwhile_is_left_alone(pool: PgPool) {
        let setup = setup(&pool, false).await;
        let issuer = setup.idp.issuer.clone();
        let alice = user(&pool, &issuer, "alice", false).await;
        setup.fake.workspace("research");
        admin_of(&pool, ORG, alice).await;
        link(&pool, ORG, "research").await;
        // Added by hand between kanbot's list and its add.
        setup.fake.state.lock().unwrap().added_after_list.push((
            "research".to_owned(),
            "alice".to_owned(),
            1,
        ));
        let changes = sync_once(&pool, &setup).await;
        assert_eq!((changes.added, changes.skipped, changes.failed), (0, 1, 0));
        assert_eq!(members(&setup.fake), [("alice".to_owned(), 1)]);
        assert!(recorded(&pool, "research").await.is_empty(), "not recorded");
        // Kanbot never takes them over: not their role, not on unlinking.
        sync_once(&pool, &setup).await;
        sqlx::query!("UPDATE organizations SET openshell_workspace = NULL")
            .execute(&pool)
            .await
            .unwrap();
        sync_once(&pool, &setup).await;
        assert_eq!(members(&setup.fake), [("alice".to_owned(), 1)]);
    }

    #[sqlx::test]
    async fn a_member_kanbot_recorded_and_finds_already_there_is_its_own(pool: PgPool) {
        let setup = setup(&pool, false).await;
        let issuer = setup.idp.issuer.clone();
        let alice = user(&pool, &issuer, "alice", false).await;
        setup.fake.workspace("research");
        admin_of(&pool, ORG, alice).await;
        link(&pool, ORG, "research").await;
        // An earlier run recorded alice and asked for her to be added; the
        // gateway shows her only once this run has listed.
        sqlx::query!(
            "INSERT INTO openshell_members (workspace, subject, role) VALUES ('research', 'alice', 'admin')"
        )
        .execute(&pool)
        .await
        .unwrap();
        setup.fake.state.lock().unwrap().added_after_list.push((
            "research".to_owned(),
            "alice".to_owned(),
            2,
        ));
        let changes = sync_once(&pool, &setup).await;
        assert_eq!((changes.added, changes.skipped, changes.failed), (1, 0, 0));
        assert_eq!(recorded(&pool, "research").await, [pair("alice", "admin")]);
        // Still kanbot's: removed when unlinked.
        sqlx::query!("UPDATE organizations SET openshell_workspace = NULL")
            .execute(&pool)
            .await
            .unwrap();
        assert_eq!(sync_once(&pool, &setup).await.removed, 1);
        assert!(members(&setup.fake).is_empty(), "removed");
    }

    #[sqlx::test]
    async fn every_gateway_call_takes_its_token_from_the_cache(pool: PgPool) {
        let setup = setup(&pool, false).await;
        let issuer = setup.idp.issuer.clone();
        for subject in ["alice", "bob"] {
            let id = user(&pool, &issuer, subject, false).await;
            admin_of(&pool, ORG, id).await;
        }
        setup.fake.workspace("research");
        link(&pool, ORG, "research").await;
        // A token within the cache's margin of expiry is never reused, so
        // each call needs a new one.
        let token = sign(
            "rsa-a",
            &json!({ "iss": issuer, "sub": "svc", "aud": "openshell-gateway", "exp": now().saturating_add(30) }),
        );
        setup
            .idp
            .set_token(Reply::Json(json!({ "access_token": token })));
        setup.fake.accept(&token);
        let changes = sync_once(&pool, &setup).await;
        assert_eq!((changes.added, changes.failed), (2, 0));
        // A list and two adds, plus the run's first check for a token.
        assert_eq!(setup.fake.state.lock().unwrap().tokens.len(), 3);
        assert_eq!(setup.idp.token_requests().len(), 1 + 3);
    }

    #[sqlx::test]
    async fn a_refused_token_is_replaced_and_the_call_made_once_more(pool: PgPool) {
        let setup = setup(&pool, false).await;
        let issuer = setup.idp.issuer.clone();
        let alice = user(&pool, &issuer, "alice", false).await;
        admin_of(&pool, ORG, alice).await;
        setup.fake.workspace("research");
        link(&pool, ORG, "research").await;
        // The gateway stops accepting the cached token (a key rotation).
        setup.fake.state.lock().unwrap().refuse_next = 1;
        let changes = sync_once(&pool, &setup).await;
        assert_eq!((changes.added, changes.failed), (1, 0));
        assert_eq!(setup.idp.token_requests().len(), 2, "a new token");
        assert_eq!(members(&setup.fake), [("alice".to_owned(), 2)]);

        // Refused again with the new one: the workspace fails, after only
        // one more call.
        let bob = user(&pool, &issuer, "bob", false).await;
        admin_of(&pool, ORG, bob).await;
        let calls = setup.fake.state.lock().unwrap().tokens.len();
        setup.fake.state.lock().unwrap().refuse_next = 2;
        let changes = sync_once(&pool, &setup).await;
        assert_eq!((changes.added, changes.failed), (0, 1));
        assert_eq!(
            setup.fake.state.lock().unwrap().tokens.len(),
            calls.saturating_add(2)
        );
        assert_eq!(setup.idp.token_requests().len(), 3);
    }

    #[sqlx::test]
    async fn a_role_change_whose_add_fails_is_finished_by_the_next_run(pool: PgPool) {
        let setup = setup(&pool, false).await;
        let issuer = setup.idp.issuer.clone();
        let alice = user(&pool, &issuer, "alice", false).await;
        team(&pool, "writers", "write", &[alice]).await;
        setup.fake.workspace("research");
        link(&pool, ORG, "research").await;
        sync_once(&pool, &setup).await;
        assert_eq!(members(&setup.fake), [("alice".to_owned(), 1)]);

        admin_of(&pool, ORG, alice).await;
        setup
            .fake
            .state
            .lock()
            .unwrap()
            .failing_adds
            .insert("research".to_owned());
        let changes = sync_once(&pool, &setup).await;
        assert_eq!((changes.added, changes.failed), (0, 1));
        // Removed, not yet back; kanbot still knows her as its own.
        assert!(members(&setup.fake).is_empty(), "removed, not yet back");
        assert_eq!(recorded(&pool, "research").await, [pair("alice", "admin")]);

        setup.fake.state.lock().unwrap().failing_adds.clear();
        let changes = sync_once(&pool, &setup).await;
        assert_eq!((changes.added, changes.failed), (1, 0));
        assert_eq!(members(&setup.fake), [("alice".to_owned(), 2)]);
    }

    #[sqlx::test]
    async fn a_run_that_loses_its_lock_stops(pool: PgPool) {
        let setup = setup(&pool, false).await;
        let issuer = setup.idp.issuer.clone();
        let alice = user(&pool, &issuer, "alice", false).await;
        let beta = organization(&pool, "beta").await;
        for (organization, workspace) in [(ORG, "alpha"), (beta, "beta")] {
            setup.fake.workspace(workspace);
            admin_of(&pool, organization, alice).await;
            link(&pool, organization, workspace).await;
        }
        let held = setup.fake.hold_list("alpha");
        let run = spawn_run(&pool, &setup);
        held.reached.await.unwrap();
        // The lock's connection dies (a server timeout, a failover): the
        // lock goes with it, and another instance could start syncing.
        assert_eq!(lock_holders(&pool).await, 1);
        let ended = sqlx::query_scalar!(
            r#"SELECT count(pg_terminate_backend(pid)) AS "n!" FROM (
                   SELECT pid FROM pg_locks
                   WHERE locktype = 'advisory' AND granted
                     AND database = (SELECT oid FROM pg_database WHERE datname = current_database())
                     AND ((classid::bigint << 32) | objid::bigint) = $1
               ) holders"#,
            SYNC_LOCK
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(ended, 1);
        held.release.send(()).unwrap();
        assert!(matches!(run.await.unwrap(), Err(sync::SyncError::LockLost)));
        assert_eq!(setup.fake.lists_of("beta"), 0, "beta is left alone");
    }

    #[sqlx::test]
    async fn a_workspace_linked_to_another_organization_meanwhile_waits_for_the_next_run(
        pool: PgPool,
    ) {
        let setup = setup(&pool, false).await;
        let issuer = setup.idp.issuer.clone();
        let (beta, gamma) = (
            organization(&pool, "beta").await,
            organization(&pool, "gamma").await,
        );
        for (organization, subject) in [(ORG, "alice"), (beta, "bob"), (gamma, "carol")] {
            let id = user(&pool, &issuer, subject, false).await;
            admin_of(&pool, organization, id).await;
        }
        for (organization, workspace) in [(ORG, "alpha"), (beta, "beta")] {
            setup.fake.workspace(workspace);
            link(&pool, organization, workspace).await;
        }
        let held = setup.fake.hold_list("alpha");
        let run = spawn_run(&pool, &setup);
        held.reached.await.unwrap();
        // While alpha syncs, beta moves from Beta to Gamma.
        sqlx::query!(
            "UPDATE organizations SET openshell_workspace = NULL WHERE id = $1",
            beta
        )
        .execute(&pool)
        .await
        .unwrap();
        link(&pool, gamma, "beta").await;
        held.release.send(()).unwrap();
        let changes = run.await.unwrap().unwrap().unwrap();
        assert_eq!(changes.added, 1, "alpha only");
        assert!(
            members_of(&setup.fake, "beta").is_empty(),
            "not Beta's admin"
        );

        sync_once(&pool, &setup).await;
        assert_eq!(members_of(&setup.fake, "beta"), [("carol".to_owned(), 2)]);
    }

    #[sqlx::test]
    async fn an_unlinked_workspace_linked_again_meanwhile_is_not_emptied(pool: PgPool) {
        let setup = setup(&pool, false).await;
        let issuer = setup.idp.issuer.clone();
        let beta = organization(&pool, "beta").await;
        let alice = user(&pool, &issuer, "alice", false).await;
        let bob = user(&pool, &issuer, "bob", false).await;
        admin_of(&pool, ORG, alice).await;
        admin_of(&pool, beta, bob).await;
        setup.fake.workspace("alpha");
        link(&pool, ORG, "alpha").await;
        // Beta's workspace, unlinked: kanbot's member is to be removed...
        setup.fake.workspace("beta");
        link(&pool, beta, "beta").await;
        sync_once(&pool, &setup).await;
        sqlx::query!(
            "UPDATE organizations SET openshell_workspace = NULL WHERE id = $1",
            beta
        )
        .execute(&pool)
        .await
        .unwrap();
        let held = setup.fake.hold_list("alpha");
        let run = spawn_run(&pool, &setup);
        held.reached.await.unwrap();
        // ... but is linked again before its turn.
        link(&pool, beta, "beta").await;
        held.release.send(()).unwrap();
        let changes = run.await.unwrap().unwrap().unwrap();
        assert_eq!(changes.removed, 0);
        assert_eq!(members_of(&setup.fake, "beta"), [("bob".to_owned(), 2)]);
        assert_eq!(recorded(&pool, "beta").await, [pair("bob", "admin")]);
    }

    #[sqlx::test]
    async fn a_failed_run_is_retried(pool: PgPool) {
        let setup = setup(&pool, false).await;
        let issuer = setup.idp.issuer.clone();
        let alice = user(&pool, &issuer, "alice", false).await;
        admin_of(&pool, ORG, alice).await;
        setup.fake.workspace("research");
        link(&pool, ORG, "research").await;
        setup.idp.set_token(Reply::Status(StatusCode::UNAUTHORIZED));
        sync::spawn_sync_with(
            pool.clone(),
            Arc::clone(&setup.policies),
            Arc::clone(&setup.openshell),
            issuer,
            fast(200),
        );
        eventually("a refused token request", || {
            !setup.idp.token_requests().is_empty()
        })
        .await;
        assert!(members(&setup.fake).is_empty(), "nothing synced yet");
        // Nothing changes in the database: only the retry can sync.
        issue_gateway_token(&setup.idp, &setup.fake, "svc");
        eventually("alice added", || {
            members(&setup.fake) == [("alice".to_owned(), 2)]
        })
        .await;
    }

    #[sqlx::test]
    async fn a_failing_workspace_is_retried_on_its_own(pool: PgPool) {
        let setup = setup(&pool, false).await;
        let issuer = setup.idp.issuer.clone();
        let alice = user(&pool, &issuer, "alice", false).await;
        let beta = organization(&pool, "beta").await;
        for (organization, workspace) in [(ORG, "alpha"), (beta, "beta")] {
            setup.fake.workspace(workspace);
            admin_of(&pool, organization, alice).await;
            link(&pool, organization, workspace).await;
        }
        setup
            .fake
            .state
            .lock()
            .unwrap()
            .failing_adds
            .insert("alpha".to_owned());
        sync::spawn_sync_with(
            pool.clone(),
            Arc::clone(&setup.policies),
            Arc::clone(&setup.openshell),
            issuer,
            fast(200),
        );
        // Retried after 0.2 s, 0.4 s more, 0.8 s more...
        eventually("alpha retried twice", || setup.fake.lists_of("alpha") >= 3).await;
        // ... without syncing beta again.
        assert_eq!(setup.fake.lists_of("beta"), 1);
        assert_eq!(members_of(&setup.fake, "beta"), [("alice".to_owned(), 2)]);
    }

    /// A TCP proxy to the database at `port` that drops every connection
    /// until it is opened.
    async fn proxy(port: u16) -> (u16, Arc<std::sync::atomic::AtomicBool>) {
        use std::sync::atomic::{AtomicBool, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = listener.local_addr().unwrap().port();
        let open = Arc::new(AtomicBool::new(false));
        let opened = Arc::clone(&open);
        tokio::spawn(async move {
            loop {
                let (mut inbound, _) = listener.accept().await.unwrap();
                if !opened.load(Ordering::SeqCst) {
                    continue;
                }
                tokio::spawn(async move {
                    let mut outbound = tokio::net::TcpStream::connect(("127.0.0.1", port))
                        .await
                        .unwrap();
                    let _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound).await;
                });
            }
        });
        (proxy_port, open)
    }

    #[sqlx::test]
    async fn listening_for_changes_resumes_once_the_database_is_back(pool: PgPool) {
        let setup = setup(&pool, false).await;
        let issuer = setup.idp.issuer.clone();
        let alice = user(&pool, &issuer, "alice", false).await;
        let bob = user(&pool, &issuer, "bob", false).await;
        admin_of(&pool, ORG, alice).await;
        setup.fake.workspace("research");
        let options = pool.connect_options();
        let (port, open) = proxy(options.get_port()).await;
        let down = db::pool_with((*options).clone().port(port));
        // No timer run after the first, and a failed run retried only in
        // an hour: only listening again can sync.
        sync::spawn_sync_with(
            down,
            Arc::clone(&setup.policies),
            Arc::clone(&setup.openshell),
            issuer,
            fast(3_600_000),
        );
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        open.store(true, std::sync::atomic::Ordering::SeqCst);
        link(&pool, ORG, "research").await;
        eventually("alice added once listening", || {
            members(&setup.fake) == [("alice".to_owned(), 2)]
        })
        .await;
        // And it hears about changes again.
        admin_of(&pool, ORG, bob).await;
        eventually("bob added on notification", || {
            members(&setup.fake).len() == 2
        })
        .await;
    }
}

/// The database's check on workspace names accepts exactly what
/// `WorkspaceName::parse` does.
#[sqlx::test]
async fn the_database_checks_workspace_names_like_kanbot(pool: sqlx::PgPool) {
    let long = "w".repeat(253);
    let too_long = "w".repeat(254);
    for name in [
        "research", "a", "0", "a.b-2", &long, "", "Team", "a/b", "a\\b", "..", "-a", "a-", ".a",
        "é", "a b", &too_long,
    ] {
        let stored = sqlx::query!(
            "INSERT INTO openshell_members (workspace, subject, role) VALUES ($1, 's', 'user')",
            name
        )
        .execute(&pool)
        .await
        .is_ok();
        assert_eq!(stored, WorkspaceName::parse(name).is_some(), "{name:?}");
    }
}
