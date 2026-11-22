//! The `OpenShell` integration against a fake gateway (`common/openshell.rs`).

pub mod common;

use std::collections::HashMap;

use common::openshell::FakeGateway;
use kanbot_backend::openshell::{
    config::OpenShellConfig,
    gateway::{Gateway, GatewayError, Member},
    model::{MemberRole, WorkspaceName},
};
use secrecy::SecretString;

fn config(gateway: &str) -> OpenShellConfig {
    let vars: HashMap<&'static str, String> = [
        ("OPENSHELL_GATEWAY_URL", gateway.to_owned()),
        (
            "OPENSHELL_DANGEROUSLY_ALLOW_INSECURE_HTTP",
            "true".to_owned(),
        ),
        ("OPENSHELL_AUDIENCE", "openshell-gateway".to_owned()),
        ("OPENSHELL_CLIENT_ID", "kanbot-openshell".to_owned()),
        (
            "OPENSHELL_CLIENT_SECRET",
            "openshell-test-secret".to_owned(),
        ),
    ]
    .into_iter()
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
        gateway
            .add_member(&token, &workspace("research"), subject, role)
            .await
            .unwrap();
    }
    // Adding a member already there (another instance, a retry) is fine.
    gateway
        .add_member(&token, &workspace("research"), "a", MemberRole::Admin)
        .await
        .unwrap();
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
        assert_eq!(result.subject.as_deref(), Some("alice"));
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
    async fn without_token_exchange_user_calls_use_the_service_account() {
        let idp = TestIdp::start().await;
        idp.set_token(reply(&gateway(&idp, now() + 300)));
        let credentials = credentials(&idp, &[]).await;
        let token = credentials
            .on_behalf_of(&SecretString::from("the-users-access-token"))
            .await
            .unwrap();
        assert_eq!(token.subject, None);
        let form = &idp.token_requests()[0].form;
        assert_eq!(form["grant_type"], "client_credentials");
        assert!(!form.values().any(|value| value == "the-users-access-token"));
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

        let (status, body) = setup.api.delete(&uri, &root).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["openshell_workspace"], Value::Null);

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
        // The workspace was checked with the service account (no exchange).
        assert!(
            setup
                .idp
                .token_requests()
                .iter()
                .all(|request| request.form["grant_type"] == "client_credentials")
        );
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
    }

    #[sqlx::test]
    async fn a_member_already_there_counts_as_added(pool: PgPool) {
        // Recorded but not yet confirmed (the instance stopped after the
        // gateway call): the next run's add finds them, which is fine.
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
        let changes = sync_once(&pool, &setup).await;
        assert_eq!(changes.failed, 0);
        let role = sqlx::query_scalar!("SELECT role FROM openshell_members")
            .fetch_one(&pool)
            .await
            .unwrap();
        assert_eq!(role, "admin");
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
