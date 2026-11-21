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

    use common::idp::{Reply, TestIdp, now, sign};
    use kanbot_backend::openshell::credentials::{CredentialError, Credentials};
    use secrecy::{ExposeSecret, SecretString};
    use serde_json::{Value, json};

    use super::*;

    fn token(aud: &Value, exp: u64) -> String {
        sign(
            "rsa-a",
            &json!({ "iss": "x", "sub": "svc", "aud": aud, "exp": exp }),
        )
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
        let issued = token(&json!("openshell-gateway"), now() + 300);
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
    async fn an_expiring_service_token_is_replaced() {
        let idp = TestIdp::start().await;
        idp.set_token(reply(&token(&json!("openshell-gateway"), now() + 10)));
        let credentials = credentials(&idp, &[]).await;
        credentials.service_token().await.unwrap();
        credentials.service_token().await.unwrap();
        assert_eq!(idp.token_requests().len(), 2);
    }

    #[tokio::test]
    async fn tokens_for_both_services_or_the_wrong_one_are_refused() {
        let idp = TestIdp::start().await;
        let credentials = credentials(&idp, &[]).await;
        for (aud, expected) in [
            (json!(["openshell-gateway", "kanbot-api"]), "shared"),
            (json!("kanbot-api"), "shared"),
            (json!("someone-else"), "wrong"),
        ] {
            idp.set_token(reply(&token(&aud, now() + 300)));
            let error = credentials.service_token().await.unwrap_err();
            let kind = match error {
                CredentialError::SharedAudience => "shared",
                CredentialError::WrongAudience => "wrong",
                other => panic!("{other}"),
            };
            assert_eq!(kind, expected, "{aud}");
        }
        idp.set_token(reply("opaque-token"));
        assert!(matches!(
            credentials.service_token().await,
            Err(CredentialError::Malformed)
        ));
        idp.set_token(Reply::Status(axum::http::StatusCode::UNAUTHORIZED));
        assert!(matches!(
            credentials.service_token().await,
            Err(CredentialError::Request(_))
        ));
    }

    #[tokio::test]
    async fn user_calls_exchange_the_users_token() {
        let idp = TestIdp::start().await;
        let exchanged = token(&json!("openshell-gateway"), now() + 300);
        idp.set_token(reply(&exchanged));
        let credentials = credentials(&idp, &[("OPENSHELL_TOKEN_EXCHANGE", "true")]).await;

        let user = SecretString::from("the-users-access-token");
        let result = credentials.on_behalf_of(&user).await.unwrap();
        assert_eq!(result.expose_secret(), exchanged);
        let form = &idp.token_requests()[0].form;
        assert_eq!(
            form["grant_type"],
            "urn:ietf:params:oauth:grant-type:token-exchange"
        );
        assert_eq!(form["subject_token"], "the-users-access-token");
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
            &json!(["kanbot-api", "openshell-gateway"]),
            now() + 300,
        )));
        assert!(matches!(
            credentials.on_behalf_of(&user).await,
            Err(CredentialError::SharedAudience)
        ));
    }

    #[tokio::test]
    async fn without_token_exchange_user_calls_use_the_service_account() {
        let idp = TestIdp::start().await;
        idp.set_token(reply(&token(&json!("openshell-gateway"), now() + 300)));
        let credentials = credentials(&idp, &[]).await;
        credentials
            .on_behalf_of(&SecretString::from("the-users-access-token"))
            .await
            .unwrap();
        let form = &idp.token_requests()[0].form;
        assert_eq!(form["grant_type"], "client_credentials");
        assert!(!form.values().any(|value| value == "the-users-access-token"));
    }
}
