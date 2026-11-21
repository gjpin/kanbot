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
