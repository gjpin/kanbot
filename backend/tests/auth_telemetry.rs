//! Authentication never puts tokens or claim values into telemetry: not in
//! spans, logs (at any level) or metrics, for accepted and refused tokens
//! alike.

pub mod common;

use axum::{
    body::Body,
    http::{Request, header},
};
use common::idp::{claims, sign};
use kanbot_backend::{auth::middleware::AuthMetrics, db, http::HttpSettings, state::AppState};
use opentelemetry::{metrics::MeterProvider, trace::TracerProvider as _};
use opentelemetry_appender_tracing::layer::OpenTelemetryTracingBridge;
use opentelemetry_sdk::{
    logs::{InMemoryLogExporter, SdkLoggerProvider},
    metrics::{InMemoryMetricExporter, PeriodicReader, SdkMeterProvider},
    trace::{InMemorySpanExporter, SdkTracerProvider},
};
use serde_json::json;
use sqlx::PgPool;
use tower::ServiceExt;
use tracing_subscriber::layer::SubscriberExt;

/// Claim values that must never be recorded.
const SUBJECT: &str = "subject-6f1c2b";
const NAME: &str = "Name-9d7e41";
const USERNAME: &str = "username-3a8c55";
const GROUP: &str = "group-b42e90";
const CLIENT: &str = "client-77c1d3";

#[sqlx::test]
async fn no_token_or_claim_value_is_recorded(pool: PgPool) {
    let spans = InMemorySpanExporter::default();
    let tracer_provider = SdkTracerProvider::builder()
        .with_simple_exporter(spans.clone())
        .build();
    let logs = InMemoryLogExporter::default();
    let logger_provider = SdkLoggerProvider::builder()
        .with_simple_exporter(logs.clone())
        .build();
    let metrics = InMemoryMetricExporter::default();
    let meter_provider = SdkMeterProvider::builder()
        .with_reader(PeriodicReader::builder(metrics.clone()).build())
        .build();
    // No level filter: debug and trace events are recorded too.
    let subscriber = tracing_subscriber::registry()
        .with(tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("test")))
        .with(OpenTelemetryTracingBridge::new(&logger_provider));
    let _guard = tracing::subscriber::set_default(subscriber);

    let app = common::serve(
        AppState {
            db: pool,
            migrator: &db::MIGRATOR,
            keys: common::idp::static_key_cache(),
            sessions: common::session_config(),
            authz: common::policies(),
            openshell: None,
        },
        HttpSettings {
            auth_metrics: AuthMetrics::new(&meter_provider.meter("test")),
            ..HttpSettings::new()
        },
        None,
    );

    let mut user = claims(SUBJECT, &["kanbot-user", GROUP]);
    user["name"] = json!(NAME);
    user["preferred_username"] = json!(USERNAME);
    user["azp"] = json!(CLIENT);
    let mut no_role = user.clone();
    no_role["groups"] = json!([GROUP]);
    let mut expired = user.clone();
    expired["exp"] = json!(1_000);
    let tokens = [
        sign("rsa-a", &user),
        sign("rsa-a", &no_role),
        sign("rsa-a", &expired),
        sign("rsa-b", &user),
    ];
    for token in &tokens {
        for path in ["/me", "/health"] {
            let request = Request::get(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .header(header::COOKIE, "session=cookie-5e2a17")
                .body(Body::empty())
                .unwrap();
            app.clone().oneshot(request).await.unwrap();
        }
    }

    tracer_provider.force_flush().unwrap();
    logger_provider.force_flush().unwrap();
    meter_provider.force_flush().unwrap();
    let recorded = format!(
        "{:?}\n{:?}\n{:?}",
        spans.get_finished_spans().unwrap(),
        logs.get_emitted_logs().unwrap(),
        metrics.get_finished_metrics().unwrap(),
    );
    // The recording is not empty: the requests were seen.
    assert!(
        recorded.contains("kanbot.auth.token.rejections"),
        "{recorded}"
    );
    assert!(recorded.contains("GET /me"), "{recorded}");

    let mut secrets = vec![
        SUBJECT,
        NAME,
        USERNAME,
        GROUP,
        CLIENT,
        "cookie-5e2a17",
        "Bearer",
    ];
    for token in &tokens {
        secrets.push(token);
        secrets.extend(token.split('.'));
    }
    for secret in secrets {
        assert!(!recorded.contains(secret), "recorded: {secret}");
    }
}

/// Records everything the closure's requests emit, at every level.
struct Recorder {
    spans: InMemorySpanExporter,
    logs: InMemoryLogExporter,
    tracer_provider: SdkTracerProvider,
    logger_provider: SdkLoggerProvider,
}

impl Recorder {
    fn new() -> (Self, impl tracing::Subscriber + Send + Sync) {
        let spans = InMemorySpanExporter::default();
        let tracer_provider = SdkTracerProvider::builder()
            .with_simple_exporter(spans.clone())
            .build();
        let logs = InMemoryLogExporter::default();
        let logger_provider = SdkLoggerProvider::builder()
            .with_simple_exporter(logs.clone())
            .build();
        let subscriber = tracing_subscriber::registry()
            .with(tracing_opentelemetry::layer().with_tracer(tracer_provider.tracer("test")))
            .with(OpenTelemetryTracingBridge::new(&logger_provider));
        (
            Self {
                spans,
                logs,
                tracer_provider,
                logger_provider,
            },
            subscriber,
        )
    }

    fn recorded(&self) -> String {
        self.tracer_provider.force_flush().unwrap();
        self.logger_provider.force_flush().unwrap();
        format!(
            "{:?}\n{:?}",
            self.spans.get_finished_spans().unwrap(),
            self.logs.get_emitted_logs().unwrap(),
        )
    }
}

fn query_value(url: &str, name: &str) -> String {
    reqwest::Url::parse(url)
        .unwrap()
        .query_pairs()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.into_owned())
        .unwrap()
}

fn cookie_value(response: &axum::response::Response, name: &str) -> String {
    response
        .headers()
        .get_all(header::SET_COOKIE)
        .iter()
        .map(|value| value.to_str().unwrap())
        .find_map(|cookie| cookie.strip_prefix(&format!("{name}=")))
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned()
}

/// The login flow, a refresh and the sign-out: no state, nonce, code,
/// verifier, binding, session token, identity provider token or client
/// secret is ever recorded.
#[sqlx::test]
async fn no_session_secret_is_recorded(pool: PgPool) {
    use common::idp::{Reply, TestIdp, issued_claims, now};

    let (recorder, subscriber) = Recorder::new();
    let _guard = tracing::subscriber::set_default(subscriber);
    let idp = TestIdp::start().await;
    let app = common::serve(
        AppState {
            db: pool.clone(),
            migrator: &db::MIGRATOR,
            keys: idp.loaded_key_cache(&[]).await,
            sessions: common::session_config(),
            authz: common::policies(),
            openshell: None,
        },
        HttpSettings::new(),
        None,
    );
    let send = |request: Request<Body>| {
        let app = app.clone();
        async move { app.oneshot(request).await.unwrap() }
    };

    let login = send(
        Request::get("/auth/login?platform=web")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let location = login.headers()[header::LOCATION]
        .to_str()
        .unwrap()
        .to_owned();
    let state = query_value(&location, "state");
    let nonce = query_value(&location, "nonce");
    let challenge = query_value(&location, "code_challenge");
    let binding = cookie_value(&login, "__Host-kanbot_login");

    let mut access = issued_claims(&idp.issuer, SUBJECT, &["kanbot-user", GROUP]);
    access["name"] = json!(NAME);
    let access_token = sign("rsa-a", &access);
    let id_token = sign(
        "rsa-a",
        &json!({
            "iss": idp.issuer, "aud": "kanbot", "azp": "kanbot", "sub": SUBJECT,
            "exp": now().saturating_add(300), "iat": now(), "nonce": nonce,
        }),
    );
    let refresh_token = "refresh-token-8c1f5a";
    idp.set_token(Reply::Json(json!({
        "access_token": access_token,
        "id_token": id_token,
        "refresh_token": refresh_token,
    })));
    let callback = send(
        Request::get(format!("/auth/callback?state={state}&code=code-4b9d2e"))
            .header(header::COOKIE, format!("__Host-kanbot_login={binding}"))
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    let session = cookie_value(&callback, "__Host-kanbot_session");
    let cookie = format!("__Host-kanbot_session={session}");

    // A refresh, with a rotated refresh token.
    sqlx::query!("UPDATE sessions SET access_expires_at = now() + interval '30 seconds'")
        .execute(&pool)
        .await
        .unwrap();
    access["exp"] = json!(now().saturating_add(900));
    let refreshed = sign("rsa-a", &access);
    let rotated = "rotated-refresh-2d7e90";
    idp.set_token(Reply::Json(json!({
        "access_token": refreshed,
        "refresh_token": rotated,
    })));
    let me = send(
        Request::get("/me")
            .header(header::COOKIE, &cookie)
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(me.status(), axum::http::StatusCode::OK);
    let logout = send(
        Request::post("/auth/logout")
            .header(header::COOKIE, &cookie)
            .header(header::ORIGIN, "http://localhost:3000")
            .header("x-kanbot-csrf", "1")
            .body(Body::empty())
            .unwrap(),
    )
    .await;
    assert_eq!(logout.status(), axum::http::StatusCode::OK);

    let recorded = recorder.recorded();
    assert!(recorded.contains("signed in"), "{recorded}");
    assert!(recorded.contains("session refreshed"), "{recorded}");
    assert!(recorded.contains("signed out"), "{recorded}");
    let mut secrets = vec![
        state,
        nonce,
        challenge,
        binding,
        session,
        "code-4b9d2e".to_owned(),
        refresh_token.to_owned(),
        rotated.to_owned(),
        "kanbot-dev-client-secret".to_owned(),
        SUBJECT.to_owned(),
        NAME.to_owned(),
        GROUP.to_owned(),
    ];
    for token in [&access_token, &id_token, &refreshed] {
        secrets.extend(token.split('.').map(str::to_owned));
    }
    for secret in secrets {
        assert!(!recorded.contains(&secret), "recorded: {secret}");
    }
}
