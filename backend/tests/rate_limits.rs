//! Rate limits and load shedding on the full router: per client IP (IPv6 by
//! /64, `X-Forwarded-For` only from trusted proxies), per user, and the cap
//! on requests in flight.

pub mod common;

use std::{
    net::SocketAddr,
    num::{NonZeroU32, NonZeroUsize},
    sync::Arc,
    time::Duration,
};

use axum::{
    Router,
    body::Body,
    http::{Request, StatusCode, header},
    response::Response,
    routing::post,
};
use common::idp::access_token;
use http_body_util::BodyExt;
use kanbot_backend::{
    db,
    http::{
        self, HttpSettings,
        client_ip::TrustedProxies,
        middleware::rate_limit::{RateLimit, RateLimits},
    },
    state::AppState,
    telemetry_relay,
};
use serde_json::{Value, json};
use sqlx::{PgPool, postgres::PgConnectOptions};
use tokio::net::TcpListener;
use tower::ServiceExt;

fn limit(per_second: u32, burst: u32) -> RateLimit {
    RateLimit {
        per_second: NonZeroU32::new(per_second).unwrap(),
        burst: NonZeroU32::new(burst).unwrap(),
    }
}

fn state(pool: PgPool) -> AppState {
    AppState {
        db: pool,
        migrator: &db::MIGRATOR,
        keys: common::idp::static_key_cache(),
        sessions: common::session_config(),
        authz: common::policies(),
    }
}

fn unreachable_pool() -> PgPool {
    db::pool_with(
        PgConnectOptions::new_without_pgpass()
            .host("127.0.0.1")
            .port(1),
    )
}

fn settings(rate_limits: RateLimits) -> HttpSettings {
    HttpSettings {
        rate_limits,
        ..HttpSettings::new()
    }
}

/// The app with `settings`, as the real server serves it to `peer`.
fn app_from(peer: &str, pool: PgPool, settings: HttpSettings) -> Router {
    common::serve_from(peer.parse().unwrap(), state(pool), settings, None)
}

async fn status(app: &Router, request: Request<Body>) -> StatusCode {
    app.clone().oneshot(request).await.unwrap().status()
}

fn health() -> Request<Body> {
    Request::get("/health").body(Body::empty()).unwrap()
}

fn health_forwarded_for(client: &str) -> Request<Body> {
    Request::get("/health")
        .header("x-forwarded-for", client)
        .body(Body::empty())
        .unwrap()
}

async fn problem_code(response: Response) -> String {
    let body = response.into_body().collect().await.unwrap().to_bytes();
    let body: Value = serde_json::from_slice(&body).unwrap();
    body["code"].as_str().unwrap().to_owned()
}

fn ip_limited(per_second: u32, burst: u32) -> RateLimits {
    RateLimits {
        ip: limit(per_second, burst),
        ..RateLimits::DEFAULT
    }
}

#[tokio::test]
async fn rate_limits_each_client_ip() {
    let app = app_from(
        "203.0.113.9:1000",
        unreachable_pool(),
        settings(ip_limited(1, 3)),
    );
    for _ in 0..3 {
        assert_eq!(status(&app, health()).await, StatusCode::OK);
    }
    let rejected = app.clone().oneshot(health()).await.unwrap();
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(rejected.headers()[header::RETRY_AFTER], "1");
    assert_eq!(problem_code(rejected).await, "rate_limited");

    // The limiter is shared by every router built from these settings only;
    // a client with another address has its own budget.
    let limits = ip_limited(1, 3);
    let app = http::router(state(unreachable_pool()), settings(limits), None).unwrap();
    for (peer, expected) in [
        ("203.0.113.9:1", StatusCode::OK),
        ("203.0.113.9:2", StatusCode::OK),
        ("203.0.113.9:3", StatusCode::OK),
        ("203.0.113.9:4", StatusCode::TOO_MANY_REQUESTS),
        ("198.51.100.7:1", StatusCode::OK),
    ] {
        let app = app
            .clone()
            .layer(axum::Extension(axum::extract::ConnectInfo(
                peer.parse::<SocketAddr>().unwrap(),
            )));
        assert_eq!(status(&app, health()).await, expected, "{peer}");
    }
}

#[tokio::test]
async fn ipv6_clients_share_a_limit_per_slash_64() {
    let app = http::router(state(unreachable_pool()), settings(ip_limited(1, 2)), None).unwrap();
    let from = |peer: &str| {
        app.clone()
            .layer(axum::Extension(axum::extract::ConnectInfo(
                peer.parse::<SocketAddr>().unwrap(),
            )))
    };
    assert_eq!(
        status(&from("[2001:db8:1:2::1]:1"), health()).await,
        StatusCode::OK
    );
    assert_eq!(
        status(&from("[2001:db8:1:2:ffff:ffff:ffff:ffff]:1"), health()).await,
        StatusCode::OK
    );
    // Same /64: over the limit.
    assert_eq!(
        status(&from("[2001:db8:1:2::abcd]:1"), health()).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Another /64 has its own budget.
    assert_eq!(
        status(&from("[2001:db8:1:3::1]:1"), health()).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn spoofed_forwarded_for_does_not_escape_the_limit() {
    // The peer is not a trusted proxy, so X-Forwarded-For is ignored.
    let app = app_from(
        "203.0.113.9:1000",
        unreachable_pool(),
        settings(ip_limited(1, 3)),
    );
    for (i, expected) in [
        StatusCode::OK,
        StatusCode::OK,
        StatusCode::OK,
        StatusCode::TOO_MANY_REQUESTS,
    ]
    .into_iter()
    .enumerate()
    {
        let spoofed = format!("10.0.0.{i}");
        assert_eq!(
            status(&app, health_forwarded_for(&spoofed)).await,
            expected,
            "{spoofed}"
        );
    }
}

#[tokio::test]
async fn behind_a_trusted_proxy_each_forwarded_client_has_its_own_limit() {
    let app = app_from(
        "10.0.0.1:40000",
        unreachable_pool(),
        HttpSettings {
            trusted_proxies: Arc::new(TrustedProxies::parse_list("10.0.0.0/8").unwrap()),
            ..settings(ip_limited(1, 2))
        },
    );
    for expected in [
        StatusCode::OK,
        StatusCode::OK,
        StatusCode::TOO_MANY_REQUESTS,
    ] {
        assert_eq!(
            status(&app, health_forwarded_for("203.0.113.9")).await,
            expected
        );
    }
    assert_eq!(
        status(&app, health_forwarded_for("198.51.100.7")).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn without_connect_info_requests_fail_closed() {
    let app = http::router(state(unreachable_pool()), HttpSettings::new(), None).unwrap();

    let response = app.oneshot(health()).await.unwrap();

    assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    assert_eq!(problem_code(response).await, "internal");
}

fn me(subject: Option<&str>) -> Request<Body> {
    let mut request = Request::get("/me");
    if let Some(subject) = subject {
        request = request.header(
            header::AUTHORIZATION,
            format!("Bearer {}", access_token(subject, &["kanbot-user"])),
        );
    }
    request.body(Body::empty()).unwrap()
}

#[sqlx::test]
async fn rate_limits_each_user(pool: PgPool) {
    let app = app_from(
        common::PEER,
        pool,
        settings(RateLimits {
            user: limit(1, 2),
            ..RateLimits::DEFAULT
        }),
    );

    assert_eq!(status(&app, me(Some("alice"))).await, StatusCode::OK);
    assert_eq!(status(&app, me(Some("alice"))).await, StatusCode::OK);
    let rejected = app.clone().oneshot(me(Some("alice"))).await.unwrap();
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(rejected.headers()[header::RETRY_AFTER], "1");
    assert_eq!(problem_code(rejected).await, "rate_limited");

    // From the same address, another user has their own budget...
    assert_eq!(status(&app, me(Some("bob"))).await, StatusCode::OK);
    // ...and anonymous requests are not limited per user.
    for _ in 0..5 {
        assert_eq!(status(&app, health()).await, StatusCode::OK);
        assert_eq!(status(&app, me(None)).await, StatusCode::UNAUTHORIZED);
    }
}

/// A collector that answers after `delay`.
async fn slow_collector(delay: Duration) -> reqwest::Url {
    let app = Router::new().route(
        "/{*path}",
        post(move || async move {
            tokio::time::sleep(delay).await;
            "ok"
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    format!("http://{addr}").parse().unwrap()
}

#[sqlx::test]
async fn sheds_load_above_the_in_flight_cap(pool: PgPool) {
    let relay = telemetry_relay::routes(
        slow_collector(Duration::from_millis(500)).await,
        RateLimits::DEFAULT.telemetry,
    )
    .unwrap();
    let app = common::serve(
        state(pool),
        HttpSettings {
            max_in_flight_requests: NonZeroUsize::new(1).unwrap(),
            ..HttpSettings::new()
        },
        Some(relay),
    );
    let token = format!("Bearer {}", access_token("alice", &["kanbot-user"]));
    let opt_in = Request::put("/me/preferences")
        .header(header::AUTHORIZATION, &token)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(json!({ "telemetry_opt_in": true }).to_string()))
        .unwrap();
    assert_eq!(status(&app, opt_in).await, StatusCode::OK);

    // One slow request holds the only slot...
    let slow = Request::post("/telemetry/v1/traces")
        .header(header::AUTHORIZATION, &token)
        .header(header::CONTENT_TYPE, "application/x-protobuf")
        .body(Body::from("batch"))
        .unwrap();
    let in_flight = tokio::spawn(app.clone().oneshot(slow));
    tokio::time::sleep(Duration::from_millis(100)).await;

    // ...so the next one is shed at once.
    let shed = app.clone().oneshot(health()).await.unwrap();
    assert_eq!(shed.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(shed.headers()[header::RETRY_AFTER], "1");
    assert_eq!(problem_code(shed).await, "unavailable");

    assert_eq!(in_flight.await.unwrap().unwrap().status(), StatusCode::OK);
    assert_eq!(status(&app, health()).await, StatusCode::OK);
}

#[tokio::test]
async fn sign_in_routes_have_their_own_limit_per_client() {
    let app = app_from(
        "203.0.113.9:1000",
        unreachable_pool(),
        settings(RateLimits {
            login: limit(1, 2),
            ..RateLimits::DEFAULT
        }),
    );
    let login = || {
        Request::get("/auth/login?platform=web")
            .body(Body::empty())
            .unwrap()
    };
    // Discovery never ran here: 503, but counted.
    assert_eq!(status(&app, login()).await, StatusCode::SERVICE_UNAVAILABLE);
    let token = Request::post("/auth/token")
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from("{}"))
        .unwrap();
    assert_eq!(status(&app, token).await, StatusCode::UNPROCESSABLE_ENTITY);
    let rejected = app.clone().oneshot(login()).await.unwrap();
    assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(problem_code(rejected).await, "rate_limited");
    let callback = Request::get("/auth/callback").body(Body::empty()).unwrap();
    assert_eq!(status(&app, callback).await, StatusCode::TOO_MANY_REQUESTS);

    // Other routes are not affected.
    for _ in 0..5 {
        assert_eq!(status(&app, health()).await, StatusCode::OK);
        let config = Request::get("/auth/config").body(Body::empty()).unwrap();
        assert_eq!(status(&app, config).await, StatusCode::OK);
    }
}
