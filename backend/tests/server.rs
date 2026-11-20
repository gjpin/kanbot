//! Runs the real binary: startup, serving, graceful shutdown and startup
//! failures.
#![cfg(unix)]

use std::{
    net::SocketAddr,
    process::Stdio,
    sync::{Arc, Mutex},
    time::Duration,
};

use sqlx::{
    ConnectOptions, Connection,
    migrate::Migrate,
    postgres::{PgConnectOptions, PgConnection, PgPoolOptions},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    process::{Child, Command},
    time::{sleep, timeout},
};

const UNREACHABLE_DB: &str = "postgres://127.0.0.1:1/kanbot";

/// The binary, configured only by what the test sets. Telemetry export is
/// off unless a test turns it on.
fn server(listen_addr: SocketAddr, database_url: Option<&str>) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kanbot-backend"));
    for (name, _) in std::env::vars_os() {
        if name.to_string_lossy().starts_with("OTEL_") {
            command.env_remove(name);
        }
    }
    command
        .env("LISTEN_ADDR", listen_addr.to_string())
        .env("OTEL_SDK_DISABLED", "true")
        .env_remove("DATABASE_URL")
        .env_remove("RUST_LOG")
        .env_remove("CORS_ALLOWED_ORIGINS")
        .env_remove("TRUSTED_PROXIES")
        .env_remove("TELEMETRY_RELAY_UPSTREAM")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true);
    if let Some(url) = database_url {
        command.env("DATABASE_URL", url);
    }
    command
}

async fn free_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

async fn get(addr: SocketAddr, path: &str) -> std::io::Result<String> {
    send(
        addr,
        &format!("GET {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n"),
    )
    .await
}

async fn post_protobuf(addr: SocketAddr, path: &str, body: &str) -> std::io::Result<String> {
    send(
        addr,
        &format!(
            "POST {path} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\
             Content-Type: application/x-protobuf\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        ),
    )
    .await
}

async fn send(addr: SocketAddr, request: &str) -> std::io::Result<String> {
    let mut stream = TcpStream::connect(addr).await?;
    stream.write_all(request.as_bytes()).await?;
    let mut response = String::new();
    stream.read_to_string(&mut response).await?;
    Ok(response)
}

/// A fake OTLP/HTTP collector: records the path of every POST it receives.
async fn collector() -> (SocketAddr, Arc<Mutex<Vec<String>>>) {
    let paths = Arc::new(Mutex::new(Vec::new()));
    let recorded = Arc::clone(&paths);
    let app = axum::Router::new().route(
        "/{*path}",
        axum::routing::post(move |uri: axum::http::Uri| async move {
            recorded.lock().unwrap().push(uri.path().to_owned());
            "ok"
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (addr, paths)
}

/// Polls `/health` until the server answers, for up to 10 seconds.
async fn wait_until_serving(addr: SocketAddr) -> String {
    for _ in 0..200 {
        if let Ok(response) = get(addr, "/health").await {
            return response;
        }
        sleep(Duration::from_millis(50)).await;
    }
    panic!("server did not start on {addr}");
}

async fn send_signal(child: &Child, signal: &str) {
    let pid = child.id().unwrap().to_string();
    let status = Command::new("kill")
        .args([signal, &pid])
        .status()
        .await
        .unwrap();
    assert!(status.success());
}

async fn stderr_of_failed_start(mut command: Command) -> String {
    let output = timeout(Duration::from_secs(10), command.output())
        .await
        .unwrap()
        .unwrap();
    assert!(!output.status.success(), "expected startup to fail");
    String::from_utf8(output.stderr).unwrap()
}

async fn serves_then_exits_cleanly_on(signal: &str) {
    let addr = free_addr().await;
    let child = server(addr, Some(UNREACHABLE_DB)).spawn().unwrap();

    let response = wait_until_serving(addr).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with("ok"), "{response}");

    send_signal(&child, signal).await;
    let output = timeout(Duration::from_secs(10), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();
    assert!(output.status.success(), "exit status: {}", output.status);

    // Without RUST_LOG, info-level events are logged (to stdout).
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("listening"), "{stdout}");
    assert!(stdout.contains("shutting down"), "{stdout}");
}

#[tokio::test]
async fn serves_then_exits_cleanly_on_sigterm() {
    serves_then_exits_cleanly_on("-TERM").await;
}

#[tokio::test]
async fn serves_then_exits_cleanly_on_sigint() {
    serves_then_exits_cleanly_on("-INT").await;
}

#[tokio::test]
async fn fails_without_database_url() {
    let stderr = stderr_of_failed_start(server(free_addr().await, None)).await;
    assert!(stderr.contains("DATABASE_URL"), "{stderr}");
}

#[tokio::test]
async fn fails_with_invalid_database_url() {
    let stderr = stderr_of_failed_start(server(free_addr().await, Some("not a url"))).await;
    assert!(stderr.contains("Database"), "{stderr}");
}

#[tokio::test]
async fn fails_when_port_is_taken() {
    let taken = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = taken.local_addr().unwrap();
    let stderr = stderr_of_failed_start(server(addr, Some(UNREACHABLE_DB))).await;
    assert!(stderr.contains("Bind"), "{stderr}");
}

#[tokio::test]
async fn fails_with_invalid_cors_origin() {
    let mut command = server(free_addr().await, Some(UNREACHABLE_DB));
    command.env("CORS_ALLOWED_ORIGINS", "*");
    let stderr = stderr_of_failed_start(command).await;
    assert!(stderr.contains("CorsOrigin"), "{stderr}");
}

#[tokio::test]
async fn fails_with_unknown_arguments() {
    let mut command = server(free_addr().await, Some(UNREACHABLE_DB));
    command.arg("serve");
    let stderr = stderr_of_failed_start(command).await;
    assert!(stderr.contains("Usage"), "{stderr}");
}

#[sqlx::test]
async fn migrate_applies_migrations_and_exits(_: PgPoolOptions, options: PgConnectOptions) {
    let mut command = server(free_addr().await, Some(options.to_url_lossy().as_str()));
    command.arg("migrate");

    let output = timeout(Duration::from_secs(30), command.output())
        .await
        .unwrap()
        .unwrap();

    assert!(output.status.success(), "exit status: {}", output.status);
    let stdout = String::from_utf8(output.stdout).unwrap();
    assert!(stdout.contains("migrations are up to date"), "{stdout}");
    let mut conn = PgConnection::connect_with(&options).await.unwrap();
    assert!(
        conn.list_applied_migrations("_sqlx_migrations")
            .await
            .is_ok(),
        "migrate must create the migrations table"
    );
}

#[tokio::test]
async fn migrate_fails_without_database() {
    let mut command = server(free_addr().await, Some(UNREACHABLE_DB));
    command.arg("migrate");
    let stderr = stderr_of_failed_start(command).await;
    assert!(stderr.contains("Migrate"), "{stderr}");
}

#[tokio::test]
async fn exports_telemetry_over_otlp() {
    let (collector, paths) = collector().await;
    let addr = free_addr().await;
    let mut command = server(addr, Some(UNREACHABLE_DB));
    command
        .env_remove("OTEL_SDK_DISABLED")
        .env("OTEL_EXPORTER_OTLP_ENDPOINT", format!("http://{collector}"));
    let child = command.spawn().unwrap();

    let response = wait_until_serving(addr).await;
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    send_signal(&child, "-TERM").await;
    let output = timeout(Duration::from_secs(30), child.wait_with_output())
        .await
        .unwrap()
        .unwrap();

    assert!(output.status.success(), "exit status: {}", output.status);
    // Shutdown flushes every signal: the request's span, the startup and
    // shutdown logs, and the HTTP metrics.
    let paths = paths.lock().unwrap();
    for signal in ["/v1/traces", "/v1/logs", "/v1/metrics"] {
        assert!(
            paths.iter().any(|path| path == signal),
            "{signal}: {paths:?}"
        );
    }
}

#[tokio::test]
async fn relays_telemetry_through_the_real_server() {
    let (collector, paths) = collector().await;
    let addr = free_addr().await;
    let mut command = server(addr, Some(UNREACHABLE_DB));
    command.env("TELEMETRY_RELAY_UPSTREAM", format!("http://{collector}"));
    let child = command.spawn().unwrap();
    wait_until_serving(addr).await;

    let response = post_protobuf(addr, "/telemetry/v1/traces", "batch")
        .await
        .unwrap();

    // 200 needs the peer address for the rate limit: proves the server
    // provides connect info.
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert_eq!(*paths.lock().unwrap(), ["/v1/traces"]);
    send_signal(&child, "-TERM").await;
}

#[tokio::test]
async fn fails_with_invalid_relay_upstream() {
    let mut command = server(free_addr().await, Some(UNREACHABLE_DB));
    command.env("TELEMETRY_RELAY_UPSTREAM", "ftp://collector");
    let stderr = stderr_of_failed_start(command).await;
    assert!(stderr.contains("RelayUpstream"), "{stderr}");
}
