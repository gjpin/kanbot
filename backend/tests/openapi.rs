//! The committed `OpenAPI` document (`openapi.json`, the contract the
//! frontend's client is generated from) matches the code.

use std::{
    path::PathBuf,
    process::Command,
    sync::atomic::{AtomicUsize, Ordering},
};

use serde_json::Value;

fn committed_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("openapi.json")
}

/// Runs the `openapi` binary, as a developer would, into a temporary file.
fn generate() -> String {
    static CALLS: AtomicUsize = AtomicUsize::new(0);
    let call = CALLS.fetch_add(1, Ordering::Relaxed);
    let path =
        std::env::temp_dir().join(format!("kanbot-openapi-{}-{call}.json", std::process::id()));
    let status = Command::new(env!("CARGO_BIN_EXE_openapi"))
        .arg(&path)
        .status()
        .unwrap();
    assert!(status.success(), "openapi exited with {status}");
    let json = std::fs::read_to_string(&path).unwrap();
    std::fs::remove_file(&path).unwrap();
    json
}

#[test]
fn committed_document_is_up_to_date() {
    let committed = std::fs::read_to_string(committed_path()).unwrap_or_default();
    assert!(
        committed == generate(),
        "openapi.json is out of date. From backend/, run\n\n    \
         cargo run --bin openapi -- openapi.json\n\n\
         then regenerate the frontend client (see frontend/AGENTS.md) and commit both."
    );
}

#[test]
fn document_describes_routes_and_errors() {
    let doc: Value = serde_json::from_str(&generate()).unwrap();

    assert_eq!(doc["openapi"], "3.1.0");
    assert_eq!(doc["info"].get("license"), None);
    assert_eq!(doc["paths"]["/health"]["get"]["operationId"], "health");
    let ready_503 = &doc["paths"]["/ready"]["get"]["responses"]["503"];
    assert_eq!(
        ready_503["content"]["application/problem+json"]["schema"]["$ref"],
        "#/components/schemas/Problem"
    );
    let problem = &doc["components"]["schemas"]["Problem"];
    assert_eq!(
        problem["required"],
        serde_json::json!(["type", "title", "status", "code"])
    );
    let codes = doc["components"]["schemas"]["ErrorCode"]["enum"]
        .as_array()
        .unwrap();
    assert!(
        codes.contains(&Value::from("validation_failed")),
        "{codes:?}"
    );
}

#[test]
fn rejects_missing_or_extra_arguments() {
    for args in [&[][..], &["a.json", "b.json"]] {
        let output = Command::new(env!("CARGO_BIN_EXE_openapi"))
            .args(args)
            .output()
            .unwrap();
        assert!(!output.status.success(), "{args:?}");
        let stderr = String::from_utf8(output.stderr).unwrap();
        assert!(stderr.contains("Usage"), "{stderr}");
    }
}

/// Generated clients name a method after each operation ID: two
/// operations with the same ID cannot both be generated.
#[test]
fn operation_ids_are_unique() {
    let doc: Value = serde_json::from_str(&generate()).unwrap();
    let mut ids: Vec<&str> = doc["paths"]
        .as_object()
        .unwrap()
        .values()
        .flat_map(|item| item.as_object().unwrap().values())
        .filter_map(|operation| operation["operationId"].as_str())
        .collect();
    let count = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), count, "duplicate operation IDs");
    assert!(count >= 30, "{count}");
}
