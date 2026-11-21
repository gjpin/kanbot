//! Generates the OpenShell gateway's gRPC client and server from the
//! vendored `.proto` files. Needs `PROTOC` (see `fetch-protoc.sh`).

use std::path::PathBuf;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("..");
    let proto = root.join("proto");
    tonic_prost_build::configure()
        .build_client(true)
        // The server side is for kanbot's tests: a fake gateway.
        .build_server(true)
        // kanbot builds its own channel (TLS settings, timeouts).
        .build_transport(false)
        // A fake gateway in tests implements only what it needs.
        .generate_default_stubs(true)
        .out_dir(root.join("src/generated"))
        .compile_protos(&[proto.join("openshell.proto")], &[proto])?;
    Ok(())
}
