//! Rebuilds the crate when a migration is added. `sqlx::migrate!` embeds the
//! files in `migrations/`, but on stable Rust it cannot tell Cargo to watch
//! the directory for new ones.

fn main() {
    println!("cargo:rerun-if-changed=migrations");
}
