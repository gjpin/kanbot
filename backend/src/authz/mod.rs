//! Authorization with Cedar (docs/authorization.md): built-in `permit`
//! policies compiled into the binary, decided on entities loaded from the
//! database for each decision.

pub mod entities;
pub mod model;
pub mod policies;
mod repo;
pub mod service;
