//! The `OpenShell` integration (docs/openshell.md): organizations linked to
//! `OpenShell` workspaces, whose membership kanbot keeps in sync, one way.
//! Off unless `OPENSHELL_GATEWAY_URL` is set.

pub mod config;
pub mod gateway;
pub mod model;
