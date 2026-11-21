//! The `OpenShell` integration (docs/openshell.md): organizations linked to
//! `OpenShell` workspaces, whose membership kanbot keeps in sync, one way.
//! Off unless `OPENSHELL_GATEWAY_URL` is set.

pub mod config;
pub mod credentials;
pub mod gateway;
pub mod model;
mod repo;
pub mod sync;

use std::sync::Arc;

use tokio::sync::Notify;

use crate::{
    auth::keys::KeyCache,
    openshell::{config::OpenShellConfig, credentials::Credentials, gateway::Gateway},
};

/// The running integration: the gateway, tokens for it, and the sync's
/// wake-up.
pub struct OpenShell {
    pub gateway: Gateway,
    pub credentials: Credentials,
    wake: Notify,
}

impl OpenShell {
    /// # Errors
    ///
    /// [`gateway::GatewayError::Setup`] if the gateway's URL or
    /// certificates cannot be used.
    pub fn new(
        config: OpenShellConfig,
        keys: Arc<KeyCache>,
    ) -> Result<Self, gateway::GatewayError> {
        let gateway = Gateway::new(&config)?;
        Ok(Self {
            gateway,
            credentials: Credentials::new(Arc::new(config), keys),
            wake: Notify::new(),
        })
    }

    /// Asks the sync to run now (a link changed).
    pub fn wake_sync(&self) {
        self.wake.notify_one();
    }
}
