//! The `OpenShell` integration (docs/openshell.md): organizations linked to
//! `OpenShell` workspaces, whose membership kanbot keeps in sync, one way.
//! Off unless `OPENSHELL_GATEWAY_URL` is set.

pub mod config;
pub mod credentials;
pub mod gateway;
pub mod model;
mod repo;
pub mod service;
pub mod sync;

use std::sync::Arc;

use secrecy::SecretString;

use crate::{
    auth::keys::KeyCache,
    openshell::{
        config::OpenShellConfig,
        credentials::{CredentialError, Credentials},
        gateway::{Gateway, GatewayError},
    },
};

/// Why a call with the service account's token failed. Never holds a
/// token.
#[derive(Debug, thiserror::Error)]
pub enum ServiceCallError {
    #[error("no token for the gateway: {0}")]
    Credentials(#[from] CredentialError),
    #[error("gateway call failed: {}", .0.kind())]
    Gateway(#[from] GatewayError),
}

/// The running integration: the gateway and tokens for it. The sync wakes
/// on the database's change notifications, so nothing here needs to.
pub struct OpenShell {
    pub gateway: Gateway,
    pub credentials: Credentials,
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
        })
    }

    /// Makes one gateway call with the service account's token, taken from
    /// the cache for each call, so a long sync never uses one about to
    /// expire. A token the gateway does not accept (`unauthenticated`) is
    /// dropped, and the call made once more with a new one. A denial
    /// (`permission_denied`) is final: a new token would be denied too.
    ///
    /// # Errors
    ///
    /// [`ServiceCallError`]: no token, or the call failed (for a refused
    /// token: with the new one too).
    pub async fn as_service<T, F>(
        &self,
        call: impl Fn(SecretString) -> F,
    ) -> Result<T, ServiceCallError>
    where
        F: Future<Output = Result<T, GatewayError>>,
    {
        let token = self.credentials.service_token().await?;
        match call(token).await {
            Err(GatewayError::Refused) => {
                self.credentials.forget_service_token().await;
                let token = self.credentials.service_token().await?;
                Ok(call(token).await?)
            }
            outcome => Ok(outcome?),
        }
    }
}
