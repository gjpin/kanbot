//! The `OpenShell` gateway's gRPC API, for workspace membership. Every call
//! carries a bearer token for the gateway's audience (`credentials.rs`);
//! the token is marked sensitive and never logged.

use std::time::Duration;

use openshell_api::openshell::{
    datamodel::v1::{WorkspaceSelector, workspace_selector::Selection},
    v1::{
        AddWorkspaceMemberRequest, GetWorkspaceRequest, ListWorkspaceMembersRequest,
        RemoveWorkspaceMemberRequest, WorkspaceRole, open_shell_client::OpenShellClient,
    },
};
use secrecy::{ExposeSecret, SecretString};
use tonic::{
    Code, Request, Status,
    metadata::MetadataValue,
    transport::{Certificate, Channel, ClientTlsConfig, Endpoint},
};

use crate::openshell::{
    config::OpenShellConfig,
    model::{MemberRole, WorkspaceName},
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Bounds a whole call, connecting and the TLS handshake included.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
/// HTTP/2 pings keep the connection alive between syncs, and find a dead
/// one before a call waits on it.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(30);
const KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// Largest message read: a page of 500 members is far smaller.
const MAX_MESSAGE_BYTES: usize = 1024 * 1024;
/// Members per page when listing.
const PAGE_SIZE: i32 = 500;
/// Pages read at most: 50,000 members.
const MAX_PAGES: usize = 100;

/// A failed gateway call. Never holds a token.
#[derive(Debug, thiserror::Error)]
pub enum GatewayError {
    #[error("the gateway's endpoint cannot be used")]
    Setup(#[source] tonic::transport::Error),
    #[error("not found at the gateway")]
    NotFound,
    /// `unauthenticated` or `permission_denied`: the token is not good
    /// enough for this call.
    #[error("refused by the gateway")]
    Refused,
    /// The gateway is unreachable or overloaded; retrying later may work.
    #[error("the gateway is unavailable")]
    Unavailable,
    #[error("the gateway answered {0:?}")]
    Other(Code),
    #[error("the gateway listed more members than kanbot reads")]
    TooManyMembers,
    #[error("the gateway repeated a page")]
    RepeatedPage,
}

impl GatewayError {
    /// A bounded name for logs and metrics.
    #[must_use]
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Setup(_) => "setup",
            Self::NotFound => "not_found",
            Self::Refused => "refused",
            Self::Unavailable => "unavailable",
            Self::Other(_) => "other",
            Self::TooManyMembers => "too_many_members",
            Self::RepeatedPage => "repeated_page",
        }
    }
}

impl From<Status> for GatewayError {
    fn from(status: Status) -> Self {
        match status.code() {
            Code::NotFound => Self::NotFound,
            Code::Unauthenticated | Code::PermissionDenied => Self::Refused,
            Code::Unavailable | Code::DeadlineExceeded | Code::ResourceExhausted => {
                Self::Unavailable
            }
            code => Self::Other(code),
        }
    }
}

/// A member of a workspace, as the gateway lists it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Member {
    /// The OIDC subject.
    pub subject: String,
    /// `None` for a role this kanbot version does not know.
    pub role: Option<MemberRole>,
}

/// A client of one gateway. Cheap to clone; connects lazily.
#[derive(Clone)]
pub struct Gateway {
    client: OpenShellClient<Channel>,
}

fn selector(workspace: &WorkspaceName) -> WorkspaceSelector {
    WorkspaceSelector {
        selection: Some(Selection::Workspace(workspace.as_str().to_owned())),
    }
}

fn role_to(role: MemberRole) -> i32 {
    match role {
        MemberRole::User => WorkspaceRole::User.into(),
        MemberRole::Admin => WorkspaceRole::Admin.into(),
    }
}

impl Gateway {
    /// A client of `config.gateway`: TLS with the system roots plus
    /// `OPENSHELL_CA_FILE`, connect and request timeouts.
    ///
    /// # Errors
    ///
    /// [`GatewayError::Setup`] if the URL or the certificates cannot be
    /// used.
    pub fn new(config: &OpenShellConfig) -> Result<Self, GatewayError> {
        let mut endpoint = Endpoint::from_shared(config.gateway.as_str().to_owned())
            .map_err(GatewayError::Setup)?
            .connect_timeout(CONNECT_TIMEOUT)
            .timeout(REQUEST_TIMEOUT)
            .http2_keep_alive_interval(KEEPALIVE_INTERVAL)
            .keep_alive_timeout(KEEPALIVE_TIMEOUT)
            .keep_alive_while_idle(true);
        if config.gateway.scheme() == "https" {
            let tls = |native_roots: bool| {
                let mut tls = ClientTlsConfig::new();
                if native_roots {
                    tls = tls.with_native_roots();
                }
                if let Some(pem) = &config.ca_pem {
                    tls = tls.ca_certificate(Certificate::from_pem(pem));
                }
                tls
            };
            endpoint = match endpoint.clone().tls_config(tls(true)) {
                Ok(endpoint) => endpoint,
                // A minimal image may have no system roots: with
                // OPENSHELL_CA_FILE, that file is enough.
                Err(_) if config.ca_pem.is_some() => endpoint
                    .tls_config(tls(false))
                    .map_err(GatewayError::Setup)?,
                Err(error) => return Err(GatewayError::Setup(error)),
            };
        }
        Ok(Self {
            client: OpenShellClient::new(endpoint.connect_lazy())
                .max_decoding_message_size(MAX_MESSAGE_BYTES),
        })
    }

    /// `message` with `token` as its bearer credential.
    fn request<T>(token: &SecretString, message: T) -> Result<Request<T>, GatewayError> {
        let mut value = MetadataValue::try_from(format!("Bearer {}", token.expose_secret()))
            .map_err(|_| GatewayError::Refused)?;
        value.set_sensitive(true);
        let mut request = Request::new(message);
        request.metadata_mut().insert("authorization", value);
        Ok(request)
    }

    /// Whether the workspace exists and `token`'s principal may see it.
    ///
    /// # Errors
    ///
    /// A [`GatewayError`] other than not found.
    pub async fn workspace_exists(
        &self,
        token: &SecretString,
        workspace: &WorkspaceName,
    ) -> Result<bool, GatewayError> {
        let request = Self::request(
            token,
            GetWorkspaceRequest {
                name: workspace.as_str().to_owned(),
            },
        )?;
        match self.client.clone().get_workspace(request).await {
            Ok(_) => Ok(true),
            Err(status) => match GatewayError::from(status) {
                GatewayError::NotFound => Ok(false),
                error => Err(error),
            },
        }
    }

    /// Every member of the workspace.
    ///
    /// # Errors
    ///
    /// A [`GatewayError`], or [`GatewayError::TooManyMembers`].
    pub async fn members(
        &self,
        token: &SecretString,
        workspace: &WorkspaceName,
    ) -> Result<Vec<Member>, GatewayError> {
        let mut members = Vec::new();
        let mut page_token = String::new();
        for _ in 0..MAX_PAGES {
            let request = Self::request(
                token,
                ListWorkspaceMembersRequest {
                    workspace_scope: Some(selector(workspace)),
                    page_size: PAGE_SIZE,
                    page_token: page_token.clone(),
                },
            )?;
            let page = self
                .client
                .clone()
                .list_workspace_members(request)
                .await?
                .into_inner();
            members.extend(page.members.into_iter().map(|member| Member {
                subject: member.principal_subject,
                role: match WorkspaceRole::try_from(member.role) {
                    Ok(WorkspaceRole::User) => Some(MemberRole::User),
                    Ok(WorkspaceRole::Admin) => Some(MemberRole::Admin),
                    _ => None,
                },
            }));
            if page.next_page_token.is_empty() {
                return Ok(members);
            }
            if page.next_page_token == page_token {
                return Err(GatewayError::RepeatedPage);
            }
            page_token = page.next_page_token;
        }
        Err(GatewayError::TooManyMembers)
    }

    /// Makes `subject` a member with `role`. Already a member is fine: an
    /// earlier attempt, or another instance, got there first.
    ///
    /// # Errors
    ///
    /// A [`GatewayError`].
    pub async fn add_member(
        &self,
        token: &SecretString,
        workspace: &WorkspaceName,
        subject: &str,
        role: MemberRole,
    ) -> Result<(), GatewayError> {
        let request = Self::request(
            token,
            AddWorkspaceMemberRequest {
                workspace_scope: Some(selector(workspace)),
                principal_subject: subject.to_owned(),
                role: role_to(role),
                request_id: uuid::Uuid::new_v4().to_string(),
            },
        )?;
        match self.client.clone().add_workspace_member(request).await {
            Ok(_) => Ok(()),
            Err(status) if status.code() == Code::AlreadyExists => Ok(()),
            Err(status) => Err(status.into()),
        }
    }

    /// Removes `subject` from the workspace; already absent is fine.
    ///
    /// # Errors
    ///
    /// A [`GatewayError`].
    pub async fn remove_member(
        &self,
        token: &SecretString,
        workspace: &WorkspaceName,
        subject: &str,
    ) -> Result<(), GatewayError> {
        let request = Self::request(
            token,
            RemoveWorkspaceMemberRequest {
                workspace_scope: Some(selector(workspace)),
                principal_subject: subject.to_owned(),
                allow_missing: true,
                request_id: uuid::Uuid::new_v4().to_string(),
            },
        )?;
        self.client.clone().remove_workspace_member(request).await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statuses_map_to_errors() {
        for (code, expected) in [
            (Code::NotFound, "not found at the gateway"),
            (Code::Unauthenticated, "refused by the gateway"),
            (Code::PermissionDenied, "refused by the gateway"),
            (Code::Unavailable, "the gateway is unavailable"),
            (Code::DeadlineExceeded, "the gateway is unavailable"),
            (Code::ResourceExhausted, "the gateway is unavailable"),
            (Code::Internal, "the gateway answered Internal"),
        ] {
            assert_eq!(
                GatewayError::from(Status::new(code, "secret detail")).to_string(),
                expected
            );
        }
    }

    #[test]
    fn roles_on_the_wire() {
        assert_eq!(role_to(MemberRole::User), 1);
        assert_eq!(role_to(MemberRole::Admin), 2);
    }
}
