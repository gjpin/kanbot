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

/// Bounds opening the TCP connection.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Bounds each call as a whole ([`bounded`]): connecting, the TLS
/// handshake, and reading the answer's headers and body. Tonic's own
/// `Endpoint::timeout` would start only once the connection is ready and
/// end at the headers, and `connect_timeout` covers only TCP: a gateway that
/// accepts connections but never answers would hold the sync, and its lock,
/// for good.
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
    /// `unauthenticated`: the token is not accepted (expired, revoked, a
    /// key rotation); a new one may be.
    #[error("refused by the gateway")]
    Refused,
    /// `permission_denied`: the token is good, but its principal may not
    /// do this. A new token would not change that.
    #[error("denied by the gateway")]
    Denied,
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
            Self::Denied => "denied",
            Self::Unavailable => "unavailable",
            Self::Other(_) => "other",
            Self::TooManyMembers => "too_many_members",
            Self::RepeatedPage => "repeated_page",
        }
    }

    /// Whether the gateway certainly did not apply the call: it refused it
    /// outright, before changing anything. A timeout, an unavailable
    /// gateway or an internal error leave it unknown.
    #[must_use]
    pub const fn not_applied(&self) -> bool {
        matches!(
            self,
            Self::Refused
                | Self::Denied
                | Self::Other(Code::InvalidArgument | Code::FailedPrecondition)
        )
    }
}

/// `call`, given at most [`REQUEST_TIMEOUT`]; past it, the gateway is
/// [`GatewayError::Unavailable`].
async fn bounded<T>(
    call: impl Future<Output = Result<T, Status>>,
) -> Result<Result<T, Status>, GatewayError> {
    tokio::time::timeout(REQUEST_TIMEOUT, call)
        .await
        .map_err(|_| GatewayError::Unavailable)
}

impl From<Status> for GatewayError {
    fn from(status: Status) -> Self {
        match status.code() {
            Code::NotFound => Self::NotFound,
            Code::Unauthenticated => Self::Refused,
            Code::PermissionDenied => Self::Denied,
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

/// What adding a member did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Added {
    Added,
    /// They were a member already: an earlier attempt, or someone else,
    /// got there first. Their role is whatever it was.
    AlreadyMember,
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
    /// `OPENSHELL_CA_FILE`; each call is bounded ([`REQUEST_TIMEOUT`]).
    ///
    /// # Errors
    ///
    /// [`GatewayError::Setup`] if the URL or the certificates cannot be
    /// used.
    pub fn new(config: &OpenShellConfig) -> Result<Self, GatewayError> {
        let mut endpoint = Endpoint::from_shared(config.gateway.as_str().to_owned())
            .map_err(GatewayError::Setup)?
            .connect_timeout(CONNECT_TIMEOUT)
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
        match bounded(self.client.clone().get_workspace(request)).await? {
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
            let page = bounded(self.client.clone().list_workspace_members(request))
                .await??
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

    /// Makes `subject` a member with `role`, unless they are a member
    /// already ([`Added::AlreadyMember`]: the caller decides whose member
    /// that is).
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
    ) -> Result<Added, GatewayError> {
        let request = Self::request(
            token,
            AddWorkspaceMemberRequest {
                workspace_scope: Some(selector(workspace)),
                principal_subject: subject.to_owned(),
                role: role_to(role),
                request_id: uuid::Uuid::new_v4().to_string(),
            },
        )?;
        match bounded(self.client.clone().add_workspace_member(request)).await? {
            Ok(_) => Ok(Added::Added),
            Err(status) if status.code() == Code::AlreadyExists => Ok(Added::AlreadyMember),
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
        bounded(self.client.clone().remove_workspace_member(request)).await??;
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
            (Code::PermissionDenied, "denied by the gateway"),
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
    fn only_outright_refusals_are_known_not_applied() {
        for (code, not_applied) in [
            (Code::Unauthenticated, true),
            (Code::PermissionDenied, true),
            (Code::InvalidArgument, true),
            (Code::FailedPrecondition, true),
            // May have been applied before the answer went missing.
            (Code::Unavailable, false),
            (Code::DeadlineExceeded, false),
            (Code::Internal, false),
            (Code::Unknown, false),
            (Code::Cancelled, false),
            // Also what tonic says of an answer too large to read.
            (Code::OutOfRange, false),
        ] {
            assert_eq!(
                GatewayError::from(Status::new(code, "")).not_applied(),
                not_applied,
                "{code:?}"
            );
        }
        assert!(!GatewayError::TooManyMembers.not_applied());
    }

    #[test]
    fn roles_on_the_wire() {
        assert_eq!(role_to(MemberRole::User), 1);
        assert_eq!(role_to(MemberRole::Admin), 2);
    }
}
