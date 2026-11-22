//! A fake `OpenShell` gateway: a real gRPC server on `127.0.0.1:0` that
//! implements the workspace membership calls in memory, and records the
//! bearer token of every call. Tests can hold a call, refuse tokens, add
//! members behind kanbot's back, and page oddly.

use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
    sync::{Arc, Mutex},
};

use openshell_api::openshell::{
    datamodel::v1::{ObjectMeta, Workspace, WorkspaceSelector, workspace_selector::Selection},
    v1::{
        AddWorkspaceMemberRequest, AddWorkspaceMemberResponse, DeletionOutcome,
        GetWorkspaceRequest, GetWorkspaceResponse, ListWorkspaceMembersRequest,
        ListWorkspaceMembersResponse, RemoveWorkspaceMemberRequest, RemoveWorkspaceMemberResponse,
        WorkspaceMember,
        open_shell_server::{OpenShell, OpenShellServer},
    },
};
use tokio::sync::oneshot;
use tonic::{
    Request, Response, Status,
    transport::{Identity, ServerTlsConfig, server::TcpIncoming},
};

/// How the fake pages member lists.
#[derive(Default)]
pub enum Paging {
    /// Pages of two.
    #[default]
    Normal,
    /// Always the same next page token.
    Repeat,
    /// Always another page.
    Endless,
}

/// A list call held until the test releases it.
pub struct Held {
    /// Resolves once the call is held.
    pub reached: oneshot::Receiver<()>,
    /// Lets the call go on.
    pub release: oneshot::Sender<()>,
}

#[derive(Default)]
pub struct State {
    /// Workspace → member subject → role (1 user, 2 admin).
    pub workspaces: BTreeMap<String, BTreeMap<String, i32>>,
    /// The `authorization` header of every call, in order.
    pub tokens: Vec<String>,
    /// Calls that change membership, as `add <workspace> <subject> <role>`
    /// or `remove <workspace> <subject>`.
    pub changes: Vec<String>,
    /// Bearer tokens accepted; any other is `unauthenticated`.
    pub accepted: BTreeSet<String>,
    /// Workspaces where adding a member fails (`unavailable`).
    pub failing_adds: BTreeSet<String>,
    /// The next this many calls are `unauthenticated`, whatever their
    /// token.
    pub refuse_next: usize,
    /// The workspace of every list call, in order.
    pub lists: Vec<String>,
    /// Members (workspace, subject, role) someone adds right after the
    /// next list call of their workspace answers.
    pub added_after_list: Vec<(String, String, i32)>,
    pub paging: Paging,
    /// The next list call of each of these workspaces waits.
    holds: BTreeMap<String, (oneshot::Sender<()>, oneshot::Receiver<()>)>,
}

#[derive(Clone, Default)]
pub struct FakeGateway {
    pub state: Arc<Mutex<State>>,
}

impl FakeGateway {
    /// Serves on a free loopback port; the URL to reach it.
    ///
    /// # Panics
    ///
    /// If the port cannot be bound.
    pub async fn start(&self) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr: SocketAddr = listener.local_addr().unwrap();
        let service = OpenShellServer::new(self.clone());
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(service)
                .serve_with_incoming(TcpIncoming::from(listener)),
        );
        format!("http://{addr}")
    }

    /// Serves over TLS with `certificate` and `key` (PEM) on a free
    /// loopback port; that port.
    ///
    /// # Panics
    ///
    /// If the port cannot be bound or the certificate is unusable.
    pub async fn start_tls(&self, certificate: &[u8], key: &[u8]) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let service = OpenShellServer::new(self.clone());
        tokio::spawn(
            tonic::transport::Server::builder()
                .tls_config(ServerTlsConfig::new().identity(Identity::from_pem(certificate, key)))
                .unwrap()
                .add_service(service)
                .serve_with_incoming(TcpIncoming::from(listener)),
        );
        port
    }

    /// Holds the next list call of `workspace` until released.
    ///
    /// # Panics
    ///
    /// If the state lock is poisoned.
    #[must_use]
    pub fn hold_list(&self, workspace: &str) -> Held {
        let (reached_tx, reached) = oneshot::channel();
        let (release, release_rx) = oneshot::channel();
        self.state
            .lock()
            .unwrap()
            .holds
            .insert(workspace.to_owned(), (reached_tx, release_rx));
        Held { reached, release }
    }

    /// How many list calls `workspace` got.
    ///
    /// # Panics
    ///
    /// If the state lock is poisoned.
    #[must_use]
    pub fn lists_of(&self, workspace: &str) -> usize {
        self.state
            .lock()
            .unwrap()
            .lists
            .iter()
            .filter(|listed| *listed == workspace)
            .count()
    }

    /// Creates an empty workspace.
    ///
    /// # Panics
    ///
    /// If the state lock is poisoned.
    pub fn workspace(&self, name: &str) {
        self.state
            .lock()
            .unwrap()
            .workspaces
            .entry(name.to_owned())
            .or_default();
    }

    /// Accepts `token` as a bearer token.
    ///
    /// # Panics
    ///
    /// If the state lock is poisoned.
    pub fn accept(&self, token: &str) {
        self.state
            .lock()
            .unwrap()
            .accepted
            .insert(format!("Bearer {token}"));
    }

    fn check<T>(&self, request: &Request<T>) -> Result<(), Status> {
        let header = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let mut state = self.state.lock().unwrap();
        state.tokens.push(header.clone());
        if state.refuse_next > 0 {
            state.refuse_next = state.refuse_next.saturating_sub(1);
            return Err(Status::unauthenticated("token no longer accepted"));
        }
        if state.accepted.contains(&header) {
            Ok(())
        } else {
            Err(Status::unauthenticated("invalid token"))
        }
    }
}

fn workspace_of(selector: Option<&WorkspaceSelector>) -> Result<String, Status> {
    match selector.and_then(|selector| selector.selection.as_ref()) {
        Some(Selection::Workspace(name)) => Ok(name.clone()),
        _ => Err(Status::invalid_argument("a named workspace is required")),
    }
}

#[tonic::async_trait]
impl OpenShell for FakeGateway {
    async fn get_workspace(
        &self,
        request: Request<GetWorkspaceRequest>,
    ) -> Result<Response<GetWorkspaceResponse>, Status> {
        self.check(&request)?;
        let name = request.into_inner().name;
        if !self.state.lock().unwrap().workspaces.contains_key(&name) {
            return Err(Status::not_found("workspace"));
        }
        Ok(Response::new(GetWorkspaceResponse {
            workspace: Some(Workspace {
                metadata: Some(ObjectMeta {
                    name,
                    ..ObjectMeta::default()
                }),
                ..Workspace::default()
            }),
        }))
    }

    async fn add_workspace_member(
        &self,
        request: Request<AddWorkspaceMemberRequest>,
    ) -> Result<Response<AddWorkspaceMemberResponse>, Status> {
        self.check(&request)?;
        let body = request.into_inner();
        let workspace = workspace_of(body.workspace_scope.as_ref())?;
        let mut state = self.state.lock().unwrap();
        if state.failing_adds.contains(&workspace) {
            return Err(Status::unavailable("try again"));
        }
        let members = state
            .workspaces
            .get_mut(&workspace)
            .ok_or_else(|| Status::not_found("workspace"))?;
        // As OpenShell: adding an existing member is a conflict.
        if members.contains_key(&body.principal_subject) {
            return Err(Status::already_exists("member"));
        }
        members.insert(body.principal_subject.clone(), body.role);
        state.changes.push(format!(
            "add {workspace} {} {}",
            body.principal_subject, body.role
        ));
        Ok(Response::new(AddWorkspaceMemberResponse {
            member: Some(WorkspaceMember {
                metadata: None,
                principal_subject: body.principal_subject,
                role: body.role,
            }),
        }))
    }

    async fn remove_workspace_member(
        &self,
        request: Request<RemoveWorkspaceMemberRequest>,
    ) -> Result<Response<RemoveWorkspaceMemberResponse>, Status> {
        self.check(&request)?;
        let body = request.into_inner();
        let workspace = workspace_of(body.workspace_scope.as_ref())?;
        let mut state = self.state.lock().unwrap();
        let members = state
            .workspaces
            .get_mut(&workspace)
            .ok_or_else(|| Status::not_found("workspace"))?;
        let removed = members.remove(&body.principal_subject).is_some();
        if !removed && !body.allow_missing {
            return Err(Status::not_found("member"));
        }
        state
            .changes
            .push(format!("remove {workspace} {}", body.principal_subject));
        Ok(Response::new(RemoveWorkspaceMemberResponse {
            outcome: if removed {
                DeletionOutcome::Completed.into()
            } else {
                DeletionOutcome::AlreadyAbsent.into()
            },
        }))
    }

    async fn list_workspace_members(
        &self,
        request: Request<ListWorkspaceMembersRequest>,
    ) -> Result<Response<ListWorkspaceMembersResponse>, Status> {
        self.check(&request)?;
        let body = request.into_inner();
        let workspace = workspace_of(body.workspace_scope.as_ref())?;
        let hold = {
            let mut state = self.state.lock().unwrap();
            state.lists.push(workspace.clone());
            state.holds.remove(&workspace)
        };
        if let Some((reached, release)) = hold {
            reached.send(()).unwrap();
            release.await.unwrap();
        }
        let mut state = self.state.lock().unwrap();
        let state = &mut *state;
        let members = state
            .workspaces
            .get_mut(&workspace)
            .ok_or_else(|| Status::not_found("workspace"))?;
        // Pages of two, so callers must follow next_page_token.
        let start: usize = body.page_token.parse().unwrap_or(0);
        let page: Vec<WorkspaceMember> = members
            .iter()
            .skip(start)
            .take(2)
            .map(|(subject, role)| WorkspaceMember {
                metadata: None,
                principal_subject: subject.clone(),
                role: *role,
            })
            .collect();
        let next = start.saturating_add(page.len());
        let next_page_token = match state.paging {
            Paging::Normal if next < members.len() => next.to_string(),
            Paging::Normal => String::new(),
            Paging::Repeat => "again".to_owned(),
            Paging::Endless => start.saturating_add(1).to_string(),
        };
        if next_page_token.is_empty() {
            let (now, later) = std::mem::take(&mut state.added_after_list)
                .into_iter()
                .partition(|(added_to, _, _)| *added_to == workspace);
            state.added_after_list = later;
            for (_, subject, role) in now {
                members.insert(subject, role);
            }
        }
        Ok(Response::new(ListWorkspaceMembersResponse {
            members: page,
            next_page_token,
        }))
    }
}
