//! A fake `OpenShell` gateway: a real gRPC server on `127.0.0.1:0` that
//! implements the workspace membership calls in memory, and records the
//! bearer token of every call.

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
use tonic::{Request, Response, Status, transport::server::TcpIncoming};

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
        let members = state
            .workspaces
            .get_mut(&workspace)
            .ok_or_else(|| Status::not_found("workspace"))?;
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
        let state = self.state.lock().unwrap();
        let members = state
            .workspaces
            .get(&workspace)
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
        Ok(Response::new(ListWorkspaceMembersResponse {
            members: page,
            next_page_token: if next < members.len() {
                next.to_string()
            } else {
                String::new()
            },
        }))
    }
}
