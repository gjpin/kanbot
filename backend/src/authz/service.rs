//! Authorization decisions for the other features. Every feature that
//! touches organization data asks here; none checks roles itself.

use std::collections::BTreeSet;

use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::token::PlatformRole,
    authz::{
        model::{Action, Actor, Decision, Facts, Resource},
        policies::Policies,
        repo,
    },
    error::AppError,
    organizations::model::OrganizationId,
    teams::model::TeamId,
};

/// The facts for decisions by `actor` on `resources`. Resources that do
/// not exist are left out; [`exists`] tells.
async fn load(db: &PgPool, actor: &Actor, resources: &[Resource]) -> Result<Facts, AppError> {
    let user = repo::user_facts(db, actor.user.id).await?;
    let mut teams: BTreeSet<Uuid> = user.teams.iter().map(TeamId::as_uuid).collect();
    let mut organizations: BTreeSet<Uuid> = BTreeSet::new();
    for resource in resources {
        match resource {
            Resource::Platform => {}
            Resource::Organization(id) => {
                organizations.insert(id.as_uuid());
            }
            Resource::Team(id) => {
                teams.insert(id.as_uuid());
            }
        }
    }
    let teams: Vec<Uuid> = teams.into_iter().collect();
    let organizations: Vec<Uuid> = organizations.into_iter().collect();
    Ok(Facts {
        user,
        teams: repo::team_facts(db, &teams).await?,
        organizations: repo::organization_facts(db, &organizations).await?,
    })
}

fn exists(facts: &Facts, resource: Resource) -> bool {
    match resource {
        Resource::Platform => true,
        Resource::Organization(id) => facts.organizations.iter().any(|found| found.id == id),
        Resource::Team(id) => facts.teams.iter().any(|found| found.id == id),
    }
}

fn decide_all(
    policies: &Policies,
    actor: &Actor,
    facts: &Facts,
    requests: &[(Action, Resource)],
) -> Result<Vec<Decision>, AppError> {
    policies
        .decide_all(actor, facts, requests)
        // Cedar's message can quote attribute values: the kind only.
        .map_err(|_| AppError::Internal("authz"))
}

/// The decisions on `requests` by `actor`, in order: what the caller may
/// do, for example to show only the controls they can use.
///
/// # Errors
///
/// [`AppError::NotFound`] if a resource does not exist, or a database
/// error.
pub async fn decisions(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    requests: &[(Action, Resource)],
) -> Result<Vec<Decision>, AppError> {
    let resources: Vec<Resource> = requests.iter().map(|(_, resource)| *resource).collect();
    let facts = load(db, actor, &resources).await?;
    if !resources.iter().all(|resource| exists(&facts, *resource)) {
        return Err(AppError::NotFound);
    }
    decide_all(policies, actor, &facts, requests)
}

/// Whether `actor` may do `action` to `resource`.
///
/// # Errors
///
/// [`AppError::NotFound`] if the resource does not exist, or a database
/// error.
pub async fn can(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    action: Action,
    resource: Resource,
) -> Result<Decision, AppError> {
    let mut decisions = decisions(db, policies, actor, &[(action, resource)]).await?;
    decisions.pop().ok_or(AppError::Internal("authz"))
}

/// The action that lets a user know a resource exists.
const fn visibility(resource: Resource) -> Option<Action> {
    match resource {
        Resource::Platform => None,
        Resource::Organization(_) => Some(Action::Read),
        Resource::Team(_) => Some(Action::ViewTeam),
    }
}

/// The decision allowing `actor` to do `action` to `resource`, whose
/// policy IDs go to the audit log.
///
/// # Errors
///
/// - [`AppError::NotFound`] if the resource does not exist, or exists but
///   the actor may not know it (no `read` of an organization, no
///   `viewTeam` of a team);
/// - [`AppError::Forbidden`] if the actor may know it but not do this;
/// - a database error.
pub async fn require(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    action: Action,
    resource: Resource,
) -> Result<Decision, AppError> {
    let mut requests = vec![(action, resource)];
    let visibility = visibility(resource).filter(|visibility| *visibility != action);
    if let Some(visibility) = visibility {
        requests.push((visibility, resource));
    }
    let decisions = decisions(db, policies, actor, &requests).await?;
    let mut decisions = decisions.into_iter();
    let decision = decisions.next().ok_or(AppError::Internal("authz"))?;
    if decision.allowed {
        return Ok(decision);
    }
    tracing::info!(
        user.id = %actor.user.id.as_uuid(),
        action = action.name(),
        policy.ids = ?decision.policy_ids,
        "denied"
    );
    let may_know = match visibility {
        Some(_) => decisions.next().is_some_and(|decision| decision.allowed),
        // The action is the visibility action itself, or the resource is
        // the platform.
        None => !matches!(
            (action, resource),
            (Action::Read, Resource::Organization(_)) | (Action::ViewTeam, Resource::Team(_))
        ),
    };
    Err(if may_know {
        AppError::Forbidden
    } else {
        AppError::NotFound
    })
}

/// The candidates that `actor` may see, among `candidates` (all of one
/// kind), in order.
async fn filter_visible(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    candidates: Vec<Resource>,
) -> Result<Vec<Resource>, AppError> {
    let facts = load(db, actor, &candidates).await?;
    // Deleted since the candidates were listed: not visible.
    let candidates: Vec<Resource> = candidates
        .into_iter()
        .filter(|resource| exists(&facts, *resource))
        .collect();
    let requests: Vec<(Action, Resource)> = candidates
        .iter()
        .filter_map(|resource| visibility(*resource).map(|action| (action, *resource)))
        .collect();
    let decisions = decide_all(policies, actor, &facts, &requests)?;
    Ok(requests
        .into_iter()
        .zip(decisions)
        .filter(|(_, decision)| decision.allowed)
        .map(|((_, resource), _)| resource)
        .collect())
}

// `visible_*`: SQL lists the candidates the built-in permits could allow
// (a superset), then Cedar decides each one. This is correct only because
// deployer policies are forbid-only (`Policies::with_deployer`): a forbid
// can only remove candidates, never add one SQL did not list. Anyone
// allowing deployer `permit` policies must replace this pre-filter.
// `tests/authz.rs` checks, for random data, that the result equals Cedar's
// decision on every organization and team.

/// The organizations `actor` may read, by slug.
///
/// # Errors
///
/// A database error.
pub async fn visible_organizations(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
) -> Result<Vec<OrganizationId>, AppError> {
    let candidates =
        repo::candidate_organizations(db, actor.user.id, actor.user.role == PlatformRole::Admin)
            .await?;
    let candidates = candidates
        .into_iter()
        .map(|id| Resource::Organization(OrganizationId::from_uuid(id)))
        .collect();
    Ok(filter_visible(db, policies, actor, candidates)
        .await?
        .into_iter()
        .filter_map(|resource| match resource {
            Resource::Organization(id) => Some(id),
            Resource::Platform | Resource::Team(_) => None,
        })
        .collect())
}

/// The teams `actor` may see, by slug.
///
/// # Errors
///
/// A database error.
pub async fn visible_teams(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
) -> Result<Vec<TeamId>, AppError> {
    let candidates =
        repo::candidate_teams(db, actor.user.id, actor.user.role == PlatformRole::Admin).await?;
    let candidates = candidates
        .into_iter()
        .map(|id| Resource::Team(TeamId::from_uuid(id)))
        .collect();
    Ok(filter_visible(db, policies, actor, candidates)
        .await?
        .into_iter()
        .filter_map(|resource| match resource {
            Resource::Team(id) => Some(id),
            Resource::Platform | Resource::Organization(_) => None,
        })
        .collect())
}
