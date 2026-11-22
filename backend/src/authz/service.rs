//! Authorization decisions for the other features. Every feature that
//! touches organization data asks here; none checks roles itself.

use std::collections::{BTreeSet, HashMap};

use sqlx::PgPool;
use uuid::Uuid;

use crate::{
    auth::token::PlatformRole,
    authz::{
        model::{Action, Actor, Decision, Facts, Resource, SYNC_IP, TeamFacts, Via},
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
        teams: if teams.is_empty() {
            Vec::new()
        } else {
            repo::team_facts(db, &teams).await?
        },
        organizations: if organizations.is_empty() {
            Vec::new()
        } else {
            repo::organization_facts(db, &organizations).await?
        },
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

/// The actions among `actions` that `decisions` (made in the same order)
/// allow.
#[must_use]
pub fn allowed_actions(actions: &[Action], decisions: &[Decision]) -> Vec<Action> {
    actions
        .iter()
        .zip(decisions)
        .filter(|(_, decision)| decision.allowed)
        .map(|(action, _)| *action)
        .collect()
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
    require_all(db, policies, actor, &[action], resource).await
}

/// Like [`require`], for several actions on one resource, decided
/// together: all must be allowed. The decision lists the policies of all
/// of them.
///
/// # Errors
///
/// As [`require`]: `404` unless the actor may see the resource, `403` for
/// the first action denied.
pub async fn require_all(
    db: &PgPool,
    policies: &Policies,
    actor: &Actor,
    actions: &[Action],
    resource: Resource,
) -> Result<Decision, AppError> {
    let mut requests: Vec<(Action, Resource)> =
        actions.iter().map(|action| (*action, resource)).collect();
    let visibility = visibility(resource).filter(|visibility| !actions.contains(visibility));
    if let Some(visibility) = visibility {
        requests.push((visibility, resource));
    }
    let decisions = decisions(db, policies, actor, &requests).await?;
    let (asked, visible) = decisions.split_at(actions.len().min(decisions.len()));
    let mut policy_ids = Vec::new();
    for (action, decision) in actions.iter().zip(asked) {
        if decision.allowed {
            policy_ids.extend(decision.policy_ids.iter().cloned());
            continue;
        }
        tracing::info!(
            user.id = %actor.user.id.as_uuid(),
            action = action.name(),
            policy.ids = ?decision.policy_ids,
            "denied"
        );
        let may_know = match visibility {
            Some(_) => visible.first().is_some_and(|decision| decision.allowed),
            // The resource is the platform, or the visibility action is
            // among those asked: knowing it is allowed unless that action
            // itself was denied.
            None => !asked.iter().zip(actions).any(|(decision, action)| {
                !decision.allowed
                    && matches!(
                        (action, resource),
                        (Action::Read, Resource::Organization(_))
                            | (Action::ViewTeam, Resource::Team(_))
                    )
            }),
        };
        return Err(if may_know {
            AppError::Forbidden
        } else {
            AppError::NotFound
        });
    }
    if asked.len() != actions.len() {
        return Err(AppError::Internal("authz"));
    }
    policy_ids.sort();
    policy_ids.dedup();
    Ok(Decision {
        allowed: true,
        policy_ids,
    })
}

/// The decisions on `actions` for `resource`, for each of `users`, made
/// without a request ([`Via::Sync`] from [`SYNC_IP`]): for background work
/// that acts on users' behalf, such as the `OpenShell` membership sync. The
/// facts of all users are loaded at once. Users that no longer exist are
/// denied everything.
///
/// # Errors
///
/// [`AppError::NotFound`] if the resource does not exist, or a database
/// error.
pub async fn decide_for_users(
    db: &PgPool,
    policies: &Policies,
    users: &[crate::users::model::AuthenticatedUser],
    actions: &[Action],
    resource: Resource,
) -> Result<Vec<Vec<Decision>>, AppError> {
    let ids: Vec<Uuid> = users.iter().map(|user| user.id.as_uuid()).collect();
    let user_facts: HashMap<_, _> = repo::user_facts_many(db, &ids).await?.into_iter().collect();
    let mut team_ids: BTreeSet<Uuid> = user_facts
        .values()
        .flat_map(|facts| facts.teams.iter().map(TeamId::as_uuid))
        .collect();
    let mut organization_ids = Vec::new();
    match resource {
        Resource::Platform => {}
        Resource::Organization(id) => organization_ids.push(id.as_uuid()),
        Resource::Team(id) => {
            team_ids.insert(id.as_uuid());
        }
    }
    let team_ids: Vec<Uuid> = team_ids.into_iter().collect();
    let teams = if team_ids.is_empty() {
        Vec::new()
    } else {
        repo::team_facts(db, &team_ids).await?
    };
    let organizations = if organization_ids.is_empty() {
        Vec::new()
    } else {
        repo::organization_facts(db, &organization_ids).await?
    };
    let requests: Vec<(Action, Resource)> =
        actions.iter().map(|action| (*action, resource)).collect();
    let denied = || {
        actions
            .iter()
            .map(|_| Decision {
                allowed: false,
                policy_ids: Vec::new(),
            })
            .collect::<Vec<_>>()
    };
    let teams: HashMap<TeamId, &TeamFacts> = teams.iter().map(|team| (team.id, team)).collect();
    let resource_team = match resource {
        Resource::Team(id) => teams.get(&id).copied(),
        Resource::Platform | Resource::Organization(_) => None,
    };
    let mut all = Vec::with_capacity(users.len());
    for user in users {
        let Some(facts) = user_facts.get(&user.id) else {
            all.push(denied());
            continue;
        };
        let mut user_teams: Vec<TeamFacts> = facts
            .teams
            .iter()
            .filter_map(|id| teams.get(id).map(|team| (*team).clone()))
            .collect();
        if let Some(team) = resource_team
            && !facts.teams.contains(&team.id)
        {
            user_teams.push(team.clone());
        }
        let facts = Facts {
            user: facts.clone(),
            teams: user_teams,
            organizations: organizations.clone(),
        };
        if !exists(&facts, resource) {
            return Err(AppError::NotFound);
        }
        let actor = Actor {
            user: user.clone(),
            via: Via::Sync,
            ip: SYNC_IP,
        };
        all.push(decide_all(policies, &actor, &facts, &requests)?);
    }
    Ok(all)
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
