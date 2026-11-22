//! Cedar entities, built from [`Facts`] for one actor. Pure: the facts are
//! loaded from the database by the caller.

use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use cedar_policy::{
    Context, Entities, Entity, EntityId, EntityTypeName, EntityUid, RestrictedExpression, Schema,
};

use crate::{
    authz::model::{Action, Actor, Facts, Resource},
    organizations::model::{Access, OrganizationId},
    teams::model::TeamId,
    users::model::UserId,
};

/// Building the entities, request or context failed: a bug, since every
/// value comes from kanbot itself. The message is Cedar's, safe to log.
#[derive(Debug, thiserror::Error)]
#[error("cedar: {0}")]
pub struct EntityError(pub String);

fn uid(type_name: &str, id: &str) -> Result<EntityUid, EntityError> {
    let type_name: EntityTypeName = format!("Kanbot::{type_name}")
        .parse()
        .map_err(|error: cedar_policy::ParseErrors| EntityError(error.to_string()))?;
    Ok(EntityUid::from_type_name_and_id(
        type_name,
        EntityId::new(id),
    ))
}

/// `Kanbot::User::"<id>"`.
///
/// # Errors
///
/// Never in practice (see [`EntityError`]).
pub fn user_uid(id: UserId) -> Result<EntityUid, EntityError> {
    uid("User", &id.as_uuid().to_string())
}

fn team_uid(id: TeamId) -> Result<EntityUid, EntityError> {
    uid("Team", &id.as_uuid().to_string())
}

fn organization_uid(id: OrganizationId) -> Result<EntityUid, EntityError> {
    uid("Organization", &id.as_uuid().to_string())
}

/// `Kanbot::OrgGroup::"<organization id>/read"` or `.../write"`.
fn group_uid(organization: OrganizationId, access: Access) -> Result<EntityUid, EntityError> {
    uid(
        "OrgGroup",
        &format!("{}/{}", organization.as_uuid(), access.as_str()),
    )
}

/// The resource's entity UID.
///
/// # Errors
///
/// Never in practice (see [`EntityError`]).
pub fn resource_uid(resource: Resource) -> Result<EntityUid, EntityError> {
    match resource {
        Resource::Platform => uid("Platform", "kanbot"),
        Resource::Organization(id) => organization_uid(id),
        Resource::Team(id) => team_uid(id),
    }
}

/// `Kanbot::Action::"<name>"`.
///
/// # Errors
///
/// Never in practice (see [`EntityError`]).
pub fn action_uid(action: Action) -> Result<EntityUid, EntityError> {
    uid("Action", action.name())
}

/// The request context: how the actor authenticated, and from where.
///
/// # Errors
///
/// Never in practice (see [`EntityError`]).
pub fn context(actor: &Actor) -> Result<Context, EntityError> {
    Context::from_pairs([
        (
            "via".to_owned(),
            RestrictedExpression::new_string(actor.via.as_str().to_owned()),
        ),
        (
            "ip".to_owned(),
            // An IPv4 client as IPv4, also when it reached a dual-stack
            // socket (`::ffff:a.b.c.d`): Cedar refuses that form, and
            // IPv4 ranges in policies would not match it.
            RestrictedExpression::new_ip(actor.ip.to_canonical().to_string()),
        ),
    ])
    .map_err(|error| EntityError(error.to_string()))
}

fn users(ids: &[UserId]) -> Result<RestrictedExpression, EntityError> {
    Ok(RestrictedExpression::new_set(
        ids.iter()
            .map(|id| user_uid(*id).map(RestrictedExpression::new_entity_uid))
            .collect::<Result<Vec<_>, _>>()?,
    ))
}

fn entity(
    uid: EntityUid,
    attrs: HashMap<String, RestrictedExpression>,
    parents: HashSet<EntityUid>,
) -> Result<Entity, EntityError> {
    Entity::new(uid, attrs, parents).map_err(|error| EntityError(error.to_string()))
}

/// The entities of `facts` for `actor`, checked against `schema`: the
/// actor, the teams with their maintainers and organization links, the
/// organizations with their admins, the access groups of every
/// organization mentioned, and the platform.
///
/// # Errors
///
/// [`EntityError`] if an entity does not match the schema (a bug).
pub fn entities(actor: &Actor, facts: &Facts, schema: &Schema) -> Result<Entities, EntityError> {
    let mut built: BTreeMap<String, Entity> = BTreeMap::new();
    let mut add = |entity: Entity| {
        built.entry(entity.uid().to_string()).or_insert(entity);
    };

    let mut user_attrs = HashMap::from([
        (
            "platformRole".to_owned(),
            RestrictedExpression::new_string(actor.user.role.as_str().to_owned()),
        ),
        (
            "groups".to_owned(),
            RestrictedExpression::new_set(
                actor
                    .user
                    .groups
                    .iter()
                    .map(|group| RestrictedExpression::new_string(group.clone())),
            ),
        ),
        (
            "organizationAdmin".to_owned(),
            RestrictedExpression::new_bool(facts.user.organization_admin),
        ),
        (
            "teamMaintainer".to_owned(),
            RestrictedExpression::new_bool(facts.user.team_maintainer),
        ),
    ]);
    if let Some(client_id) = &actor.user.client_id {
        user_attrs.insert(
            "clientId".to_owned(),
            RestrictedExpression::new_string(client_id.clone()),
        );
    }
    let user_parents = facts
        .user
        .teams
        .iter()
        .map(|team| team_uid(*team))
        .collect::<Result<_, _>>()?;
    add(entity(user_uid(actor.user.id)?, user_attrs, user_parents)?);

    let mut organizations: BTreeSet<OrganizationId> = BTreeSet::new();
    for team in &facts.teams {
        let parents = team
            .links
            .iter()
            .map(|(organization, access)| {
                organizations.insert(*organization);
                group_uid(*organization, *access)
            })
            .collect::<Result<_, _>>()?;
        let attrs = HashMap::from([("maintainers".to_owned(), users(&team.maintainers)?)]);
        add(entity(team_uid(team.id)?, attrs, parents)?);
    }
    for organization in &facts.organizations {
        organizations.insert(organization.id);
        let attrs = HashMap::from([
            (
                "readers".to_owned(),
                RestrictedExpression::new_entity_uid(group_uid(organization.id, Access::Read)?),
            ),
            (
                "writers".to_owned(),
                RestrictedExpression::new_entity_uid(group_uid(organization.id, Access::Write)?),
            ),
            ("admins".to_owned(), users(&organization.admins)?),
        ]);
        add(entity(
            organization_uid(organization.id)?,
            attrs,
            HashSet::new(),
        )?);
    }
    for organization in organizations {
        let read = group_uid(organization, Access::Read)?;
        add(Entity::new_no_attrs(
            group_uid(organization, Access::Write)?,
            HashSet::from([read.clone()]),
        ));
        add(Entity::new_no_attrs(read, HashSet::new()));
    }
    add(Entity::new_no_attrs(
        resource_uid(Resource::Platform)?,
        HashSet::new(),
    ));

    Entities::from_entities(built.into_values(), Some(schema))
        .map_err(|error| EntityError(error.to_string()))
}
