//! The Cedar schema and policies, and decisions against them.

use std::str::FromStr;

use cedar_policy::{
    AuthorizationError, Authorizer, Decision as CedarDecision, Effect, PolicyId, PolicySet,
    Request, Schema, ValidationMode, Validator,
};

use crate::authz::{
    entities::{self, EntityError, action_uid, context, resource_uid, user_uid},
    model::{Action, Actor, Decision, Facts, Resource},
};

const SCHEMA: &str = include_str!("schema.cedarschema");
const BUILTIN_POLICIES: &str = include_str!("policies.cedar");
/// Prefix of the built-in policies' IDs: `builtin.<@id>`.
pub const BUILTIN_PREFIX: &str = "builtin.";
/// Prefix of the deployer's policies' IDs: `deployer.<@id>`.
pub const DEPLOYER_PREFIX: &str = "deployer.";
/// Where the deployer's policies come from, in error messages.
const DEPLOYER_SOURCE: &str = "AUTHZ_POLICY_FILE";

/// Why the policies cannot be used. Messages are Cedar's diagnostics,
/// about policy text only (never request data).
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    #[error("the Cedar schema is invalid: {0}")]
    Schema(String),
    #[error("{source_name}: policies do not parse: {message}")]
    Parse {
        source_name: &'static str,
        message: String,
    },
    #[error("{source_name}: policy {index} has no @id annotation")]
    MissingId {
        source_name: &'static str,
        index: usize,
    },
    #[error("{source_name}: policy @id {id:?} is used twice")]
    DuplicateId {
        source_name: &'static str,
        id: String,
    },
    #[error("policies do not validate against the schema: {0}")]
    Validation(String),
    #[error(
        "AUTHZ_POLICY_FILE: policy {0} is a permit; only forbid policies may be added \
         (grants are teams, links and admins)"
    )]
    Permit(String),
    #[error("AUTHZ_POLICY_FILE: policy templates are not supported")]
    Template,
}

/// The schema and the policy set every decision is made with.
pub struct Policies {
    schema: Schema,
    policies: PolicySet,
}

impl Policies {
    /// The schema and the built-in policies, validated (strict mode).
    ///
    /// # Errors
    ///
    /// [`PolicyError`] if the embedded files are broken: a bug, caught by
    /// the tests.
    pub fn builtin() -> Result<Self, PolicyError> {
        let (schema, _warnings) = Schema::from_cedarschema_str(SCHEMA)
            .map_err(|error| PolicyError::Schema(error.to_string()))?;
        let mut policies = PolicySet::new();
        add_named(
            &mut policies,
            "built-in policies",
            BUILTIN_POLICIES,
            BUILTIN_PREFIX,
        )?;
        let built = Self { schema, policies };
        built.validate()?;
        Ok(built)
    }

    /// The built-in policies plus the deployer's `forbid` policies in
    /// `text` (`AUTHZ_POLICY_FILE`), validated together.
    ///
    /// # Errors
    ///
    /// [`PolicyError`] if `text` does not parse, contains a `permit` or a
    /// template, has a policy without a unique `@id`, or does not validate
    /// against the schema.
    pub fn with_deployer(text: &str) -> Result<Self, PolicyError> {
        let mut built = Self::builtin()?;
        let parsed = PolicySet::from_str(text).map_err(|error| PolicyError::Parse {
            source_name: DEPLOYER_SOURCE,
            message: error.to_string(),
        })?;
        if parsed.templates().next().is_some() {
            return Err(PolicyError::Template);
        }
        // Forbid-only keeps two promises: custom policies can never widen
        // access, and `visible`'s SQL pre-filter stays a superset.
        for (index, policy) in parsed.policies().enumerate() {
            if policy.effect() == Effect::Permit {
                return Err(PolicyError::Permit(match policy.annotation("id") {
                    Some(id) => format!("@id {id:?}"),
                    None => format!("number {index}"),
                }));
            }
        }
        add_named(&mut built.policies, DEPLOYER_SOURCE, text, DEPLOYER_PREFIX)?;
        built.validate()?;
        Ok(built)
    }

    /// The IDs of the deployer's policies, sorted.
    #[must_use]
    pub fn deployer_policy_ids(&self) -> Vec<String> {
        let mut ids: Vec<String> = self
            .policies
            .policies()
            .map(|policy| policy.id().to_string())
            .filter(|id| id.starts_with(DEPLOYER_PREFIX))
            .collect();
        ids.sort();
        ids
    }

    fn validate(&self) -> Result<(), PolicyError> {
        let result =
            Validator::new(self.schema.clone()).validate(&self.policies, ValidationMode::Strict);
        if result.validation_passed() {
            Ok(())
        } else {
            Err(PolicyError::Validation(
                result
                    .validation_errors()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; "),
            ))
        }
    }

    /// The decisions on `requests` by `actor`, with `facts` from the
    /// database (one entity set for all of them).
    ///
    /// # Errors
    ///
    /// [`EntityError`] if the facts or a request do not match the schema (a
    /// bug, for example an action on the wrong kind of resource).
    pub fn decide_all(
        &self,
        actor: &Actor,
        facts: &Facts,
        requests: &[(Action, Resource)],
    ) -> Result<Vec<Decision>, EntityError> {
        let entities = entities::entities(actor, facts, &self.schema)?;
        let principal = user_uid(actor.user.id)?;
        let context = context(actor)?;
        let authorizer = Authorizer::new();
        requests
            .iter()
            .map(|(action, resource)| {
                let request = Request::new(
                    principal.clone(),
                    action_uid(*action)?,
                    resource_uid(*resource)?,
                    context.clone(),
                    Some(&self.schema),
                )
                .map_err(|error| EntityError(error.to_string()))?;
                let response = authorizer.is_authorized(&request, &self.policies, &entities);
                for error in response.diagnostics().errors() {
                    // The policy only: the error's message can quote
                    // attribute values, such as a user's groups.
                    let AuthorizationError::PolicyEvaluationError(error) = error;
                    tracing::warn!(
                        policy.id = %error.policy_id(),
                        action = action.name(),
                        "policy evaluation error"
                    );
                }
                Ok(Decision {
                    allowed: response.decision() == CedarDecision::Allow,
                    policy_ids: response
                        .diagnostics()
                        .reason()
                        .map(ToString::to_string)
                        .collect(),
                })
            })
            .collect()
    }

    /// The decision on one request (see [`Policies::decide_all`]).
    ///
    /// # Errors
    ///
    /// [`EntityError`], as for [`Policies::decide_all`].
    pub fn decide(
        &self,
        actor: &Actor,
        facts: &Facts,
        action: Action,
        resource: Resource,
    ) -> Result<Decision, EntityError> {
        let mut decisions = self.decide_all(actor, facts, &[(action, resource)])?;
        decisions
            .pop()
            .ok_or_else(|| EntityError("no decision".to_owned()))
    }
}

/// Parses `text` and adds each policy to `set` as `<prefix><@id>`.
fn add_named(
    set: &mut PolicySet,
    source_name: &'static str,
    text: &str,
    prefix: &str,
) -> Result<(), PolicyError> {
    let parsed = PolicySet::from_str(text).map_err(|error| PolicyError::Parse {
        source_name,
        message: error.to_string(),
    })?;
    for (index, policy) in parsed.policies().enumerate() {
        let id = policy
            .annotation("id")
            .ok_or(PolicyError::MissingId { source_name, index })?;
        let named = policy.new_id(PolicyId::new(format!("{prefix}{id}")));
        set.add(named).map_err(|_| PolicyError::DuplicateId {
            source_name,
            id: id.to_owned(),
        })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests;
