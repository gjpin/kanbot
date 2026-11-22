//! The Cedar schema and policies, and decisions against them.

use std::str::FromStr;

use opentelemetry::{KeyValue, global, metrics::Counter};

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
    /// Cedar's warnings, such as a policy that can never apply (a forbid
    /// that silently never fires): refused like errors.
    #[error("policies have warnings, for example a policy that can never apply: {0}")]
    Warnings(String),
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
            &parse("built-in policies", BUILTIN_POLICIES)?,
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
        let parsed = parse(DEPLOYER_SOURCE, text)?;
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
        add_named(
            &mut built.policies,
            DEPLOYER_SOURCE,
            &parsed,
            DEPLOYER_PREFIX,
        )?;
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
        if !result.validation_passed() {
            return Err(PolicyError::Validation(
                result
                    .validation_errors()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("; "),
            ));
        }
        let warnings: Vec<String> = result
            .validation_warnings()
            .map(ToString::to_string)
            .collect();
        if warnings.is_empty() {
            Ok(())
        } else {
            Err(PolicyError::Warnings(warnings.join("; ")))
        }
    }

    /// The decisions on `requests` by `actor`, with `facts` from the
    /// database (one entity set for all of them). A policy that fails to
    /// evaluate denies the request (Cedar would skip it, so a broken
    /// forbid would let everything through): fail closed, logged and
    /// counted (`kanbot.authz.policy.errors`).
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
                let mut failed = Vec::new();
                for error in response.diagnostics().errors() {
                    // The policy only: the error's message can quote
                    // attribute values, such as a user's groups.
                    let AuthorizationError::PolicyEvaluationError(error) = error;
                    let policy = error.policy_id().to_string();
                    tracing::warn!(
                        policy.id = %policy,
                        action = action.name(),
                        "policy evaluation error: denied"
                    );
                    policy_errors().add(
                        1,
                        &[
                            KeyValue::new("policy.id", policy.clone()),
                            KeyValue::new("action", action.name()),
                        ],
                    );
                    failed.push(policy);
                }
                let evaluated = failed.is_empty();
                let mut policy_ids: Vec<String> = if evaluated {
                    response
                        .diagnostics()
                        .reason()
                        .map(ToString::to_string)
                        .collect()
                } else {
                    failed
                };
                policy_ids.sort();
                Ok(Decision {
                    allowed: evaluated && response.decision() == CedarDecision::Allow,
                    policy_ids,
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

/// `kanbot.authz.policy.errors`: policies that failed to evaluate, by
/// policy ID (a fixed set) and action.
fn policy_errors() -> Counter<u64> {
    global::meter(crate::telemetry::SCOPE)
        .u64_counter("kanbot.authz.policy.errors")
        .with_unit("{error}")
        .with_description("Policies that failed to evaluate; each denied its request.")
        .build()
}

fn parse(source_name: &'static str, text: &str) -> Result<PolicySet, PolicyError> {
    PolicySet::from_str(text).map_err(|error| PolicyError::Parse {
        source_name,
        message: error.to_string(),
    })
}

/// Adds each policy of `parsed` to `set` as `<prefix><@id>`.
fn add_named(
    set: &mut PolicySet,
    source_name: &'static str,
    parsed: &PolicySet,
    prefix: &str,
) -> Result<(), PolicyError> {
    for (index, policy) in parsed.policies().enumerate() {
        let id = policy
            .annotation("id")
            .filter(|id| !id.trim().is_empty())
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
