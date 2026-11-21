//! Teams: instance-wide groups of users, linked to organizations. A team
//! with an identity provider group (`idp_group`) gets its members from the
//! groups claim.

pub mod model;
mod repo;
pub mod service;
