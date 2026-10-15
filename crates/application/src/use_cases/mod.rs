//! One `reconcile_*` use-case per CRD. Each returns an [`Outcome`] the
//! controller turns into a status patch and Events — always through a
//! `ReasonCode`, never a free string.

pub mod import;
pub mod reconcile_instance;
pub mod reconcile_maintenance;
pub mod reconcile_managed;
pub mod reconcile_namespace_claim;
pub mod reconcile_package_grant;
pub mod reconcile_package_policy;
pub mod reconcile_registry;
pub mod render_config;

use domain::error::ReasonCode;
use domain::{Advisory, Failure};

use crate::ports::{
    BoundInstance, GatewayError, GatewayFactoryError, InstanceError, instance_reason,
};

impl From<GatewayError> for Failure {
    fn from(err: GatewayError) -> Self {
        Failure::new(err.reason(), err.to_string())
    }
}

impl From<GatewayFactoryError> for Failure {
    fn from(err: GatewayFactoryError) -> Self {
        Failure::new(err.reason(), err.to_string())
    }
}

/// An instance that couldn't be resolved, as a failure (`Failure` and
/// `InstanceError` both being the kit's, no `From` between them).
pub fn instance_failure(err: InstanceError) -> Failure {
    Failure::new(instance_reason(&err), err.to_string())
}

/// What a reconcile ended on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// The instance the CR was resolved to, to record in its status.
    pub instance: Option<BoundInstance>,
    /// `Ok(message)` for `Ready: True`.
    pub ready: Result<String, Failure>,
    /// Non-blocking conditions next to `Ready: True`.
    pub advisories: Vec<Advisory>,
}

impl Outcome {
    pub fn synced(message: impl Into<String>) -> Self {
        Self {
            instance: None,
            ready: Ok(message.into()),
            advisories: Vec::new(),
        }
    }

    pub fn failed(failure: impl Into<Failure>) -> Self {
        Self {
            instance: None,
            ready: Err(failure.into()),
            advisories: Vec::new(),
        }
    }

    /// Adds an advisory (shown only while `Ready` is `True`).
    pub fn advise(mut self, reason: ReasonCode, message: impl Into<String>) -> Self {
        self.advisories.push(Advisory {
            reason,
            message: message.into(),
        });
        self
    }

    /// Records the instance the CR is bound to.
    pub fn on(mut self, instance: BoundInstance) -> Self {
        self.instance = Some(instance);
        self
    }

    /// The reason `Ready` ends on — what metrics and Events are keyed by.
    pub fn reason(&self) -> ReasonCode {
        match &self.ready {
            Ok(_) => ReasonCode::Reconciled,
            Err(f) => f.reason,
        }
    }

    /// Whether the next pass waits for the steady interval: a success,
    /// or a failure only a change of the spec can clear.
    pub fn steady(&self) -> bool {
        self.ready
            .as_ref()
            .map_or_else(|f| f.reason.needs_a_change(), |_| true)
    }
}
