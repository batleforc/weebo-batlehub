//! Port traits: what the use-cases need from the outside world. One
//! [`AdminGateway`] per `BatleHubLocalInstance`, produced on demand by the
//! [`GatewayFactory`]; which instance a CR lives on is the kit's
//! [`InstanceDirectory`]; whether a configuration is valid is BatleHub's
//! own parser, behind [`ConfigParser`].

use std::sync::Arc;

use domain::error::ReasonCode;
pub use weebo_kit_application::instances::{
    BoundInstance, InstanceDirectory, InstanceError, ResolveError,
};

/// A failed call to BatleHub's admin API, neutral: the use case maps it
/// onto a reason code. Each gateway method translates the answers of its
/// own endpoint (a status code means different things on different
/// endpoints of BatleHub).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GatewayError {
    /// No answer: network error, timeout, 502/504.
    #[error("BatleHub unreachable: {0}")]
    Unreachable(String),
    /// The token was refused (401/403), or doesn't carry the admin role.
    #[error("BatleHub refused the operator's token: {0}")]
    Unauthorized(String),
    /// Any answer the endpoint doesn't document (a 500, an unknown body).
    #[error("BatleHub API error: {0}")]
    Remote(String),
}

impl GatewayError {
    pub fn reason(&self) -> ReasonCode {
        match self {
            GatewayError::Unreachable(_) => ReasonCode::InstanceUnreachable,
            GatewayError::Unauthorized(_) => ReasonCode::OperatorUnauthorized,
            GatewayError::Remote(_) => ReasonCode::RemoteError,
        }
    }
}

/// What the instance says about itself.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceInfo {
    /// BatleHub's version, as `/livez` reports it.
    pub version: String,
}

/// Talks to one BatleHub instance's admin API.
///
/// `#[async_trait]` rather than native `async fn` in trait: it is used as
/// `dyn AdminGateway`, and native async-fn-in-traits are not
/// `dyn`-compatible.
#[async_trait::async_trait]
pub trait AdminGateway: Send + Sync {
    /// Whether the instance answers and accepts the operator's token; its
    /// version.
    async fn ping(&self) -> Result<InstanceInfo, GatewayError>;
}

/// Why no gateway could be built for an instance.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum GatewayFactoryError {
    /// The instance is gone since it was resolved.
    #[error("{0} not found")]
    InstanceNotFound(BoundInstance),
    /// The token `Secret` or its key is missing / not UTF-8.
    #[error("token secret: {0}")]
    TokenSecret(String),
    /// The token `Secret` doesn't carry the consent label.
    #[error("{0}")]
    TokenNotAllowed(String),
    /// A Kubernetes API read failed — usually transient.
    #[error("Kubernetes API error: {0}")]
    Kubernetes(String),
    /// The instance's spec can't produce a client.
    #[error("invalid instance: {0}")]
    InvalidSpec(String),
}

impl GatewayFactoryError {
    pub fn reason(&self) -> ReasonCode {
        match self {
            GatewayFactoryError::InstanceNotFound(_) => ReasonCode::InstanceNotFound,
            GatewayFactoryError::TokenSecret(_) => ReasonCode::TokenSecretMissing,
            GatewayFactoryError::TokenNotAllowed(_) => ReasonCode::TokenSecretNotAllowed,
            GatewayFactoryError::Kubernetes(_) => ReasonCode::KubernetesApiError,
            GatewayFactoryError::InvalidSpec(_) => ReasonCode::InvalidSpec,
        }
    }
}

/// The gateway of a resolved instance. Implementations re-read the token
/// `Secret` on every call: rotating it needs no restart.
#[async_trait::async_trait]
pub trait GatewayFactory: Send + Sync {
    async fn gateway_for(
        &self,
        instance: &BoundInstance,
    ) -> Result<Arc<dyn AdminGateway>, GatewayFactoryError>;
}

/// What BatleHub's parser says of a configuration it accepts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigVerdict {
    /// Legal but probably unintended settings.
    pub warnings: Vec<String>,
}

/// Why a configuration couldn't be accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The parser refuses it (`ConfigInvalid`).
    #[error("{0}")]
    Invalid(String),
    /// No parser to ask: validating needs `batlehub-config` v1.5.0
    /// (`merge_layers`, `validate_layers`).
    #[error("{0}")]
    Unavailable(String),
}

/// BatleHub's own configuration parser: the layers merged the way BatleHub
/// merges them, validated with the instance's environment (`env` answers
/// the `${VAR}` placeholders and the `PROXY_CACHE__*` overrides), never
/// the operator's.
pub trait ConfigParser: Send + Sync {
    fn validate(
        &self,
        layers: &[&str],
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<ConfigVerdict, ConfigError>;
}

/// The reason code of an instance that couldn't be resolved.
pub fn instance_reason(err: &InstanceError) -> ReasonCode {
    match err {
        InstanceError::Kubernetes(_) => ReasonCode::KubernetesApiError,
        InstanceError::Resolve(e) => match e {
            ResolveError::NotFound { .. } | ResolveError::NoInstance => {
                ReasonCode::InstanceNotFound
            }
            ResolveError::Ambiguous { .. } => ReasonCode::InstanceAmbiguous,
            ResolveError::InvalidRef(_)
            | ResolveError::OutsideScope(_)
            | ResolveError::NotShared { .. } => ReasonCode::InstanceNotAllowed,
            ResolveError::BindingChanged { .. } => ReasonCode::InstanceBindingChanged,
        },
    }
}
