//! Port traits: what the use-cases need from the outside world. One
//! [`AdminGateway`] per `BatleHubLocalInstance` (and per proxy pod with
//! `external.podSelector`), produced on demand by the [`GatewayFactory`];
//! which instance a CR lives on is the kit's [`InstanceDirectory`]
//! ([`RegistryResolver`] for a registry, which may come from another
//! namespace); the configuration's sources are read through
//! [`ConfigSources`], and judged by BatleHub's own parser, behind
//! [`ConfigParser`].

use std::sync::Arc;

pub use api::config::ConfigSource;
pub use api::local_instance::ConfigWarning;
use api::registry::RegistrySpec;
use domain::error::ReasonCode;
pub use weebo_kit_application::instances::{
    BoundInstance, InstanceDirectory, InstanceError, InstanceRef, ResolveError,
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
    /// A configuration endpoint answered 503: hot reload is disabled on
    /// the instance.
    #[error("hot reload is disabled on the instance: {0}")]
    HotReloadDisabled(String),
    /// A configuration endpoint answered 400: the instance refuses the
    /// configuration (its message).
    #[error("{0}")]
    Rejected(String),
    /// `pending/apply` found nothing staged (404), or what was staged
    /// expired (409).
    #[error("no pending reload to apply: {0}")]
    NoPending(String),
    /// A namespace claim answered 409: the prefix is already claimed.
    #[error("{0}")]
    AlreadyClaimed(String),
    /// A governance endpoint answered 503: the instance has no grant
    /// storage.
    #[error("{0}")]
    StorageUnavailable(String),
    /// A grant write answered 409: the subject holds these actions
    /// through package ownership.
    #[error("{0}")]
    HeldByOwnership(String),
    /// What the request names doesn't exist (a registry the instance
    /// doesn't serve).
    #[error("{0}")]
    NotFound(String),
    /// A governance write answered 400 (its message).
    #[error("{0}")]
    Refused(String),
    /// An exemption answered 403: the operator's identity lacks
    /// `gates:exempt` there.
    #[error("{0}")]
    NotPermitted(String),
    /// A request the operator won't send: a name that would be a dot
    /// segment of its path (`.`, `..`), which the URL would resolve to
    /// another route.
    #[error("{0}")]
    InvalidPath(String),
}

impl GatewayError {
    pub fn reason(&self) -> ReasonCode {
        match self {
            GatewayError::Unreachable(_) => ReasonCode::InstanceUnreachable,
            GatewayError::Unauthorized(_) => ReasonCode::OperatorUnauthorized,
            GatewayError::Remote(_) | GatewayError::NoPending(_) => ReasonCode::RemoteError,
            GatewayError::HotReloadDisabled(_) => ReasonCode::HotReloadDisabled,
            GatewayError::Rejected(_) => ReasonCode::ConfigRejected,
            GatewayError::AlreadyClaimed(_) => ReasonCode::ClaimConflict,
            GatewayError::StorageUnavailable(_) => ReasonCode::GrantStorageUnavailable,
            GatewayError::HeldByOwnership(_) => ReasonCode::GrantHeldByOwnership,
            GatewayError::NotFound(_) => ReasonCode::RemoteNotFound,
            GatewayError::Refused(_) => ReasonCode::RemoteRejected,
            GatewayError::NotPermitted(_) => ReasonCode::ExemptionNotPermitted,
            GatewayError::InvalidPath(_) => ReasonCode::InvalidSpec,
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
    /// What BatleHub finds legal but probably unintended in its own
    /// configuration.
    async fn config_warnings(&self) -> Result<Vec<ConfigWarning>, GatewayError>;
    /// The instance's first configuration file, as on its disk.
    async fn config_content(&self) -> Result<String, GatewayError>;
    /// A dry run of `content` as the first configuration file, with the
    /// instance's environment and other layers: what it would change.
    async fn validate_config(&self, content: &str) -> Result<ReloadCheck, GatewayError>;
    /// Stages `content` as a pending reload; `false` when the instance
    /// staged nothing, having already seen these exact bytes.
    async fn stage_config(&self, content: &str) -> Result<bool, GatewayError>;
    /// Applies the pending reload (and writes it to the instance's disk).
    async fn apply_pending(&self) -> Result<(), GatewayError>;
    /// The reload staged on the instance, if any.
    async fn pending(&self) -> Result<Option<PendingSource>, GatewayError>;
    /// Drops the reload staged on the instance (none is fine).
    async fn discard_pending(&self) -> Result<(), GatewayError>;
    /// Reloads the instance's configuration files from its disk. An
    /// expired pending is [`GatewayError::NoPending`].
    async fn reload(&self) -> Result<Reloaded, GatewayError>;
    /// The names of the registries the instance serves.
    async fn registry_names(&self) -> Result<Vec<String>, GatewayError>;
    /// The team namespaces claimed on `registry`.
    async fn team_namespaces(&self, registry: &str) -> Result<Vec<TeamNamespace>, GatewayError>;
    /// Claims `namespace.prefix` on `registry` for `namespace.group`
    /// ([`GatewayError::AlreadyClaimed`] when the prefix is taken).
    async fn claim_namespace(
        &self,
        registry: &str,
        namespace: &TeamNamespace,
    ) -> Result<(), GatewayError>;
    /// Releases `prefix` on `registry` (none claimed is fine).
    async fn release_namespace(&self, registry: &str, prefix: &str) -> Result<(), GatewayError>;
    /// The grants stored on `node` itself (not on the versions of a
    /// package node).
    async fn grants(&self, node: &PackageNode) -> Result<Vec<StoredGrant>, GatewayError>;
    /// Writes `subject`'s grant on `node`, replacing the one in place.
    async fn put_grant(
        &self,
        node: &PackageNode,
        subject: &str,
        actions: &[String],
    ) -> Result<GrantWrite, GatewayError>;
    /// Removes `subject`'s grant on `node`; `false` when there was none.
    async fn delete_grant(&self, node: &PackageNode, subject: &str) -> Result<bool, GatewayError>;
    /// The policy written on `node` (snake_case keys, as BatleHub reports
    /// it, the defaults filled), `None` when none is.
    async fn policy(&self, node: &PackageNode) -> Result<Option<serde_json::Value>, GatewayError>;
    /// Replaces the policy of `node`.
    async fn put_policy(
        &self,
        node: &PackageNode,
        policy: &serde_json::Value,
    ) -> Result<(), GatewayError>;
    /// Clears the policy of `node` (none is fine).
    async fn delete_policy(&self, node: &PackageNode) -> Result<(), GatewayError>;
    /// Exempts the version `node` from `exemption.gate`
    /// ([`GatewayError::NotPermitted`] without `gates:exempt`).
    async fn set_exemption(
        &self,
        node: &PackageNode,
        exemption: &Exemption,
    ) -> Result<(), GatewayError>;
    /// Removes the exemption of the version `node` from `gate` (none is
    /// fine).
    async fn delete_exemption(&self, node: &PackageNode, gate: &str) -> Result<(), GatewayError>;
    /// The packages of `registry` the instance knows, with their versions
    /// (every page of its admin listing).
    async fn packages(
        &self,
        registry: &str,
    ) -> Result<std::collections::BTreeMap<String, Vec<String>>, GatewayError>;
    /// Every grant of `package` in `registry`: the package node's (`None`)
    /// and each version's.
    async fn package_grants(
        &self,
        registry: &str,
        package: &str,
    ) -> Result<Vec<(Option<String>, StoredGrant)>, GatewayError>;
    /// The `(package, version)` nodes of `registry` holding an exemption.
    async fn exemption_nodes(&self, registry: &str) -> Result<Vec<(String, String)>, GatewayError>;
    /// The user the operator's token authenticates as, if it has one.
    async fn whoami(&self) -> Result<Option<String>, GatewayError>;
    /// A call of the admin API: its JSON answer (`null` when empty).
    async fn call(&self, request: &AdminRequest) -> Result<serde_json::Value, GatewayError>;
}

/// A package, or one version of it, in a registry: where grants and
/// policies are written.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PackageNode {
    pub registry: String,
    pub package: String,
    /// `None`: the package itself.
    pub version: Option<String>,
}

impl std::fmt::Display for PackageNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.version {
            Some(v) => write!(f, "{}@{v} in registry {}", self.package, self.registry),
            None => write!(f, "{} in registry {}", self.package, self.registry),
        }
    }
}

/// One subject's grant, as stored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct StoredGrant {
    pub subject: String,
    /// The expanded actions.
    pub actions: Vec<String>,
    /// The row of the ownership projection (an owner of the package).
    pub from_ownership: bool,
    pub granted_by: Option<String>,
}

/// What a grant write stored.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GrantWrite {
    /// The expanded actions stored.
    pub stored: Vec<String>,
    /// Legal but probably unintended.
    pub warnings: Vec<String>,
}

/// An exemption of a version from a gate.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Exemption {
    pub gate: String,
    /// RFC 3339.
    pub exempt_until: String,
    pub reason: String,
}

/// An HTTP method of the admin API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
}

/// One call of the admin API, by path: what a maintenance action runs.
#[derive(Debug, Clone, PartialEq)]
pub struct AdminRequest {
    pub method: Method,
    /// The path's segments after the base URL, each percent-encoded
    /// (`["api", "v1", "admin", "registries", "npm", "warm"]`).
    pub path: Vec<String>,
    pub query: Vec<(String, String)>,
    pub body: Option<serde_json::Value>,
    /// Instead of the gateway's own timeout (a maintenance run's).
    pub timeout: Option<std::time::Duration>,
}

/// Records a maintenance run as started — only if the object is unchanged
/// since it was read (a patch conditioned on its `resourceVersion`): a
/// run is decided once, by whoever writes first.
#[async_trait::async_trait]
pub trait RunGuard: Send + Sync {
    /// `Ok(false)`: the object changed meanwhile, nothing was written.
    async fn start(
        &self,
        run: &api::maintenance::LastRun,
        run_now: Option<&str>,
    ) -> Result<bool, String>;
}

/// Approves the configuration an instance holds (`reload.strategy:
/// Manual`): its `approved-config-hash` annotation.
#[async_trait::async_trait]
pub trait Approver: Send + Sync {
    async fn approve(&self, hash: &str) -> Result<(), String>;
}

/// A team namespace of a registry: a package name prefix reserved to a
/// group.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TeamNamespace {
    pub prefix: String,
    /// The group, as the instance's auth providers name it.
    pub group: String,
    /// Who claimed it (free text): the operator writes its marker there.
    pub claimed_by: Option<String>,
    /// How many packages it holds (`0` when written).
    pub package_count: i64,
}

/// What a dry run of a configuration says.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReloadCheck {
    /// The keys needing a restart the running process doesn't have, once
    /// this configuration is loaded (`["*"]`: BatleHub couldn't compare).
    pub restart_required: Vec<String>,
}

/// What `POST …/config/reload` did.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reloaded {
    /// The instance loaded its files.
    Loaded {
        /// The keys needing a restart the process doesn't have, against
        /// the configuration it **started** on (credentials layer and
        /// environment included; `["*"]`: BatleHub couldn't compare).
        restart_required: Vec<String>,
        /// The keys a component built at startup (warming, imports, the
        /// scan worker) keeps the old value of until a restart.
        partially_applied: Vec<String>,
    },
    /// Nothing loaded: the instance had already tried these exact bytes —
    /// it runs them, refused them (its file watcher tried them first), or
    /// let their pending reload expire. It doesn't say which.
    AlreadyTried,
}

/// Who staged a pending reload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PendingSource {
    /// The instance's own watcher, from its file on disk.
    FileWatcher,
    /// An admin call (the configuration editor, or the operator).
    AdminRequest,
}

/// A proxy pod of an instance, and its gateway.
pub struct PodGateway {
    pub name: String,
    pub gateway: Arc<dyn AdminGateway>,
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

/// What reaching a resolved instance takes. Implementations re-read the
/// token `Secret` on every call: rotating it needs no restart.
pub struct InstanceAccess {
    /// The instance's `url`.
    pub gateway: Arc<dyn AdminGateway>,
    /// The token the gateways present, to check the configuration still
    /// accepts it before pushing one.
    pub token: String,
}

#[async_trait::async_trait]
pub trait GatewayFactory: Send + Sync {
    async fn gateway_for(
        &self,
        instance: &BoundInstance,
    ) -> Result<InstanceAccess, GatewayFactoryError>;

    /// The ready proxy pods of `instance` (`external.podSelector`), each
    /// reached on its IP, sorted by name; `None` without a selector.
    async fn pod_gateways(
        &self,
        instance: &BoundInstance,
    ) -> Result<Option<Vec<PodGateway>>, GatewayFactoryError>;

    /// How many proxy pods of `instance` exist but aren't ready yet: one
    /// becoming ready must be approved soon, not at the next resync.
    async fn waiting_pods(&self, _instance: &BoundInstance) -> Result<usize, GatewayFactoryError> {
        Ok(0)
    }
}

/// Where a governance reconcile records what it wrote, right after each
/// write (a status patch): a pass that fails half-way must not find its
/// own first writes unknown next time, and take them for a conflict.
#[async_trait::async_trait]
pub trait Ledger<T: Send + Sync>: Send + Sync {
    async fn record(&self, written: &T) -> Result<(), String>;
}

pub use weebo_kit_application::workload::{
    OwnedObject, OwnedObjects, Owner, Rollout, WorkloadError,
};

/// The reason code of a [`WorkloadError`].
pub fn workload_reason(e: &WorkloadError) -> ReasonCode {
    match e {
        WorkloadError::Conflict(_) => ReasonCode::OwnedObjectConflict,
        WorkloadError::Kubernetes(_) => ReasonCode::KubernetesApiError,
        WorkloadError::Refused(_) => ReasonCode::InvalidSpec,
        WorkloadError::SecretNotAllowed(_) => ReasonCode::SecretNotAllowed,
    }
}

/// The Kubernetes objects of a managed instance: the kit's
/// [`OwnedObjects`], plus the operator's token and the TokenReview binding.
#[async_trait::async_trait]
pub trait Workloads: OwnedObjects {
    /// The operator's token of `owner`: generated once in the `Secret`
    /// `name` (labelled for it, owned by the instance), read back after.
    async fn operator_token(&self, owner: &Owner, name: &str) -> Result<String, WorkloadError>;
    /// Binds the account `service_account` of the owner's namespace to the
    /// `ClusterRole` `cluster_role` (TokenReview): a subject of the one
    /// `ClusterRoleBinding` named after the role, shared by every instance
    /// (the operator may write that binding only), recorded there for the
    /// owner and removed by [`Self::unbind_token_review`].
    async fn bind_token_review(
        &self,
        owner: &Owner,
        service_account: &str,
        cluster_role: &str,
    ) -> Result<(), WorkloadError>;
    /// Removes the owner's subject from the TokenReview binding of
    /// `cluster_role` — kept while another instance binds the same
    /// account (none is fine).
    async fn unbind_token_review(
        &self,
        owner: &Owner,
        cluster_role: &str,
    ) -> Result<(), WorkloadError>;
    /// Restarts the pods of the `Deployment` `name` (its template's
    /// `kubectl.kubernetes.io/restartedAt`), its `config-hash` set to
    /// `config_hash` when given; `false` when it doesn't exist.
    async fn restart(
        &self,
        owner: &Owner,
        name: &str,
        config_hash: Option<&str>,
    ) -> Result<bool, WorkloadError> {
        let annotations = config_hash
            .map(|hash| {
                std::collections::BTreeMap::from([(
                    api::managed::CONFIG_HASH_ANNOTATION.to_string(),
                    hash.to_string(),
                )])
            })
            .unwrap_or_default();
        self.annotate_template(owner, name, &annotations, true)
            .await
    }
}

/// The CRs bound to an instance, which hold its deletion.
#[async_trait::async_trait]
pub trait InstanceDependents: Send + Sync {
    /// The CRs (`Kind/namespace/name`) bound to `instance`: recorded in
    /// their status, or — not resolved yet — naming it in `instanceRef`,
    /// or naming nothing when `default` (it is the only instance of its
    /// namespace, the one they would default to).
    async fn dependents(
        &self,
        instance: &BoundInstance,
        default: bool,
    ) -> Result<Vec<String>, String>;
}

/// What BatleHub's parser says of a configuration it accepts.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigVerdict {
    /// Legal but probably unintended settings.
    pub warnings: Vec<String>,
}

/// The changed keys a reload doesn't fully apply (BatleHub's tiers).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct KeyChanges {
    /// Read at startup only (`Restart`): a running process doesn't apply
    /// them.
    pub restart: Vec<String>,
    /// Applied to requests, while a component built at startup — warming,
    /// release imports, the scan worker — keeps the old value until a
    /// restart (`Partial`).
    pub partial: Vec<String>,
}

/// Why a configuration couldn't be accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConfigError {
    /// The parser refuses it (`ConfigInvalid`).
    #[error("{0}")]
    Invalid(String),
}

/// Whether a configuration still lets the operator in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenCheck {
    /// An `admin` entry of a `type = "token"` provider accepts the token.
    Accepted,
    /// None does, but one is a `${VAR}` the instance resolves.
    Unverifiable,
    /// None does: the operator would lock itself out.
    Refused,
}

/// BatleHub's own configuration parser: the layers merged the way BatleHub
/// merges them, validated with the instance's environment (`env` answers
/// the `${VAR}` placeholders and the `PROXY_CACHE__*` overrides), never
/// the operator's.
pub trait ConfigParser: Send + Sync {
    /// A configuration written in YAML (as JSON) as a TOML layer.
    fn layer(&self, object: &serde_json::Value) -> Result<String, ConfigError>;
    /// A TOML fragment as JSON, to merge into a CR's object.
    fn fragment(&self, text: &str) -> Result<serde_json::Value, ConfigError>;
    /// The layers merged as BatleHub merges them, placeholders kept: one
    /// canonical document, whose hash moves only when its meaning does.
    fn merge(&self, layers: &[&str]) -> Result<String, ConfigError>;
    fn validate(
        &self,
        layers: &[&str],
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<ConfigVerdict, ConfigError>;
    /// Whether `document` (as [`Self::merge`] returns it) accepts `token`
    /// with the admin role.
    fn token_check(&self, document: &str, token: &str) -> TokenCheck;
    /// The changed keys between two documents (as [`Self::merge`] returns
    /// them) that a reload doesn't fully apply: BatleHub's own
    /// `reload_keys::classify`.
    fn classify(&self, before: &str, after: &str) -> Result<KeyChanges, ConfigError>;
    /// `token` as BatleHub's `hash-token` writes it (Argon2id, its
    /// parameters), salted from the token itself: the same token, the same
    /// hash, the same rendered file.
    fn hash_token(&self, token: &str) -> String;
}

/// Why a configuration source couldn't be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SourceError {
    /// The `ConfigMap`/`Secret`, or its key, doesn't exist.
    #[error("{0}")]
    Missing(String),
    /// A `Secret` without the `batlehub.weebo.io/credential` label.
    #[error("{0}")]
    NotAllowed(String),
    #[error("Kubernetes API error: {0}")]
    Kubernetes(String),
}

impl SourceError {
    pub fn reason(&self) -> ReasonCode {
        match self {
            SourceError::Missing(_) => ReasonCode::ConfigLayerMissing,
            SourceError::NotAllowed(_) => ReasonCode::SecretNotAllowed,
            SourceError::Kubernetes(_) => ReasonCode::KubernetesApiError,
        }
    }
}

/// A `BatleHubRegistry` as the instance renders it.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistryView {
    pub namespace: String,
    /// `metadata.name`.
    pub name: String,
    /// `metadata.creationTimestamp` (RFC 3339: sorts as text).
    pub created: String,
    pub labels: std::collections::BTreeMap<String, String>,
    pub spec: RegistrySpec,
    /// The instance it resolves to.
    pub bound: Result<BoundInstance, InstanceError>,
}

/// Where an instance's configuration comes from, besides its own spec.
#[async_trait::async_trait]
pub trait ConfigSources: Send + Sync {
    /// The text of a `ConfigMap`/`Secret` key of `namespace`: a `Secret`
    /// only when labelled `batlehub.weebo.io/credential: "true"`.
    async fn read(&self, namespace: &str, source: &ConfigSource) -> Result<String, SourceError>;
    /// Every key of a `ConfigMap`/`Secret` of `namespace` (the key of
    /// `source` aside), on the same terms as [`Self::read`]: an `envFrom`.
    async fn read_all(
        &self,
        namespace: &str,
        source: &ConfigSource,
    ) -> Result<std::collections::BTreeMap<String, String>, SourceError>;
    /// Every `BatleHubRegistry` the operator sees, resolved.
    async fn registries(&self) -> Result<Vec<RegistryView>, String>;
    /// Whether the `Secret` `name` of `namespace` carries
    /// `batlehub.weebo.io/credential: "true"` (its metadata only, its
    /// content never read); `None` when it doesn't exist.
    async fn secret_consents(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<bool>, SourceError>;
}

/// The instance a `BatleHubRegistry` attaches to: the kit's resolution,
/// where an instance of another namespace consents through its
/// `registrySelector.namespaces`.
#[async_trait::async_trait]
pub trait RegistryResolver: Send + Sync {
    async fn resolve_registry(
        &self,
        namespace: &str,
        instance_ref: Option<&InstanceRef>,
        recorded: Option<&BoundInstance>,
    ) -> Result<BoundInstance, InstanceError>;

    /// The instance `bound` designates, `None` when it is gone.
    async fn instance(&self, bound: &BoundInstance) -> Result<Option<api::LocalInstance>, String>;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neutral_errors_map_onto_reason_codes() {
        let bound = BoundInstance::local("ns", "hub");
        let cases = [
            (
                GatewayError::Unreachable("x".into()).reason(),
                ReasonCode::InstanceUnreachable,
            ),
            (
                GatewayError::Unauthorized("x".into()).reason(),
                ReasonCode::OperatorUnauthorized,
            ),
            (
                GatewayError::Remote("x".into()).reason(),
                ReasonCode::RemoteError,
            ),
            (
                GatewayFactoryError::InstanceNotFound(bound).reason(),
                ReasonCode::InstanceNotFound,
            ),
            (
                GatewayFactoryError::TokenSecret("x".into()).reason(),
                ReasonCode::TokenSecretMissing,
            ),
            (
                GatewayFactoryError::TokenNotAllowed("x".into()).reason(),
                ReasonCode::TokenSecretNotAllowed,
            ),
            (
                GatewayFactoryError::Kubernetes("x".into()).reason(),
                ReasonCode::KubernetesApiError,
            ),
            (
                GatewayFactoryError::InvalidSpec("x".into()).reason(),
                ReasonCode::InvalidSpec,
            ),
        ];
        for (got, want) in cases {
            assert_eq!(got, want);
        }
    }

    #[test]
    fn resolution_errors_map_onto_the_instance_codes() {
        let resolve = |e| instance_reason(&InstanceError::Resolve(e));
        assert_eq!(
            instance_reason(&InstanceError::Kubernetes("x".into())),
            ReasonCode::KubernetesApiError
        );
        assert_eq!(
            resolve(ResolveError::NoInstance),
            ReasonCode::InstanceNotFound
        );
        assert_eq!(
            resolve(ResolveError::NotFound {
                kind: "k".into(),
                name: "n".into()
            }),
            ReasonCode::InstanceNotFound
        );
        assert_eq!(
            resolve(ResolveError::Ambiguous {
                kind: "k".into(),
                count: 2
            }),
            ReasonCode::InstanceAmbiguous
        );
        for refused in [
            ResolveError::InvalidRef("x".into()),
            ResolveError::OutsideScope("x".into()),
            ResolveError::NotShared {
                instance: "i".into(),
                with: "w".into(),
            },
        ] {
            assert_eq!(resolve(refused), ReasonCode::InstanceNotAllowed);
        }
        assert_eq!(
            resolve(ResolveError::BindingChanged {
                name: "n".into(),
                recorded: Box::new(BoundInstance::local("ns", "a")),
                now: Box::new(BoundInstance::local("ns", "b")),
            }),
            ReasonCode::InstanceBindingChanged
        );
    }
}
