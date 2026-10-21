//! `spec.managed` of a `BatleHubLocalInstance`: the operator deploys
//! BatleHub. The defaults follow BatleHub's own Helm chart, so that a
//! `values.yaml` translates line by line.

use std::collections::BTreeMap;

use k8s_openapi::api::core::v1::{
    Affinity, EnvFromSource, EnvVar, LocalObjectReference, PodSecurityContext,
    ResourceRequirements, SecurityContext, Toleration, Volume, VolumeMount,
};
use k8s_openapi::api::networking::v1::{IngressTLS, NetworkPolicyPeer};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use weebo_kit_api::LocalSecretKeyRef;

/// The image BatleHub runs when `image.tag` is unset: the version this
/// operator targets.
pub const DEFAULT_IMAGE_REPOSITORY: &str = "ghcr.io/batlehub/batlehub";
pub const DEFAULT_IMAGE_TAG: &str = "1.6.0";
pub const DEFAULT_WORKER_REPOSITORY: &str = "ghcr.io/batlehub/batlehub-worker";
/// The user id of the operator's generated token.
pub const DEFAULT_OPERATOR_USER: &str = "weebo-batlehub-operator";

/// A BatleHub the operator deploys: a `Deployment` of proxy pods (and of
/// workers), its `Service`, the configuration `Secret`, a cache volume,
/// and what goes around them. Every object carries an owner reference to
/// the instance; an object of the same name the operator didn't create is
/// never taken over (`OwnedObjectConflict`).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ManagedInstance {
    #[serde(default, skip_serializing_if = "Image::is_default")]
    pub image: Image,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub image_pull_secrets: Vec<LocalObjectReference>,
    /// Proxy pods. A filesystem cache on a `ReadWriteOnce` volume allows
    /// one.
    #[serde(default = "one")]
    #[schemars(range(min = 0))]
    pub replicas: i32,
    /// How the proxy pods are replaced when a key read at startup
    /// changes; unset, derived (`Recreate` with a filesystem cache on a
    /// `ReadWriteOnce` volume, `RollingUpdate` with `maxUnavailable: 0`
    /// otherwise). `status.updateStrategy` shows the one in effect.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_strategy: Option<UpdateStrategy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,
    #[serde(default, skip_serializing_if = "Service::is_default")]
    pub service: Service,
    /// An `Ingress` to the proxy pods. Its hosts are not derived from the
    /// registries' `hosts`: set `server.trusted_proxies` knowingly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress: Option<Ingress>,
    /// The artifact cache, with BatleHub's default filesystem storage.
    #[serde(default, skip_serializing_if = "Persistence::is_default")]
    pub persistence: Persistence,
    /// A separate `Deployment` of workers (`--roles worker`: vulnerability
    /// scans); the proxy pods then run `--roles proxy`. Unset: one pod does
    /// both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worker: Option<Worker>,
    /// Rendered from 2 proxy replicas.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_disruption_budget: Option<PodDisruptionBudget>,
    /// A `NetworkPolicy` on the proxy and worker pods: egress refused but
    /// DNS and `egressTo`; ingress on the HTTP port from `ingressFrom`
    /// (every source when empty) and the operator.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network_policy: Option<NetworkPolicy>,
    #[serde(default, skip_serializing_if = "ServiceAccount::is_default")]
    pub service_account: ServiceAccount,
    #[serde(default, skip_serializing_if = "OperatorAccess::is_default")]
    pub operator_access: OperatorAccess,
    /// `false` sets `BATLEHUB_DISABLE_HOT_RELOAD=1`: every change of the
    /// configuration is then a restart.
    #[serde(default = "yes", skip_serializing_if = "is_true")]
    pub hot_reload: bool,
    /// A `Secret` of this namespace holding a second configuration layer
    /// (`credentials.toml`: upstream tokens, database passwords…), labelled
    /// `batlehub.weebo.io/credential: "true"`. Mounted as is, never
    /// rendered: its hash only (`status.credentialsHash`) enters the
    /// configuration, so a rotation is a reload.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials: Option<LocalSecretKeyRef>,
    /// The environment of the proxy and worker containers: where `${VAR}`
    /// placeholders resolve.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<EnvVar>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env_from: Vec<EnvFromSource>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pod_annotations: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub pod_labels: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub node_selector: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tolerations: Vec<Toleration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub affinity: Option<Affinity>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_class_name: Option<String>,
    /// CA bundles, a `static_dir`, a `cli_binary_path`…
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(schema_with = "open_list")]
    pub extra_volumes: Vec<Volume>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_volume_mounts: Vec<VolumeMount>,
    /// Unset: non-root (65532), seccomp `RuntimeDefault`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "open_object")]
    pub pod_security_context: Option<PodSecurityContext>,
    /// Unset: read-only root filesystem, no capability, no privilege
    /// escalation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "open_object")]
    pub security_context: Option<SecurityContext>,
}

impl Default for ManagedInstance {
    /// Every field at its default, as an empty `managed: {}` reads.
    #[expect(
        clippy::expect_used,
        reason = "a constant `{}`: every field has a serde default, every test building a default spec runs it"
    )]
    fn default() -> Self {
        serde_json::from_value(serde_json::json!({})).expect("every field has a default")
    }
}

/// A Kubernetes type whose schema would weigh the CRD down: kept open,
/// the API server checks it where it lands (the pod template).
fn open_object(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({"type": "object", "x-kubernetes-preserve-unknown-fields": true})
}

fn open_list(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "array",
        "items": {"type": "object", "x-kubernetes-preserve-unknown-fields": true},
    })
}

fn one() -> i32 {
    1
}

fn yes() -> bool {
    true
}

fn is_true(b: &bool) -> bool {
    *b
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Image {
    /// Default `ghcr.io/batlehub/batlehub`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repository: Option<String>,
    /// Default: the BatleHub version this operator targets.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// Default `IfNotPresent`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pull_policy: Option<PullPolicy>,
}

/// The container's `imagePullPolicy`.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, JsonSchema)]
pub enum PullPolicy {
    Always,
    #[default]
    IfNotPresent,
    Never,
}

impl PullPolicy {
    pub fn as_str(self) -> &'static str {
        match self {
            PullPolicy::Always => "Always",
            PullPolicy::IfNotPresent => "IfNotPresent",
            PullPolicy::Never => "Never",
        }
    }
}

impl Image {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// `repository:tag`, the defaults filled.
    pub fn reference(&self) -> String {
        format!(
            "{}:{}",
            self.repository
                .as_deref()
                .unwrap_or(DEFAULT_IMAGE_REPOSITORY),
            self.tag.as_deref().unwrap_or(DEFAULT_IMAGE_TAG)
        )
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
pub enum UpdateStrategy {
    Recreate,
    RollingUpdate,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    /// Default `ClusterIP`.
    #[serde(default, rename = "type")]
    pub r#type: ServiceType,
    /// The `Service`'s port (default 8080); the container's follows
    /// `config.server.port`.
    #[serde(default = "http_port")]
    #[schemars(range(min = 1, max = 65535))]
    pub port: i32,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
}

/// The `Service`'s `type` (`ExternalName` names no pod: not offered).
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, JsonSchema)]
pub enum ServiceType {
    #[default]
    ClusterIP,
    NodePort,
    LoadBalancer,
}

impl ServiceType {
    pub fn as_str(self) -> &'static str {
        match self {
            ServiceType::ClusterIP => "ClusterIP",
            ServiceType::NodePort => "NodePort",
            ServiceType::LoadBalancer => "LoadBalancer",
        }
    }
}

fn http_port() -> i32 {
    8080
}

impl Default for Service {
    fn default() -> Self {
        Self {
            r#type: ServiceType::default(),
            port: http_port(),
            annotations: BTreeMap::new(),
        }
    }
}

impl Service {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Ingress {
    #[schemars(length(min = 1))]
    pub host: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub extra_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub class_name: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tls: Vec<IngressTLS>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Persistence {
    /// A `PersistentVolumeClaim` for the cache; `false`: an `emptyDir`
    /// (`ephemeralSizeLimit`), lost with the pod.
    #[serde(default = "yes")]
    pub enabled: bool,
    #[serde(default = "ten_gi")]
    pub size: Quantity,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub storage_class: Option<String>,
    /// Default `ReadWriteOnce`. A single-writer mode (`ReadWriteOnce`,
    /// `ReadWriteOncePod`) allows one proxy pod; `ReadWriteOncePod`, no
    /// separate worker either (it mounts the cache too).
    #[serde(default)]
    pub access_mode: AccessMode,
    /// A claim of this namespace to use instead of creating one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub existing_claim: Option<String>,
    #[serde(default = "one_gi")]
    pub ephemeral_size_limit: Quantity,
}

fn ten_gi() -> Quantity {
    Quantity("10Gi".into())
}

fn one_gi() -> Quantity {
    Quantity("1Gi".into())
}

/// The claim's access mode.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, JsonSchema)]
pub enum AccessMode {
    #[default]
    ReadWriteOnce,
    ReadWriteOncePod,
    ReadWriteMany,
}

impl AccessMode {
    pub fn as_str(self) -> &'static str {
        match self {
            AccessMode::ReadWriteOnce => "ReadWriteOnce",
            AccessMode::ReadWriteOncePod => "ReadWriteOncePod",
            AccessMode::ReadWriteMany => "ReadWriteMany",
        }
    }
}

impl Default for Persistence {
    fn default() -> Self {
        Self {
            enabled: true,
            size: ten_gi(),
            storage_class: None,
            access_mode: AccessMode::default(),
            existing_claim: None,
            ephemeral_size_limit: one_gi(),
        }
    }
}

impl Persistence {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }

    /// One writer at a time: a surge pod would wait for the volume.
    pub fn single_writer(&self) -> bool {
        self.enabled
            && matches!(
                self.access_mode,
                AccessMode::ReadWriteOnce | AccessMode::ReadWriteOncePod
            )
    }
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Worker {
    #[serde(default = "one")]
    #[schemars(range(min = 0))]
    pub replicas: i32,
    /// Default `ghcr.io/batlehub/batlehub-worker`, the proxy's tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<Image>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceRequirements>,
    /// `gvisor`, to sandbox the scanners.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_class_name: Option<String>,
    /// The scratch `emptyDir` of the scans (`TMPDIR`), default 4Gi.
    #[serde(default = "four_gi")]
    pub scratch_size_limit: Quantity,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub node_selector: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tolerations: Vec<Toleration>,
    /// A `HorizontalPodAutoscaler` on the scan queue's depth.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub autoscaling: Option<Autoscaling>,
}

fn four_gi() -> Quantity {
    Quantity("4Gi".into())
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "self.minReplicas <= self.maxReplicas", "message": "minReplicas exceeds maxReplicas"}
]))]
pub struct Autoscaling {
    #[serde(default = "one")]
    #[schemars(range(min = 1))]
    pub min_replicas: i32,
    #[schemars(range(min = 1))]
    pub max_replicas: i32,
    /// Queued scans per worker the autoscaler aims at.
    #[serde(default = "twenty")]
    #[schemars(range(min = 1))]
    pub target_queued: i64,
    /// The external metric of the queue's depth (a metrics adapter
    /// serves it), default `batlehub_scan_jobs_queued`.
    #[serde(default = "queue_metric")]
    pub metric_name: String,
}

fn twenty() -> i64 {
    20
}

fn queue_metric() -> String {
    "batlehub_scan_jobs_queued".into()
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "has(self.minAvailable) != has(self.maxUnavailable)", "message": "set one of minAvailable and maxUnavailable"}
]))]
pub struct PodDisruptionBudget {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_available: Option<IntOrString>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_unavailable: Option<IntOrString>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct NetworkPolicy {
    /// Who may reach the HTTP port; empty: anyone. The operator's pods
    /// (its chart's selector labels, in its namespace) are added.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(schema_with = "open_list")]
    pub ingress_from: Vec<NetworkPolicyPeer>,
    /// Where the pods may connect besides DNS (the database, the object
    /// store, the upstream registries).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(schema_with = "open_list")]
    pub egress_to: Vec<NetworkPolicyPeer>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ServiceAccount {
    /// `false`: use `name`, which must exist.
    #[serde(default = "yes")]
    pub create: bool,
    /// Default: the instance's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub annotations: BTreeMap<String, String>,
    /// With a `kubernetes` auth provider in the configuration, bind the
    /// account to TokenReview (the chart's `<release>-tokenreview`
    /// ClusterRole); the pods then mount its token.
    #[serde(default = "yes")]
    pub auto_token_review: bool,
}

impl Default for ServiceAccount {
    fn default() -> Self {
        Self {
            create: true,
            name: None,
            annotations: BTreeMap::new(),
            auto_token_review: true,
        }
    }
}

impl ServiceAccount {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// How the operator reaches the admin API it needs.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "self.generateToken || has(self.tokenSecretRef)", "message": "tokenSecretRef is required without generateToken"}
]))]
pub struct OperatorAccess {
    /// Generate a token once in `<name>-operator-token` and declare its
    /// Argon2id hash in the configuration (`[[auth]] type = "token"`, role
    /// `admin`). Delete that Secret to rotate it (a restart: `auth` is
    /// read at startup).
    #[serde(default = "yes")]
    pub generate_token: bool,
    /// Without `generateToken`: your own admin token, in a `Secret` of
    /// this namespace labelled `batlehub.weebo.io/instance-token: "true"`,
    /// that `config` must declare.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub token_secret_ref: Option<LocalSecretKeyRef>,
    /// The generated token's user id, as BatleHub's audit records it.
    #[serde(default = "operator_user")]
    pub user_id: String,
}

fn operator_user() -> String {
    DEFAULT_OPERATOR_USER.into()
}

impl Default for OperatorAccess {
    fn default() -> Self {
        Self {
            generate_token: true,
            token_secret_ref: None,
            user_id: operator_user(),
        }
    }
}

impl OperatorAccess {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// The names and labels of what the operator creates for a managed
/// instance `name`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Names {
    pub instance: String,
}

/// `app.kubernetes.io/managed-by` of every object the operator creates: an
/// object carrying it with `app.kubernetes.io/instance: <instance>` (and
/// controlled by no other object), or an owner reference to the instance,
/// may be written over; any other is a conflict.
pub const MANAGED_BY: &str = "weebo-batlehub";
/// The key of the generated token in `<name>-operator-token`.
pub const TOKEN_KEY: &str = "token";
/// The key of the rendered configuration in `<name>-config`.
pub const CONFIG_KEY: &str = "config.toml";
/// The pod template annotation whose change rolls the pods: the hash of
/// the configuration last needing a restart.
pub const CONFIG_HASH_ANNOTATION: &str = "batlehub.weebo.io/config-hash";

impl Names {
    pub fn new(instance: impl Into<String>) -> Self {
        Self {
            instance: instance.into(),
        }
    }

    /// The proxy `Deployment`, its `Service` (and `Ingress`, PDB,
    /// `NetworkPolicy`).
    pub fn proxy(&self) -> String {
        self.instance.clone()
    }

    pub fn worker(&self) -> String {
        format!("{}-worker", self.instance)
    }

    pub fn config(&self) -> String {
        format!("{}-config", self.instance)
    }

    pub fn token(&self) -> String {
        format!("{}-operator-token", self.instance)
    }

    pub fn cache(&self) -> String {
        format!("{}-cache", self.instance)
    }

    /// The labels every object carries.
    pub fn labels(&self, component: &str) -> BTreeMap<String, String> {
        let mut labels = self.selector(component);
        labels.insert("app.kubernetes.io/managed-by".into(), MANAGED_BY.into());
        labels
    }

    /// What selects the pods of `component` (`proxy`, `worker`).
    pub fn selector(&self, component: &str) -> BTreeMap<String, String> {
        BTreeMap::from([
            ("app.kubernetes.io/name".into(), "batlehub".into()),
            ("app.kubernetes.io/instance".into(), self.instance.clone()),
            ("app.kubernetes.io/component".into(), component.into()),
        ])
    }
}
