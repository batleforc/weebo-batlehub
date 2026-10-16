use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use weebo_kit_api::{LocalSecretKeyRef, LocalTlsOptions};

use crate::config::{ConfigSource, open_object};
use crate::status::Condition;

/// The short names the rest of the workspace uses.
pub use self::BatleHubLocalInstance as LocalInstance;
pub use self::BatleHubLocalInstanceSpec as LocalInstanceSpec;
pub use self::BatleHubLocalInstanceStatus as LocalInstanceStatus;

/// One BatleHub instance, owned by a namespace: its token is that
/// namespace's, and only the objects of that namespace use it (plus the
/// `BatleHubRegistry`s of the namespaces it accepts). `Ready` tells
/// whether the instance answers, accepts the operator's token with the
/// admin role and, with `external.manageConfig`, runs the configuration
/// rendered from this object.
///
/// While objects are bound to it, its deletion waits (`InstanceInUse`);
/// `batlehub.weebo.io/force-orphan: "true"` releases it and leaves them
/// orphaned.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "batlehub.weebo.io",
    version = "v1alpha1",
    kind = "BatleHubLocalInstance",
    plural = "batlehublocalinstances",
    namespaced,
    shortname = "bhli",
    status = "BatleHubLocalInstanceStatus",
    printcolumn = r#"{"name":"Endpoint","type":"string","jsonPath":".status.endpoint"}"#,
    printcolumn = r#"{"name":"Version","type":"string","jsonPath":".status.version"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#,
    // A managed instance's name is its Service's (a DNS-1035 label) and
    // the `app.kubernetes.io/instance` label of every object it owns.
    validation = Rule::new(
        "!has(self.spec.managed) || (size(self.metadata.name) <= 63 && self.metadata.name.matches('^[a-z]([-a-z0-9]*[a-z0-9])?$'))"
    ).message("a managed instance's name names its Service: a DNS-1035 label (lowercase letters, digits and '-', starting with a letter), at most 63 characters")
)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "has(self.external) != has(self.managed)", "message": "set exactly one of external and managed"},
    {"rule": "has(self.external) == has(oldSelf.external)", "message": "the mode (external or managed) is immutable"}
]))]
pub struct BatleHubLocalInstanceSpec {
    /// A BatleHub the operator doesn't deploy: it reaches it at `url`
    /// with an admin token, observes it and, with `manageConfig`, pushes
    /// its configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external: Option<ExternalInstance>,
    /// A BatleHub the operator deploys, in this namespace, and whose
    /// configuration it always manages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub managed: Option<crate::managed::ManagedInstance>,
    /// BatleHub's configuration file (`config.toml`) written in YAML, key
    /// for key: a TOML table is an object, an array of tables a list of
    /// objects. Never typed here: BatleHub's own parser validates it.
    /// `${VAR}` placeholders are kept and resolved by the instance from
    /// its own environment (`managed.env`). Rendered with `managed`, or
    /// `external.manageConfig`.
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    #[schemars(schema_with = "open_object")]
    pub config: serde_json::Value,
    /// TOML documents merged in order over `config`, the way BatleHub
    /// merges its `--config` layers (the later wins; tables merge; arrays
    /// of tables merge entry by entry on a unique `name`, else `type`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config_layers: Vec<ConfigSource>,
    /// How a new configuration reaches the instance.
    #[serde(default, skip_serializing_if = "Reload::is_default")]
    pub reload: Reload,
    /// Which `BatleHubRegistry`s this instance serves, rendered as
    /// `[[registries]]` entries after `configLayers`.
    #[serde(default, skip_serializing_if = "RegistrySelector::is_default")]
    pub registry_selector: RegistrySelector,
}

/// A BatleHub deployed by other means (its Helm chart, another cluster).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ExternalInstance {
    /// Base URL of the BatleHub instance, e.g. `https://batlehub.example.com`.
    pub url: String,
    /// A token of BatleHub's `admin` role, in a `Secret` of this namespace
    /// labelled `batlehub.weebo.io/instance-token: "true"` (without the
    /// label the operator doesn't read it). Read on every reconcile:
    /// rotating it needs no restart.
    pub admin_token_secret_ref: LocalSecretKeyRef,
    /// TLS verification of the connection to `url`: a private CA to trust
    /// (`tls.caSecretRef`, a `Secret` of this namespace), or the
    /// `tls.insecureSkipVerify` escape hatch.
    #[serde(default)]
    pub tls: LocalTlsOptions,
    /// Push the configuration rendered from `config`, `configLayers` and
    /// the registries through the admin API, replacing the instance's
    /// first configuration file. The instance needs hot reload enabled.
    /// A change of a key that needs a restart is held back
    /// (`RestartForbidden`): the operator can't restart an instance it
    /// doesn't deploy. Without it, the operator only observes.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub manage_config: bool,
    /// The instance's proxy pods, when it runs in this namespace (the
    /// BatleHub chart): its replicas don't share a reload, so the operator
    /// pushes and approves the configuration on each selected pod, over
    /// plain HTTP on its IP and container port (the one named `http`,
    /// else the first container's first). Select the proxy pods only: the
    /// chart's worker pods carry the same labels plus
    /// `app.kubernetes.io/component: worker` (exclude it with a
    /// `DoesNotExist` expression). Without it, `url` is the only entry
    /// point, and an instance of several replicas is not supported with
    /// `manageConfig`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pod_selector: Option<LabelSelector>,
}

/// How a new configuration reaches the instance.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct Reload {
    /// `Auto` applies every validated configuration; `Manual` holds it
    /// (`ConfigHeld`, its hash in `status.pendingConfigHash`) until the
    /// annotation `batlehub.weebo.io/approved-config-hash` carries that
    /// exact hash.
    #[serde(default)]
    pub strategy: ReloadStrategy,
    /// `Strict` blocks a configuration BatleHub's parser refuses
    /// (`ConfigInvalid`); `Lenient` pushes it anyway
    /// (`ConfigInvalidLenient`), for when the stand-in value the operator
    /// gives a `${VAR}` it can't read is what fails. The instance still
    /// validates it with its real environment before loading it.
    #[serde(default)]
    pub validation: Validation,
    /// `managed`: `Rollout` restarts the pods when a key BatleHub reads at
    /// startup changes; `Never` raises `RestartRequired` instead, naming
    /// the keys, until the pods restart otherwise.
    #[serde(default)]
    pub restart: RestartPolicy,
    /// `managed`: what a change of a key BatleHub applies to requests but
    /// not to the components it built at startup (warming, release
    /// imports, the scan worker — BatleHub's `Partial` tier, every
    /// `registries[*]` among them) is. `Reload` (default) hot-reloads it
    /// and raises `PartiallyApplied`, naming the keys, until the pods
    /// restart; `Restart` treats it as a key read at startup
    /// (`reload.restart` decides).
    #[serde(default)]
    pub partial: PartialPolicy,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, JsonSchema)]
pub enum PartialPolicy {
    #[default]
    Reload,
    Restart,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, JsonSchema)]
pub enum RestartPolicy {
    #[default]
    Rollout,
    Never,
}

impl Reload {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, JsonSchema)]
pub enum ReloadStrategy {
    #[default]
    Auto,
    Manual,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, PartialEq, Eq, JsonSchema)]
pub enum Validation {
    #[default]
    Strict,
    Lenient,
}

/// Which `BatleHubRegistry`s the instance serves.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct RegistrySelector {
    /// Only the registries whose labels match; all of them when unset.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub selector: Option<LabelSelector>,
    /// The namespaces whose registries may attach to this instance (with
    /// an `instanceRef` naming it): its own always.
    #[serde(default, skip_serializing_if = "RegistryNamespaces::is_default")]
    pub namespaces: RegistryNamespaces,
}

impl RegistrySelector {
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}

/// The namespaces a registry may come from: the kit's consent of the
/// instance's owner.
pub use weebo_kit_api::{AttachNamespaces as RegistryNamespaces, NamespacesFrom};

impl BatleHubLocalInstanceSpec {
    /// Whether the operator renders and applies the configuration.
    pub fn manages_config(&self) -> bool {
        self.managed.is_some() || self.external.as_ref().is_some_and(|e| e.manage_config)
    }
}

/// The URL the operator calls: external, `url`; managed, its `Service`.
pub fn endpoint(instance: &BatleHubLocalInstance) -> String {
    use kube::ResourceExt;
    match (&instance.spec.external, &instance.spec.managed) {
        (Some(external), _) => external.url.clone(),
        (None, Some(managed)) => format!(
            "http://{}.{}.svc:{}",
            crate::managed::Names::new(instance.name_any()).proxy(),
            instance.namespace().unwrap_or_default(),
            managed.service.port
        ),
        (None, None) => String::new(),
    }
}

/// What the operator observed of the instance.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BatleHubLocalInstanceStatus {
    /// The `metadata.generation` the last successful reconcile applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// `Ready`, carrying one of the operator's reason codes, and the
    /// advisories next to it (`ConfigWarnings`, `ConfigHeld`…).
    #[serde(default)]
    pub conditions: Vec<Condition>,
    /// The URL the operator calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// BatleHub's version, as its `/livez` reports it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// What BatleHub finds legal but probably unintended in its own
    /// configuration (`GET /api/v1/admin/config/warnings`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<ConfigWarning>,
    /// SHA-256 of the configuration rendered from this object (the
    /// desired one), with `manageConfig`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
    /// SHA-256 of the configuration every pod was last seen running.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_config_hash: Option<String>,
    /// SHA-256 of a configuration held by `reload.strategy: Manual`: set
    /// `batlehub.weebo.io/approved-config-hash` to it to apply it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pending_config_hash: Option<String>,
    /// Bumped to make BatleHub stage bytes it has already seen once (a
    /// load attempt that failed or expired): written as a final comment
    /// of the pushed file, outside `configHash`.
    #[serde(default, skip_serializing_if = "is_zero")]
    pub reload_nonce: u64,
    /// The last configuration the instance refused (or loaded without
    /// being able to write it, `unpersistedConfigHash`), and when: the same
    /// one is pushed again at most every 10 minutes. `managed`: without a
    /// time, it is being retried under a new `reloadNonce` — a pod that
    /// stages nothing for those new bytes refused them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejected_config_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_rejection_time: Option<String>,
    /// What the instance said when it refused `rejectedConfigHash`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rejection_message: Option<String>,
    /// A configuration the instance loaded but couldn't write to its first
    /// configuration file (`ConfigReadOnly`): lost on its next restart.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub unpersisted_config_hash: Option<String>,
    /// The keys needing a restart the instance doesn't run yet: external,
    /// while the push is held back; managed, until the proxy pods start on
    /// the configuration (rolled out, or `RestartRequired`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub restart_keys: Vec<String>,
    /// `managed`: keys of BatleHub's `Partial` tier changed since the proxy
    /// pods started, hot-reloaded (`reload.partial: Reload`): what was
    /// built at startup keeps their old value until a restart.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub partial_keys: Vec<String>,
    /// The pods (with `external.podSelector`) not running the desired
    /// configuration yet; empty once it is applied.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pods: Vec<PodConfig>,
    /// When the operator last made the instance load a configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_reload_time: Option<String>,
    /// `managed`: SHA-256 of the credentials layer, a comment of the
    /// rendered file (a rotation is a reload).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credentials_hash: Option<String>,
    /// `managed`: how the proxy pods are replaced (`Recreate`,
    /// `RollingUpdate`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub update_strategy: Option<String>,
    /// `managed`: the proxy pods ready.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub available_replicas: Option<i32>,
}

fn is_zero(n: &u64) -> bool {
    *n == 0
}

/// One warning of BatleHub on its configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigWarning {
    /// Stable identifier, e.g. `proxy-trust.unconfigured`.
    pub code: String,
    /// The configuration key it is about, e.g. `server.trusted_proxies`.
    pub path: String,
    pub message: String,
}

/// A pod behind on the configuration.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct PodConfig {
    pub name: String,
    /// SHA-256 of the configuration file it serves, when it could be read.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_hash: Option<String>,
}
