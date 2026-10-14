use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use weebo_kit_api::{LocalSecretKeyRef, LocalTlsOptions};

use crate::status::Condition;

/// The short names the rest of the workspace uses.
pub use self::BatleHubLocalInstance as LocalInstance;
pub use self::BatleHubLocalInstanceSpec as LocalInstanceSpec;
pub use self::BatleHubLocalInstanceStatus as LocalInstanceStatus;

/// One BatleHub instance, owned by a namespace: its token is that
/// namespace's, and only the objects of that namespace use it. `Ready`
/// tells whether the instance answers and accepts the operator's token
/// with the admin role.
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
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct BatleHubLocalInstanceSpec {
    /// A BatleHub the operator doesn't deploy: it reaches it at `url`
    /// with an admin token, and observes it. (The mode where the operator
    /// deploys BatleHub itself comes in a later version.)
    pub external: ExternalInstance,
}

/// A BatleHub deployed by other means (its Helm chart, another cluster).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
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
}

/// What the operator observed of the instance.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BatleHubLocalInstanceStatus {
    /// The `metadata.generation` the last successful reconcile applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// `Ready`, carrying one of the operator's reason codes, and the
    /// advisories next to it (`ConfigWarnings`).
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
