use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use weebo_kit_api::InstanceRef;

pub use crate::common::DeletionPolicy;
use crate::status::{BoundInstance, Condition};

/// The short names the rest of the workspace uses.
pub use self::BatleHubPackageGrant as PackageGrant;
pub use self::BatleHubPackageGrantSpec as PackageGrantSpec;
pub use self::BatleHubPackageGrantStatus as PackageGrantStatus;

/// The grants of a package, or of one version of it, in a registry of the
/// instance: who may do what there, beyond what the instance's and the
/// registry's configuration grant (`grants`, `registries[].grants`).
///
/// BatleHub keeps these grants in its database: the operator writes each
/// subject's grant through the admin API, reads them again on every pass
/// (rewriting what drifted), and revokes what it wrote when this object
/// is deleted (unless `deletionPolicy: Orphan`). It only ever touches the
/// grants it wrote: a subject already holding a grant on that node is a
/// conflict, never taken over.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "batlehub.weebo.io",
    version = "v1alpha1",
    kind = "BatleHubPackageGrant",
    plural = "batlehubpackagegrants",
    namespaced,
    shortname = "bhpg",
    status = "BatleHubPackageGrantStatus",
    printcolumn = r#"{"name":"Registry","type":"string","jsonPath":".spec.registry"}"#,
    printcolumn = r#"{"name":"Package","type":"string","jsonPath":".spec.package"}"#,
    printcolumn = r#"{"name":"Version","type":"string","jsonPath":".spec.version"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "has(self.instanceRef) == has(oldSelf.instanceRef)", "message": "instanceRef is immutable"},
    {"rule": "has(self.version) == has(oldSelf.version)", "message": "version is immutable"}
]))]
pub struct BatleHubPackageGrantSpec {
    /// The `BatleHubLocalInstance` of this namespace holding the registry;
    /// unset, the only one of this namespace. Immutable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::common::local_instance_ref")]
    pub instance_ref: Option<InstanceRef>,
    /// The registry's name on the instance. Immutable.
    #[schemars(schema_with = "crate::common::registry_name")]
    pub registry: String,
    /// The package, as the registry names it (`@acme/billing`). Immutable.
    #[schemars(schema_with = "crate::common::package_name")]
    pub package: String,
    /// One version of the package (it must exist); unset, the package
    /// itself (every version). Immutable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::common::version_name")]
    pub version: Option<String>,
    /// One grant per subject.
    #[schemars(length(min = 1, max = 256), extend("x-kubernetes-list-type" = "map", "x-kubernetes-list-map-keys" = ["subject"]))]
    pub grants: Vec<SubjectGrant>,
    /// `Delete` (default) revokes the grants this object wrote when it is
    /// deleted; `Orphan` leaves them on the instance.
    #[serde(default)]
    pub deletion_policy: DeletionPolicy,
}

/// What one subject may do on the node.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
pub struct SubjectGrant {
    /// Who, as BatleHub spells it: `user:alice`, `group:oidc1:eng`,
    /// `role:user`, `*`.
    #[schemars(length(min = 1, max = 512), regex(pattern = r"^\S+$"))]
    pub subject: String,
    /// Action patterns: `releases:read`, `releases:*`… BatleHub expands a
    /// pattern when it stores the grant (`status.applied[].stored`).
    #[schemars(
        length(min = 1, max = 64),
        inner(length(min = 1, max = 128), regex(pattern = r"^\S+$"))
    )]
    pub actions: Vec<String>,
}

/// One grant the operator wrote.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AppliedGrant {
    pub subject: String,
    /// The actions asked for, as written in the spec then.
    pub requested: Vec<String>,
    /// The actions BatleHub stored (the patterns expanded).
    pub stored: Vec<String>,
    /// What BatleHub found legal but probably unintended in it.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,
}

/// What the operator wrote.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BatleHubPackageGrantStatus {
    /// The `metadata.generation` the last successful reconcile applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// The instance this object was resolved to and stays bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<BoundInstance>,
    /// `Ready`, carrying one of the operator's reason codes.
    #[serde(default)]
    pub conditions: Vec<Condition>,
    /// The grants the operator wrote, one per subject, recorded right
    /// after each write: what it may rewrite and revoke.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applied: Vec<AppliedGrant>,
    /// The last pass that changed something on the instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync_time: Option<String>,
}
