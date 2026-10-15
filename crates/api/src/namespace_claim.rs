use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use weebo_kit_api::InstanceRef;

pub use crate::common::DeletionPolicy;
use crate::status::{BoundInstance, Condition};

/// The short names the rest of the workspace uses.
pub use self::BatleHubNamespaceClaim as NamespaceClaim;
pub use self::BatleHubNamespaceClaimSpec as NamespaceClaimSpec;
pub use self::BatleHubNamespaceClaimStatus as NamespaceClaimStatus;

/// A team namespace of a registry: a package name prefix reserved to a
/// group of the instance's auth providers. Only its members (and admins)
/// may publish `prefix`, or a package under it (`prefix/…`, with the
/// registry's own separator), and the group is the audience of the `team`
/// visibility there.
///
/// BatleHub keeps these claims in its database, not in its configuration:
/// the operator claims the prefix through the admin API, checks it again
/// on every pass, and releases it when this object is deleted (unless
/// `deletionPolicy: Orphan`). A prefix already claimed by anything else
/// is never taken over.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "batlehub.weebo.io",
    version = "v1alpha1",
    kind = "BatleHubNamespaceClaim",
    plural = "batlehubnamespaceclaims",
    namespaced,
    shortname = "bhnc",
    status = "BatleHubNamespaceClaimStatus",
    printcolumn = r#"{"name":"Registry","type":"string","jsonPath":".spec.registry"}"#,
    printcolumn = r#"{"name":"Prefix","type":"string","jsonPath":".spec.prefix"}"#,
    printcolumn = r#"{"name":"Group","type":"string","jsonPath":".spec.group"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "has(self.instanceRef) == has(oldSelf.instanceRef)", "message": "instanceRef is immutable"}
]))]
pub struct BatleHubNamespaceClaimSpec {
    /// The `BatleHubLocalInstance` of this namespace holding the registry;
    /// unset, the only one of this namespace. Immutable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::common::local_instance_ref")]
    pub instance_ref: Option<InstanceRef>,
    /// The registry's name on the instance (a `[[registries]]` entry, from
    /// the instance's configuration or a `BatleHubRegistry`). Immutable.
    #[schemars(length(min = 1, max = 253), extend("x-kubernetes-validations" = [
        {"rule": "self == oldSelf", "message": "registry is immutable"},
        {"rule": "self != '.' && self != '..' && !self.contains('/')", "message": "registry must be a registry name"}
    ]))]
    pub registry: String,
    /// The package name prefix, in the ecosystem's own spelling: an npm
    /// scope (`@acme`), a Go module or Maven path, an OpenVSX publisher… A
    /// claim covers `prefix` itself and every package under it. No part
    /// between slashes may be `.` or `..`. Immutable.
    #[schemars(length(min = 1, max = 1024), extend("x-kubernetes-validations" = [
        {"rule": "self == oldSelf", "message": "prefix is immutable"},
        {"rule": "self == self.trim() && self.split('/').all(s, s != '.' && s != '..')", "message": "prefix may not be blank, have a `.` or `..` part between slashes, nor start or end with a space"}
    ]))]
    pub prefix: String,
    /// The group owning the prefix, as the instance's auth providers name
    /// it: `oidc:frontend-team`, `kubernetes:system:serviceaccounts:ci`…
    /// Changing it releases the prefix then claims it for the new group.
    #[schemars(length(min = 1, max = 512), regex(pattern = r"^\S+$"))]
    pub group: String,
    /// `Delete` (default) releases the prefix when this object is deleted;
    /// `Orphan` leaves the claim on the instance.
    #[serde(default)]
    pub deletion_policy: DeletionPolicy,
}

/// What the operator claimed.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BatleHubNamespaceClaimStatus {
    /// The `metadata.generation` the last successful reconcile applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// The instance this claim was resolved to and stays bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<BoundInstance>,
    /// `Ready`, carrying one of the operator's reason codes.
    #[serde(default)]
    pub conditions: Vec<Condition>,
    /// The group the operator last claimed the prefix for: the claim on
    /// the instance is this object's while it names this group.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub claimed_group: Option<String>,
    /// How many packages the namespace holds, as the instance counted
    /// them on the last pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub package_count: Option<i64>,
    /// The last pass that changed something on the instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync_time: Option<String>,
}
