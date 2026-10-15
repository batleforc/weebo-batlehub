use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use weebo_kit_api::InstanceRef;

pub use crate::common::DeletionPolicy;
use crate::status::{BoundInstance, Condition};

/// The short names the rest of the workspace uses.
pub use self::BatleHubPackagePolicy as PackagePolicy;
pub use self::BatleHubPackagePolicySpec as PackagePolicySpec;
pub use self::BatleHubPackagePolicyStatus as PackagePolicyStatus;

/// The policy of a package, or of one version of it, in a registry of the
/// instance, and the exemptions of a version from its gates.
///
/// BatleHub keeps these in its database: the operator writes the policy
/// through the admin API, reads it back on every pass (rewriting it when
/// it was changed elsewhere), and clears it when this object is deleted
/// (unless `deletionPolicy: Orphan`). A policy already on the node that
/// this object didn't write is a conflict, never taken over.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "batlehub.weebo.io",
    version = "v1alpha1",
    kind = "BatleHubPackagePolicy",
    plural = "batlehubpackagepolicies",
    namespaced,
    shortname = "bhpp",
    status = "BatleHubPackagePolicyStatus",
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
    {"rule": "has(self.version) == has(oldSelf.version)", "message": "version is immutable"},
    {"rule": "has(self.policy) || (has(self.exemptions) && size(self.exemptions) > 0)", "message": "set policy, exemptions, or both"},
    {"rule": "!has(self.exemptions) || size(self.exemptions) == 0 || has(self.version)", "message": "exemptions apply to a version: set version"}
]))]
pub struct BatleHubPackagePolicySpec {
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
    /// One version of the package; unset, the package itself. Immutable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::common::version_name")]
    pub version: Option<String>,
    /// The node's policy, as BatleHub's API takes it (snake_case keys): it
    /// replaces the node's policy as a whole, a key left out inherits from
    /// the tier above.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "policy_schema")]
    pub policy: Option<serde_json::Value>,
    /// The version's exemptions from its gates, one per gate. Needs
    /// `version`, and a grant of `gates:exempt` to the operator's identity
    /// on the version or its package (no role carries it).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schemars(length(max = 4), extend("x-kubernetes-list-type" = "map", "x-kubernetes-list-map-keys" = ["gate"]))]
    pub exemptions: Vec<GateExemption>,
    /// `Delete` (default) clears what this object wrote when it is
    /// deleted; `Orphan` leaves it on the instance.
    #[serde(default)]
    pub deletion_policy: DeletionPolicy,
}

/// BatleHub's `PolicyDto`, its sections open: only the top-level keys are
/// declared — a misspelled one, which BatleHub would ignore without a
/// word, is an unknown field to the API server (refused by `kubectl`'s
/// strict field validation, pruned otherwise) — the values are BatleHub's
/// to check.
fn policy_schema(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    let open =
        || serde_json::json!({"type": "object", "x-kubernetes-preserve-unknown-fields": true});
    let visibility =
        || serde_json::json!({"type": "string", "enum": ["public", "internal", "team", "private"]});
    schemars::json_schema!({
        "type": "object",
        "properties": {
            "visibility": visibility(),
            "prerelease_visibility": visibility(),
            "versioning": open(),
            "quota": open(),
            "rules": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["gate"],
                    "properties": {
                        "gate": {"type": "string", "minLength": 1},
                        "settings": open(),
                    },
                },
            },
        },
    })
}

/// A gate the version is exempted from, until a date.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct GateExemption {
    pub gate: Gate,
    /// RFC 3339, in the future when written: an expired exemption is
    /// reported (`ExemptionExpired`), never written.
    #[schemars(length(min = 1), extend("format" = "date-time"))]
    pub exempt_until: String,
    /// Why: kept in BatleHub's audit trail.
    #[schemars(length(min = 1, max = 1024))]
    pub reason: String,
}

/// The gates a version may be exempted from.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum Gate {
    CveGate,
    LicenseGate,
    SecurityVerdict,
    Flags,
}

impl Gate {
    pub fn as_str(self) -> &'static str {
        match self {
            Gate::CveGate => "cve_gate",
            Gate::LicenseGate => "license_gate",
            Gate::SecurityVerdict => "security_verdict",
            Gate::Flags => "flags",
        }
    }
}

/// One exemption the operator wrote.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct AppliedExemption {
    pub gate: String,
    /// As BatleHub stored it (UTC).
    pub exempt_until: String,
    pub reason: String,
}

/// What the operator wrote.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BatleHubPackagePolicyStatus {
    /// The `metadata.generation` the last successful reconcile applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// The instance this object was resolved to and stays bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<BoundInstance>,
    /// `Ready`, carrying one of the operator's reason codes.
    #[serde(default)]
    pub conditions: Vec<Condition>,
    /// The hash of `spec.policy` when the operator wrote it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applied_policy_hash: Option<String>,
    /// The hash of the policy the instance returned right after
    /// (exemptions left out): a later read hashing otherwise was changed
    /// elsewhere, and is written again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_policy_hash: Option<String>,
    /// The exemptions the operator wrote, recorded after each write.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub applied_exemptions: Vec<AppliedExemption>,
    /// The last pass that changed something on the instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_sync_time: Option<String>,
}

/// The part of the status a pass records right after each write.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyRecord {
    pub applied_policy_hash: Option<String>,
    pub observed_policy_hash: Option<String>,
    pub applied_exemptions: Vec<AppliedExemption>,
}

impl From<&BatleHubPackagePolicyStatus> for PolicyRecord {
    fn from(status: &BatleHubPackagePolicyStatus) -> Self {
        Self {
            applied_policy_hash: status.applied_policy_hash.clone(),
            observed_policy_hash: status.observed_policy_hash.clone(),
            applied_exemptions: status.applied_exemptions.clone(),
        }
    }
}
