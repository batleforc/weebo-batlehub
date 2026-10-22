use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use weebo_kit_api::InstanceRef;

use crate::config::{ConfigSource, open_object};
use crate::status::{BoundInstance, Condition};

/// The short names the rest of the workspace uses.
pub use self::BatleHubRegistry as Registry;
pub use self::BatleHubRegistrySpec as RegistrySpec;
pub use self::BatleHubRegistryStatus as RegistryStatus;

/// One `[[registries]]` entry of an instance's configuration, as its own
/// object, so each team manages its registries. The instance renders
/// every registry it accepts after its `configLayers`, sorted by
/// namespace then name, and pushes the result (`external.manageConfig`);
/// `Ready` tells whether that configuration was applied.
///
/// A registry of another namespace than the instance's attaches only when
/// the instance accepts that namespace (`registrySelector.namespaces`),
/// may not contain a `${VAR}` placeholder (they resolve from the
/// instance's environment), and may not complete an entry of the
/// instance's own configuration.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "batlehub.weebo.io",
    version = "v1alpha1",
    kind = "BatleHubRegistry",
    plural = "batlehubregistries",
    namespaced,
    shortname = "bhr",
    status = "BatleHubRegistryStatus",
    printcolumn = r#"{"name":"Registry","type":"string","jsonPath":".status.registryName"}"#,
    printcolumn = r#"{"name":"Type","type":"string","jsonPath":".spec.type"}"#,
    printcolumn = r#"{"name":"Instance","type":"string","jsonPath":".status.instance.name"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#,
    printcolumn = r#"{"name":"Age","type":"date","jsonPath":".metadata.creationTimestamp"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct BatleHubRegistrySpec {
    /// The `BatleHubLocalInstance` serving this registry; unset, the only
    /// one of this namespace. Another namespace's instance must accept
    /// this one (its `registrySelector.namespaces`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "registry_instance_ref")]
    pub instance_ref: Option<InstanceRef>,
    /// The registry's type: `npm`, `cargo`, `pypi`… (validated by
    /// BatleHub's parser).
    #[serde(rename = "type")]
    #[schemars(length(min = 1))]
    pub r#type: String,
    /// The name BatleHub serves it under; defaults to this object's name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1))]
    pub name: Option<String>,
    /// Every other key of the `[[registries]]` table, written in YAML key
    /// for key (`mode`, `upstreams`, `rbac`, `rules`, `cache`, `hosts`…).
    #[serde(default, skip_serializing_if = "serde_json::Value::is_null")]
    #[schemars(schema_with = "open_object")]
    // The docs' CRD IDE draws each upstream URL (the kit's shared kind).
    #[schemars(extend("x-weebo-produces" = { "kind": { "group": "schematic.weebo.io", "kind": "UpstreamRegistry" }, "each": "upstreams[]", "name": ["."] }))]
    pub config: serde_json::Value,
    /// TOML fragments of the table merged over `config` (`upstream_auth`,
    /// `tls`…), from this namespace. A fragment may not set `type` nor
    /// `name`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub config_from: Vec<ConfigSource>,
    /// Keep the object, leave the registry out of the configuration.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub suspend: bool,
}

/// The kit's `InstanceRef`, described for this operator: a
/// `BatleHubLocalInstance` only (no cluster-scoped kind in `v1alpha1`),
/// another namespace's when its `registrySelector.namespaces` accepts this
/// one (the kit's description speaks of `sharedWith`, which this operator
/// doesn't have).
fn registry_instance_ref(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "required": ["name"],
        "properties": {
            "name": {
                "description": "`metadata.name` of the `BatleHubLocalInstance`.",
                "type": "string",
                "minLength": 1,
            },
            "kind": {
                "description": "`LocalInstance`, the only kind (may be left out).",
                "type": "string",
                "enum": ["LocalInstance"],
            },
            "namespace": {
                "description": "Namespace of the instance; defaults to this registry's own. \
                    Another namespace's instance must accept this one \
                    (its `registrySelector.namespaces`).",
                "type": "string",
            },
        },
    })
}

impl BatleHubRegistrySpec {
    /// The name BatleHub serves it under.
    pub fn registry_name<'a>(&'a self, object_name: &'a str) -> &'a str {
        self.name.as_deref().unwrap_or(object_name)
    }
}

/// What the operator rendered of the registry.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BatleHubRegistryStatus {
    /// The `metadata.generation` the last successful reconcile applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// The instance this registry was resolved to and stays bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<BoundInstance>,
    /// `Ready`, carrying one of the operator's reason codes.
    #[serde(default)]
    pub conditions: Vec<Condition>,
    /// The name BatleHub serves it under.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub registry_name: Option<String>,
    /// The instance's `configHash` this registry was rendered into.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_config_hash: Option<String>,
}
