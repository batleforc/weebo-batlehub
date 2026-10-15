//! What the instance and its registries share to describe BatleHub's
//! configuration: TOML fragments read from a `ConfigMap` or a `Secret`.

pub use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// A TOML document in a `ConfigMap` or a `Secret` of this object's
/// namespace. A `Secret` must be labelled
/// `batlehub.weebo.io/credential: "true"`: its content is sent to
/// BatleHub, so it has to opt in.
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[schemars(extend("x-kubernetes-validations" = [
    {"rule": "has(self.configMapRef) != has(self.secretRef)", "message": "set exactly one of configMapRef and secretRef"}
]))]
pub struct ConfigSource {
    /// A key of a `ConfigMap`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config_map_ref: Option<ConfigKeyRef>,
    /// A key of a `Secret` labelled `batlehub.weebo.io/credential: "true"`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret_ref: Option<ConfigKeyRef>,
}

/// A key of a `ConfigMap` or a `Secret` of this object's namespace.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ConfigKeyRef {
    #[schemars(length(min = 1))]
    pub name: String,
    /// Defaults to `config.toml`.
    #[serde(default = "default_key")]
    pub key: String,
}

fn default_key() -> String {
    "config.toml".into()
}

impl ConfigSource {
    pub fn config_map(name: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            config_map_ref: Some(ConfigKeyRef {
                name: name.into(),
                key: key.into(),
            }),
            secret_ref: None,
        }
    }

    pub fn secret(name: impl Into<String>, key: impl Into<String>) -> Self {
        Self {
            config_map_ref: None,
            secret_ref: Some(ConfigKeyRef {
                name: name.into(),
                key: key.into(),
            }),
        }
    }
}

/// The schema of a field holding BatleHub's TOML written as YAML, key for
/// key: an open object (`x-kubernetes-preserve-unknown-fields`), never
/// typed here — BatleHub's own parser validates it.
pub fn open_object(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "x-kubernetes-preserve-unknown-fields": true,
    })
}
