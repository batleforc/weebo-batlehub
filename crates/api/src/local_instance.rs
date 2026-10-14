use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

pub use weebo_kit_api::LocalSecretKeyRef;

use crate::status::Status;

/// The short names the rest of the workspace uses.
pub use self::BatleHubLocalInstance as LocalInstance;
pub use self::BatleHubLocalInstanceSpec as LocalInstanceSpec;

/// One BatleHub instance, owned by a namespace: its token is that
/// namespace's, and only the objects of that namespace use it. `Ready`
/// tells whether the instance answers and accepts the token below.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "batlehub.weebo.io",
    version = "v1alpha1",
    kind = "BatleHubLocalInstance",
    plural = "batlehublocalinstances",
    namespaced,
    shortname = "bhli",
    status = "Status",
    printcolumn = r#"{"name":"URL","type":"string","jsonPath":".spec.url"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#,
    printcolumn = r#"{"name":"Reason","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].reason"}"#
)]
#[serde(rename_all = "camelCase")]
pub struct BatleHubLocalInstanceSpec {
    /// Base URL of the BatleHub instance, e.g. `https://example.com`.
    pub url: String,
    /// The API token the operator authenticates with, in a `Secret` of
    /// this namespace labelled
    /// `batlehub.weebo.io/instance-token: "true"` (without the
    /// label the operator doesn't read it). Read on every reconcile:
    /// rotating it needs no restart.
    pub token_secret_ref: LocalSecretKeyRef,
}
