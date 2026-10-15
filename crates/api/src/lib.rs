//! The CRDs of the operator. Pure types: `serde`/`schemars` derives and
//! the kit's shared field types, no client code. Doc comments become the
//! CRD schema descriptions (`crdgen` → `deploy/crd/`).
//!
//! The kinds' Rust types carry their kind's name
//! (`BatleHubLocalInstance`, the CRD's title); the workspace uses them
//! through short re-exports ([`LocalInstance`]). The instance is
//! namespaced only: there is no cluster-scoped kind in `v1alpha1`.

pub mod common;
pub mod config;
pub mod local_instance;
pub mod namespace_claim;
pub mod package_grant;
pub mod package_policy;
pub mod registry;
pub mod status;

/// API group shared by every CRD of this operator.
pub const GROUP: &str = "batlehub.weebo.io";

/// The kit's common annotations under [`GROUP`]:
/// `batlehub.weebo.io/force-orphan` (release a CR without cleanup),
/// `allow-disruptive-update`, `rotate-secret`, `import-pending`, and the
/// opt-in label of a token Secret, `batlehub.weebo.io/instance-token`.
pub const ANNOTATIONS: weebo_kit_api::Annotations = weebo_kit_api::Annotations::new(GROUP);

/// The opt-in label of a `Secret` whose content the operator sends to
/// BatleHub (`configLayers`, a registry's `configFrom`): `"true"`.
pub const CREDENTIAL_LABEL: &str = "batlehub.weebo.io/credential";

/// On a `BatleHubLocalInstance` with `reload.strategy: Manual`: the exact
/// `status.pendingConfigHash` to apply.
pub const APPROVED_CONFIG_HASH: &str = "batlehub.weebo.io/approved-config-hash";

pub use local_instance::{LocalInstance, LocalInstanceStatus};
pub use namespace_claim::{NamespaceClaim, NamespaceClaimStatus};
pub use package_grant::{PackageGrant, PackageGrantStatus};
pub use package_policy::{PackagePolicy, PackagePolicyStatus};
pub use registry::{Registry, RegistryStatus};
pub use status::Status;
