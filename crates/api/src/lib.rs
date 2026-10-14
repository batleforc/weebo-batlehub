//! The CRDs of the operator. Pure types: `serde`/`schemars` derives and
//! the kit's shared field types, no client code. Doc comments become the
//! CRD schema descriptions (`crdgen` → `deploy/crd/`).
//!
//! The kinds' Rust types carry their kind's name
//! (`BatleHubLocalInstance`, the CRD's title); the workspace uses them
//! through short re-exports ([`LocalInstance`]). The instance is
//! namespaced only: there is no cluster-scoped kind in `v1alpha1`.

pub mod local_instance;
pub mod status;

/// API group shared by every CRD of this operator.
pub const GROUP: &str = "batlehub.weebo.io";

/// The kit's common annotations under [`GROUP`]:
/// `batlehub.weebo.io/force-orphan` (release a CR without cleanup),
/// `allow-disruptive-update`, `rotate-secret`, `import-pending`, and the
/// opt-in label of a token Secret, `batlehub.weebo.io/instance-token`.
pub const ANNOTATIONS: weebo_kit_api::Annotations = weebo_kit_api::Annotations::new(GROUP);

pub use local_instance::{LocalInstance, LocalInstanceStatus};
pub use status::Status;
