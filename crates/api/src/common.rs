//! What the kinds bound to an instance of their own namespace share: the
//! `instanceRef` schema, the deletion policy, and the coordinate of a
//! package or version in a registry (`BatleHubPackageGrant`,
//! `BatleHubPackagePolicy`).

use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

/// What happens on the instance to what this object wrote, when it is
/// deleted.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, Default, JsonSchema, PartialEq, Eq)]
pub enum DeletionPolicy {
    /// Remove it: release, revoke, clear.
    #[default]
    Delete,
    /// Leave it in place, only drop this object.
    Orphan,
}

/// The kit's `InstanceRef`, described for a kind bound to an instance of
/// its own namespace: a `BatleHubLocalInstance`, immutable (the status
/// records what was written there).
pub fn local_instance_ref(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "required": ["name"],
        "x-kubernetes-validations": [
            {"rule": "self == oldSelf", "message": "instanceRef is immutable"},
            {"rule": "!has(self.__namespace__)", "message": "the instance must be in this object's namespace"},
        ],
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
                "description": "Not allowed: the instance is in this object's namespace.",
                "type": "string",
            },
        },
    })
}

/// A registry name: immutable, never `.`, `..` nor containing `/`.
pub fn registry_name(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": 253,
        "x-kubernetes-validations": [
            {"rule": "self == oldSelf", "message": "registry is immutable"},
            {"rule": "self != '.' && self != '..' && !self.contains('/')", "message": "registry must be a registry name"},
        ],
    })
}

/// A package name: immutable, never blank, and no `/`-separated part of it
/// `.` nor `..` (its parts become segments of the admin API's paths).
pub fn package_name(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": 1024,
        "x-kubernetes-validations": [
            {"rule": "self == oldSelf", "message": "package is immutable"},
            {"rule": "self == self.trim() && self.split('/').all(s, s != '.' && s != '..')", "message": "package may not be blank, have a `.` or `..` part between slashes, nor start or end with a space"},
        ],
    })
}

/// A version: immutable, never `.`, nor containing `..` or a path separator.
pub fn version_name(_: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "string",
        "minLength": 1,
        "maxLength": 256,
        "x-kubernetes-validations": [
            {"rule": "self == oldSelf", "message": "version is immutable"},
            {"rule": "self == self.trim() && self != '.' && !self.contains('..') && !self.contains('/') && !self.contains('\\\\')", "message": "version may not be `.`, contain `..`, `/` or `\\`, nor start or end with a space"},
        ],
    })
}
