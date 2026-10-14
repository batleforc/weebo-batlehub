//! [`InstanceDependents`] over the kinds bound to a `BatleHubLocalInstance`.
//!
//! No kind binds to an instance yet: `BatleHubRegistry` is the first (the
//! spec's M2), then the grants, policies and maintenances (M3). Each one
//! adds its list here; until then an instance always goes.

use application::ports::{BoundInstance, InstanceDependents};

#[derive(Debug, Default, Clone, Copy)]
pub struct ClusterDependents;

#[async_trait::async_trait]
impl InstanceDependents for ClusterDependents {
    async fn dependents(
        &self,
        _instance: &BoundInstance,
        _default: bool,
    ) -> Result<Vec<String>, String> {
        Ok(Vec::new())
    }
}
