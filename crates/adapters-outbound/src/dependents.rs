//! [`InstanceDependents`] over the kinds bound to a `BatleHubLocalInstance`:
//! `BatleHubRegistry` (of any namespace: one may attach from another);
//! the grants, policies and maintenances join it with the spec's M3.

use api::Registry;
use application::ports::{BoundInstance, InstanceDependents};
use kube::api::{Api, ListParams};
use kube::core::Selector;
use kube::{Client, ResourceExt};

pub struct ClusterDependents {
    client: Client,
    watched_namespace: Option<String>,
    selector: Option<Selector>,
}

impl ClusterDependents {
    pub fn new(client: Client, watched_namespace: Option<String>) -> Self {
        Self {
            client,
            watched_namespace,
            selector: None,
        }
    }

    /// The operator's label selector: a registry outside it is another
    /// operator's, and never holds this one's instance.
    pub fn with_selector(mut self, selector: Option<Selector>) -> Self {
        self.selector = selector;
        self
    }
}

/// Whether `registry` is bound to `instance`: recorded in its status, or —
/// not resolved yet — named by its `instanceRef`, or naming nothing in the
/// instance's namespace when it is the only one there (`default`).
pub fn binds(registry: &Registry, instance: &BoundInstance, default: bool) -> bool {
    if let Some(recorded) = registry.status.as_ref().and_then(|s| s.instance.as_ref()) {
        return recorded == instance;
    }
    let namespace = registry.namespace().unwrap_or_default();
    match &registry.spec.instance_ref {
        Some(r) => {
            r.name == instance.name
                && Some(r.namespace.as_deref().unwrap_or(&namespace))
                    == instance.namespace.as_deref()
        }
        None => default && Some(namespace.as_str()) == instance.namespace.as_deref(),
    }
}

#[async_trait::async_trait]
impl InstanceDependents for ClusterDependents {
    async fn dependents(
        &self,
        instance: &BoundInstance,
        default: bool,
    ) -> Result<Vec<String>, String> {
        let api: Api<Registry> = match &self.watched_namespace {
            Some(namespace) => Api::namespaced(self.client.clone(), namespace),
            None => Api::all(self.client.clone()),
        };
        let params = match &self.selector {
            Some(selector) => ListParams::default().labels_from(selector),
            None => ListParams::default(),
        };
        let registries = api
            .list(&params)
            .await
            .map_err(|e| format!("listing BatleHubRegistries: {e}"))?
            .items;
        Ok(registries
            .iter()
            .filter(|r| binds(r, instance, default))
            .map(|r| {
                format!(
                    "BatleHubRegistry/{}/{}",
                    r.namespace().unwrap_or_default(),
                    r.name_any()
                )
            })
            .collect())
    }
}

#[cfg(test)]
mod tests {
    use api::registry::{RegistrySpec, RegistryStatus};
    use weebo_kit_api::InstanceRef;

    use super::*;

    fn registry(instance_ref: Option<InstanceRef>, recorded: Option<BoundInstance>) -> Registry {
        let mut registry = Registry::new(
            "npm",
            RegistrySpec {
                instance_ref,
                r#type: "npm".into(),
                name: None,
                config: Default::default(),
                config_from: vec![],
                suspend: false,
            },
        );
        registry.metadata.namespace = Some("team".into());
        registry.status = recorded.map(|instance| RegistryStatus {
            instance: Some(instance),
            ..Default::default()
        });
        registry
    }

    #[test]
    fn a_registry_is_bound_by_status_by_reference_or_by_default() {
        let hub = BoundInstance::local("team", "hub");
        let elsewhere = BoundInstance::local("infra", "hub");
        assert!(binds(&registry(None, Some(hub.clone())), &hub, false));
        assert!(!binds(&registry(None, Some(hub.clone())), &elsewhere, true));
        assert!(binds(
            &registry(Some(InstanceRef::named("hub")), None),
            &hub,
            false
        ));
        assert!(!binds(
            &registry(Some(InstanceRef::named("hub")), None),
            &elsewhere,
            false
        ));
        let foreign = InstanceRef {
            namespace: Some("infra".into()),
            ..InstanceRef::named("hub")
        };
        assert!(binds(&registry(Some(foreign), None), &elsewhere, false));
        assert!(binds(&registry(None, None), &hub, true));
        assert!(!binds(&registry(None, None), &hub, false));
        assert!(!binds(&registry(None, None), &elsewhere, true));
    }
}
