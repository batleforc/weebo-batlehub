//! [`InstanceDependents`] over the kinds bound to a `BatleHubLocalInstance`:
//! `BatleHubRegistry` (of any namespace: one may attach from another), and
//! the kinds bound to an instance of their own namespace
//! ([`LocalBound`]: claims, grants, policies, maintenances).

use std::fmt::Debug;

use api::{NamespaceClaim, PackageGrant, PackagePolicy, Registry};
use application::ports::{BoundInstance, InstanceDependents};
use kube::Resource;
use kube::api::{Api, ListParams};
use kube::core::Selector;
use kube::{Client, ResourceExt};
use serde::de::DeserializeOwned;
use weebo_kit_api::InstanceRef;

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

/// A kind bound to an instance of its own namespace.
pub trait LocalBound:
    Resource<DynamicType = (), Scope = k8s_openapi::NamespaceResourceScope>
    + Clone
    + Debug
    + DeserializeOwned
    + Send
    + Sync
    + 'static
{
    const KIND: &'static str;
    fn instance_ref(&self) -> Option<&InstanceRef>;
    fn recorded(&self) -> Option<&BoundInstance>;
}

impl LocalBound for NamespaceClaim {
    const KIND: &'static str = "BatleHubNamespaceClaim";
    fn instance_ref(&self) -> Option<&InstanceRef> {
        self.spec.instance_ref.as_ref()
    }
    fn recorded(&self) -> Option<&BoundInstance> {
        self.status.as_ref().and_then(|s| s.instance.as_ref())
    }
}

impl LocalBound for PackageGrant {
    const KIND: &'static str = "BatleHubPackageGrant";
    fn instance_ref(&self) -> Option<&InstanceRef> {
        self.spec.instance_ref.as_ref()
    }
    fn recorded(&self) -> Option<&BoundInstance> {
        self.status.as_ref().and_then(|s| s.instance.as_ref())
    }
}

impl LocalBound for PackagePolicy {
    const KIND: &'static str = "BatleHubPackagePolicy";
    fn instance_ref(&self) -> Option<&InstanceRef> {
        self.spec.instance_ref.as_ref()
    }
    fn recorded(&self) -> Option<&BoundInstance> {
        self.status.as_ref().and_then(|s| s.instance.as_ref())
    }
}

/// Whether `object` is bound to `instance`, as [`binds`] for a registry:
/// its instance is always of its own namespace.
pub fn local_binds<K: LocalBound>(object: &K, instance: &BoundInstance, default: bool) -> bool {
    if let Some(recorded) = object.recorded() {
        return recorded == instance;
    }
    let namespace = object.namespace().unwrap_or_default();
    if Some(namespace.as_str()) != instance.namespace.as_deref() {
        return false;
    }
    match object.instance_ref() {
        Some(r) => r.name == instance.name,
        None => default,
    }
}

impl ClusterDependents {
    fn params(&self) -> ListParams {
        match &self.selector {
            Some(selector) => ListParams::default().labels_from(selector),
            None => ListParams::default(),
        }
    }

    /// The `K`s of the instance's namespace bound to it.
    async fn local<K: LocalBound>(
        &self,
        instance: &BoundInstance,
        default: bool,
    ) -> Result<Vec<String>, String> {
        let Some(namespace) = instance.namespace.as_deref() else {
            return Ok(Vec::new());
        };
        let api: Api<K> = Api::namespaced(self.client.clone(), namespace);
        let objects = api
            .list(&self.params())
            .await
            .map_err(|e| format!("listing {}s: {e}", K::KIND))?
            .items;
        Ok(objects
            .iter()
            .filter(|o| local_binds(*o, instance, default))
            .map(|o| format!("{}/{namespace}/{}", K::KIND, o.name_any()))
            .collect())
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
        let registries = api
            .list(&self.params())
            .await
            .map_err(|e| format!("listing BatleHubRegistries: {e}"))?
            .items;
        let mut dependents: Vec<String> = registries
            .iter()
            .filter(|r| binds(r, instance, default))
            .map(|r| {
                format!(
                    "BatleHubRegistry/{}/{}",
                    r.namespace().unwrap_or_default(),
                    r.name_any()
                )
            })
            .collect();
        dependents.extend(self.local::<NamespaceClaim>(instance, default).await?);
        dependents.extend(self.local::<PackageGrant>(instance, default).await?);
        dependents.extend(self.local::<PackagePolicy>(instance, default).await?);
        Ok(dependents)
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

    fn claim(instance_ref: Option<InstanceRef>, recorded: Option<BoundInstance>) -> NamespaceClaim {
        let mut claim = NamespaceClaim::new(
            "web",
            api::namespace_claim::NamespaceClaimSpec {
                instance_ref,
                registry: "npm".into(),
                prefix: "@acme/web".into(),
                group: "oidc:web".into(),
                deletion_policy: Default::default(),
            },
        );
        claim.metadata.namespace = Some("team".into());
        claim.status = recorded.map(|instance| api::NamespaceClaimStatus {
            instance: Some(instance),
            ..Default::default()
        });
        claim
    }

    #[test]
    fn a_claim_is_bound_in_its_namespace_only() {
        let hub = BoundInstance::local("team", "hub");
        let elsewhere = BoundInstance::local("infra", "hub");
        assert!(local_binds(&claim(None, Some(hub.clone())), &hub, false));
        assert!(!local_binds(
            &claim(None, Some(hub.clone())),
            &elsewhere,
            true
        ));
        assert!(local_binds(
            &claim(Some(InstanceRef::named("hub")), None),
            &hub,
            false
        ));
        assert!(!local_binds(
            &claim(Some(InstanceRef::named("hub")), None),
            &elsewhere,
            false
        ));
        assert!(local_binds(&claim(None, None), &hub, true));
        assert!(!local_binds(&claim(None, None), &hub, false));
        assert!(!local_binds(&claim(None, None), &elsewhere, true));
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
