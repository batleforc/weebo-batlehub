//! The operator's [`InstanceDirectory`] over its only instance kind, the
//! namespaced `BatleHubLocalInstance` (the kit's `LocalInstance` role):
//! the kit's `LocalInstances`, which shares an instance with the
//! registries of other namespaces through its `registrySelector`
//! ([`registry_sharing`]) and with nothing else.

use api::LocalInstance;
use application::ports::{BoundInstance, InstanceDirectory, InstanceError, RegistryResolver};
use kube::Client;
use kube::core::Selector;
use kube::runtime::reflector::Store;
use weebo_kit_adapters::LocalInstances;
use weebo_kit_api::{InstanceRef, SharedWith};

/// How long a reconcile waits for the reflector to finish its first list
/// before reading from the API instead (the kit's value).
pub const STORE_READY_TIMEOUT: std::time::Duration =
    weebo_kit_adapters::instance::STORE_READY_TIMEOUT;

pub struct LocalInstanceDirectory {
    instances: LocalInstances<LocalInstance>,
}

impl LocalInstanceDirectory {
    /// Read from the API on every call (tests): wire the binary's
    /// reflector in with [`Self::with_store`].
    pub fn new(client: Client) -> Self {
        Self {
            instances: LocalInstances::new(client),
        }
    }

    pub fn with_store(mut self, store: Store<LocalInstance>) -> Self {
        self.instances = self.instances.with_store(store);
        self
    }

    /// The operator's watch scope: the namespace it is limited to and its
    /// label selector.
    pub fn with_scope(
        mut self,
        watched_namespace: Option<String>,
        selector: Option<Selector>,
    ) -> Self {
        self.instances = self.instances.with_scope(watched_namespace, selector);
        self
    }

    /// The instances of `namespace` in scope.
    pub async fn instances(&self, namespace: &str) -> Result<Vec<LocalInstance>, String> {
        self.instances.instances(namespace).await
    }

    /// The instance `bound` designates, `None` when it is gone (or out of
    /// scope, or not a local instance).
    pub async fn get(&self, bound: &BoundInstance) -> Result<Option<LocalInstance>, String> {
        self.instances.get(bound).await
    }
}

/// What an instance shares with the registries of other namespaces: its
/// `registrySelector.namespaces` (`Same`: none, `All`: an empty selector,
/// `Selector`: that one).
pub fn registry_sharing(instance: &LocalInstance) -> Option<SharedWith> {
    instance.spec.registry_selector.namespaces.shared_with()
}

#[async_trait::async_trait]
impl RegistryResolver for LocalInstanceDirectory {
    async fn resolve_registry(
        &self,
        namespace: &str,
        instance_ref: Option<&InstanceRef>,
        recorded: Option<&BoundInstance>,
    ) -> Result<BoundInstance, InstanceError> {
        self.instances
            .resolve_with(Some(namespace), instance_ref, recorded, registry_sharing)
            .await
    }

    async fn instance(&self, bound: &BoundInstance) -> Result<Option<LocalInstance>, String> {
        self.get(bound).await
    }
}

#[async_trait::async_trait]
impl InstanceDirectory for LocalInstanceDirectory {
    async fn resolve(
        &self,
        cr_namespace: Option<&str>,
        instance_ref: Option<&InstanceRef>,
        recorded: Option<&BoundInstance>,
    ) -> Result<BoundInstance, InstanceError> {
        // A BatleHubLocalInstance shares itself with no other namespace in
        // v1alpha1 (but with registries, `resolve_registry`): only the CR's
        // own namespace has candidates, and an instanceRef naming another
        // namespace resolves to nothing it may use.
        self.instances
            .resolve(cr_namespace, instance_ref, recorded)
            .await
    }
}

#[cfg(test)]
mod tests {
    use api::local_instance::{
        ExternalInstance, LocalInstanceSpec, LocalSecretKeyRef, NamespacesFrom, RegistryNamespaces,
        RegistrySelector,
    };

    use super::*;

    fn instance(
        from: NamespacesFrom,
        selector: Option<api::config::LabelSelector>,
    ) -> LocalInstance {
        LocalInstance::new(
            "hub",
            LocalInstanceSpec {
                external: Some(ExternalInstance {
                    url: "http://hub".into(),
                    admin_token_secret_ref: LocalSecretKeyRef {
                        name: "t".into(),
                        key: "token".into(),
                    },
                    tls: Default::default(),
                    manage_config: true,
                    pod_selector: None,
                }),
                managed: None,
                config: Default::default(),
                config_layers: vec![],
                reload: Default::default(),
                registry_selector: RegistrySelector {
                    selector: None,
                    namespaces: RegistryNamespaces { from, selector },
                },
            },
        )
    }

    #[test]
    fn registries_of_other_namespaces_need_the_instance_s_consent() {
        assert_eq!(
            registry_sharing(&instance(NamespacesFrom::Same, None)),
            None
        );
        let all = registry_sharing(&instance(NamespacesFrom::All, None)).unwrap();
        assert_eq!(all.namespace_selector, Some(Default::default()));
        let sel = api::config::LabelSelector {
            match_labels: Some([("team".to_string(), "a".to_string())].into()),
            ..Default::default()
        };
        let chosen =
            registry_sharing(&instance(NamespacesFrom::Selector, Some(sel.clone()))).unwrap();
        assert_eq!(chosen.namespace_selector, Some(sel));
        // CEL requires the selector; without it, nothing is shared.
        assert_eq!(
            registry_sharing(&instance(NamespacesFrom::Selector, None)),
            None
        );
    }
}
