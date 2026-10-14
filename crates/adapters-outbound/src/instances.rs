//! The operator's [`InstanceDirectory`] over its only instance kind, the
//! namespaced `BatleHubLocalInstance` (the kit's `LocalInstance` role).
//! The kit's `Instances<I, L>` needs a cluster-scoped kind as well, which
//! BatleHub doesn't have: this is its local half, on the kit's pure
//! resolution (`resolve_bound`, `check_binding`), with no cluster
//! candidate.
//!
//! Read from a live reflector `Store` when the binary wires one in, from
//! the API otherwise (tests). The operator's watch scope applies: its
//! label selector and the namespace it is limited to.

use api::LocalInstance;
use application::ports::{BoundInstance, InstanceDirectory, InstanceError};
use kube::api::{Api, ListParams};
use kube::core::{Selector, SelectorExt};
use kube::runtime::reflector::Store;
use kube::{Client, ResourceExt};
use weebo_kit_api::{InstanceKind, InstanceRef};
use weebo_kit_application::instances::{Candidate, Candidates, Request, resolve_bound};

/// How long a reconcile waits for the reflector to finish its first list
/// before reading from the API instead (the kit's value).
pub const STORE_READY_TIMEOUT: std::time::Duration =
    weebo_kit_adapters::instance::STORE_READY_TIMEOUT;

pub struct LocalInstanceDirectory {
    client: Client,
    store: Option<Store<LocalInstance>>,
    watched_namespace: Option<String>,
    selector: Option<Selector>,
}

impl LocalInstanceDirectory {
    /// Read from the API on every call (tests): wire the binary's
    /// reflector in with [`Self::with_store`].
    pub fn new(client: Client) -> Self {
        Self {
            client,
            store: None,
            watched_namespace: None,
            selector: None,
        }
    }

    pub fn with_store(mut self, store: Store<LocalInstance>) -> Self {
        self.store = Some(store);
        self
    }

    /// The operator's watch scope: the namespace it is limited to and its
    /// label selector.
    pub fn with_scope(
        mut self,
        watched_namespace: Option<String>,
        selector: Option<Selector>,
    ) -> Self {
        self.watched_namespace = watched_namespace;
        self.selector = selector;
        self
    }

    fn selects(&self, instance: &LocalInstance) -> bool {
        let Some(selector) = &self.selector else {
            return true;
        };
        let empty = Default::default();
        selector.matches(instance.metadata.labels.as_ref().unwrap_or(&empty))
    }

    /// The live store once it has listed; `None` (read from the API) when
    /// its writer is gone or it still hasn't listed after
    /// [`STORE_READY_TIMEOUT`] — a watch that can't list must not hang
    /// every reconcile.
    async fn ready_store(&self) -> Option<&Store<LocalInstance>> {
        let store = self.store.as_ref()?;
        match tokio::time::timeout(STORE_READY_TIMEOUT, store.wait_until_ready()).await {
            Ok(Ok(())) => Some(store),
            Ok(Err(_)) => None,
            Err(_) => {
                tracing::warn!(
                    "the BatleHubLocalInstance watch has not listed yet: reading from the API"
                );
                None
            }
        }
    }

    /// The instances of `namespace` in scope.
    pub async fn instances(&self, namespace: &str) -> Result<Vec<LocalInstance>, String> {
        if self
            .watched_namespace
            .as_deref()
            .is_some_and(|w| w != namespace)
        {
            return Ok(Vec::new());
        }
        if let Some(store) = self.ready_store().await {
            return Ok(store
                .state()
                .iter()
                .filter(|i| i.namespace().as_deref() == Some(namespace) && self.selects(i))
                .map(|i| (**i).clone())
                .collect());
        }
        let params = match &self.selector {
            Some(selector) => ListParams::default().labels_from(selector),
            None => ListParams::default(),
        };
        Api::<LocalInstance>::namespaced(self.client.clone(), namespace)
            .list(&params)
            .await
            .map(|l| l.items)
            .map_err(|e| format!("listing BatleHubLocalInstances in {namespace:?}: {e}"))
    }

    /// The instance `bound` designates, `None` when it is gone (or out of
    /// scope, or not a local instance).
    pub async fn get(&self, bound: &BoundInstance) -> Result<Option<LocalInstance>, String> {
        let (InstanceKind::LocalInstance, Some(namespace)) =
            (bound.kind, bound.namespace.as_deref())
        else {
            return Ok(None);
        };
        Ok(self
            .instances(namespace)
            .await?
            .into_iter()
            .find(|i| i.name_any() == bound.name))
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
        let request = Request {
            cr_namespace,
            instance_ref,
        };
        // A BatleHubLocalInstance shares itself with no other namespace in
        // v1alpha1: only the CR's own namespace has candidates, and an
        // instanceRef naming another namespace resolves to nothing it may
        // use.
        let mut candidates = Candidates {
            watched_namespace: self.watched_namespace.as_deref(),
            ..Default::default()
        };
        let namespaces = [cr_namespace, request.foreign_namespace()];
        for namespace in namespaces.into_iter().flatten() {
            candidates.local.extend(
                self.instances(namespace)
                    .await
                    .map_err(InstanceError::Kubernetes)?
                    .iter()
                    .map(|i| Candidate::local(namespace, i.name_any(), None)),
            );
        }
        Ok(resolve_bound(request, &candidates, recorded)?)
    }
}
