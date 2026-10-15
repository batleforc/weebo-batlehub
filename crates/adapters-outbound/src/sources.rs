//! [`ConfigSources`] on the cluster: `ConfigMap`/`Secret` keys read by
//! name on every reconcile (no watch on Secrets: it would grant reading
//! all of them, the spec's D9), a `Secret` only when labelled
//! `batlehub.weebo.io/credential: "true"` — its content leaves for
//! BatleHub —, and the `BatleHubRegistry`s in the operator's scope, each
//! resolved to its instance.

use std::sync::Arc;

use api::Registry;
use api::config::{ConfigKeyRef, ConfigSource};
use application::ports::{ConfigSources, RegistryResolver, RegistryView, SourceError};
use k8s_openapi::api::core::v1::{ConfigMap, Secret};
use kube::api::{Api, ListParams};
use kube::core::Selector;
use kube::{Client, ResourceExt};

use crate::instances::LocalInstanceDirectory;

pub struct KubeConfigSources {
    client: Client,
    instances: Arc<LocalInstanceDirectory>,
    watched_namespace: Option<String>,
    selector: Option<Selector>,
}

impl KubeConfigSources {
    pub fn new(client: Client, instances: Arc<LocalInstanceDirectory>) -> Self {
        Self {
            client,
            instances,
            watched_namespace: None,
            selector: None,
        }
    }

    /// The operator's watch scope: the namespace it is limited to and its
    /// label selector (registries outside it are not seen).
    pub fn with_scope(
        mut self,
        watched_namespace: Option<String>,
        selector: Option<Selector>,
    ) -> Self {
        self.watched_namespace = watched_namespace;
        self.selector = selector;
        self
    }

    async fn config_map(&self, namespace: &str, r: &ConfigKeyRef) -> Result<String, SourceError> {
        let what = format!("configmap {namespace}/{} key {:?}", r.name, r.key);
        let map = Api::<ConfigMap>::namespaced(self.client.clone(), namespace)
            .get_opt(&r.name)
            .await
            .map_err(|e| SourceError::Kubernetes(format!("reading {what}: {e}")))?
            .ok_or_else(|| SourceError::Missing(format!("{what}: not found")))?;
        if let Some(text) = map.data.as_ref().and_then(|d| d.get(&r.key)) {
            return Ok(text.clone());
        }
        let bytes = map
            .binary_data
            .and_then(|d| d.get(&r.key).cloned())
            .ok_or_else(|| SourceError::Missing(format!("{what}: no such key")))?;
        String::from_utf8(bytes.0).map_err(|_| SourceError::Missing(format!("{what}: not UTF-8")))
    }

    async fn secret(&self, namespace: &str, r: &ConfigKeyRef) -> Result<String, SourceError> {
        let what = format!("secret {namespace}/{} key {:?}", r.name, r.key);
        let secret = Api::<Secret>::namespaced(self.client.clone(), namespace)
            .get_opt(&r.name)
            .await
            .map_err(|e| SourceError::Kubernetes(format!("reading {what}: {e}")))?
            .ok_or_else(|| SourceError::Missing(format!("{what}: not found")))?;
        let consents = secret
            .labels()
            .get(api::CREDENTIAL_LABEL)
            .is_some_and(|v| v == "true");
        if !consents {
            return Err(SourceError::NotAllowed(format!(
                "secret {namespace}/{} lacks the label {}=\"true\": its content would be sent \
                 to BatleHub, so it must opt in (kubectl label secret -n {namespace} {} {}=true)",
                r.name,
                api::CREDENTIAL_LABEL,
                r.name,
                api::CREDENTIAL_LABEL
            )));
        }
        let bytes = secret
            .data
            .and_then(|d| d.get(&r.key).cloned())
            .ok_or_else(|| SourceError::Missing(format!("{what}: no such key")))?;
        String::from_utf8(bytes.0).map_err(|_| SourceError::Missing(format!("{what}: not UTF-8")))
    }
}

#[async_trait::async_trait]
impl ConfigSources for KubeConfigSources {
    async fn read(&self, namespace: &str, source: &ConfigSource) -> Result<String, SourceError> {
        match (&source.config_map_ref, &source.secret_ref) {
            (Some(r), None) => self.config_map(namespace, r).await,
            (None, Some(r)) => self.secret(namespace, r).await,
            _ => Err(SourceError::Missing(
                "set exactly one of configMapRef and secretRef".into(),
            )),
        }
    }

    async fn registries(&self) -> Result<Vec<RegistryView>, String> {
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
        let mut views = Vec::with_capacity(registries.len());
        for registry in registries {
            let namespace = registry.namespace().unwrap_or_default();
            let recorded = registry.status.as_ref().and_then(|s| s.instance.as_ref());
            let bound = self
                .instances
                .resolve_registry(&namespace, registry.spec.instance_ref.as_ref(), recorded)
                .await;
            views.push(RegistryView {
                created: registry
                    .metadata
                    .creation_timestamp
                    .as_ref()
                    .map(|t| t.0.to_string())
                    .unwrap_or_default(),
                labels: registry.labels().clone(),
                name: registry.name_any(),
                namespace,
                spec: registry.spec,
                bound,
            });
        }
        Ok(views)
    }
}
