//! `weebo_batlehub_admin_requests_total{endpoint,status}`: every call of a
//! gateway the factory hands out, counted by a decorator — `endpoint` is
//! the port method (a bounded set: no registry, package or pod in it),
//! `status` `ok` or the class of the [`GatewayError`].

use std::future::Future;
use std::sync::{Arc, OnceLock};

use application::ports::{
    AdminGateway, AdminRequest, BoundInstance, ConfigWarning, Exemption, GatewayError,
    GatewayFactory, GatewayFactoryError, GrantWrite, InstanceAccess, InstanceInfo, PackageNode,
    PendingSource, PodGateway, ReloadCheck, Reloaded, StoredGrant, TeamNamespace,
};
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;

pub const ADMIN_REQUESTS: &str = "weebo_batlehub_admin_requests_total";

fn requests() -> &'static Counter<u64> {
    static REQUESTS: OnceLock<Counter<u64>> = OnceLock::new();
    REQUESTS.get_or_init(|| {
        opentelemetry::global::meter("weebo-batlehub-operator")
            .u64_counter(ADMIN_REQUESTS)
            .with_description("Calls of BatleHub's admin API, by endpoint and outcome")
            .build()
    })
}

/// The `status` label of an outcome.
pub fn status_class<T>(result: &Result<T, GatewayError>) -> &'static str {
    match result {
        Ok(_) => "ok",
        Err(GatewayError::Unreachable(_)) => "unreachable",
        Err(GatewayError::Unauthorized(_)) => "unauthorized",
        Err(GatewayError::Remote(_)) => "remote_error",
        Err(GatewayError::HotReloadDisabled(_)) => "hot_reload_disabled",
        Err(GatewayError::Rejected(_)) => "rejected",
        Err(GatewayError::NoPending(_)) => "no_pending",
        Err(GatewayError::AlreadyClaimed(_)) => "already_claimed",
        Err(GatewayError::StorageUnavailable(_)) => "storage_unavailable",
        Err(GatewayError::HeldByOwnership(_)) => "held_by_ownership",
        Err(GatewayError::NotFound(_)) => "not_found",
        Err(GatewayError::Refused(_)) => "refused",
        Err(GatewayError::NotPermitted(_)) => "not_permitted",
        Err(GatewayError::InvalidPath(_)) => "invalid_path",
    }
}

/// A gateway whose calls are counted.
pub struct MeteredGateway {
    inner: Arc<dyn AdminGateway>,
}

impl MeteredGateway {
    pub fn wrap(inner: Arc<dyn AdminGateway>) -> Arc<dyn AdminGateway> {
        Arc::new(Self { inner })
    }
}

async fn counted<T>(
    endpoint: &'static str,
    call: impl Future<Output = Result<T, GatewayError>>,
) -> Result<T, GatewayError> {
    let result = call.await;
    requests().add(
        1,
        &[
            KeyValue::new("endpoint", endpoint),
            KeyValue::new("status", status_class(&result)),
        ],
    );
    result
}

#[async_trait::async_trait]
impl AdminGateway for MeteredGateway {
    async fn ping(&self) -> Result<InstanceInfo, GatewayError> {
        counted("ping", self.inner.ping()).await
    }
    async fn config_warnings(&self) -> Result<Vec<ConfigWarning>, GatewayError> {
        counted("config_warnings", self.inner.config_warnings()).await
    }
    async fn config_content(&self) -> Result<String, GatewayError> {
        counted("config_content", self.inner.config_content()).await
    }
    async fn validate_config(&self, content: &str) -> Result<ReloadCheck, GatewayError> {
        counted("validate_config", self.inner.validate_config(content)).await
    }
    async fn stage_config(&self, content: &str) -> Result<bool, GatewayError> {
        counted("stage_config", self.inner.stage_config(content)).await
    }
    async fn apply_pending(&self) -> Result<(), GatewayError> {
        counted("apply_pending", self.inner.apply_pending()).await
    }
    async fn pending(&self) -> Result<Option<PendingSource>, GatewayError> {
        counted("pending", self.inner.pending()).await
    }
    async fn discard_pending(&self) -> Result<(), GatewayError> {
        counted("discard_pending", self.inner.discard_pending()).await
    }
    async fn reload(&self) -> Result<Reloaded, GatewayError> {
        counted("reload", self.inner.reload()).await
    }
    async fn registry_names(&self) -> Result<Vec<String>, GatewayError> {
        counted("registry_names", self.inner.registry_names()).await
    }
    async fn team_namespaces(&self, registry: &str) -> Result<Vec<TeamNamespace>, GatewayError> {
        counted("team_namespaces", self.inner.team_namespaces(registry)).await
    }
    async fn claim_namespace(
        &self,
        registry: &str,
        namespace: &TeamNamespace,
    ) -> Result<(), GatewayError> {
        counted(
            "claim_namespace",
            self.inner.claim_namespace(registry, namespace),
        )
        .await
    }
    async fn release_namespace(&self, registry: &str, prefix: &str) -> Result<(), GatewayError> {
        counted(
            "release_namespace",
            self.inner.release_namespace(registry, prefix),
        )
        .await
    }
    async fn grants(&self, node: &PackageNode) -> Result<Vec<StoredGrant>, GatewayError> {
        counted("grants", self.inner.grants(node)).await
    }
    async fn put_grant(
        &self,
        node: &PackageNode,
        subject: &str,
        actions: &[String],
    ) -> Result<GrantWrite, GatewayError> {
        counted("put_grant", self.inner.put_grant(node, subject, actions)).await
    }
    async fn delete_grant(&self, node: &PackageNode, subject: &str) -> Result<bool, GatewayError> {
        counted("delete_grant", self.inner.delete_grant(node, subject)).await
    }
    async fn policy(&self, node: &PackageNode) -> Result<Option<serde_json::Value>, GatewayError> {
        counted("policy", self.inner.policy(node)).await
    }
    async fn put_policy(
        &self,
        node: &PackageNode,
        policy: &serde_json::Value,
    ) -> Result<(), GatewayError> {
        counted("put_policy", self.inner.put_policy(node, policy)).await
    }
    async fn delete_policy(&self, node: &PackageNode) -> Result<(), GatewayError> {
        counted("delete_policy", self.inner.delete_policy(node)).await
    }
    async fn set_exemption(
        &self,
        node: &PackageNode,
        exemption: &Exemption,
    ) -> Result<(), GatewayError> {
        counted("set_exemption", self.inner.set_exemption(node, exemption)).await
    }
    async fn delete_exemption(&self, node: &PackageNode, gate: &str) -> Result<(), GatewayError> {
        counted("delete_exemption", self.inner.delete_exemption(node, gate)).await
    }
    async fn packages(
        &self,
        registry: &str,
    ) -> Result<std::collections::BTreeMap<String, Vec<String>>, GatewayError> {
        counted("packages", self.inner.packages(registry)).await
    }
    async fn package_grants(
        &self,
        registry: &str,
        package: &str,
    ) -> Result<Vec<(Option<String>, StoredGrant)>, GatewayError> {
        counted(
            "package_grants",
            self.inner.package_grants(registry, package),
        )
        .await
    }
    async fn exemption_nodes(&self, registry: &str) -> Result<Vec<(String, String)>, GatewayError> {
        counted("exemption_nodes", self.inner.exemption_nodes(registry)).await
    }
    async fn whoami(&self) -> Result<Option<String>, GatewayError> {
        counted("whoami", self.inner.whoami()).await
    }
    /// A maintenance action's call: one label for all (their paths name
    /// registries, users, IPs).
    async fn call(&self, request: &AdminRequest) -> Result<serde_json::Value, GatewayError> {
        counted("maintenance", self.inner.call(request)).await
    }
}

/// A factory whose gateways are [`MeteredGateway`]s.
pub struct MeteredFactory<F> {
    inner: F,
}

impl<F: GatewayFactory> MeteredFactory<F> {
    pub fn new(inner: F) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl<F: GatewayFactory> GatewayFactory for MeteredFactory<F> {
    async fn gateway_for(
        &self,
        instance: &BoundInstance,
    ) -> Result<InstanceAccess, GatewayFactoryError> {
        let access = self.inner.gateway_for(instance).await?;
        Ok(InstanceAccess {
            gateway: MeteredGateway::wrap(access.gateway),
            token: access.token,
        })
    }

    async fn pod_gateways(
        &self,
        instance: &BoundInstance,
    ) -> Result<Option<Vec<PodGateway>>, GatewayFactoryError> {
        Ok(self.inner.pod_gateways(instance).await?.map(|pods| {
            pods.into_iter()
                .map(|pod| PodGateway {
                    name: pod.name,
                    gateway: MeteredGateway::wrap(pod.gateway),
                })
                .collect()
        }))
    }

    async fn waiting_pods(&self, instance: &BoundInstance) -> Result<usize, GatewayFactoryError> {
        self.inner.waiting_pods(instance).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_error_has_its_status_class() {
        assert_eq!(status_class(&Ok::<(), GatewayError>(())), "ok");
        assert_eq!(
            status_class::<()>(&Err(GatewayError::Unreachable("x".into()))),
            "unreachable"
        );
        assert_eq!(
            status_class::<()>(&Err(GatewayError::NoPending("x".into()))),
            "no_pending"
        );
    }

    #[tokio::test]
    async fn a_metered_gateway_answers_as_the_inner_one() {
        use application::test_support::FakeGateway;
        let inner = Arc::new(FakeGateway::default());
        let metered = MeteredGateway::wrap(inner.clone());
        assert_eq!(metered.ping().await, inner.ping().await);
        inner.fail_with(Some(GatewayError::Unreachable("dns".into())));
        assert_eq!(
            metered.ping().await,
            Err(GatewayError::Unreachable("dns".into()))
        );
    }
}
