//! One [`HttpAdminGateway`] per `BatleHubLocalInstance`, built on every
//! call: the instance comes from the [`LocalInstanceDirectory`] (a live
//! reflector `Store` when `operator::main` wires one in, the API
//! otherwise), its token and CA are read fresh — a rotated token or CA, or
//! an edited `url`, takes effect on the next reconcile.
//!
//! - external: `url`, the token of `adminTokenSecretRef`, the CA of
//!   `tls.caSecretRef`; with `podSelector`, one more gateway per ready
//!   proxy pod, on its IP;
//! - managed: its `Service` (`http://<name>.<namespace>.svc:<port>`), the
//!   generated token (`<name>-operator-token`) or `tokenSecretRef`, and
//!   always one gateway per ready proxy pod.

use std::sync::Arc;

use api::LocalInstance;
use api::managed::Names;
use application::ports::{
    BoundInstance, GatewayFactory, GatewayFactoryError, InstanceAccess, PodGateway,
};
use k8s_openapi::api::core::v1::Pod;
use kube::api::{Api, ListParams};
use kube::core::Selector;
use kube::{Client, ResourceExt};
use weebo_kit_adapters::{TokenSecretError, read_local_instance_token, read_secret_key};
use weebo_kit_api::SecretKeyRef;

use crate::admin_gateway::HttpAdminGateway;
use crate::instances::LocalInstanceDirectory;

pub struct HttpGatewayFactory {
    client: Client,
    instances: Arc<LocalInstanceDirectory>,
}

impl HttpGatewayFactory {
    pub fn new(client: Client, instances: Arc<LocalInstanceDirectory>) -> Self {
        Self { client, instances }
    }

    /// The token is only read from a Secret labelled for it
    /// (`batlehub.weebo.io/instance-token: "true"`): the operator reads
    /// with its own rights, and the CR names the URL the token is sent to.
    async fn token(&self, secret_ref: &SecretKeyRef) -> Result<String, GatewayFactoryError> {
        let where_ = || {
            format!(
                "secret {}/{} key {:?}",
                secret_ref.namespace, secret_ref.name, secret_ref.key
            )
        };
        let bytes = read_local_instance_token(&self.client, secret_ref, &api::ANNOTATIONS)
            .await
            .map_err(|e| match e {
                TokenSecretError::NotAllowed { .. } => {
                    GatewayFactoryError::TokenNotAllowed(e.to_string())
                }
                TokenSecretError::Kubernetes(e) => GatewayFactoryError::Kubernetes(e),
            })?
            .ok_or_else(|| GatewayFactoryError::TokenSecret(format!("{} not found", where_())))?;
        let token = String::from_utf8(bytes)
            .map_err(|_| GatewayFactoryError::TokenSecret(format!("{} is not UTF-8", where_())))?;
        // A token written with `echo` carries a trailing newline.
        Ok(token.trim().to_string())
    }

    /// A CA is no secret: read without a consent label.
    async fn ca(&self, ca_ref: &SecretKeyRef) -> Result<Vec<u8>, GatewayFactoryError> {
        read_secret_key(&self.client, ca_ref)
            .await
            .map_err(GatewayFactoryError::Kubernetes)?
            .ok_or_else(|| {
                GatewayFactoryError::InvalidSpec(format!(
                    "tls.caSecretRef: secret {}/{} key {:?} not found",
                    ca_ref.namespace, ca_ref.name, ca_ref.key
                ))
            })
    }
}

impl HttpGatewayFactory {
    async fn instance(&self, bound: &BoundInstance) -> Result<LocalInstance, GatewayFactoryError> {
        self.instances
            .get(bound)
            .await
            .map_err(GatewayFactoryError::Kubernetes)?
            .ok_or_else(|| GatewayFactoryError::InstanceNotFound(bound.clone()))
    }

    /// The admin token: external, `adminTokenSecretRef`; managed, the
    /// generated one or `operatorAccess.tokenSecretRef`.
    async fn admin_token(&self, instance: &LocalInstance) -> Result<String, GatewayFactoryError> {
        let namespace = instance.namespace().unwrap_or_default();
        let secret_ref = match (&instance.spec.external, &instance.spec.managed) {
            (Some(external), _) => external.admin_token_secret_ref.clone(),
            (None, Some(managed)) => match &managed.operator_access.token_secret_ref {
                Some(own) if !managed.operator_access.generate_token => own.clone(),
                _ => weebo_kit_api::LocalSecretKeyRef {
                    name: Names::new(instance.name_any()).token(),
                    key: api::managed::TOKEN_KEY.into(),
                },
            },
            (None, None) => {
                return Err(GatewayFactoryError::InvalidSpec(
                    "neither external nor managed".into(),
                ));
            }
        };
        self.token(&secret_ref.in_namespace(&namespace)).await
    }
}

/// Where a ready pod serves: its IP, and its container port named `http`,
/// else the first container's first one, else BatleHub's default.
fn pod_endpoint(pod: &Pod) -> Option<String> {
    let status = pod.status.as_ref()?;
    let ready = status
        .conditions
        .iter()
        .flatten()
        .any(|c| c.type_ == "Ready" && c.status == "True");
    if !ready || pod.metadata.deletion_timestamp.is_some() {
        return None;
    }
    let ip = status.pod_ip.as_deref().filter(|ip| !ip.is_empty())?;
    let containers = pod.spec.iter().flat_map(|s| &s.containers);
    // The port named `http` of any container (BatleHub's chart names it so),
    // else the first port of the first container — never a sidecar's.
    let named = containers
        .clone()
        .flat_map(|c| c.ports.iter().flatten())
        .find(|p| p.name.as_deref() == Some("http"));
    let first = containers
        .clone()
        .next()
        .and_then(|c| c.ports.as_ref()?.first());
    let port = named.or(first).map_or(8080, |p| p.container_port);
    let host = if ip.contains(':') {
        format!("[{ip}]")
    } else {
        ip.to_string()
    };
    Some(format!("http://{host}:{port}"))
}

impl HttpGatewayFactory {
    /// The proxy pods of `instance` (external: `podSelector`; managed: its
    /// own), sorted by name; `None` without a selector.
    async fn proxy_pods(
        &self,
        instance: &LocalInstance,
    ) -> Result<Option<Vec<Pod>>, GatewayFactoryError> {
        let selector = match (&instance.spec.external, &instance.spec.managed) {
            (Some(external), _) => match &external.pod_selector {
                None => return Ok(None),
                Some(selector) => Selector::try_from(selector.clone()).map_err(|e| {
                    GatewayFactoryError::InvalidSpec(format!("external.podSelector: {e}"))
                })?,
            },
            (None, Some(_)) => Selector::try_from(
                k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector {
                    match_labels: Some(Names::new(instance.name_any()).selector("proxy")),
                    ..Default::default()
                },
            )
            .map_err(|e| GatewayFactoryError::InvalidSpec(e.to_string()))?,
            (None, None) => return Ok(None),
        };
        let namespace = instance.namespace().unwrap_or_default();
        let mut pods = Api::<Pod>::namespaced(self.client.clone(), &namespace)
            .list(&ListParams::default().labels_from(&selector))
            .await
            .map_err(|e| GatewayFactoryError::Kubernetes(format!("listing pods: {e}")))?
            .items;
        pods.sort_by_key(|p| p.name_any());
        Ok(Some(pods))
    }
}

#[async_trait::async_trait]
impl GatewayFactory for HttpGatewayFactory {
    async fn waiting_pods(&self, bound: &BoundInstance) -> Result<usize, GatewayFactoryError> {
        let instance = self.instance(bound).await?;
        Ok(self
            .proxy_pods(&instance)
            .await?
            .unwrap_or_default()
            .iter()
            .filter(|p| p.metadata.deletion_timestamp.is_none() && pod_endpoint(p).is_none())
            .count())
    }

    async fn pod_gateways(
        &self,
        bound: &BoundInstance,
    ) -> Result<Option<Vec<PodGateway>>, GatewayFactoryError> {
        let instance = self.instance(bound).await?;
        let Some(pods) = self.proxy_pods(&instance).await? else {
            return Ok(None);
        };
        let token = self.admin_token(&instance).await?;
        // Pods are reached in the cluster, over plain HTTP: no CA to read.
        let client =
            HttpAdminGateway::client(None, false).map_err(GatewayFactoryError::InvalidSpec)?;
        let mut gateways = Vec::new();
        for pod in pods {
            let Some(url) = pod_endpoint(&pod) else {
                continue;
            };
            let gateway = HttpAdminGateway::new(&url, token.clone(), client.clone())
                .map_err(GatewayFactoryError::InvalidSpec)?;
            gateways.push(PodGateway {
                name: pod.name_any(),
                gateway: Arc::new(gateway),
            });
        }
        Ok(Some(gateways))
    }

    async fn gateway_for(
        &self,
        bound: &BoundInstance,
    ) -> Result<InstanceAccess, GatewayFactoryError> {
        let instance = self.instance(bound).await?;
        // The token and the CA live in the instance's own namespace.
        let namespace = instance.namespace().unwrap_or_default();
        let token = self.admin_token(&instance).await?;
        let (url, client) = match &instance.spec.external {
            Some(external) => {
                let tls = external.tls.in_namespace(&namespace);
                let ca_pem = match &tls.ca_secret_ref {
                    Some(ca_ref) => Some(self.ca(ca_ref).await?),
                    None => None,
                };
                let client = HttpAdminGateway::client(ca_pem.as_deref(), tls.insecure_skip_verify)
                    .map_err(GatewayFactoryError::InvalidSpec)?;
                (external.url.clone(), client)
            }
            None => (
                api::local_instance::endpoint(&instance),
                HttpAdminGateway::client(None, false).map_err(GatewayFactoryError::InvalidSpec)?,
            ),
        };
        let gateway = HttpAdminGateway::new(&url, token.clone(), client)
            .map_err(GatewayFactoryError::InvalidSpec)?;
        Ok(InstanceAccess {
            gateway: Arc::new(gateway),
            token,
        })
    }
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::{Container, ContainerPort, PodCondition, PodSpec, PodStatus};

    use super::*;

    fn pod(ip: &str, ready: &str, ports: Vec<(Option<&str>, i32)>) -> Pod {
        Pod {
            spec: Some(PodSpec {
                containers: vec![Container {
                    name: "batlehub".into(),
                    ports: Some(
                        ports
                            .into_iter()
                            .map(|(name, port)| ContainerPort {
                                name: name.map(String::from),
                                container_port: port,
                                ..Default::default()
                            })
                            .collect(),
                    ),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            status: Some(PodStatus {
                pod_ip: Some(ip.into()),
                conditions: Some(vec![PodCondition {
                    type_: "Ready".into(),
                    status: ready.into(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        }
    }

    #[test]
    fn a_ready_pod_is_reached_on_its_http_port() {
        let named = pod(
            "10.0.0.1",
            "True",
            vec![(Some("metrics"), 9000), (Some("http"), 8081)],
        );
        assert_eq!(
            pod_endpoint(&named).as_deref(),
            Some("http://10.0.0.1:8081")
        );
        let first = pod("10.0.0.1", "True", vec![(None, 9000)]);
        assert_eq!(
            pod_endpoint(&first).as_deref(),
            Some("http://10.0.0.1:9000")
        );
        let none = pod("fd00::1", "True", vec![]);
        assert_eq!(
            pod_endpoint(&none).as_deref(),
            Some("http://[fd00::1]:8080")
        );
        assert_eq!(pod_endpoint(&pod("10.0.0.1", "False", vec![])), None);
        assert_eq!(pod_endpoint(&pod("", "True", vec![])), None);
        let mut leaving = pod("10.0.0.1", "True", vec![]);
        leaving.metadata.deletion_timestamp =
            Some(k8s_openapi::apimachinery::pkg::apis::meta::v1::Time(
                k8s_openapi::jiff::Timestamp::UNIX_EPOCH,
            ));
        assert_eq!(pod_endpoint(&leaving), None);
    }
}
