//! One [`HttpAdminGateway`] per `BatleHubLocalInstance`, built on every
//! call: the instance comes from the [`LocalInstanceDirectory`] (a live
//! reflector `Store` when `operator::main` wires one in, the API
//! otherwise), its token and CA are read fresh — a rotated token or CA, or
//! an edited `url`, takes effect on the next reconcile.
//!
//! - external: `url`, the token of `adminTokenSecretRef`, the CA of
//!   `tls.caSecretRef`; with `podSelector`, one more gateway per ready
//!   proxy pod, on its IP — with `url`'s scheme and TLS settings: over
//!   `https`, the pod's certificate is verified against `url`'s host name
//!   (the name resolves to the pod's IP for that call);
//! - managed: its `Service` (`http://<name>.<namespace>.svc:<port>`), the
//!   generated token (`<name>-operator-token`) or `tokenSecretRef`, and
//!   always one gateway per ready proxy pod.
//!
//! The token goes to a pod only when the pod belongs to the instance's
//! workload, not to whatever matches a label selector: managed, a pod of a
//! `ReplicaSet` controlled by the instance's proxy `Deployment`, itself
//! controlled by the instance (UIDs checked along the chain); external, a
//! pod controlled by a `ReplicaSet` or `StatefulSet` that exists with that
//! UID and whose own selector matches the pod — never a bare pod. With
//! `podSelector`, whoever may create such a workload in the instance's
//! namespace matching it still receives the token (the spec's §6.6).

use std::sync::Arc;

use api::LocalInstance;
use api::managed::Names;
use application::ports::{
    BoundInstance, GatewayFactory, GatewayFactoryError, InstanceAccess, KubernetesError,
    PodGateway, Token,
};
use k8s_openapi::api::apps::v1::{Deployment, ReplicaSet, StatefulSet};
use k8s_openapi::api::core::v1::Pod;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, OwnerReference};
use kube::api::{Api, ListParams};
use kube::core::{Selector, SelectorExt};
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
                TokenSecretError::Kubernetes(e) => {
                    GatewayFactoryError::Kubernetes(KubernetesError::new(where_(), e))
                }
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
            .map_err(|e| {
                GatewayFactoryError::Kubernetes(KubernetesError::new("tls.caSecretRef", e))
            })?
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
            .map_err(|e| {
                GatewayFactoryError::Kubernetes(KubernetesError::new(format!("reading {bound}"), e))
            })?
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
    let (ip, port) = pod_address(pod)?;
    let host = if ip.contains(':') {
        format!("[{ip}]")
    } else {
        ip
    };
    Some(format!("http://{host}:{port}"))
}

/// A ready pod's IP and the port it serves on.
fn pod_address(pod: &Pod) -> Option<(String, i32)> {
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
    Some((ip.to_string(), port))
}

/// The object controlling a pod, as read from the API server.
#[derive(Debug, Clone)]
struct Workload {
    kind: String,
    uid: String,
    selector: Option<LabelSelector>,
    /// Its own controller.
    controller: Option<OwnerReference>,
}

/// Which pods the token may go to.
#[derive(Debug, Clone)]
enum Belongs {
    /// Managed: a `ReplicaSet` of the proxy `Deployment` with this UID.
    Deployment(String),
    /// External: a `ReplicaSet` or a `StatefulSet`.
    AnyWorkload,
}

fn controller_of(
    meta: &k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta,
) -> Option<&OwnerReference> {
    meta.owner_references
        .iter()
        .flatten()
        .find(|r| r.controller == Some(true))
}

/// Whether `pod` belongs to the instance: its controller (as `workload`
/// reads) exists with the UID the pod names, selects it, and is of the
/// kind `belongs` asks for.
fn belongs(pod: &Pod, workload: Option<&Workload>, rule: &Belongs) -> bool {
    let (Some(reference), Some(workload)) = (controller_of(&pod.metadata), workload) else {
        return false;
    };
    let selects = workload
        .selector
        .clone()
        .and_then(|s| Selector::try_from(s).ok())
        .is_some_and(|s| {
            // An empty selector selects everything: not a proof.
            !s.selects_all()
                && s.matches(pod.metadata.labels.as_ref().unwrap_or(&Default::default()))
        });
    if reference.uid != workload.uid || reference.kind != workload.kind || !selects {
        return false;
    }
    match rule {
        Belongs::Deployment(uid) => {
            workload.kind == "ReplicaSet"
                && workload
                    .controller
                    .as_ref()
                    .is_some_and(|c| c.kind == "Deployment" && &c.uid == uid)
        }
        Belongs::AnyWorkload => matches!(workload.kind.as_str(), "ReplicaSet" | "StatefulSet"),
    }
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
        // Read from the API: the operator watches no Pod, ReplicaSet nor
        // StatefulSet (a cluster-wide watch of them would cost more than
        // one labelled LIST per reconcile of an instance with pods).
        let mut pods = Api::<Pod>::namespaced(self.client.clone(), &namespace)
            .list(&ListParams::default().labels_from(&selector))
            .await
            .map_err(|e| GatewayFactoryError::Kubernetes(KubernetesError::new("listing pods", e)))?
            .items;
        pods.sort_by_key(|p| p.name_any());
        Ok(Some(self.owned_pods(instance, pods).await?))
    }

    /// The pods of `pods` that belong to the instance's own workload.
    async fn owned_pods(
        &self,
        instance: &LocalInstance,
        pods: Vec<Pod>,
    ) -> Result<Vec<Pod>, GatewayFactoryError> {
        let namespace = instance.namespace().unwrap_or_default();
        let kube = |what: String| {
            move |e: kube::Error| GatewayFactoryError::Kubernetes(KubernetesError::new(what, e))
        };
        let rule = match (&instance.spec.external, &instance.spec.managed) {
            (None, Some(_)) => {
                let name = Names::new(instance.name_any()).proxy();
                let deployment = Api::<Deployment>::namespaced(self.client.clone(), &namespace)
                    .get_opt(&name)
                    .await
                    .map_err(kube(format!("reading Deployment {name}")))?;
                match deployment {
                    Some(d)
                        if controller_of(&d.metadata).map(|r| &r.uid)
                            == instance.uid().as_ref() =>
                    {
                        Belongs::Deployment(d.uid().unwrap_or_default())
                    }
                    // Not the instance's (yet): no pod of it to call.
                    _ => return Ok(Vec::new()),
                }
            }
            _ => Belongs::AnyWorkload,
        };
        let mut workloads: std::collections::HashMap<(String, String), Option<Workload>> =
            Default::default();
        let mut owned = Vec::new();
        for pod in pods {
            let workload = match controller_of(&pod.metadata) {
                Some(reference) => {
                    let key = (reference.kind.clone(), reference.name.clone());
                    if !workloads.contains_key(&key) {
                        let read = self.workload(&namespace, reference).await?;
                        workloads.insert(key.clone(), read);
                    }
                    workloads[&key].clone()
                }
                None => None,
            };
            if belongs(&pod, workload.as_ref(), &rule) {
                owned.push(pod);
            } else {
                tracing::debug!(pod = %pod.name_any(), "not the instance's workload: not called");
            }
        }
        Ok(owned)
    }

    /// The `ReplicaSet` or `StatefulSet` `reference` names, `None` for
    /// another kind or when absent.
    async fn workload(
        &self,
        namespace: &str,
        reference: &OwnerReference,
    ) -> Result<Option<Workload>, GatewayFactoryError> {
        let what = format!("reading {} {}", reference.kind, reference.name);
        let kube = |e: kube::Error| GatewayFactoryError::Kubernetes(KubernetesError::new(what, e));
        Ok(match reference.kind.as_str() {
            "ReplicaSet" => Api::<ReplicaSet>::namespaced(self.client.clone(), namespace)
                .get_opt(&reference.name)
                .await
                .map_err(kube)?
                .map(|rs| Workload {
                    kind: "ReplicaSet".into(),
                    uid: rs.uid().unwrap_or_default(),
                    controller: controller_of(&rs.metadata).cloned(),
                    selector: rs.spec.map(|s| s.selector),
                }),
            "StatefulSet" => Api::<StatefulSet>::namespaced(self.client.clone(), namespace)
                .get_opt(&reference.name)
                .await
                .map_err(kube)?
                .map(|set| Workload {
                    kind: "StatefulSet".into(),
                    uid: set.uid().unwrap_or_default(),
                    controller: controller_of(&set.metadata).cloned(),
                    selector: set.spec.map(|s| s.selector),
                }),
            _ => None,
        })
    }
}

/// Where the pods of `instance` are called: `url`'s scheme and TLS for an
/// external instance, plain HTTP in the cluster for a managed one.
struct PodTls {
    https: bool,
    /// `url`'s host name, the pods' certificates are verified against;
    /// `None` when `url` names an IP (the pod's own IP is called).
    host: Option<String>,
    ca_pem: Option<Vec<u8>>,
    insecure_skip_verify: bool,
}

impl PodTls {
    /// The gateway's base URL and client for a pod at `ip:port`.
    fn reach(&self, ip: &str, port: i32) -> Result<(String, reqwest::Client), String> {
        let literal = if ip.contains(':') {
            format!("[{ip}]")
        } else {
            ip.to_string()
        };
        if !self.https {
            return Ok((
                format!("http://{literal}:{port}"),
                HttpAdminGateway::client(None, false)?,
            ));
        }
        match &self.host {
            Some(host) => {
                let addr = std::net::SocketAddr::new(
                    ip.parse().map_err(|e| format!("pod IP {ip:?}: {e}"))?,
                    u16::try_from(port).map_err(|_| format!("port {port}"))?,
                );
                Ok((
                    format!("https://{host}:{port}"),
                    HttpAdminGateway::client_resolving(
                        self.ca_pem.as_deref(),
                        self.insecure_skip_verify,
                        Some((host, addr)),
                    )?,
                ))
            }
            None => Ok((
                format!("https://{literal}:{port}"),
                HttpAdminGateway::client(self.ca_pem.as_deref(), self.insecure_skip_verify)?,
            )),
        }
    }
}

impl HttpGatewayFactory {
    /// External: `url`'s scheme, host and `tls`; managed: plain HTTP.
    async fn pod_tls(&self, instance: &LocalInstance) -> Result<PodTls, GatewayFactoryError> {
        let Some(external) = &instance.spec.external else {
            return Ok(PodTls {
                https: false,
                host: None,
                ca_pem: None,
                insecure_skip_verify: false,
            });
        };
        let url = reqwest::Url::parse(&external.url)
            .map_err(|e| GatewayFactoryError::InvalidSpec(format!("external.url: {e}")))?;
        if url.scheme() != "https" {
            return Ok(PodTls {
                https: false,
                host: None,
                ca_pem: None,
                insecure_skip_verify: false,
            });
        }
        let tls = external
            .tls
            .in_namespace(&instance.namespace().unwrap_or_default());
        let ca_pem = match &tls.ca_secret_ref {
            Some(ca_ref) => Some(self.ca(ca_ref).await?),
            None => None,
        };
        Ok(PodTls {
            https: true,
            host: url
                .host_str()
                .filter(|h| !h.starts_with('[') && h.parse::<std::net::IpAddr>().is_err())
                .map(String::from),
            ca_pem,
            insecure_skip_verify: tls.insecure_skip_verify,
        })
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
        let tls = self.pod_tls(&instance).await?;
        let mut gateways = Vec::new();
        for pod in pods {
            let Some((ip, port)) = pod_address(&pod) else {
                continue;
            };
            let (url, client) = tls
                .reach(&ip, port)
                .map_err(GatewayFactoryError::InvalidSpec)?;
            let gateway = HttpAdminGateway::new(&url, token.clone(), client)
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
            token: Token::new(token),
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

    fn controlled(kind: &str, uid: &str) -> Pod {
        let mut pod = pod("10.0.0.1", "True", vec![]);
        pod.metadata.labels = Some([("app".to_string(), "hub".to_string())].into());
        pod.metadata.owner_references = Some(vec![OwnerReference {
            kind: kind.into(),
            name: "hub-abc".into(),
            uid: uid.into(),
            controller: Some(true),
            ..Default::default()
        }]);
        pod
    }

    fn workload(kind: &str, uid: &str, deployment: Option<&str>) -> Workload {
        Workload {
            kind: kind.into(),
            uid: uid.into(),
            selector: Some(LabelSelector {
                match_labels: Some([("app".to_string(), "hub".to_string())].into()),
                ..Default::default()
            }),
            controller: deployment.map(|uid| OwnerReference {
                kind: "Deployment".into(),
                uid: uid.into(),
                controller: Some(true),
                ..Default::default()
            }),
        }
    }

    #[test]
    fn only_pods_of_the_instance_s_workload_get_the_token() {
        let managed = Belongs::Deployment("d-1".into());
        let rs = workload("ReplicaSet", "rs-1", Some("d-1"));
        assert!(belongs(
            &controlled("ReplicaSet", "rs-1"),
            Some(&rs),
            &managed
        ));
        // Another Deployment's ReplicaSet, a forged UID, a bare pod, a pod
        // the ReplicaSet doesn't select.
        let other = workload("ReplicaSet", "rs-1", Some("d-2"));
        assert!(!belongs(
            &controlled("ReplicaSet", "rs-1"),
            Some(&other),
            &managed
        ));
        assert!(!belongs(
            &controlled("ReplicaSet", "forged"),
            Some(&rs),
            &managed
        ));
        assert!(!belongs(
            &pod("10.0.0.1", "True", vec![]),
            Some(&rs),
            &managed
        ));
        assert!(!belongs(&controlled("ReplicaSet", "rs-1"), None, &managed));
        let mut unselected = controlled("ReplicaSet", "rs-1");
        unselected.metadata.labels = None;
        assert!(!belongs(&unselected, Some(&rs), &managed));
        let mut everything = rs.clone();
        everything.selector = Some(LabelSelector::default());
        assert!(!belongs(
            &controlled("ReplicaSet", "rs-1"),
            Some(&everything),
            &managed
        ));
        // External: a ReplicaSet or a StatefulSet, never another kind.
        let external = Belongs::AnyWorkload;
        assert!(belongs(
            &controlled("ReplicaSet", "rs-1"),
            Some(&other),
            &external
        ));
        let set = workload("StatefulSet", "s-1", None);
        assert!(belongs(
            &controlled("StatefulSet", "s-1"),
            Some(&set),
            &external
        ));
        let daemons = workload("DaemonSet", "ds-1", None);
        assert!(!belongs(
            &controlled("DaemonSet", "ds-1"),
            Some(&daemons),
            &external
        ));
        // A managed pod of a StatefulSet isn't the proxy Deployment's.
        assert!(!belongs(
            &controlled("StatefulSet", "s-1"),
            Some(&set),
            &managed
        ));
    }

    #[test]
    fn pods_are_called_with_the_instance_s_scheme_and_host() {
        let plain = PodTls {
            https: false,
            host: None,
            ca_pem: None,
            insecure_skip_verify: false,
        };
        assert_eq!(
            plain.reach("10.0.0.1", 8080).unwrap().0,
            "http://10.0.0.1:8080"
        );
        let tls = PodTls {
            https: true,
            host: Some("hub.example.com".into()),
            ca_pem: None,
            insecure_skip_verify: false,
        };
        // The host name, resolved to the pod: the certificate is checked
        // against it.
        assert_eq!(
            tls.reach("10.0.0.1", 8443).unwrap().0,
            "https://hub.example.com:8443"
        );
        assert_eq!(
            tls.reach("fd00::1", 8443).unwrap().0,
            "https://hub.example.com:8443"
        );
        let by_ip = PodTls { host: None, ..tls };
        assert_eq!(
            by_ip.reach("fd00::1", 8443).unwrap().0,
            "https://[fd00::1]:8443"
        );
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
