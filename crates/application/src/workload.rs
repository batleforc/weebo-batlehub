//! The Kubernetes objects of a managed instance, built from its spec and
//! its rendered configuration — pure, no client. Their shape follows
//! BatleHub's own Helm chart (probes, security contexts, mounts, worker),
//! so that moving from the chart changes nothing the pods see.

use std::collections::BTreeMap;

use api::managed::{
    CONFIG_HASH_ANNOTATION, CONFIG_KEY, DEFAULT_IMAGE_TAG, DEFAULT_WORKER_REPOSITORY,
    ManagedInstance, Names, UpdateStrategy,
};
use k8s_openapi::ByteString;
use k8s_openapi::api::apps::v1::{
    Deployment, DeploymentSpec, DeploymentStrategy, RollingUpdateDeployment,
};
use k8s_openapi::api::autoscaling::v2::{
    CrossVersionObjectReference, ExternalMetricSource, HorizontalPodAutoscaler,
    HorizontalPodAutoscalerSpec, MetricIdentifier, MetricSpec, MetricTarget,
};
use k8s_openapi::api::core::v1::{
    Affinity, Capabilities, Container, ContainerPort, EmptyDirVolumeSource, EnvVar, HTTPGetAction,
    KeyToPath, PersistentVolumeClaim, PersistentVolumeClaimSpec, PersistentVolumeClaimVolumeSource,
    PodAffinity, PodAffinityTerm, PodSecurityContext, PodSpec, PodTemplateSpec, Probe,
    ResourceRequirements, SeccompProfile, Secret, SecretVolumeSource, SecurityContext, Service,
    ServiceAccount, ServicePort, ServiceSpec, Volume, VolumeMount, VolumeResourceRequirements,
};
use k8s_openapi::api::networking::v1::{
    HTTPIngressPath, HTTPIngressRuleValue, Ingress, IngressBackend, IngressRule,
    IngressServiceBackend, IngressSpec, NetworkPolicy, NetworkPolicyEgressRule,
    NetworkPolicyIngressRule, NetworkPolicyPeer, NetworkPolicyPort, NetworkPolicySpec,
    ServiceBackendPort,
};
use k8s_openapi::api::policy::v1::{PodDisruptionBudget, PodDisruptionBudgetSpec};
use k8s_openapi::apimachinery::pkg::api::resource::Quantity;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{LabelSelector, ObjectMeta};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use k8s_openapi::{Metadata, Resource};
use serde_json::Value;

use crate::ports::OwnedObject;

/// Where the configuration is mounted, and the credentials beside it.
pub const CONFIG_DIR: &str = "/etc/batlehub";
pub const CREDENTIALS_DIR: &str = "/etc/batlehub/credentials";

/// What the objects need of the rendered configuration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DocumentFacts {
    /// `server.port`.
    pub port: i32,
    /// `storage.path`, when the storage is `filesystem` (the default).
    pub cache_path: Option<String>,
    /// An `[[auth]] type = "kubernetes"` provider: the pods mount their
    /// account's token, bound to TokenReview.
    pub kubernetes_auth: bool,
}

impl DocumentFacts {
    /// Read from the configuration as JSON (`ConfigParser::fragment` of
    /// the rendered document).
    pub fn of(config: &Value) -> Self {
        let port = config
            .pointer("/server/port")
            .and_then(Value::as_i64)
            .unwrap_or(8080) as i32;
        let storage = config.get("storage");
        let filesystem = storage
            .and_then(|s| s.get("type"))
            .and_then(Value::as_str)
            .is_none_or(|t| t == "filesystem");
        let cache_path = filesystem.then(|| {
            storage
                .and_then(|s| s.get("path"))
                .and_then(Value::as_str)
                .unwrap_or("/var/cache/batlehub")
                .to_string()
        });
        let kubernetes_auth = config
            .get("auth")
            .and_then(Value::as_array)
            .is_some_and(|a| {
                a.iter()
                    .any(|p| p.get("type").and_then(Value::as_str) == Some("kubernetes"))
            });
        Self {
            port,
            cache_path,
            kubernetes_auth,
        }
    }
}

/// Everything the objects are built from.
#[derive(Debug, Clone)]
pub struct WorkloadInput<'a> {
    pub name: &'a str,
    pub namespace: &'a str,
    pub spec: &'a ManagedInstance,
    /// The configuration file as written (nonce and comments included).
    pub file: &'a str,
    pub facts: &'a DocumentFacts,
    /// The pod template's `batlehub.weebo.io/config-hash`: changing it
    /// rolls the pods.
    pub restart_hash: &'a str,
    /// The worker template's: every change of the configuration (workers
    /// have no reload API).
    pub config_hash: &'a str,
    /// The operator's namespace, let in by the `NetworkPolicy`.
    pub operator_namespace: Option<&'a str>,
}

/// The update strategy of the proxy `Deployment`, and why.
pub fn update_strategy(spec: &ManagedInstance, facts: &DocumentFacts) -> UpdateStrategy {
    if let Some(forced) = spec.update_strategy {
        return forced;
    }
    // A filesystem cache on a single-writer claim (`accessMode` says so,
    // an `existingClaim`'s included): a surge pod would wait for it.
    if facts.cache_path.is_some() && spec.persistence.single_writer() {
        UpdateStrategy::Recreate
    } else {
        UpdateStrategy::RollingUpdate
    }
}

fn object<K: Resource + Metadata<Ty = ObjectMeta> + serde::Serialize>(
    k: &K,
    create_only: bool,
) -> OwnedObject {
    OwnedObject {
        api_version: K::API_VERSION.to_string(),
        kind: K::KIND.to_string(),
        name: k.metadata().name.clone().unwrap_or_default(),
        manifest: serde_json::to_value(k).expect("a Kubernetes object serializes"),
        create_only,
    }
}

fn meta(input: &WorkloadInput<'_>, name: String, component: &str) -> ObjectMeta {
    ObjectMeta {
        name: Some(name),
        namespace: Some(input.namespace.to_string()),
        labels: Some(Names::new(input.name).labels(component)),
        ..Default::default()
    }
}

fn some_map(map: &BTreeMap<String, String>) -> Option<BTreeMap<String, String>> {
    (!map.is_empty()).then(|| map.clone())
}

fn quantity(text: &str) -> Quantity {
    Quantity(text.into())
}

fn default_resources() -> ResourceRequirements {
    ResourceRequirements {
        requests: Some(BTreeMap::from([
            ("cpu".into(), quantity("100m")),
            ("memory".into(), quantity("128Mi")),
            ("ephemeral-storage".into(), quantity("256Mi")),
        ])),
        limits: Some(BTreeMap::from([
            ("memory".into(), quantity("512Mi")),
            ("ephemeral-storage".into(), quantity("1Gi")),
        ])),
        ..Default::default()
    }
}

fn pod_security(spec: &ManagedInstance) -> PodSecurityContext {
    spec.pod_security_context
        .clone()
        .unwrap_or(PodSecurityContext {
            run_as_non_root: Some(true),
            run_as_user: Some(65532),
            run_as_group: Some(65532),
            fs_group: Some(65532),
            seccomp_profile: Some(SeccompProfile {
                type_: "RuntimeDefault".into(),
                ..Default::default()
            }),
            ..Default::default()
        })
}

fn container_security(spec: &ManagedInstance) -> SecurityContext {
    spec.security_context.clone().unwrap_or(SecurityContext {
        allow_privilege_escalation: Some(false),
        read_only_root_filesystem: Some(true),
        capabilities: Some(Capabilities {
            drop: Some(vec!["ALL".into()]),
            ..Default::default()
        }),
        ..Default::default()
    })
}

fn http_probe(path: &str, delay: i32, period: i32) -> Probe {
    Probe {
        http_get: Some(HTTPGetAction {
            path: Some(path.into()),
            port: IntOrString::String("http".into()),
            ..Default::default()
        }),
        initial_delay_seconds: Some(delay),
        period_seconds: Some(period),
        ..Default::default()
    }
}

/// The config `Secret`, the credentials and the cache: what both
/// deployments mount.
fn volumes(input: &WorkloadInput<'_>) -> (Vec<Volume>, Vec<VolumeMount>) {
    let names = Names::new(input.name);
    let spec = input.spec;
    let mut volumes = vec![Volume {
        name: "config".into(),
        secret: Some(SecretVolumeSource {
            secret_name: Some(names.config()),
            items: Some(vec![KeyToPath {
                key: CONFIG_KEY.into(),
                path: CONFIG_KEY.into(),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    }];
    let mut mounts = vec![VolumeMount {
        name: "config".into(),
        mount_path: CONFIG_DIR.into(),
        read_only: Some(true),
        ..Default::default()
    }];
    if let Some(credentials) = &spec.credentials {
        volumes.push(Volume {
            name: "credentials".into(),
            secret: Some(SecretVolumeSource {
                secret_name: Some(credentials.name.clone()),
                items: Some(vec![KeyToPath {
                    key: credentials.key.clone(),
                    path: credentials.key.clone(),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        });
        mounts.push(VolumeMount {
            name: "credentials".into(),
            mount_path: CREDENTIALS_DIR.into(),
            read_only: Some(true),
            ..Default::default()
        });
    }
    if let Some(path) = &input.facts.cache_path {
        let persistence = &spec.persistence;
        volumes.push(Volume {
            name: "cache".into(),
            persistent_volume_claim: persistence.enabled.then(|| {
                PersistentVolumeClaimVolumeSource {
                    claim_name: persistence
                        .existing_claim
                        .clone()
                        .unwrap_or_else(|| names.cache()),
                    ..Default::default()
                }
            }),
            empty_dir: (!persistence.enabled).then(|| EmptyDirVolumeSource {
                size_limit: Some(persistence.ephemeral_size_limit.clone()),
                ..Default::default()
            }),
            ..Default::default()
        });
        mounts.push(VolumeMount {
            name: "cache".into(),
            mount_path: path.clone(),
            ..Default::default()
        });
    }
    (volumes, mounts)
}

/// `--config` for the file and the credentials, then the roles.
fn args(spec: &ManagedInstance, roles: Option<&str>) -> Vec<String> {
    let mut args = vec!["--config".into(), format!("{CONFIG_DIR}/{CONFIG_KEY}")];
    if let Some(credentials) = &spec.credentials {
        args.push("--config".into());
        args.push(format!("{CREDENTIALS_DIR}/{}", credentials.key));
    }
    if let Some(roles) = roles {
        args.push("--roles".into());
        args.push(roles.into());
    }
    args
}

fn env(spec: &ManagedInstance, extra: Vec<EnvVar>) -> Option<Vec<EnvVar>> {
    let mut env = extra;
    if !spec.hot_reload {
        env.push(EnvVar {
            name: "BATLEHUB_DISABLE_HOT_RELOAD".into(),
            value: Some("1".into()),
            ..Default::default()
        });
    }
    env.extend(spec.env.iter().cloned());
    (!env.is_empty()).then_some(env)
}

fn service_account_name(input: &WorkloadInput<'_>) -> String {
    input
        .spec
        .service_account
        .name
        .clone()
        .unwrap_or_else(|| input.name.to_string())
}

fn proxy(input: &WorkloadInput<'_>) -> Deployment {
    let names = Names::new(input.name);
    let spec = input.spec;
    let (mut volumes, mut mounts) = volumes(input);
    volumes.extend(spec.extra_volumes.iter().cloned());
    mounts.extend(spec.extra_volume_mounts.iter().cloned());
    let mut labels = names.selector("proxy");
    labels.extend(spec.pod_labels.clone());
    let mut annotations = spec.pod_annotations.clone();
    annotations.insert(CONFIG_HASH_ANNOTATION.into(), input.restart_hash.into());
    let strategy = match update_strategy(spec, input.facts) {
        UpdateStrategy::Recreate => DeploymentStrategy {
            type_: Some("Recreate".into()),
            ..Default::default()
        },
        UpdateStrategy::RollingUpdate => DeploymentStrategy {
            type_: Some("RollingUpdate".into()),
            rolling_update: Some(RollingUpdateDeployment {
                max_unavailable: Some(IntOrString::Int(0)),
                max_surge: Some(IntOrString::Int(1)),
            }),
        },
    };
    Deployment {
        metadata: meta(input, names.proxy(), "proxy"),
        spec: Some(DeploymentSpec {
            replicas: Some(spec.replicas),
            selector: LabelSelector {
                match_labels: Some(names.selector("proxy")),
                ..Default::default()
            },
            strategy: Some(strategy),
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    annotations: Some(annotations),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    image_pull_secrets: (!spec.image_pull_secrets.is_empty())
                        .then(|| spec.image_pull_secrets.clone()),
                    service_account_name: Some(service_account_name(input)),
                    automount_service_account_token: Some(input.facts.kubernetes_auth),
                    security_context: Some(pod_security(spec)),
                    runtime_class_name: spec.runtime_class_name.clone(),
                    node_selector: some_map(&spec.node_selector),
                    tolerations: (!spec.tolerations.is_empty()).then(|| spec.tolerations.clone()),
                    affinity: spec.affinity.clone(),
                    volumes: Some(volumes),
                    containers: vec![Container {
                        name: "batlehub".into(),
                        image: Some(spec.image.reference()),
                        image_pull_policy: Some(
                            spec.image
                                .pull_policy
                                .clone()
                                .unwrap_or_else(|| "IfNotPresent".into()),
                        ),
                        args: Some(args(spec, spec.worker.as_ref().map(|_| "proxy"))),
                        env: env(spec, Vec::new()),
                        env_from: (!spec.env_from.is_empty()).then(|| spec.env_from.clone()),
                        ports: Some(vec![ContainerPort {
                            name: Some("http".into()),
                            container_port: input.facts.port,
                            protocol: Some("TCP".into()),
                            ..Default::default()
                        }]),
                        liveness_probe: Some(http_probe("/livez", 10, 30)),
                        readiness_probe: Some(http_probe("/healthz", 5, 10)),
                        resources: Some(spec.resources.clone().unwrap_or_else(default_resources)),
                        security_context: Some(container_security(spec)),
                        volume_mounts: Some(mounts),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

fn worker(input: &WorkloadInput<'_>, worker: &api::managed::Worker) -> Deployment {
    let names = Names::new(input.name);
    let spec = input.spec;
    let (mut volumes, mut mounts) = volumes(input);
    volumes.push(Volume {
        name: "scratch".into(),
        empty_dir: Some(EmptyDirVolumeSource {
            medium: Some("Memory".into()),
            size_limit: Some(worker.scratch_size_limit.clone()),
        }),
        ..Default::default()
    });
    mounts.push(VolumeMount {
        name: "scratch".into(),
        mount_path: "/tmp/batlehub".into(),
        ..Default::default()
    });
    let image = worker.image.clone().unwrap_or_default();
    let reference = format!(
        "{}:{}",
        image
            .repository
            .as_deref()
            .unwrap_or(DEFAULT_WORKER_REPOSITORY),
        image
            .tag
            .as_deref()
            .or(spec.image.tag.as_deref())
            .unwrap_or(DEFAULT_IMAGE_TAG)
    );
    let mut annotations = spec.pod_annotations.clone();
    annotations.insert(CONFIG_HASH_ANNOTATION.into(), input.config_hash.into());
    let mut labels = names.selector("worker");
    labels.extend(spec.pod_labels.clone());
    Deployment {
        metadata: meta(input, names.worker(), "worker"),
        spec: Some(DeploymentSpec {
            // The autoscaler owns the count.
            replicas: worker.autoscaling.is_none().then_some(worker.replicas),
            selector: LabelSelector {
                match_labels: Some(names.selector("worker")),
                ..Default::default()
            },
            template: PodTemplateSpec {
                metadata: Some(ObjectMeta {
                    labels: Some(labels),
                    annotations: Some(annotations),
                    ..Default::default()
                }),
                spec: Some(PodSpec {
                    image_pull_secrets: (!spec.image_pull_secrets.is_empty())
                        .then(|| spec.image_pull_secrets.clone()),
                    service_account_name: Some(service_account_name(input)),
                    automount_service_account_token: Some(false),
                    security_context: Some(pod_security(spec)),
                    runtime_class_name: worker.runtime_class_name.clone(),
                    node_selector: some_map(&worker.node_selector),
                    tolerations: (!worker.tolerations.is_empty())
                        .then(|| worker.tolerations.clone()),
                    affinity: beside_the_proxy(input),
                    volumes: Some(volumes),
                    containers: vec![Container {
                        name: "worker".into(),
                        image: Some(reference),
                        image_pull_policy: Some(
                            image.pull_policy.unwrap_or_else(|| "IfNotPresent".into()),
                        ),
                        args: Some(args(spec, Some("worker"))),
                        env: env(
                            spec,
                            vec![EnvVar {
                                name: "TMPDIR".into(),
                                value: Some("/tmp/batlehub".into()),
                                ..Default::default()
                            }],
                        ),
                        env_from: (!spec.env_from.is_empty()).then(|| spec.env_from.clone()),
                        ports: Some(vec![ContainerPort {
                            name: Some("http".into()),
                            container_port: input.facts.port,
                            protocol: Some("TCP".into()),
                            ..Default::default()
                        }]),
                        liveness_probe: Some(http_probe("/livez", 10, 30)),
                        resources: worker.resources.clone(),
                        security_context: Some(container_security(spec)),
                        volume_mounts: Some(mounts),
                        ..Default::default()
                    }],
                    ..Default::default()
                }),
            },
            ..Default::default()
        }),
        ..Default::default()
    }
}

/// A filesystem cache on a single-writer claim is mounted by one node: the
/// worker goes where a proxy pod runs.
fn beside_the_proxy(input: &WorkloadInput<'_>) -> Option<Affinity> {
    let spec = input.spec;
    (input.facts.cache_path.is_some() && spec.persistence.single_writer()).then(|| Affinity {
        pod_affinity: Some(PodAffinity {
            required_during_scheduling_ignored_during_execution: Some(vec![PodAffinityTerm {
                label_selector: Some(LabelSelector {
                    match_labels: Some(Names::new(input.name).selector("proxy")),
                    ..Default::default()
                }),
                topology_key: "kubernetes.io/hostname".into(),
                ..Default::default()
            }]),
            ..Default::default()
        }),
        ..Default::default()
    })
}

/// Every object of the instance, in the order they are applied (what a pod
/// mounts before the pods).
pub fn objects(input: &WorkloadInput<'_>) -> Vec<OwnedObject> {
    let names = Names::new(input.name);
    let spec = input.spec;
    let mut out = Vec::new();
    out.push(object(
        &Secret {
            metadata: meta(input, names.config(), "proxy"),
            data: Some(BTreeMap::from([(
                CONFIG_KEY.into(),
                ByteString(input.file.as_bytes().to_vec()),
            )])),
            ..Default::default()
        },
        false,
    ));
    if spec.service_account.create {
        let mut sa_meta = meta(input, service_account_name(input), "proxy");
        sa_meta.annotations = some_map(&spec.service_account.annotations);
        out.push(object(
            &ServiceAccount {
                metadata: sa_meta,
                automount_service_account_token: Some(false),
                ..Default::default()
            },
            false,
        ));
    }
    if input.facts.cache_path.is_some()
        && spec.persistence.enabled
        && spec.persistence.existing_claim.is_none()
    {
        out.push(object(
            &PersistentVolumeClaim {
                metadata: meta(input, names.cache(), "proxy"),
                spec: Some(PersistentVolumeClaimSpec {
                    access_modes: Some(vec![spec.persistence.access_mode.clone()]),
                    storage_class_name: spec.persistence.storage_class.clone(),
                    resources: Some(VolumeResourceRequirements {
                        requests: Some(BTreeMap::from([(
                            "storage".into(),
                            spec.persistence.size.clone(),
                        )])),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            },
            true,
        ));
    }
    let mut service_meta = meta(input, names.proxy(), "proxy");
    service_meta.annotations = some_map(&spec.service.annotations);
    out.push(object(
        &Service {
            metadata: service_meta,
            spec: Some(ServiceSpec {
                type_: Some(spec.service.r#type.clone()),
                selector: Some(names.selector("proxy")),
                ports: Some(vec![ServicePort {
                    name: Some("http".into()),
                    port: spec.service.port,
                    target_port: Some(IntOrString::String("http".into())),
                    protocol: Some("TCP".into()),
                    ..Default::default()
                }]),
                ..Default::default()
            }),
            ..Default::default()
        },
        false,
    ));
    out.push(object(&proxy(input), false));
    if let Some(w) = &spec.worker {
        out.push(object(&worker(input, w), false));
        if let Some(autoscaling) = &w.autoscaling {
            out.push(object(
                &HorizontalPodAutoscaler {
                    metadata: meta(input, names.worker(), "worker"),
                    spec: HorizontalPodAutoscalerSpec {
                        scale_target_ref: CrossVersionObjectReference {
                            api_version: Some("apps/v1".into()),
                            kind: "Deployment".into(),
                            name: names.worker(),
                        },
                        min_replicas: Some(autoscaling.min_replicas),
                        max_replicas: autoscaling.max_replicas,
                        metrics: Some(vec![MetricSpec {
                            type_: "External".into(),
                            external: Some(ExternalMetricSource {
                                metric: MetricIdentifier {
                                    name: autoscaling.metric_name.clone(),
                                    ..Default::default()
                                },
                                target: MetricTarget {
                                    type_: "AverageValue".into(),
                                    average_value: Some(quantity(
                                        &autoscaling.target_queued.to_string(),
                                    )),
                                    ..Default::default()
                                },
                            }),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    },
                    ..Default::default()
                },
                false,
            ));
        }
    }
    if let Some(ingress) = &spec.ingress {
        let backend = IngressBackend {
            service: Some(IngressServiceBackend {
                name: names.proxy(),
                port: Some(ServiceBackendPort {
                    name: Some("http".into()),
                    ..Default::default()
                }),
            }),
            ..Default::default()
        };
        let rule = |host: &String| IngressRule {
            host: Some(host.clone()),
            http: Some(HTTPIngressRuleValue {
                paths: vec![HTTPIngressPath {
                    path: Some("/".into()),
                    path_type: "Prefix".into(),
                    backend: backend.clone(),
                }],
            }),
        };
        let mut ingress_meta = meta(input, names.proxy(), "proxy");
        ingress_meta.annotations = some_map(&ingress.annotations);
        out.push(object(
            &Ingress {
                metadata: ingress_meta,
                spec: Some(IngressSpec {
                    ingress_class_name: ingress.class_name.clone(),
                    rules: Some(
                        std::iter::once(&ingress.host)
                            .chain(&ingress.extra_hosts)
                            .map(rule)
                            .collect(),
                    ),
                    tls: (!ingress.tls.is_empty()).then(|| ingress.tls.clone()),
                    ..Default::default()
                }),
                ..Default::default()
            },
            false,
        ));
    }
    if let Some(budget) = spec
        .pod_disruption_budget
        .as_ref()
        .filter(|_| spec.replicas >= 2)
    {
        out.push(object(
            &PodDisruptionBudget {
                metadata: meta(input, names.proxy(), "proxy"),
                spec: Some(PodDisruptionBudgetSpec {
                    selector: Some(LabelSelector {
                        match_labels: Some(names.selector("proxy")),
                        ..Default::default()
                    }),
                    min_available: budget.min_available.clone(),
                    max_unavailable: budget.max_unavailable.clone(),
                    ..Default::default()
                }),
                ..Default::default()
            },
            false,
        ));
    }
    if let Some(policy) = &spec.network_policy {
        out.push(object(&network_policy(input, policy), false));
    }
    out
}

fn network_policy(
    input: &WorkloadInput<'_>,
    policy: &api::managed::NetworkPolicy,
) -> NetworkPolicy {
    let names = Names::new(input.name);
    let mut from = policy.ingress_from.clone();
    if !from.is_empty() {
        // The operator keeps its access to the admin API.
        from.push(NetworkPolicyPeer {
            namespace_selector: input.operator_namespace.map(|ns| LabelSelector {
                match_labels: Some(BTreeMap::from([(
                    "kubernetes.io/metadata.name".into(),
                    ns.to_string(),
                )])),
                ..Default::default()
            }),
            pod_selector: Some(LabelSelector {
                match_labels: Some(BTreeMap::from([(
                    "app.kubernetes.io/name".into(),
                    "weebo-batlehub".into(),
                )])),
                ..Default::default()
            }),
            ..Default::default()
        });
    }
    let dns = NetworkPolicyEgressRule {
        ports: Some(
            ["UDP", "TCP"]
                .iter()
                .map(|protocol| NetworkPolicyPort {
                    port: Some(IntOrString::Int(53)),
                    protocol: Some(protocol.to_string()),
                    ..Default::default()
                })
                .collect(),
        ),
        ..Default::default()
    };
    let mut egress = vec![dns];
    if !policy.egress_to.is_empty() {
        egress.push(NetworkPolicyEgressRule {
            to: Some(policy.egress_to.clone()),
            ..Default::default()
        });
    }
    NetworkPolicy {
        metadata: meta(input, names.proxy(), "proxy"),
        spec: Some(NetworkPolicySpec {
            pod_selector: Some(LabelSelector {
                match_labels: Some(BTreeMap::from([
                    ("app.kubernetes.io/name".into(), "batlehub".into()),
                    ("app.kubernetes.io/instance".into(), input.name.to_string()),
                ])),
                ..Default::default()
            }),
            policy_types: Some(vec!["Ingress".into(), "Egress".into()]),
            ingress: Some(vec![NetworkPolicyIngressRule {
                from: (!from.is_empty()).then_some(from),
                ports: Some(vec![NetworkPolicyPort {
                    port: Some(IntOrString::String("http".into())),
                    protocol: Some("TCP".into()),
                    ..Default::default()
                }]),
            }]),
            egress: Some(egress),
        }),
    }
}

/// The objects a spec no longer renders, which the operator removes:
/// `(apiVersion, kind, name)`.
pub fn removed(input: &WorkloadInput<'_>) -> Vec<(&'static str, &'static str, String)> {
    let names = Names::new(input.name);
    let spec = input.spec;
    let mut out = Vec::new();
    if spec.worker.is_none() {
        out.push(("apps/v1", "Deployment", names.worker()));
    }
    if spec.worker.as_ref().is_none_or(|w| w.autoscaling.is_none()) {
        out.push(("autoscaling/v2", "HorizontalPodAutoscaler", names.worker()));
    }
    if spec.ingress.is_none() {
        out.push(("networking.k8s.io/v1", "Ingress", names.proxy()));
    }
    if spec.pod_disruption_budget.is_none() || spec.replicas < 2 {
        out.push(("policy/v1", "PodDisruptionBudget", names.proxy()));
    }
    if spec.network_policy.is_none() {
        out.push(("networking.k8s.io/v1", "NetworkPolicy", names.proxy()));
    }
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn facts() -> DocumentFacts {
        DocumentFacts::of(&json!({"server": {"port": 9090}}))
    }

    fn input<'a>(spec: &'a ManagedInstance, facts: &'a DocumentFacts) -> WorkloadInput<'a> {
        WorkloadInput {
            name: "hub",
            namespace: "team",
            spec,
            file: "[server]\nport = 9090\n",
            facts,
            restart_hash: "r1",
            config_hash: "c1",
            operator_namespace: Some("weebo-batlehub-system"),
        }
    }

    fn kinds(objects: &[OwnedObject]) -> Vec<String> {
        objects
            .iter()
            .map(|o| format!("{}/{}", o.kind, o.name))
            .collect()
    }

    #[test]
    fn facts_are_read_from_the_configuration() {
        let defaults = DocumentFacts::of(&json!({}));
        assert_eq!(defaults.port, 8080);
        assert_eq!(defaults.cache_path.as_deref(), Some("/var/cache/batlehub"));
        assert!(!defaults.kubernetes_auth);
        let s3 = DocumentFacts::of(&json!({
            "storage": {"type": "s3"},
            "auth": [{"type": "token"}, {"type": "kubernetes"}],
        }));
        assert_eq!(s3.cache_path, None);
        assert!(s3.kubernetes_auth);
    }

    #[test]
    fn a_default_instance_is_a_secret_an_account_a_claim_a_service_and_a_deployment() {
        let spec = ManagedInstance::default();
        let facts = facts();
        let objects = objects(&input(&spec, &facts));
        assert_eq!(
            kinds(&objects),
            [
                "Secret/hub-config",
                "ServiceAccount/hub",
                "PersistentVolumeClaim/hub-cache",
                "Service/hub",
                "Deployment/hub",
            ]
        );
        assert!(objects[2].create_only);
        let deployment = &objects[4].manifest;
        let pod = &deployment["spec"]["template"];
        assert_eq!(pod["metadata"]["annotations"][CONFIG_HASH_ANNOTATION], "r1");
        let container = &pod["spec"]["containers"][0];
        assert_eq!(container["image"], "ghcr.io/batlehub/batlehub:1.6.0");
        assert_eq!(
            container["args"],
            json!(["--config", "/etc/batlehub/config.toml"])
        );
        assert_eq!(container["ports"][0]["containerPort"], 9090);
        assert_eq!(container["readinessProbe"]["httpGet"]["path"], "/healthz");
        assert_eq!(container["securityContext"]["readOnlyRootFilesystem"], true);
        assert_eq!(pod["spec"]["securityContext"]["runAsUser"], 65532);
        assert_eq!(pod["spec"]["automountServiceAccountToken"], false);
        // A filesystem cache on a ReadWriteOnce claim: one writer.
        assert_eq!(deployment["spec"]["strategy"]["type"], "Recreate");
        assert_eq!(
            objects[0].manifest["data"][CONFIG_KEY],
            json!("W3NlcnZlcl0KcG9ydCA9IDkwOTAK")
        );
    }

    #[test]
    fn a_full_instance_renders_every_object_and_removes_none() {
        let spec: ManagedInstance = serde_json::from_value(json!({
            "replicas": 2,
            "persistence": {"accessMode": "ReadWriteMany"},
            "credentials": {"name": "creds", "key": "credentials.toml"},
            "hotReload": false,
            "worker": {"autoscaling": {"maxReplicas": 4}},
            "ingress": {"host": "hub.example.com", "extraHosts": ["mirror.example.com"]},
            "podDisruptionBudget": {"minAvailable": 1},
            "networkPolicy": {"ingressFrom": [{"podSelector": {}}]},
        }))
        .unwrap();
        let facts = facts();
        let input = input(&spec, &facts);
        let objects = objects(&input);
        assert_eq!(
            kinds(&objects),
            [
                "Secret/hub-config",
                "ServiceAccount/hub",
                "PersistentVolumeClaim/hub-cache",
                "Service/hub",
                "Deployment/hub",
                "Deployment/hub-worker",
                "HorizontalPodAutoscaler/hub-worker",
                "Ingress/hub",
                "PodDisruptionBudget/hub",
                "NetworkPolicy/hub",
            ]
        );
        assert!(removed(&input).is_empty());
        let proxy = &objects[4].manifest["spec"];
        assert_eq!(proxy["strategy"]["type"], "RollingUpdate");
        assert_eq!(proxy["strategy"]["rollingUpdate"]["maxUnavailable"], 0);
        let container = &proxy["template"]["spec"]["containers"][0];
        assert_eq!(
            container["args"],
            json!([
                "--config",
                "/etc/batlehub/config.toml",
                "--config",
                "/etc/batlehub/credentials/credentials.toml",
                "--roles",
                "proxy"
            ])
        );
        assert_eq!(container["env"][0]["name"], "BATLEHUB_DISABLE_HOT_RELOAD");
        let worker = &objects[5].manifest["spec"];
        assert!(worker.get("replicas").is_none());
        // ReadWriteMany: no need to share a node.
        assert!(worker["template"]["spec"].get("affinity").is_none());
        assert_eq!(
            worker["template"]["metadata"]["annotations"][CONFIG_HASH_ANNOTATION],
            "c1"
        );
        assert_eq!(
            worker["template"]["spec"]["containers"][0]["image"],
            "ghcr.io/batlehub/batlehub-worker:1.6.0"
        );
        let ingress = &objects[7].manifest["spec"]["rules"];
        assert_eq!(ingress.as_array().unwrap().len(), 2);
        let from = &objects[9].manifest["spec"]["ingress"][0]["from"];
        assert_eq!(from.as_array().unwrap().len(), 2, "{from}");
    }

    #[test]
    fn a_worker_sharing_a_single_writer_cache_goes_beside_the_proxy() {
        let spec: ManagedInstance = serde_json::from_value(json!({"worker": {}})).unwrap();
        let facts = facts();
        let objects = objects(&input(&spec, &facts));
        let worker = &objects
            .iter()
            .find(|o| o.name == "hub-worker" && o.kind == "Deployment")
            .unwrap()
            .manifest;
        let term = &worker["spec"]["template"]["spec"]["affinity"]["podAffinity"]["requiredDuringSchedulingIgnoredDuringExecution"]
            [0];
        assert_eq!(term["topologyKey"], "kubernetes.io/hostname");
        assert_eq!(
            term["labelSelector"]["matchLabels"]["app.kubernetes.io/component"],
            "proxy"
        );
    }

    #[test]
    fn what_the_spec_drops_is_removed() {
        let spec = ManagedInstance::default();
        let facts = facts();
        let removed: Vec<String> = removed(&input(&spec, &facts))
            .into_iter()
            .map(|(_, kind, name)| format!("{kind}/{name}"))
            .collect();
        assert_eq!(
            removed,
            [
                "Deployment/hub-worker",
                "HorizontalPodAutoscaler/hub-worker",
                "Ingress/hub",
                "PodDisruptionBudget/hub",
                "NetworkPolicy/hub",
            ]
        );
    }
}
