//! Integration tests: the controllers limited to one namespace
//! (`WatchScope`), running as a ServiceAccount that only has the RBAC the
//! chart renders for that scope, with the real instance resolution
//! (`LocalInstanceDirectory`) — the gateway alone is in memory. The
//! control plane authorizes with RBAC: a call outside the granted scope is
//! refused.
//!
//! `watch.namespace` (+ a label selector): the kinds and the chart's
//! namespaced rules (`params.watchRules`) in a Role of the watched
//! namespace; Secrets and Events in the ClusterRole too
//! (`params.clusterSecrets: true`). BatleHub has no cluster-scoped kind;
//! `watch.clusterKinds: false` (all in Roles) renders no ClusterRole and
//! keeps managed mode (spec §7.1).
//!
//! The rules below mirror the library chart's `clusterRole` and
//! `watchRole` (`weebo-operator.kindRules`) and this chart's
//! `operator.namespacedRules`: keep them in step.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::LocalInstanceDirectory;
use api::LocalInstance;
use api::local_instance::{ExternalInstance, LocalInstanceSpec, LocalSecretKeyRef};
use k8s_openapi::api::core::v1::Namespace;
use k8s_openapi::api::rbac::v1::{
    ClusterRole, ClusterRoleBinding, PolicyRule, Role, RoleBinding, RoleRef, Subject,
};
use k8s_openapi::apimachinery::pkg::apis::meta::v1::LabelSelector;
use kube::Client;
use kube::api::{Api, ObjectMeta, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use testkit::envtest::EnvTestCluster;
use testkit::{FakeConfigParser, FakeDependents, FakeGateway, FakeSources, StaticGatewayFactory};
use weebo_kit_runtime::{Health, WatchScope};

const TIMEOUT: Duration = Duration::from_secs(15);
const POLL: Duration = Duration::from_millis(200);
const GROUP: &str = "batlehub.weebo.io";
const OPERATOR_NS: &str = "operator";
const OPERATOR_SA: &str = "operator";
const NAMESPACED_KINDS: &[&str] = &["batlehublocalinstances", "batlehubregistries"];

fn kind_rules(kinds: &[&str]) -> Vec<PolicyRule> {
    let rule = |suffix: &str, verbs: &[&str]| PolicyRule {
        api_groups: Some(vec![GROUP.into()]),
        resources: Some(kinds.iter().map(|k| format!("{k}{suffix}")).collect()),
        verbs: verbs.iter().map(|v| v.to_string()).collect(),
        ..Default::default()
    };
    vec![
        rule("", &["get", "list", "watch", "update", "patch"]),
        rule("/status", &["get", "patch", "update"]),
        rule("/finalizers", &["update"]),
    ]
}

/// The chart's `operator.namespacedRules`: what the operator reads and
/// writes in the watched namespace (`params.watchRules`, in the watch
/// Role, with `watch.namespace`).
fn namespaced_rules() -> Vec<PolicyRule> {
    let rule = |group: &str, resources: &[&str], verbs: &[&str]| PolicyRule {
        api_groups: Some(vec![group.into()]),
        resources: Some(resources.iter().map(|r| r.to_string()).collect()),
        verbs: verbs.iter().map(|v| v.to_string()).collect(),
        ..Default::default()
    };
    let write = &["get", "create", "patch", "delete"];
    vec![
        rule("", &["configmaps"], &["get", "list", "watch"]),
        rule("", &["pods"], &["list"]),
        rule("apps", &["replicasets", "statefulsets"], &["get"]),
        rule(
            "apps",
            &["deployments"],
            &["get", "list", "watch", "create", "patch", "delete"],
        ),
        rule(
            "",
            &["services", "serviceaccounts", "persistentvolumeclaims"],
            write,
        ),
        rule("policy", &["poddisruptionbudgets"], write),
        rule(
            "networking.k8s.io",
            &["ingresses", "networkpolicies"],
            write,
        ),
        rule("autoscaling", &["horizontalpodautoscalers"], write),
        rule(GROUP, &["batlehubmaintenances"], &["delete"]),
    ]
}

/// The kit's Secrets and Events rules: in its ClusterRole
/// (`params.clusterSecrets: true`) and in the watch Role.
fn secrets_and_events() -> Vec<PolicyRule> {
    vec![
        PolicyRule {
            api_groups: Some(vec!["".into()]),
            resources: Some(vec!["secrets".into()]),
            verbs: ["get", "create", "update", "patch", "delete"]
                .map(String::from)
                .to_vec(),
            ..Default::default()
        },
        PolicyRule {
            api_groups: Some(vec!["events.k8s.io".into()]),
            resources: Some(vec!["events".into()]),
            verbs: vec!["create".into(), "patch".into()],
            ..Default::default()
        },
    ]
}

fn meta(name: &str, namespace: Option<&str>) -> ObjectMeta {
    ObjectMeta {
        name: Some(name.into()),
        namespace: namespace.map(String::from),
        ..Default::default()
    }
}

fn subject() -> Vec<Subject> {
    vec![Subject {
        kind: "ServiceAccount".into(),
        name: OPERATOR_SA.into(),
        namespace: Some(OPERATOR_NS.into()),
        ..Default::default()
    }]
}

fn role_ref(kind: &str, name: &str) -> RoleRef {
    RoleRef {
        api_group: Some("rbac.authorization.k8s.io".into()),
        kind: kind.into(),
        name: name.into(),
    }
}

/// What the chart renders with `watch.namespace: <watched>`; without
/// `cluster_kinds` (`watch.clusterKinds: false`), no ClusterRole at all.
async fn grant_rbac(admin: &Client, watched: &str, cluster_kinds: bool) {
    let pp = PostParams::default();
    for ns in [OPERATOR_NS, watched, "elsewhere"] {
        Api::<Namespace>::all(admin.clone())
            .create(
                &pp,
                &Namespace {
                    metadata: meta(ns, None),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
    if cluster_kinds {
        Api::<ClusterRole>::all(admin.clone())
            .create(
                &pp,
                &ClusterRole {
                    metadata: meta("operator", None),
                    rules: Some(secrets_and_events()),
                    ..Default::default()
                },
            )
            .await
            .unwrap();
        Api::<ClusterRoleBinding>::all(admin.clone())
            .create(
                &pp,
                &ClusterRoleBinding {
                    metadata: meta("operator", None),
                    role_ref: role_ref("ClusterRole", "operator"),
                    subjects: Some(subject()),
                },
            )
            .await
            .unwrap();
    }
    let mut rules = kind_rules(NAMESPACED_KINDS);
    rules.extend(secrets_and_events());
    rules.extend(namespaced_rules());
    Api::<Role>::namespaced(admin.clone(), watched)
        .create(
            &pp,
            &Role {
                metadata: meta("operator-watch", Some(watched)),
                rules: Some(rules),
            },
        )
        .await
        .unwrap();
    Api::<RoleBinding>::namespaced(admin.clone(), watched)
        .create(
            &pp,
            &RoleBinding {
                metadata: meta("operator-watch", Some(watched)),
                role_ref: role_ref("Role", "operator-watch"),
                subjects: Some(subject()),
            },
        )
        .await
        .unwrap();
}

fn labelled<K: kube::Resource>(mut object: K, labels: &[(&str, &str)]) -> K {
    object.meta_mut().labels = Some(
        labels
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect(),
    );
    object
}

fn local_instance(name: &str) -> LocalInstance {
    LocalInstance::new(
        name,
        LocalInstanceSpec {
            external: Some(ExternalInstance {
                url: "https://batlehub.example".into(),
                admin_token_secret_ref: LocalSecretKeyRef {
                    name: "token".into(),
                    key: "token".into(),
                },
                tls: Default::default(),
                manage_config: false,
                pod_selector: None,
            }),
            managed: None,
            config: Default::default(),
            config_layers: vec![],
            reload: Default::default(),
            registry_selector: Default::default(),
        },
    )
}

/// The operator's context, as `operator::main` builds it for `scope`, on
/// the operator's own (RBAC-limited) client.
fn ctx(operator: &Client, scope: WatchScope) -> (Arc<Ctx>, Arc<Health>) {
    ctx_with(
        operator,
        scope,
        Arc::new(application::test_support::FakeWorkloads::default()),
    )
}

/// [`ctx`] with `workloads` (the real `KubeWorkloads`, on the operator's
/// client, to apply a managed instance's objects with the chart's RBAC).
fn ctx_with(
    operator: &Client,
    scope: WatchScope,
    workloads: Arc<dyn application::ports::Workloads>,
) -> (Arc<Ctx>, Arc<Health>) {
    let health = Arc::new(Health::default());
    let instances = Arc::new(LocalInstanceDirectory::new(operator.clone()).with_scope(
        scope.watched_namespace().map(String::from),
        scope.selector().cloned(),
    ));
    let ctx = Arc::new(Ctx {
        client: operator.clone(),
        gateways: Arc::new(StaticGatewayFactory::new(Arc::new(FakeGateway::default()))),
        instances: instances.clone(),
        registries: instances,
        dependents: Arc::new(FakeDependents::default()),
        workloads,
        operator: Default::default(),
        token_review_role: None,
        config: Arc::new(FakeConfigParser),
        sources: Arc::new(FakeSources::default()),
        recorder: Recorder::new(
            operator.clone(),
            Reporter {
                controller: controller::FIELD_MANAGER.into(),
                instance: None,
            },
        ),
        shutdown: Shutdown::never(),
        health: health.clone(),
        scope,
        images: Default::default(),
    });
    (ctx, health)
}

/// `Ready`'s status and reason, once there is one.
fn ready(instance: &LocalInstance) -> Option<(String, String)> {
    let c = weebo_kit_api::status::ready(&instance.status.as_ref()?.conditions)?;
    Some((c.status.clone(), c.reason.clone()))
}

async fn operator_client(cluster: &EnvTestCluster) -> Client {
    cluster
        .client_as_service_account(OPERATOR_NS, OPERATOR_SA)
        .await
}

#[tokio::test]
async fn a_namespaced_scope_runs_on_namespaced_rbac_and_sees_only_its_instances() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = testkit::envtest::start().await;
    let admin = cluster.client();
    grant_rbac(&admin, "team-a", true).await;
    let operator = operator_client(&cluster).await;

    // The RBAC is as narrow as intended: no cluster-wide list of the kind.
    assert!(
        Api::<LocalInstance>::all(operator.clone())
            .list(&Default::default())
            .await
            .is_err(),
        "the operator's account must not list instances cluster-wide"
    );

    let scope = WatchScope::namespace("team-a")
        .with_labels(LabelSelector {
            match_labels: Some(BTreeMap::from([("shard".into(), "a".into())])),
            ..Default::default()
        })
        .unwrap();
    let (ctx, health) = ctx(&operator, scope);
    tokio::spawn(controller::local_instance::run(
        operator.clone(),
        ctx.clone(),
    ));
    tokio::spawn(controller::registry::run(operator.clone(), ctx));

    let pp = PostParams::default();
    let shard_a = [("shard", "a")];
    let team_a: Api<LocalInstance> = Api::namespaced(admin.clone(), "team-a");
    let elsewhere: Api<LocalInstance> = Api::namespaced(admin.clone(), "elsewhere");
    team_a
        .create(&pp, &labelled(local_instance("in-scope"), &shard_a))
        .await
        .unwrap();
    team_a
        .create(
            &pp,
            &labelled(local_instance("other-shard"), &[("shard", "b")]),
        )
        .await
        .unwrap();
    elsewhere
        .create(&pp, &labelled(local_instance("other-namespace"), &shard_a))
        .await
        .unwrap();

    // In scope: reconciled with the namespaced RBAC alone.
    let state = testkit::polling::wait_for(&team_a, "in-scope", TIMEOUT, POLL, ready).await;
    assert_eq!(state, ("True".into(), "Reconciled".into()));

    // Out of scope: never touched, and the watches never failed.
    tokio::time::sleep(Duration::from_secs(2)).await;
    for (api, name) in [(&team_a, "other-shard"), (&elsewhere, "other-namespace")] {
        let untouched = api.get(name).await.unwrap();
        assert!(untouched.status.is_none(), "{name} was reconciled");
    }
    assert_eq!(health.live(), Ok(()));
}

/// Fully namespaced (`watch.clusterKinds: false`): no ClusterRole at all,
/// the managed instance's rules in the watch Role (`params.watchRules`).
/// Its objects are applied and its Deployments and ConfigMaps watched
/// with that Role alone; its deletion reads no cluster-scoped binding
/// (no TokenReview role in this mode).
#[tokio::test]
async fn a_managed_instance_runs_on_the_watch_role_alone_and_is_deletable() {
    use k8s_openapi::api::apps::v1::Deployment;

    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = testkit::envtest::start().await;
    let admin = cluster.client();
    grant_rbac(&admin, "team-a", false).await;
    let operator = operator_client(&cluster).await;
    let scope = WatchScope::namespace("team-a")
        .without_cluster_kinds()
        .unwrap();
    let (ctx, health) = ctx_with(
        &operator,
        scope,
        Arc::new(adapters_outbound::KubeWorkloads::new(operator.clone())),
    );
    tokio::spawn(controller::local_instance::run(operator.clone(), ctx));

    let mut managed = local_instance("managed");
    managed.spec.external = None;
    managed.spec.managed = Some(Default::default());
    managed.spec.config = serde_json::json!({
        "server": {"host": "0.0.0.0", "port": 8080},
        "storage": {"type": "filesystem", "path": "/var/cache/batlehub"},
    });
    let team_a: Api<LocalInstance> = Api::namespaced(admin.clone(), "team-a");
    team_a
        .create(&PostParams::default(), &managed)
        .await
        .unwrap();
    // Applied by the operator's own account: the Role's rules suffice.
    let deployments: Api<Deployment> = Api::namespaced(admin.clone(), "team-a");
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while deployments.get_opt("managed").await.unwrap().is_none() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the Deployment was never applied: {:?}",
            team_a.get("managed").await.unwrap().status
        );
        tokio::time::sleep(POLL).await;
    }
    let state = testkit::polling::wait_for(&team_a, "managed", TIMEOUT, POLL, ready).await;
    assert!(
        !["InvalidSpec", "KubernetesApiError"].contains(&state.1.as_str()),
        "{state:?}"
    );
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert_eq!(health.live(), Ok(()), "a watch failed on the Role alone");

    team_a.delete("managed", &Default::default()).await.unwrap();
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while team_a.get_opt("managed").await.unwrap().is_some() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "the finalizer stayed"
        );
        tokio::time::sleep(POLL).await;
    }
}

/// The chart's rules for the TokenReview binding: `create` (which RBAC
/// can't restrict by name), `get`/`patch` on the one binding named after
/// the chart's ClusterRole, `get`/`bind` on that ClusterRole — no
/// `delete`, nothing on any other binding.
fn token_review_rules(role: &str) -> Vec<PolicyRule> {
    let rule = |resource: &str, verbs: &[&str], names: Option<&str>| PolicyRule {
        api_groups: Some(vec!["rbac.authorization.k8s.io".into()]),
        resources: Some(vec![resource.into()]),
        verbs: verbs.iter().map(|v| v.to_string()).collect(),
        resource_names: names.map(|n| vec![n.to_string()]),
        ..Default::default()
    };
    vec![
        rule("clusterrolebindings", &["create"], None),
        rule("clusterrolebindings", &["get", "patch"], Some(role)),
        rule("clusterroles", &["get", "bind"], Some(role)),
    ]
}

#[tokio::test]
async fn the_token_review_binding_is_shared_and_edited_with_the_chart_rules_only() {
    use adapters_outbound::KubeWorkloads;
    use application::ports::{Owner, Workloads};
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = testkit::envtest::start().await;
    let admin = cluster.client();
    grant_rbac(&admin, "team-a", true).await;
    const ROLE: &str = "weebo-batlehub-tokenreview";
    let pp = PostParams::default();
    Api::<ClusterRole>::all(admin.clone())
        .create(
            &pp,
            &ClusterRole {
                metadata: meta(ROLE, None),
                rules: Some(vec![PolicyRule {
                    api_groups: Some(vec!["authentication.k8s.io".into()]),
                    resources: Some(vec!["tokenreviews".into()]),
                    verbs: vec!["create".into()],
                    ..Default::default()
                }]),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    Api::<ClusterRole>::all(admin.clone())
        .create(
            &pp,
            &ClusterRole {
                metadata: meta("operator-tokenreview-binding", None),
                rules: Some(token_review_rules(ROLE)),
                ..Default::default()
            },
        )
        .await
        .unwrap();
    Api::<ClusterRoleBinding>::all(admin.clone())
        .create(
            &pp,
            &ClusterRoleBinding {
                metadata: meta("operator-tokenreview-binding", None),
                role_ref: role_ref("ClusterRole", "operator-tokenreview-binding"),
                subjects: Some(subject()),
            },
        )
        .await
        .unwrap();
    let operator = operator_client(&cluster).await;
    let workloads = KubeWorkloads::new(operator.clone());
    let owner = |ns: &str, name: &str| Owner {
        namespace: ns.into(),
        name: name.into(),
        uid: format!("{ns}-{name}"),
    };
    let subjects = || async {
        let binding = Api::<ClusterRoleBinding>::all(admin.clone())
            .get(ROLE)
            .await
            .unwrap();
        binding
            .subjects
            .unwrap_or_default()
            .into_iter()
            .map(|s| format!("{}/{}", s.namespace.unwrap_or_default(), s.name))
            .collect::<Vec<_>>()
    };

    // Two instances share an account, a third has its own.
    workloads
        .bind_token_review(&owner("team-a", "hub"), "batlehub", ROLE)
        .await
        .unwrap();
    workloads
        .bind_token_review(&owner("team-a", "hub-2"), "batlehub", ROLE)
        .await
        .unwrap();
    workloads
        .bind_token_review(&owner("elsewhere", "hub"), "hub", ROLE)
        .await
        .unwrap();
    assert_eq!(subjects().await, ["elsewhere/hub", "team-a/batlehub"]);
    let binding = Api::<ClusterRoleBinding>::all(admin.clone())
        .get(ROLE)
        .await
        .unwrap();
    // Gone with the chart's ClusterRole.
    assert_eq!(
        binding.metadata.owner_references.unwrap()[0].name,
        ROLE.to_string()
    );

    // The shared account stays while one instance still binds it.
    workloads
        .unbind_token_review(&owner("team-a", "hub"), ROLE)
        .await
        .unwrap();
    assert_eq!(subjects().await, ["elsewhere/hub", "team-a/batlehub"]);
    workloads
        .unbind_token_review(&owner("team-a", "hub-2"), ROLE)
        .await
        .unwrap();
    workloads
        .unbind_token_review(&owner("elsewhere", "hub"), ROLE)
        .await
        .unwrap();
    assert!(subjects().await.is_empty());
    // Unbinding twice is fine.
    workloads
        .unbind_token_review(&owner("elsewhere", "hub"), ROLE)
        .await
        .unwrap();

    // Nothing else: no other binding read, patched or deleted.
    let bindings = Api::<ClusterRoleBinding>::all(operator);
    assert!(bindings.get("operator").await.is_err());
    assert!(bindings.delete(ROLE, &Default::default()).await.is_err());
}
