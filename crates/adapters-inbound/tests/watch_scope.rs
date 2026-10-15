//! Integration tests: the controllers limited to one namespace
//! (`WatchScope`), running as a ServiceAccount that only has the RBAC the
//! chart renders for that scope, with the real instance resolution
//! (`LocalInstanceDirectory`) — the gateway alone is in memory. The
//! control plane authorizes with RBAC: a call outside the granted scope is
//! refused.
//!
//! `watch.namespace` (+ a label selector): the kinds in a Role of the
//! watched namespace; Secrets and Events in the ClusterRole
//! (`params.clusterSecrets: true`). BatleHub has no cluster-scoped kind,
//! and the chart refuses `watch.clusterKinds: false` (spec §7.1).
//!
//! The rules below mirror the library chart's `clusterRole` and
//! `watchRole` (`weebo-operator.kindRules`): keep them in step.

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

/// The kit's ClusterRole (Secrets, Events) and the chart's
/// `params.clusterRules`, which stay cluster-wide with `watch.namespace`.
fn secrets_and_events() -> Vec<PolicyRule> {
    vec![
        PolicyRule {
            api_groups: Some(vec!["".into()]),
            resources: Some(vec![
                "configmaps".into(),
                "pods".into(),
                "namespaces".into(),
            ]),
            verbs: ["get", "list", "watch"].map(String::from).to_vec(),
            ..Default::default()
        },
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

/// What the chart renders with `watch.namespace: <watched>`.
async fn grant_rbac(admin: &Client, watched: &str) {
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
    Api::<Role>::namespaced(admin.clone(), watched)
        .create(
            &pp,
            &Role {
                metadata: meta("operator-watch", Some(watched)),
                rules: Some(kind_rules(NAMESPACED_KINDS)),
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
        workloads: Arc::new(application::test_support::FakeWorkloads::default()),
        operator_namespace: None,
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
    grant_rbac(&admin, "team-a").await;
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
