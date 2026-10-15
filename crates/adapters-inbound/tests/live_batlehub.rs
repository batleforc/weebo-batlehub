//! The `BatleHubLocalInstance` controller end to end, on envtest, against a
//! real BatleHub (`task test:live-batlehub`, ignored by default; see
//! `adapters-outbound/tests/live_batlehub.rs` for the variables).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{
    BatleHubConfigParser, ClusterDependents, HttpGatewayFactory, KubeConfigSources,
    LocalInstanceDirectory,
};
use api::local_instance::{ExternalInstance, LocalInstanceSpec, LocalSecretKeyRef};
use api::namespace_claim::{DeletionPolicy, NamespaceClaimSpec};
use api::package_grant::{PackageGrantSpec, SubjectGrant};
use api::package_policy::{Gate, GateExemption, PackagePolicySpec};
use api::registry::RegistrySpec;
use api::{LocalInstance, NamespaceClaim, PackageGrant, PackagePolicy, Registry};
use application::ports::{AdminGateway, AdminRequest, Method, PackageNode};
use k8s_openapi::api::core::v1::{Namespace, Secret};
use kube::Client;
use kube::api::{Api, DeleteParams, ObjectMeta, Patch, PatchParams, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use serde_json::json;
use weebo_kit_runtime::{Health, WatchScope};

const TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(200);
const NS: &str = "live";

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

async fn create<K>(client: &Client, object: &K)
where
    K: kube::Resource<Scope = k8s_openapi::NamespaceResourceScope, DynamicType = ()>
        + Clone
        + serde::Serialize
        + serde::de::DeserializeOwned
        + std::fmt::Debug,
{
    Api::<K>::namespaced(client.clone(), NS)
        .create(&PostParams::default(), object)
        .await
        .unwrap();
}

/// A labelled token Secret and the instance using it.
async fn instance(client: &Client, name: &str, token: &str) {
    instance_with(client, name, token, false, serde_json::Value::Null).await;
}

async fn instance_with(
    client: &Client,
    name: &str,
    token: &str,
    manage_config: bool,
    config: serde_json::Value,
) {
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(name.into()),
            labels: Some(BTreeMap::from([(
                "batlehub.weebo.io/instance-token".into(),
                "true".into(),
            )])),
            ..Default::default()
        },
        string_data: Some(BTreeMap::from([("token".into(), token.into())])),
        ..Default::default()
    };
    create(client, &secret).await;
    let instance = LocalInstance::new(
        name,
        LocalInstanceSpec {
            external: ExternalInstance {
                url: env("BATLEHUB_URL"),
                admin_token_secret_ref: LocalSecretKeyRef {
                    name: name.into(),
                    key: "token".into(),
                },
                tls: Default::default(),
                manage_config,
                pod_selector: None,
            },
            config,
            config_layers: vec![],
            reload: Default::default(),
            registry_selector: Default::default(),
        },
    );
    create(client, &instance).await;
}

fn ctx(client: &Client) -> Arc<Ctx> {
    let instances = Arc::new(LocalInstanceDirectory::new(client.clone()));
    Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(HttpGatewayFactory::new(client.clone(), instances.clone())),
        instances: instances.clone(),
        registries: instances.clone(),
        dependents: Arc::new(ClusterDependents::new(client.clone(), None)),
        config: Arc::new(BatleHubConfigParser::default()),
        sources: Arc::new(KubeConfigSources::new(client.clone(), instances)),
        recorder: Recorder::new(
            client.clone(),
            Reporter {
                controller: controller::FIELD_MANAGER.into(),
                instance: None,
            },
        ),
        shutdown: Shutdown::never(),
        health: Arc::new(Health::default()),
        scope: WatchScope::cluster(),
    })
}

fn ready(instance: &LocalInstance) -> Option<(String, String, String)> {
    let c = weebo_kit_api::status::ready(&instance.status.as_ref()?.conditions)?;
    Some((c.status.clone(), c.reason.clone(), c.message.clone()))
}

#[tokio::test]
#[ignore = "needs a real BatleHub (task test:live-batlehub)"]
async fn a_real_instance_is_ready_with_the_admin_token_only() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    Api::<Namespace>::all(client.clone())
        .create(
            &PostParams::default(),
            &Namespace {
                metadata: ObjectMeta {
                    name: Some(NS.into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    instance(&client, "admin", &env("BATLEHUB_ADMIN_TOKEN")).await;
    instance(&client, "user", &env("BATLEHUB_USER_TOKEN")).await;

    let ctx = ctx(&client);
    tokio::spawn(controller::local_instance::run(client.clone(), ctx));

    let api: Api<LocalInstance> = Api::namespaced(client.clone(), NS);
    let (status, reason, _) = testkit::polling::wait_for(&api, "admin", TIMEOUT, POLL, ready).await;
    assert_eq!((status.as_str(), reason.as_str()), ("True", "Reconciled"));
    let admin = api.get("admin").await.unwrap();
    let observed = admin.status.unwrap();
    assert!(observed.version.is_some_and(|v| !v.is_empty()));
    assert_eq!(observed.endpoint, Some(env("BATLEHUB_URL")));
    // BatleHub's warnings come with their advisory.
    let advisory = observed
        .conditions
        .iter()
        .any(|c| c.type_ == "ConfigWarnings");
    assert_eq!(advisory, !observed.warnings.is_empty());

    let (status, reason, message) =
        testkit::polling::wait_for(&api, "user", TIMEOUT, POLL, ready).await;
    assert_eq!(
        (status.as_str(), reason.as_str()),
        ("False", "OperatorUnauthorized")
    );
    assert!(message.contains("\"user\""), "{message}");
}

/// `deploy/live/config.toml`, as YAML: what the live BatleHub runs.
fn live_config() -> serde_json::Value {
    json!({
        "server": {"host": "0.0.0.0", "port": 8080},
        "database": {
            "type": "postgresql",
            "url": "postgresql://batlehub:batlehub@weebo-batlehub-test-db:5432/batlehub",
            "max_connections": 5,
        },
        "storage": {"type": "filesystem", "path": "/var/cache/batlehub"},
        "auth": [{"type": "token", "tokens": [
            {"value": env("BATLEHUB_ADMIN_TOKEN"), "role": "admin", "user_id": "weebo-batlehub-operator"},
            {"value": env("BATLEHUB_USER_TOKEN"), "role": "user", "user_id": "live-user"},
        ]}],
    })
}

fn reason(instance: &LocalInstance) -> Option<String> {
    ready(instance).map(|(_, reason, _)| reason)
}

#[tokio::test]
#[ignore = "needs a real BatleHub (task test:live-batlehub)"]
async fn a_real_instance_runs_the_configuration_and_registries_pushed() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    Api::<Namespace>::all(client.clone())
        .create(
            &PostParams::default(),
            &Namespace {
                metadata: ObjectMeta {
                    name: Some(NS.into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    instance_with(
        &client,
        "hub",
        &env("BATLEHUB_ADMIN_TOKEN"),
        true,
        live_config(),
    )
    .await;
    let registry = Registry::new(
        "live-npm",
        RegistrySpec {
            instance_ref: None,
            r#type: "npm".into(),
            name: None,
            config: json!({"upstreams": ["https://registry.npmjs.org"]}),
            config_from: vec![],
            suspend: false,
        },
    );
    create(&client, &registry).await;
    let ctx = ctx(&client);
    tokio::spawn(controller::local_instance::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::registry::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::namespace_claim::run(
        client.clone(),
        ctx.clone(),
    ));
    tokio::spawn(controller::package_grant::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::package_policy::run(client.clone(), ctx));

    let api: Api<LocalInstance> = Api::namespaced(client.clone(), NS);
    let until = |want: &'static str| {
        let api = api.clone();
        async move {
            testkit::polling::wait_for(&api, "hub", TIMEOUT, POLL, |i| {
                reason(i).filter(|r| r == want)
            })
            .await
        }
    };
    until("Reconciled").await;
    let status = api.get("hub").await.unwrap().status.unwrap();
    assert!(status.applied_config_hash.is_some());
    assert_eq!(status.applied_config_hash, status.config_hash);

    let batlehub = adapters_outbound::HttpAdminGateway::new(
        &env("BATLEHUB_URL"),
        env("BATLEHUB_ADMIN_TOKEN"),
        adapters_outbound::HttpAdminGateway::client(None, false).unwrap(),
    )
    .unwrap();
    let content = batlehub.config_content().await.unwrap();
    assert!(content.contains("name = \"live-npm\""), "{content}");
    let registries: Api<Registry> = Api::namespaced(client.clone(), NS);
    let state = testkit::polling::wait_for(&registries, "live-npm", TIMEOUT, POLL, |r| {
        let c = weebo_kit_api::status::ready(&r.status.as_ref()?.conditions)?;
        (c.reason == "Reconciled").then(|| r.status.clone().unwrap())
    })
    .await;
    assert_eq!(state.instance_config_hash, status.config_hash);

    // A key BatleHub reads at startup only: held back, the file untouched.
    api.patch(
        "hub",
        &PatchParams::default(),
        &Patch::Merge(json!({"spec": {"config": {"database": {"max_connections": 7}}}})),
    )
    .await
    .unwrap();
    until("RestartForbidden").await;
    let held = api.get("hub").await.unwrap().status.unwrap();
    assert_eq!(held.restart_keys, ["database.max_connections"]);
    assert_eq!(batlehub.config_content().await.unwrap(), content);
    // Reverted, it is in sync again without a push.
    api.patch(
        "hub",
        &PatchParams::default(),
        &Patch::Merge(json!({"spec": {"config": {"database": {"max_connections": 5}}}})),
    )
    .await
    .unwrap();
    until("Reconciled").await;

    // A team namespace of the pushed registry, its prefix holding a slash:
    // claimed, read back, then released by the finalizer.
    let claims: Api<NamespaceClaim> = Api::namespaced(client.clone(), NS);
    let claim = NamespaceClaim::new(
        "web-libs",
        NamespaceClaimSpec {
            instance_ref: None,
            registry: "live-npm".into(),
            prefix: "web/libs".into(),
            group: "oidc:web-team".into(),
            deletion_policy: DeletionPolicy::Delete,
        },
    );
    claims.create(&PostParams::default(), &claim).await.unwrap();
    testkit::polling::wait_for(&claims, "web-libs", TIMEOUT, POLL, |c| {
        let ready = weebo_kit_api::status::ready(&c.status.as_ref()?.conditions)?;
        (ready.reason == "Reconciled").then_some(())
    })
    .await;
    let held = batlehub.team_namespaces("live-npm").await.unwrap();
    let held = held.iter().find(|n| n.prefix == "web/libs").unwrap();
    assert_eq!(held.group, "oidc:web-team");
    assert_eq!(
        held.claimed_by.as_deref(),
        Some("weebo-batlehub:live/web-libs")
    );
    claims
        .delete("web-libs", &DeleteParams::default())
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while claims.get_opt("web-libs").await.unwrap().is_some() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "web-libs not released"
        );
        tokio::time::sleep(POLL).await;
    }
    assert!(
        batlehub
            .team_namespaces("live-npm")
            .await
            .unwrap()
            .iter()
            .all(|n| n.prefix != "web/libs")
    );

    governance(&client, &batlehub).await;
}

/// `name`'s `Ready` reason, once it is `want`; its message.
async fn reason_of<K>(api: &Api<K>, name: &str, want: &'static str) -> String
where
    K: kube::Resource<DynamicType = ()>
        + Clone
        + std::fmt::Debug
        + serde::de::DeserializeOwned
        + serde::Serialize
        + HasConditions,
{
    testkit::polling::wait_for(api, name, TIMEOUT, POLL, |o: &K| {
        let ready = weebo_kit_api::status::ready(o.conditions()?)?;
        (ready.reason == want).then(|| ready.message.clone())
    })
    .await
}

trait HasConditions {
    fn conditions(&self) -> Option<&Vec<api::status::Condition>>;
}

impl HasConditions for PackageGrant {
    fn conditions(&self) -> Option<&Vec<api::status::Condition>> {
        self.status.as_ref().map(|s| &s.conditions)
    }
}

impl HasConditions for PackagePolicy {
    fn conditions(&self) -> Option<&Vec<api::status::Condition>> {
        self.status.as_ref().map(|s| &s.conditions)
    }
}

async fn gone<K>(api: &Api<K>, name: &str)
where
    K: kube::Resource<DynamicType = ()> + Clone + std::fmt::Debug + serde::de::DeserializeOwned,
{
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while api.get_opt(name).await.unwrap().is_some() {
        assert!(tokio::time::Instant::now() < deadline, "{name} still there");
        tokio::time::sleep(POLL).await;
    }
}

fn grant(name: &str, version: Option<&str>, grants: &[(&str, &[&str])]) -> PackageGrant {
    PackageGrant::new(
        name,
        PackageGrantSpec {
            instance_ref: None,
            registry: "live-npm".into(),
            package: "@live/billing".into(),
            version: version.map(String::from),
            grants: grants
                .iter()
                .map(|(subject, actions)| SubjectGrant {
                    subject: subject.to_string(),
                    actions: actions.iter().map(|a| a.to_string()).collect(),
                })
                .collect(),
            deletion_policy: DeletionPolicy::Delete,
        },
    )
}

/// Grants and policies on the pushed registry, through their controllers:
/// written, read back, drift rewritten, conflicts and refusals reported,
/// revoked and cleared on deletion.
async fn governance(client: &Client, batlehub: &adapters_outbound::HttpAdminGateway) {
    let package = PackageNode {
        registry: "live-npm".into(),
        package: "@live/billing".into(),
        version: None,
    };
    let grants: Api<PackageGrant> = Api::namespaced(client.clone(), NS);
    let pp = PostParams::default();

    // Someone else's grant (the console's), and an owner.
    batlehub
        .put_grant(&package, "user:bob", &["releases:read".to_string()])
        .await
        .unwrap();
    // An owner already added by a previous run answers 409: the same.
    let _ = batlehub
        .call(&AdminRequest {
            method: Method::Post,
            path: [
                "api",
                "v1",
                "admin",
                "registries",
                "live-npm",
                "packages",
                "@live/billing",
                "owners",
            ]
            .map(String::from)
            .to_vec(),
            query: vec![],
            body: Some(json!({"principal_type": "user", "principal_id": "carol"})),
        })
        .await;

    // Partial failure: bob is a conflict, alice and the operator's own
    // `gates:exempt` written and recorded.
    grants
        .create(
            &pp,
            &grant(
                "billing",
                None,
                &[
                    ("user:alice", &["releases:*"]),
                    ("user:bob", &["releases:publish"]),
                    ("user:weebo-batlehub-operator", &["gates:exempt"]),
                ],
            ),
        )
        .await
        .unwrap();
    let message = reason_of(&grants, "billing", "GrantConflict").await;
    assert!(message.contains("user:bob"), "{message}");
    let applied = grants.get("billing").await.unwrap().status.unwrap().applied;
    let alice = applied.iter().find(|a| a.subject == "user:alice").unwrap();
    // `releases:*` as BatleHub stores it.
    assert!(alice.stored.len() > 1, "{alice:?}");
    assert!(applied.iter().all(|a| a.subject != "user:bob"));
    let rows = batlehub.grants(&package).await.unwrap();
    let bob = rows.iter().find(|r| r.subject == "user:bob").unwrap();
    assert_eq!(bob.actions, ["releases:read"]);

    // An owner, and a version that doesn't exist.
    grants
        .create(
            &pp,
            &grant("owned", None, &[("user:carol", &["releases:read"])]),
        )
        .await
        .unwrap();
    reason_of(&grants, "owned", "GrantHeldByOwnership").await;
    grants
        .create(
            &pp,
            &grant(
                "nowhere",
                Some("9.9.9"),
                &[("user:alice", &["releases:read"])],
            ),
        )
        .await
        .unwrap();
    let message = reason_of(&grants, "nowhere", "RemoteRejected").await;
    assert!(message.contains("9.9.9"), "{message}");

    // Drift: alice's grant removed at the console, bob out of the spec —
    // the next pass writes alice again and leaves bob alone.
    batlehub.delete_grant(&package, "user:alice").await.unwrap();
    grants
        .patch(
            "billing",
            &PatchParams::default(),
            &Patch::Merge(json!({"spec": {"grants": [
                {"subject": "user:alice", "actions": ["releases:*"]},
                {"subject": "user:weebo-batlehub-operator", "actions": ["gates:exempt"]},
            ]}})),
        )
        .await
        .unwrap();
    reason_of(&grants, "billing", "Reconciled").await;
    let rows = batlehub.grants(&package).await.unwrap();
    assert!(rows.iter().any(|r| r.subject == "user:alice"));
    assert!(rows.iter().any(|r| r.subject == "user:bob"));

    // A policy and an exemption of a version: the operator holds
    // `gates:exempt` on the package through `billing`.
    let policies: Api<PackagePolicy> = Api::namespaced(client.clone(), NS);
    let policy = |name: &str, package: &str| {
        PackagePolicy::new(
            name,
            PackagePolicySpec {
                instance_ref: None,
                registry: "live-npm".into(),
                package: package.into(),
                version: Some("1.0.0".into()),
                policy: Some(json!({"visibility": "team"})),
                exemptions: vec![GateExemption {
                    gate: Gate::CveGate,
                    exempt_until: "2099-01-01T00:00:00Z".into(),
                    reason: "patched downstream".into(),
                }],
                deletion_policy: DeletionPolicy::Delete,
            },
        )
    };
    policies
        .create(&pp, &policy("billing", "@live/billing"))
        .await
        .unwrap();
    reason_of(&policies, "billing", "Reconciled").await;
    let version = PackageNode {
        version: Some("1.0.0".into()),
        ..package.clone()
    };
    let stored = batlehub.policy(&version).await.unwrap().unwrap();
    assert_eq!(stored["visibility"], "team");
    assert_eq!(stored["rules"][0]["gate"], "cve_gate");
    assert_eq!(stored["rules"][0]["settings"]["exempt"], true);
    let status = policies.get("billing").await.unwrap().status.unwrap();
    assert!(status.observed_policy_hash.is_some());
    assert_eq!(status.applied_exemptions.len(), 1);
    // Nobody granted it `gates:exempt` on that one.
    policies
        .create(&pp, &policy("other", "@live/other"))
        .await
        .unwrap();
    let message = reason_of(&policies, "other", "ExemptionNotPermitted").await;
    assert!(
        message.contains("user:weebo-batlehub-operator"),
        "{message}"
    );

    // Deleted: the policy and exemption cleared, the grants revoked —
    // what others wrote stays.
    for name in ["billing", "other"] {
        policies
            .delete(name, &DeleteParams::default())
            .await
            .unwrap();
        gone(&policies, name).await;
    }
    assert!(batlehub.policy(&version).await.unwrap().is_none_or(
        |p| p.get("visibility").is_none() && p["rules"].as_array().is_none_or(Vec::is_empty)
    ));
    for name in ["billing", "owned", "nowhere"] {
        grants.delete(name, &DeleteParams::default()).await.unwrap();
        gone(&grants, name).await;
    }
    let rows = batlehub.grants(&package).await.unwrap();
    assert!(rows.iter().all(|r| r.subject != "user:alice"), "{rows:?}");
    assert!(rows.iter().any(|r| r.subject == "user:bob"));
    assert!(
        rows.iter()
            .any(|r| r.subject == "user:carol" && r.from_ownership)
    );
}
