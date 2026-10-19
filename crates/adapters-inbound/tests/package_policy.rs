//! Integration tests of `BatleHubPackagePolicy` on a real control plane
//! (envtest), with the real instance resolution and dependents — only the
//! instance is in memory (`FakeGateway`, which keeps policies as BatleHub
//! does: one per node, exemptions as its `rules`, a `PUT` replacing it).

use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{
    BatleHubConfigParser, ClusterDependents, KubeConfigSources, LocalInstanceDirectory,
};
use api::local_instance::{ExternalInstance, LocalInstanceSpec, LocalSecretKeyRef};
use api::package_policy::{DeletionPolicy, Gate, GateExemption, PackagePolicySpec};
use api::{LocalInstance, PackagePolicy};
use application::ports::PackageNode;
use k8s_openapi::api::core::v1::Namespace;
use kube::Client;
use kube::api::{Api, DeleteParams, ObjectMeta, Patch, PatchParams, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use serde_json::{Value, json};
use testkit::{FakeGateway, StaticGatewayFactory};
use weebo_kit_runtime::{Health, WatchScope};

const TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(200);

fn instance() -> LocalInstance {
    LocalInstance::new(
        "hub",
        LocalInstanceSpec {
            external: Some(ExternalInstance {
                url: "http://batlehub.invalid".into(),
                admin_token_secret_ref: LocalSecretKeyRef {
                    name: "token".into(),
                    key: "token".into(),
                },
                tls: Default::default(),
                manage_config: false,
                pod_selector: None,
            }),
            managed: None,
            config: Value::Null,
            config_layers: vec![],
            reload: Default::default(),
            registry_selector: Default::default(),
        },
    )
}

fn policy(name: &str, package: &str, policy: Option<Value>, exempt: bool) -> PackagePolicy {
    PackagePolicy::new(
        name,
        PackagePolicySpec {
            instance_ref: None,
            registry: "npm".into(),
            package: package.into(),
            version: Some("1.0.0".into()),
            policy,
            exemptions: if exempt {
                vec![GateExemption {
                    gate: Gate::CveGate,
                    exempt_until: "2099-01-01T00:00:00Z".into(),
                    reason: "patched downstream".into(),
                }]
            } else {
                vec![]
            },
            deletion_policy: DeletionPolicy::Delete,
        },
    )
}

fn node(package: &str) -> PackageNode {
    PackageNode {
        registry: "npm".into(),
        package: package.into(),
        version: Some("1.0.0".into()),
    }
}

fn ctx(client: &Client, gateway: Arc<FakeGateway>) -> Arc<Ctx> {
    let instances = Arc::new(LocalInstanceDirectory::new(client.clone()));
    Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(StaticGatewayFactory::new(gateway)),
        instances: instances.clone(),
        registries: instances.clone(),
        dependents: Arc::new(ClusterDependents::new(client.clone(), None)),
        workloads: Arc::new(application::test_support::FakeWorkloads::default()),
        operator: application::workload::OperatorPod::named(application::workload::OPERATOR_CHART),
        token_review_role: None,
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
        images: Default::default(),
        watches: Default::default(),
    })
}

/// `Ready`'s message, once its reason is `reason`.
fn ready_on<K>(reason: &'static str) -> impl Fn(&K) -> Option<String>
where
    K: Conditions,
{
    move |object| {
        let c = weebo_kit_api::status::ready(object.conditions()?)?;
        (c.reason == reason).then(|| c.message.clone())
    }
}

trait Conditions {
    fn conditions(&self) -> Option<&Vec<api::status::Condition>>;
}

impl Conditions for PackagePolicy {
    fn conditions(&self) -> Option<&Vec<api::status::Condition>> {
        self.status.as_ref().map(|s| &s.conditions)
    }
}

impl Conditions for LocalInstance {
    fn conditions(&self) -> Option<&Vec<api::status::Condition>> {
        self.status.as_ref().map(|s| &s.conditions)
    }
}

async fn gone(policies: &Api<PackagePolicy>, name: &str) {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while policies.get_opt(name).await.unwrap().is_some() {
        assert!(tokio::time::Instant::now() < deadline, "{name} still there");
        tokio::time::sleep(POLL).await;
    }
}

/// `condition` holds for the fake within the timeout.
async fn until(gateway: &FakeGateway, condition: impl Fn(&FakeGateway) -> bool) {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while !condition(gateway) {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{:?}",
            gateway.calls()
        );
        tokio::time::sleep(POLL).await;
    }
}

#[tokio::test]
async fn policies_are_written_exemptions_carried_and_never_taken_over() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    Api::<Namespace>::all(client.clone())
        .create(
            &PostParams::default(),
            &Namespace {
                metadata: ObjectMeta {
                    name: Some("infra".into()),
                    ..Default::default()
                },
                ..Default::default()
            },
        )
        .await
        .unwrap();
    let instances: Api<LocalInstance> = Api::namespaced(client.clone(), "infra");
    instances
        .create(&PostParams::default(), &instance())
        .await
        .unwrap();

    let gateway = Arc::new(FakeGateway::default());
    gateway.serve(&["npm"]);
    gateway.allow_exemptions(true);
    gateway.put_policy_row(&node("@acme/other"), json!({"visibility": "public"}));
    let policies: Api<PackagePolicy> = Api::namespaced(client.clone(), "infra");
    let pp = PostParams::default();
    policies
        .create(
            &pp,
            &policy(
                "billing",
                "@acme/billing",
                Some(json!({"visibility": "team"})),
                true,
            ),
        )
        .await
        .unwrap();
    policies
        .create(
            &pp,
            &policy(
                "taken",
                "@acme/other",
                Some(json!({"visibility": "private"})),
                false,
            ),
        )
        .await
        .unwrap();
    // Neither a policy nor an exemption, or an exemption of a package:
    // refused by the CRD.
    assert!(
        policies
            .create(&pp, &policy("empty", "@acme/x", None, false))
            .await
            .is_err()
    );
    let mut of_package = policy("of-package", "@acme/x", None, true);
    of_package.spec.version = None;
    assert!(policies.create(&pp, &of_package).await.is_err());

    let ctx = ctx(&client, gateway.clone());
    tokio::spawn(controller::package_policy::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::local_instance::run(client.clone(), ctx));
    let wait = |name: &'static str, reason: &'static str| {
        let policies = policies.clone();
        async move { testkit::polling::wait_for(&policies, name, TIMEOUT, POLL, ready_on(reason)).await }
    };

    wait("billing", "Reconciled").await;
    let status = policies.get("billing").await.unwrap().status.unwrap();
    assert!(status.applied_policy_hash.is_some());
    assert!(status.observed_policy_hash.is_some());
    assert_eq!(status.applied_exemptions.len(), 1);
    assert!(status.last_sync_time.is_some());
    let stored = gateway.stored_policy(&node("@acme/billing")).unwrap();
    assert_eq!(stored["visibility"], "team");
    assert_eq!(stored["rules"][0]["gate"], "cve_gate");
    wait("taken", "PolicyConflict").await;

    // The policy out of the spec: cleared, the exemption kept.
    policies
        .patch(
            "billing",
            &PatchParams::default(),
            &Patch::Merge(json!({"spec": {"policy": null}})),
        )
        .await
        .unwrap();
    until(&gateway, |g| {
        g.stored_policy(&node("@acme/billing"))
            .is_some_and(|p| p.get("visibility").is_none())
    })
    .await;
    let stored = gateway.stored_policy(&node("@acme/billing")).unwrap();
    assert_eq!(stored["rules"][0]["gate"], "cve_gate");

    // Deleted: its exemption removed.
    policies
        .delete("billing", &DeleteParams::default())
        .await
        .unwrap();
    gone(&policies, "billing").await;
    assert_eq!(
        gateway.stored_policy(&node("@acme/billing")).unwrap()["rules"],
        json!([])
    );

    // The instance waits for the policies still bound to it; the conflict's
    // node is never touched.
    instances
        .delete("hub", &DeleteParams::default())
        .await
        .unwrap();
    let message = testkit::polling::wait_for(
        &instances,
        "hub",
        TIMEOUT,
        POLL,
        ready_on::<LocalInstance>("InstanceInUse"),
    )
    .await;
    assert!(
        message.contains("BatleHubPackagePolicy/infra/taken"),
        "{message}"
    );
    policies
        .delete("taken", &DeleteParams::default())
        .await
        .unwrap();
    gone(&policies, "taken").await;
    assert_eq!(
        gateway.stored_policy(&node("@acme/other")),
        Some(json!({"visibility": "public"}))
    );
}
