//! Integration tests of `BatleHubMaintenance` on a real control plane
//! (envtest), with the real instance resolution and dependents — only the
//! instance is in memory (`FakeGateway`, which records every admin call).

#![expect(
    clippy::unwrap_used,
    clippy::arithmetic_side_effects,
    reason = "an integration test: a failure panics with its message, fixtures are known"
)]

use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{
    BatleHubConfigParser, ClusterDependents, KubeConfigSources, LocalInstanceDirectory,
};
use api::local_instance::{ExternalInstance, LocalInstanceSpec, LocalSecretKeyRef};
use api::maintenance::{LastRun, MaintenanceAction, MaintenanceParams, MaintenanceSpec, RunState};
use api::{LocalInstance, Maintenance};
use application::ports::GatewayError;
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

fn maintenance(name: &str, action: MaintenanceAction) -> Maintenance {
    Maintenance::new(
        name,
        MaintenanceSpec {
            instance_ref: None,
            action,
            params: MaintenanceParams {
                registry: Some("npm".into()),
                ..Default::default()
            },
            schedule: None,
            suspend: false,
            ttl_seconds_after_finished: None,
            timeout_seconds: 60,
        },
    )
}

/// The calls the fake received for `path`.
fn calls(gateway: &FakeGateway, path: &str) -> usize {
    gateway
        .requests()
        .iter()
        .filter(|r| r.path.join("/") == path)
        .count()
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

impl Conditions for Maintenance {
    fn conditions(&self) -> Option<&Vec<api::status::Condition>> {
        self.status.as_ref().map(|s| &s.conditions)
    }
}

impl Conditions for LocalInstance {
    fn conditions(&self) -> Option<&Vec<api::status::Condition>> {
        self.status.as_ref().map(|s| &s.conditions)
    }
}

async fn gone(maintenances: &Api<Maintenance>, name: &str) {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while maintenances.get_opt(name).await.unwrap().is_some() {
        assert!(tokio::time::Instant::now() < deadline, "{name} still there");
        tokio::time::sleep(POLL).await;
    }
}

#[tokio::test]
async fn maintenances_run_at_most_once() {
    // Once per test binary: a later test finds it installed.
    tracing_subscriber::fmt().with_test_writer().try_init().ok();
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
    gateway.answer(Some(Ok(json!({"evicted": 2, "dry_run": true}))));
    let maintenances: Api<Maintenance> = Api::namespaced(client.clone(), "infra");
    let pp = PostParams::default();

    // The conditional start: refused on an object changed since read.
    let probe = maintenances
        .create(&pp, &maintenance("probe", MaintenanceAction::BannerClear))
        .await
        .unwrap();
    let run = LastRun {
        state: RunState::Running,
        start_time: "2026-10-15T00:00:00Z".into(),
        completion_time: None,
        generation: 1,
        reason: None,
        message: None,
        result: None,
    };
    let stale = probe.metadata.resource_version.clone().unwrap();
    assert!(
        controller::maintenance::record_start(&maintenances, "probe", &stale, &run, None)
            .await
            .unwrap()
    );
    assert!(
        !controller::maintenance::record_start(&maintenances, "probe", &stale, &run, None)
            .await
            .unwrap()
    );
    // `probe` is now left `Running`, as by an operator killed during the
    // run: closed as interrupted, never replayed.

    maintenances
        .create(&pp, &maintenance("evict", MaintenanceAction::CacheEvict))
        .await
        .unwrap();
    let mut scheduled = maintenance("nightly", MaintenanceAction::CacheEvict);
    scheduled.spec.schedule = Some("0 3 * * *".into());
    maintenances.create(&pp, &scheduled).await.unwrap();
    let mut gone_soon = maintenance("once", MaintenanceAction::ExploreInvalidate);
    gone_soon.spec.ttl_seconds_after_finished = Some(1);
    maintenances.create(&pp, &gone_soon).await.unwrap();
    // A param an action needs, refused by the CRD.
    let mut incomplete = maintenance("incomplete", MaintenanceAction::PackageBlock);
    incomplete.spec.params = MaintenanceParams::default();
    assert!(maintenances.create(&pp, &incomplete).await.is_err());

    let ctx = ctx(&client, gateway.clone());
    tokio::spawn(controller::maintenance::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::local_instance::run(client.clone(), ctx));
    let wait = |name: &'static str, reason: &'static str| {
        let maintenances = maintenances.clone();
        async move {
            testkit::polling::wait_for(&maintenances, name, TIMEOUT, POLL, ready_on(reason)).await
        }
    };

    let message = wait("probe", "MaintenanceInterrupted").await;
    assert!(message.contains("not replayed"), "{message}");
    assert_eq!(calls(&gateway, "api/v1/admin/banner"), 0);

    let message = wait("evict", "Reconciled").await;
    assert!(message.contains("evicted=2"), "{message}");
    let status = maintenances.get("evict").await.unwrap().status.unwrap();
    assert_eq!(status.run_count, 1);
    let run = status.last_run.unwrap();
    assert_eq!(run.state, RunState::Succeeded);
    assert_eq!(run.result.unwrap()["evicted"], 2);
    assert!(status.instance.is_some());

    let message = wait("nightly", "Reconciled").await;
    assert!(message.contains("scheduled"), "{message}");
    let status = maintenances.get("nightly").await.unwrap().status.unwrap();
    assert!(status.next_run_time.unwrap().ends_with("T03:00:00Z"));
    assert_eq!(status.run_count, 0);

    // The single run with a TTL: deleted once it finished.
    gone(&maintenances, "once").await;

    // Ran once, whatever triggers it again.
    instances
        .patch(
            "hub",
            &PatchParams::default(),
            &Patch::Merge(json!({"metadata": {"labels": {"touched": "yes"}}})),
        )
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_secs(2)).await;
    let evict = "api/v1/admin/registries/npm/evict";
    assert_eq!(calls(&gateway, evict), 1);

    // run-now: one more run per value, a failure counted.
    gateway.answer(Some(Err(GatewayError::Unreachable("down".into()))));
    maintenances
        .patch(
            "evict",
            &PatchParams::default(),
            &Patch::Merge(json!({"metadata": {"annotations": {"batlehub.weebo.io/run-now": "1"}}})),
        )
        .await
        .unwrap();
    wait("evict", "MaintenanceFailed").await;
    let status = maintenances.get("evict").await.unwrap().status.unwrap();
    assert_eq!((status.run_count, status.failure_count), (2, 1));
    assert_eq!(status.run_now.as_deref(), Some("1"));
    assert_eq!(calls(&gateway, evict), 2);

    // The instance waits for the maintenances bound to it.
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
        message.contains("BatleHubMaintenance/infra/evict"),
        "{message}"
    );
}
