//! Integration tests of `BatleHubPackageGrant` on a real control plane
//! (envtest), with the real instance resolution and dependents — only the
//! instance is in memory (`FakeGateway`, which keeps grants as BatleHub
//! does: one row per node and subject, ownership rows refusing a write
//! that would drop their verbs).

use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{
    BatleHubConfigParser, ClusterDependents, KubeConfigSources, LocalInstanceDirectory,
};
use api::local_instance::{ExternalInstance, LocalInstanceSpec, LocalSecretKeyRef};
use api::package_grant::{DeletionPolicy, PackageGrantSpec, SubjectGrant};
use api::{LocalInstance, PackageGrant};
use application::ports::{PackageNode, StoredGrant};
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

fn grant(name: &str, subjects: &[&str]) -> PackageGrant {
    PackageGrant::new(
        name,
        PackageGrantSpec {
            instance_ref: None,
            registry: "npm".into(),
            package: "@acme/billing".into(),
            version: None,
            grants: subjects
                .iter()
                .map(|s| SubjectGrant {
                    subject: s.to_string(),
                    actions: vec!["releases:read".into()],
                })
                .collect(),
            deletion_policy: DeletionPolicy::Delete,
        },
    )
}

fn node() -> PackageNode {
    PackageNode {
        registry: "npm".into(),
        package: "@acme/billing".into(),
        version: None,
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
        operator: Default::default(),
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

impl Conditions for PackageGrant {
    fn conditions(&self) -> Option<&Vec<api::status::Condition>> {
        self.status.as_ref().map(|s| &s.conditions)
    }
}

impl Conditions for LocalInstance {
    fn conditions(&self) -> Option<&Vec<api::status::Condition>> {
        self.status.as_ref().map(|s| &s.conditions)
    }
}

async fn gone(grants: &Api<PackageGrant>, name: &str) {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while grants.get_opt(name).await.unwrap().is_some() {
        assert!(tokio::time::Instant::now() < deadline, "{name} still there");
        tokio::time::sleep(POLL).await;
    }
}

/// `condition` holds for the fake's grants within the timeout.
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
async fn grants_are_written_recorded_revoked_and_never_taken_over() {
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
    gateway.put_grant_row(
        &node(),
        StoredGrant {
            subject: "user:bob".into(),
            actions: vec!["releases:read".into()],
            from_ownership: false,
            granted_by: Some("admin".into()),
        },
    );
    gateway.own(&node(), "user:carol");
    let grants: Api<PackageGrant> = Api::namespaced(client.clone(), "infra");
    let pp = PostParams::default();
    grants
        .create(&pp, &grant("billing", &["user:alice", "user:bob"]))
        .await
        .unwrap();
    grants
        .create(&pp, &grant("owned", &["user:carol"]))
        .await
        .unwrap();
    let mut kept = grant("kept", &["user:dave"]);
    kept.spec.deletion_policy = DeletionPolicy::Orphan;
    grants.create(&pp, &kept).await.unwrap();

    let ctx = ctx(&client, gateway.clone());
    tokio::spawn(controller::package_grant::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::local_instance::run(client.clone(), ctx));
    let wait = |name: &'static str, reason: &'static str| {
        let grants = grants.clone();
        async move { testkit::polling::wait_for(&grants, name, TIMEOUT, POLL, ready_on(reason)).await }
    };

    // bob's row is someone else's: a conflict; alice is written anyway,
    // and recorded.
    let message = wait("billing", "GrantConflict").await;
    assert!(message.contains("granted by admin"), "{message}");
    let status = grants.get("billing").await.unwrap().status.unwrap();
    assert_eq!(status.applied.len(), 1);
    assert_eq!(status.applied[0].subject, "user:alice");
    assert!(status.instance.is_some());
    assert_eq!(
        gateway
            .grant_row(&node(), "user:bob")
            .unwrap()
            .granted_by
            .as_deref(),
        Some("admin")
    );
    wait("owned", "GrantHeldByOwnership").await;
    wait("kept", "Reconciled").await;

    // bob out of the spec: never touched, alice's grant left as is.
    grants
        .patch(
            "billing",
            &PatchParams::default(),
            &Patch::Merge(json!({"spec": {"grants": [
                {"subject": "user:alice", "actions": ["releases:*"]},
            ]}})),
        )
        .await
        .unwrap();
    until(&gateway, |g| {
        g.grant_row(&node(), "user:alice")
            .is_some_and(|r| r.actions.len() > 1)
    })
    .await;
    wait("billing", "Reconciled").await;
    assert!(gateway.grant_row(&node(), "user:bob").is_some());
    // The coordinate is immutable.
    let moved = grants
        .patch(
            "billing",
            &PatchParams::default(),
            &Patch::Merge(json!({"spec": {"version": "1.0.0"}})),
        )
        .await;
    assert!(moved.is_err(), "{moved:?}");

    // Deleted: what it wrote revoked, the orphan's kept.
    grants
        .delete("billing", &DeleteParams::default())
        .await
        .unwrap();
    gone(&grants, "billing").await;
    assert!(gateway.grant_row(&node(), "user:alice").is_none());
    assert!(gateway.grant_row(&node(), "user:bob").is_some());
    grants
        .delete("kept", &DeleteParams::default())
        .await
        .unwrap();
    gone(&grants, "kept").await;
    assert!(gateway.grant_row(&node(), "user:dave").is_some());

    // The instance waits for the grants still bound to it.
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
        message.contains("BatleHubPackageGrant/infra/owned"),
        "{message}"
    );
    grants
        .delete("owned", &DeleteParams::default())
        .await
        .unwrap();
    gone(&grants, "owned").await;
    assert!(
        gateway
            .grant_row(&node(), "user:carol")
            .unwrap()
            .from_ownership
    );
}
