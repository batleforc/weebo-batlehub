//! Integration tests of `BatleHubNamespaceClaim` on a real control plane
//! (envtest), with the real instance resolution and dependents — only the
//! instance is in memory (`FakeGateway`, which keeps claims as BatleHub
//! does: one per prefix, 409 on a second).

use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{
    BatleHubConfigParser, ClusterDependents, KubeConfigSources, LocalInstanceDirectory,
};
use api::local_instance::{ExternalInstance, LocalInstanceSpec, LocalSecretKeyRef};
use api::namespace_claim::{DeletionPolicy, NamespaceClaimSpec};
use api::{LocalInstance, NamespaceClaim};
use application::ports::TeamNamespace;
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
            external: ExternalInstance {
                url: "http://batlehub.invalid".into(),
                admin_token_secret_ref: LocalSecretKeyRef {
                    name: "token".into(),
                    key: "token".into(),
                },
                tls: Default::default(),
                manage_config: false,
                pod_selector: None,
            },
            config: Value::Null,
            config_layers: vec![],
            reload: Default::default(),
            registry_selector: Default::default(),
        },
    )
}

fn claim(name: &str, registry: &str, prefix: &str, group: &str) -> NamespaceClaim {
    NamespaceClaim::new(
        name,
        NamespaceClaimSpec {
            instance_ref: None,
            registry: registry.into(),
            prefix: prefix.into(),
            group: group.into(),
            deletion_policy: DeletionPolicy::Delete,
        },
    )
}

fn ctx(client: &Client, gateway: Arc<FakeGateway>) -> Arc<Ctx> {
    let instances = Arc::new(LocalInstanceDirectory::new(client.clone()));
    Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(StaticGatewayFactory::new(gateway)),
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

impl Conditions for NamespaceClaim {
    fn conditions(&self) -> Option<&Vec<api::status::Condition>> {
        self.status.as_ref().map(|s| &s.conditions)
    }
}

impl Conditions for LocalInstance {
    fn conditions(&self) -> Option<&Vec<api::status::Condition>> {
        self.status.as_ref().map(|s| &s.conditions)
    }
}

async fn gone(claims: &Api<NamespaceClaim>, name: &str) {
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while claims.get_opt(name).await.unwrap().is_some() {
        assert!(tokio::time::Instant::now() < deadline, "{name} still there");
        tokio::time::sleep(POLL).await;
    }
}

/// `condition` holds for the fake's claims within the timeout.
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
async fn a_claim_is_made_moved_released_and_never_taken_over() {
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
    gateway.put_claim(
        "npm",
        TeamNamespace {
            prefix: "legacy".into(),
            group: "oidc:old".into(),
            claimed_by: Some("admin".into()),
            package_count: 7,
        },
    );
    let claims: Api<NamespaceClaim> = Api::namespaced(client.clone(), "infra");
    let pp = PostParams::default();
    claims
        .create(&pp, &claim("web", "npm", "@acme/web", "oidc:web"))
        .await
        .unwrap();
    claims
        .create(&pp, &claim("legacy", "npm", "legacy", "oidc:new"))
        .await
        .unwrap();
    claims
        .create(&pp, &claim("nowhere", "pypi", "acme", "oidc:web"))
        .await
        .unwrap();
    let mut kept = claim("kept", "npm", "@acme/kept", "oidc:web");
    kept.spec.deletion_policy = DeletionPolicy::Orphan;
    claims.create(&pp, &kept).await.unwrap();

    let ctx = ctx(&client, gateway.clone());
    tokio::spawn(controller::namespace_claim::run(
        client.clone(),
        ctx.clone(),
    ));
    tokio::spawn(controller::local_instance::run(client.clone(), ctx));
    let wait = |name: &'static str, reason: &'static str| {
        let claims = claims.clone();
        async move { testkit::polling::wait_for(&claims, name, TIMEOUT, POLL, ready_on(reason)).await }
    };

    wait("web", "Reconciled").await;
    let held = gateway.claim("npm", "@acme/web").unwrap();
    assert_eq!(held.group, "oidc:web");
    assert_eq!(held.claimed_by.as_deref(), Some("weebo-batlehub:infra/web"));
    let status = claims.get("web").await.unwrap().status.unwrap();
    assert_eq!(status.claimed_group.as_deref(), Some("oidc:web"));
    assert!(status.last_sync_time.is_some());
    assert!(status.instance.is_some());
    let message = wait("legacy", "ClaimConflict").await;
    assert!(message.contains("by admin"), "{message}");
    wait("nowhere", "RemoteNotFound").await;
    wait("kept", "Reconciled").await;

    // A new group: released, then claimed again.
    claims
        .patch(
            "web",
            &PatchParams::default(),
            &Patch::Merge(json!({"spec": {"group": "oidc:frontend"}})),
        )
        .await
        .unwrap();
    until(&gateway, |g| {
        g.claim("npm", "@acme/web")
            .is_some_and(|c| c.group == "oidc:frontend")
    })
    .await;
    // The coordinate is immutable.
    let moved = claims
        .patch(
            "web",
            &PatchParams::default(),
            &Patch::Merge(json!({"spec": {"prefix": "@acme/other"}})),
        )
        .await;
    assert!(moved.is_err(), "{moved:?}");

    // Deleted: its own claim released, the orphan's kept, the conflict's
    // never touched.
    claims
        .delete("web", &DeleteParams::default())
        .await
        .unwrap();
    gone(&claims, "web").await;
    assert!(gateway.claim("npm", "@acme/web").is_none());
    claims
        .delete("kept", &DeleteParams::default())
        .await
        .unwrap();
    gone(&claims, "kept").await;
    assert!(gateway.claim("npm", "@acme/kept").is_some());

    // The instance waits for the claims still bound to it.
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
        message.contains("BatleHubNamespaceClaim/infra/legacy"),
        "{message}"
    );
    claims
        .delete("legacy", &DeleteParams::default())
        .await
        .unwrap();
    gone(&claims, "legacy").await;
    assert_eq!(
        gateway
            .claim("npm", "legacy")
            .unwrap()
            .claimed_by
            .as_deref(),
        Some("admin")
    );
}
