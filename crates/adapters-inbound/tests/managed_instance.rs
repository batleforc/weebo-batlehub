//! Integration tests of a managed `BatleHubLocalInstance` on a real
//! control plane (envtest), with the real adapters — the objects applied
//! (`KubeWorkloads`), the token read back (`HttpGatewayFactory`),
//! BatleHub's own parser. envtest runs no controller-manager nor kubelet:
//! the Deployment never rolls out by itself, the test writes its status.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{
    BatleHubConfigParser, ClusterDependents, HttpGatewayFactory, KubeConfigSources, KubeWorkloads,
    LocalInstanceDirectory,
};
use api::LocalInstance;
use api::local_instance::LocalInstanceSpec;
use api::managed::{CONFIG_HASH_ANNOTATION, ManagedInstance};
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::{
    Namespace, PersistentVolumeClaim, Secret, Service, ServiceAccount,
};
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use kube::{Client, ResourceExt};
use serde_json::{Value, json};
use weebo_kit_runtime::{Health, WatchScope};

const TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(200);
const NS: &str = "infra";

fn config() -> Value {
    json!({
        "server": {"host": "0.0.0.0", "port": 8080},
        "database": {"type": "postgresql", "url": "${DATABASE_URL}"},
        "storage": {"type": "filesystem", "path": "/var/cache/batlehub"},
        "auth": [{"type": "token", "tokens": [
            {"value": "a-user-token", "role": "user", "user_id": "alice"}
        ]}],
    })
}

fn instance(name: &str, managed: ManagedInstance) -> LocalInstance {
    LocalInstance::new(
        name,
        LocalInstanceSpec {
            external: None,
            managed: Some(managed),
            config: config(),
            config_layers: vec![],
            reload: Default::default(),
            registry_selector: Default::default(),
        },
    )
}

fn ctx(client: &Client) -> Arc<Ctx> {
    let instances = Arc::new(LocalInstanceDirectory::new(client.clone()));
    Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(HttpGatewayFactory::new(client.clone(), instances.clone())),
        instances: instances.clone(),
        registries: instances.clone(),
        dependents: Arc::new(ClusterDependents::new(client.clone(), None)),
        workloads: Arc::new(KubeWorkloads::new(client.clone())),
        operator: application::workload::OperatorPod {
            namespace: Some("weebo-batlehub-system".into()),
            ..Default::default()
        },
        token_review_role: Some("weebo-batlehub-tokenreview".into()),
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

fn reason(instance: &LocalInstance) -> Option<String> {
    let status = instance.status.as_ref()?;
    weebo_kit_api::status::ready(&status.conditions).map(|c| c.reason.clone())
}

async fn until(api: &Api<LocalInstance>, name: &str, want: &'static str) -> LocalInstance {
    testkit::polling::wait_for(api, name, TIMEOUT, POLL, |i: &LocalInstance| {
        (reason(i).as_deref() == Some(want)).then(|| i.clone())
    })
    .await
}

#[tokio::test]
async fn a_managed_instance_deploys_its_objects_and_never_takes_one_over() {
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
    let instances: Api<LocalInstance> = Api::namespaced(client.clone(), NS);
    let pp = PostParams::default();

    // Both modes, or none: refused by the CRD.
    let mut both = instance("both", ManagedInstance::default());
    both.spec.external = Some(
        serde_json::from_value(json!({
            "url": "http://x", "adminTokenSecretRef": {"name": "t", "key": "token"},
        }))
        .unwrap(),
    );
    assert!(instances.create(&pp, &both).await.is_err());
    // A managed instance's name names its Service (DNS-1035, ≤ 63).
    for name in ["1hub", &"h".repeat(64)] {
        let refused = instances
            .create(&pp, &instance(name, ManagedInstance::default()))
            .await;
        assert!(refused.is_err(), "{name}: {refused:?}");
    }
    // Kubernetes spellings only (not deserializable into the type: sent raw).
    let raw: Api<kube::api::DynamicObject> = Api::namespaced_with(
        client.clone(),
        NS,
        &kube::api::ApiResource::erase::<LocalInstance>(&()),
    );
    let typo: kube::api::DynamicObject = serde_json::from_value(json!({
        "apiVersion": "batlehub.weebo.io/v1alpha1",
        "kind": "BatleHubLocalInstance",
        "metadata": {"name": "typo"},
        "spec": {"managed": {"service": {"type": "Loadbalancer"}}},
    }))
    .unwrap();
    let refused = raw.create(&pp, &typo).await;
    assert!(refused.is_err(), "{refused:?}");

    // A Service of the same name someone else created.
    Api::<Service>::namespaced(client.clone(), NS)
        .create(
            &pp,
            &serde_json::from_value(json!({
                "metadata": {"name": "taken"},
                "spec": {"ports": [{"port": 80}]},
            }))
            .unwrap(),
        )
        .await
        .unwrap();

    instances
        .create(&pp, &instance("hub", ManagedInstance::default()))
        .await
        .unwrap();
    instances
        .create(&pp, &instance("taken", ManagedInstance::default()))
        .await
        .unwrap();
    tokio::spawn(controller::local_instance::run(
        client.clone(),
        ctx(&client),
    ));

    // No controller-manager: deployed, never rolled out.
    let hub = until(&instances, "hub", "WorkloadNotReady").await;
    let status = hub.status.clone().unwrap();
    assert_eq!(status.update_strategy.as_deref(), Some("Recreate"));
    assert_eq!(
        status.endpoint.as_deref(),
        Some("http://hub.infra.svc:8080")
    );
    assert!(status.config_hash.is_some());
    let uid = hub.uid().unwrap();
    let owned = |meta: &ObjectMeta| {
        meta.owner_references
            .iter()
            .flatten()
            .any(|r| r.uid == uid && r.controller == Some(true))
    };

    let secrets: Api<Secret> = Api::namespaced(client.clone(), NS);
    let token = secrets.get("hub-operator-token").await.unwrap();
    assert!(owned(&token.metadata));
    assert_eq!(
        token
            .labels()
            .get("batlehub.weebo.io/instance-token")
            .map(String::as_str),
        Some("true")
    );
    let file = secrets.get("hub-config").await.unwrap();
    assert!(owned(&file.metadata));
    let file = String::from_utf8(file.data.unwrap()["config.toml"].0.clone()).unwrap();
    // The operator's token added, hashed; the user's kept.
    // `$` written `\u0024` by BatleHub's merge: a literal, never a placeholder.
    assert!(file.contains("argon2id"), "{file}");
    assert!(file.contains("weebo-batlehub-operator"), "{file}");
    assert!(file.contains("a-user-token"), "{file}");
    assert!(file.contains("${DATABASE_URL}"), "{file}");

    for owned_meta in [
        Api::<ServiceAccount>::namespaced(client.clone(), NS)
            .get("hub")
            .await
            .unwrap()
            .metadata,
        Api::<Service>::namespaced(client.clone(), NS)
            .get("hub")
            .await
            .unwrap()
            .metadata,
        Api::<PersistentVolumeClaim>::namespaced(client.clone(), NS)
            .get("hub-cache")
            .await
            .unwrap()
            .metadata,
    ] {
        assert!(owned(&owned_meta), "{:?}", owned_meta.name);
    }
    let deployments: Api<Deployment> = Api::namespaced(client.clone(), NS);
    let deployment = deployments.get("hub").await.unwrap();
    assert!(owned(&deployment.metadata));
    let template = deployment.spec.clone().unwrap().template;
    let annotations: BTreeMap<String, String> =
        template.metadata.unwrap().annotations.unwrap_or_default();
    assert_eq!(
        annotations.get(CONFIG_HASH_ANNOTATION),
        status.config_hash.as_ref()
    );

    // Never taken over.
    let taken = until(&instances, "taken", "OwnedObjectConflict").await;
    let message = weebo_kit_api::status::ready(&taken.status.unwrap().conditions)
        .unwrap()
        .message
        .clone();
    assert!(message.contains("Service infra/taken"), "{message}");
    assert!(deployments.get_opt("taken").await.unwrap().is_none());

    // Rolled out (as a controller-manager would say): no pod is ready.
    deployments
        .patch_status(
            "hub",
            &PatchParams::default(),
            &Patch::Merge(json!({"status": {
                "observedGeneration": deployment.metadata.generation,
                "replicas": 1, "updatedReplicas": 1, "availableReplicas": 1, "readyReplicas": 1,
            }})),
        )
        .await
        .unwrap();
    let hub = until(&instances, "hub", "NoReadyPod").await;
    assert_eq!(hub.status.unwrap().available_replicas, Some(1));

    // Pods the operator doesn't run, or that read a Secret that didn't opt
    // in: nothing is applied (the webhook refuses them first).
    secrets
        .create(
            &pp,
            &serde_json::from_value(json!({
                "metadata": {"name": "db"}, "stringData": {"url": "postgres://x"},
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let reader: ManagedInstance =
        serde_json::from_value(json!({"envFrom": [{"secretRef": {"name": "db"}}]})).unwrap();
    instances
        .create(&pp, &instance("reader", reader))
        .await
        .unwrap();
    let foreign: ManagedInstance =
        serde_json::from_value(json!({"image": {"repository": "docker.io/evil/miner"}})).unwrap();
    instances
        .create(&pp, &instance("foreign", foreign))
        .await
        .unwrap();
    until(&instances, "reader", "SecretNotAllowed").await;
    until(&instances, "foreign", "InvalidSpec").await;
    for name in ["reader", "foreign"] {
        assert!(deployments.get_opt(name).await.unwrap().is_none());
        assert!(
            secrets
                .get_opt(&format!("{name}-config"))
                .await
                .unwrap()
                .is_none()
        );
    }
    // Labelled, it is read.
    secrets
        .patch(
            "db",
            &PatchParams::default(),
            &Patch::Merge(
                json!({"metadata": {"labels": {"batlehub.weebo.io/credential": "true"}}}),
            ),
        )
        .await
        .unwrap();
    instances
        .patch(
            "reader",
            &PatchParams::default(),
            &Patch::Merge(json!({"metadata": {"annotations": {"touch": "1"}}})),
        )
        .await
        .unwrap();
    until(&instances, "reader", "WorkloadNotReady").await;

    // Two instances never take one object from each other: `twin`'s
    // worker is `twin-worker`'s proxy Deployment.
    let twin: ManagedInstance = serde_json::from_value(json!({"worker": {}})).unwrap();
    instances
        .create(&pp, &instance("twin", twin))
        .await
        .unwrap();
    until(&instances, "twin", "WorkloadNotReady").await;
    instances
        .create(&pp, &instance("twin-worker", ManagedInstance::default()))
        .await
        .unwrap();
    until(&instances, "twin-worker", "OwnedObjectConflict").await;
    let twin = instances.get("twin").await.unwrap();
    let worker = deployments.get("twin-worker").await.unwrap();
    assert!(
        worker
            .owner_references()
            .iter()
            .any(|r| Some(&r.uid) == twin.uid().as_ref())
    );
}
