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
use api::registry::RegistrySpec;
use api::{LocalInstance, Registry};
use application::ports::AdminGateway;
use k8s_openapi::api::core::v1::{Namespace, Secret};
use kube::Client;
use kube::api::{Api, ObjectMeta, Patch, PatchParams, PostParams};
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
    tokio::spawn(controller::registry::run(client.clone(), ctx));

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
}
