//! Integration tests of `external.manageConfig` and `BatleHubRegistry` on a
//! real control plane (envtest), with the real adapters reading the
//! cluster (`KubeConfigSources`, `LocalInstanceDirectory`,
//! `ClusterDependents`) and BatleHub's own parser — only the instance is
//! in memory (`FakeGateway`, which behaves like BatleHub's reload
//! service).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{
    BatleHubConfigParser, ClusterDependents, KubeConfigSources, LocalInstanceDirectory,
};
use api::config::ConfigSource;
use api::local_instance::{
    ExternalInstance, LocalInstanceSpec, LocalSecretKeyRef, NamespacesFrom, RegistryNamespaces,
    RegistrySelector,
};
use api::registry::RegistrySpec;
use api::{LocalInstance, Registry};
use k8s_openapi::api::core::v1::{ConfigMap, Namespace, Secret};
use kube::api::{Api, ObjectMeta, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use kube::{Client, Resource};
use serde_json::{Value, json};
use testkit::{FakeGateway, STATIC_TOKEN, StaticGatewayFactory};
use weebo_kit_api::InstanceRef;
use weebo_kit_runtime::{Health, WatchScope};

const TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(200);

/// A configuration BatleHub's parser accepts, declaring the operator's
/// token (the static factory's).
fn base_config() -> Value {
    json!({
        "server": {"host": "0.0.0.0", "port": 8080},
        "database": {"type": "postgresql", "url": "${DATABASE_URL}"},
        "storage": {"type": "filesystem", "path": "/var/cache/batlehub"},
        "auth": [{"type": "token", "tokens": [
            {"value": STATIC_TOKEN, "role": "admin", "user_id": "weebo-batlehub-operator"}
        ]}],
    })
}

fn instance(name: &str, manage_config: bool, config: Value) -> LocalInstance {
    LocalInstance::new(
        name,
        LocalInstanceSpec {
            external: Some(ExternalInstance {
                url: "http://batlehub.invalid".into(),
                admin_token_secret_ref: LocalSecretKeyRef {
                    name: "token".into(),
                    key: "token".into(),
                },
                tls: Default::default(),
                manage_config,
                pod_selector: None,
            }),
            managed: None,
            config,
            config_layers: vec![],
            reload: Default::default(),
            registry_selector: Default::default(),
        },
    )
}

fn registry(
    name: &str,
    registry_name: Option<&str>,
    instance_ref: Option<InstanceRef>,
) -> Registry {
    Registry::new(
        name,
        RegistrySpec {
            instance_ref,
            r#type: "npm".into(),
            name: registry_name.map(String::from),
            config: json!({"upstreams": ["https://registry.npmjs.org"]}),
            config_from: vec![],
            suspend: false,
        },
    )
}

async fn create<K>(client: &Client, namespace: &str, object: &K)
where
    K: Resource<Scope = k8s_openapi::NamespaceResourceScope, DynamicType = ()>
        + Clone
        + serde::Serialize
        + serde::de::DeserializeOwned
        + std::fmt::Debug,
{
    Api::<K>::namespaced(client.clone(), namespace)
        .create(&PostParams::default(), object)
        .await
        .unwrap();
}

async fn namespaces(client: &Client, names: &[&str]) {
    for name in names {
        Api::<Namespace>::all(client.clone())
            .create(
                &PostParams::default(),
                &Namespace {
                    metadata: ObjectMeta {
                        name: Some(name.to_string()),
                        labels: Some(BTreeMap::from([("team".into(), name.to_string())])),
                        ..Default::default()
                    },
                    ..Default::default()
                },
            )
            .await
            .unwrap();
    }
}

fn ctx(client: &Client, gateway: Arc<FakeGateway>) -> Arc<Ctx> {
    ctx_with(client, StaticGatewayFactory::new(gateway))
}

fn ctx_with(client: &Client, gateways: StaticGatewayFactory) -> Arc<Ctx> {
    let instances = Arc::new(LocalInstanceDirectory::new(client.clone()));
    Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(gateways),
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

trait HasConditions {
    fn conditions(&self) -> Option<&Vec<api::status::Condition>>;
}

impl HasConditions for LocalInstance {
    fn conditions(&self) -> Option<&Vec<api::status::Condition>> {
        self.status.as_ref().map(|s| &s.conditions)
    }
}

impl HasConditions for Registry {
    fn conditions(&self) -> Option<&Vec<api::status::Condition>> {
        self.status.as_ref().map(|s| &s.conditions)
    }
}

/// `Ready`'s reason and message, once it is `reason`.
fn ready_on<K: HasConditions>(reason: &'static str) -> impl Fn(&K) -> Option<String> {
    move |object| {
        let c = weebo_kit_api::status::ready(object.conditions()?)?;
        (c.reason == reason).then(|| c.message.clone())
    }
}

#[tokio::test]
async fn an_instance_pushes_its_configuration_and_renders_its_registries() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    namespaces(&client, &["infra", "team-a", "team-b"]).await;

    // A layer over spec.config, from a ConfigMap.
    let layer = ConfigMap {
        metadata: ObjectMeta {
            name: Some("limits".into()),
            ..Default::default()
        },
        data: Some(BTreeMap::from([(
            "config.toml".into(),
            "[server]\nport = 9090\n".into(),
        )])),
        ..Default::default()
    };
    create(&client, "infra", &layer).await;
    let mut hub = instance("hub", true, base_config());
    hub.spec.config_layers = vec![ConfigSource::config_map("limits", "config.toml")];
    hub.spec.registry_selector = RegistrySelector {
        selector: None,
        namespaces: RegistryNamespaces {
            from: NamespacesFrom::Selector,
            selector: Some(api::config::LabelSelector {
                match_labels: Some(BTreeMap::from([("team".into(), "team-a".into())])),
                ..Default::default()
            }),
        },
    };
    create(&client, "infra", &hub).await;

    // Rendered: one of its namespace, one of an accepted namespace.
    create(&client, "infra", &registry("npm", None, None)).await;
    let to_hub = || {
        Some(InstanceRef {
            namespace: Some("infra".into()),
            ..InstanceRef::named("hub")
        })
    };
    create(&client, "team-a", &registry("team-npm", None, to_hub())).await;
    // Left out: a namespace the instance doesn't accept, a duplicate name,
    // a placeholder from another namespace, an unlabelled Secret.
    create(&client, "team-b", &registry("refused", None, to_hub())).await;
    tokio::time::sleep(Duration::from_millis(1100)).await;
    create(&client, "infra", &registry("late", Some("npm"), None)).await;
    let mut placeholder = registry("placeholder", None, to_hub());
    placeholder.spec.config = json!({"upstreams": ["${UPSTREAM}"]});
    create(&client, "team-a", &placeholder).await;
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some("npm-auth".into()),
            ..Default::default()
        },
        string_data: Some(BTreeMap::from([(
            "config.toml".into(),
            "[upstream_auth]\ntoken = \"t\"\n".into(),
        )])),
        ..Default::default()
    };
    create(&client, "infra", &secret).await;
    let mut unlabelled = registry("unlabelled", None, None);
    unlabelled.spec.config_from = vec![ConfigSource::secret("npm-auth", "config.toml")];
    create(&client, "infra", &unlabelled).await;

    // An instance that doesn't manage its configuration, and its registry.
    create(&client, "team-b", &instance("observer", false, Value::Null)).await;
    create(&client, "team-b", &registry("unmanaged", None, None)).await;

    let gateway = Arc::new(FakeGateway::default());
    gateway.write_file("# the instance's own file\n");
    let ctx = ctx(&client, gateway.clone());
    tokio::spawn(controller::local_instance::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::registry::run(client.clone(), ctx));

    let instances: Api<LocalInstance> = Api::namespaced(client.clone(), "infra");
    let message =
        testkit::polling::wait_for(&instances, "hub", TIMEOUT, POLL, ready_on("Reconciled")).await;
    assert!(message.contains("applied"), "{message}");
    let status = instances.get("hub").await.unwrap().status.unwrap();
    assert!(status.config_hash.is_some());
    assert_eq!(status.applied_config_hash, status.config_hash);
    assert!(status.last_reload_time.is_some());

    let file = gateway.file();
    assert!(file.contains("port = 9090"), "{file}");
    assert!(file.contains("url = \"${DATABASE_URL}\""), "{file}");
    assert_eq!(file.matches("[[registries]]").count(), 2, "{file}");
    assert!(file.contains("name = \"team-npm\""), "{file}");
    assert_eq!(gateway.loaded().as_deref(), Some(file.as_str()));

    let in_infra: Api<Registry> = Api::namespaced(client.clone(), "infra");
    let in_team_a: Api<Registry> = Api::namespaced(client.clone(), "team-a");
    let in_team_b: Api<Registry> = Api::namespaced(client.clone(), "team-b");
    let wait = |api: &Api<Registry>, name: &'static str, reason: &'static str| {
        let api = api.clone();
        async move { testkit::polling::wait_for(&api, name, TIMEOUT, POLL, ready_on(reason)).await }
    };
    wait(&in_infra, "npm", "Reconciled").await;
    let npm = in_infra.get("npm").await.unwrap().status.unwrap();
    assert_eq!(npm.instance_config_hash, status.config_hash);
    assert_eq!(npm.registry_name.as_deref(), Some("npm"));
    wait(&in_team_a, "team-npm", "Reconciled").await;
    let message = wait(&in_infra, "late", "DuplicateRegistryName").await;
    assert!(message.contains("infra/npm"), "{message}");
    wait(&in_team_a, "placeholder", "NamespaceNotAllowed").await;
    let message = wait(&in_infra, "unlabelled", "SecretNotAllowed").await;
    assert!(message.contains("kubectl label"), "{message}");
    wait(&in_team_b, "refused", "InstanceNotAllowed").await;
    wait(&in_team_b, "unmanaged", "InstanceConfigUnmanaged").await;

    // A new registry is pushed on its own (the registry watch).
    create(&client, "infra", &registry("cargo", None, None)).await;
    wait(&in_infra, "cargo", "Reconciled").await;
    assert_eq!(gateway.file().matches("[[registries]]").count(), 3);
}

#[tokio::test]
async fn configurations_that_cannot_be_pushed_say_why() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    namespaces(&client, &["infra"]).await;

    let mut locked = instance("locked", true, base_config());
    locked.spec.config_layers = vec![ConfigSource::secret("not-labelled", "config.toml")];
    create(&client, "infra", &locked).await;
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some("not-labelled".into()),
            ..Default::default()
        },
        string_data: Some(BTreeMap::from([("config.toml".into(), "".into())])),
        ..Default::default()
    };
    create(&client, "infra", &secret).await;
    let mut missing = instance("missing", true, base_config());
    missing.spec.config_layers = vec![ConfigSource::config_map("absent", "config.toml")];
    create(&client, "infra", &missing).await;
    let mut invalid = base_config();
    invalid["storage"] = json!({"type": "nowhere"});
    create(&client, "infra", &instance("invalid", true, invalid)).await;
    let mut shadowed = base_config();
    shadowed["auth"] =
        json!([{"type": "token", "tokens": [{"value": "someone-else", "role": "admin"}]}]);
    create(&client, "infra", &instance("shadowed", true, shadowed)).await;
    create(&client, "infra", &instance("restart", true, base_config())).await;

    let gateway = Arc::new(FakeGateway::default());
    gateway.require_restart(&["database.url"]);
    tokio::spawn(controller::local_instance::run(
        client.clone(),
        ctx(&client, gateway.clone()),
    ));
    let instances: Api<LocalInstance> = Api::namespaced(client.clone(), "infra");
    let wait = |name: &'static str, reason: &'static str| {
        let api = instances.clone();
        async move { testkit::polling::wait_for(&api, name, TIMEOUT, POLL, ready_on(reason)).await }
    };
    let message = wait("locked", "SecretNotAllowed").await;
    assert!(
        message.contains("batlehub.weebo.io/credential"),
        "{message}"
    );
    wait("missing", "ConfigLayerMissing").await;
    let message = wait("invalid", "ConfigInvalid").await;
    assert!(message.contains("StoragesConfig"), "{message}");
    wait("shadowed", "OperatorTokenShadowed").await;
    let message = wait("restart", "RestartForbidden").await;
    assert!(message.contains("database.url"), "{message}");
    let status = instances.get("restart").await.unwrap().status.unwrap();
    assert_eq!(status.restart_keys, ["database.url"]);
    assert_eq!(status.applied_config_hash, None);
    // Nothing reached the instance.
    assert_eq!(gateway.file(), "");
}

#[tokio::test]
async fn registries_get_a_status_when_their_instance_s_token_cannot_be_read() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    namespaces(&client, &["infra"]).await;
    create(
        &client,
        "infra",
        &instance("tokenless", true, base_config()),
    )
    .await;
    create(&client, "infra", &registry("npm", None, None)).await;

    let gateways = StaticGatewayFactory::new(Arc::new(FakeGateway::default())).without("tokenless");
    let ctx = ctx_with(&client, gateways);
    tokio::spawn(controller::local_instance::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::registry::run(client.clone(), ctx));

    let registries: Api<Registry> = Api::namespaced(client.clone(), "infra");
    let message = testkit::polling::wait_for(
        &registries,
        "npm",
        TIMEOUT,
        POLL,
        ready_on("InstanceNotReady"),
    )
    .await;
    assert!(message.contains("InstanceNotFound"), "{message}");
}
