//! Integration tests: the `BatleHubLocalInstance` controller with the real
//! adapters — `LocalInstanceDirectory`, `HttpGatewayFactory` reading the
//! token Secret through the kit's opt-in check, `HttpAdminGateway` — against
//! a scripted BatleHub (`wiremock`) and a real control plane (envtest).
//! The CRs bound to an instance are a fake here (`manage_config.rs` has
//! the real ones).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, FINALIZER, Shutdown};
use adapters_outbound::{
    BatleHubConfigParser, HttpGatewayFactory, KubeConfigSources, LocalInstanceDirectory,
};
use api::LocalInstance;
use api::local_instance::{
    ExternalInstance, LocalInstanceSpec, LocalSecretKeyRef, LocalTlsOptions,
};
use k8s_openapi::api::core::v1::{Namespace, Secret};
use kube::api::{Api, DeleteParams, ObjectMeta, Patch, PatchParams, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use kube::{Client, ResourceExt};
use serde_json::json;
use testkit::FakeDependents;
use weebo_kit_runtime::{Health, WatchScope};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TIMEOUT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(200);
const NS: &str = "team-a";

/// A BatleHub answering `/livez`, `/api/v1/me` with `role` for `token`,
/// and one configuration warning.
async fn batlehub(token: &str, role: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/livez"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"ok": true, "version": "1.6.0"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/me"))
        .and(header("authorization", format!("Bearer {token}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "role": role,
            "groups": [],
            "has_registry_access": true,
        })))
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/config/warnings"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"warnings": [{
                "code": "audit.no-retention",
                "message": "audit trail has no retention",
                "path": "audit",
            }]})),
        )
        .mount(&server)
        .await;
    server
}

async fn token_secret(client: &Client, name: &str, token: &str, labelled: bool) {
    let labels = labelled.then(|| {
        BTreeMap::from([(
            "batlehub.weebo.io/instance-token".to_string(),
            "true".to_string(),
        )])
    });
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(name.into()),
            labels,
            ..Default::default()
        },
        string_data: Some(BTreeMap::from([("token".into(), format!("{token}\n"))])),
        ..Default::default()
    };
    Api::<Secret>::namespaced(client.clone(), NS)
        .create(&PostParams::default(), &secret)
        .await
        .unwrap();
}

async fn instance(client: &Client, name: &str, url: &str, secret: &str) {
    instance_with_tls(client, name, url, secret, Default::default()).await;
}

async fn instance_with_tls(
    client: &Client,
    name: &str,
    url: &str,
    secret: &str,
    tls: LocalTlsOptions,
) {
    let instance = LocalInstance::new(
        name,
        LocalInstanceSpec {
            external: Some(ExternalInstance {
                url: url.into(),
                admin_token_secret_ref: LocalSecretKeyRef {
                    name: secret.into(),
                    key: "token".into(),
                },
                tls,
                manage_config: false,
                pod_selector: None,
            }),
            managed: None,
            config: Default::default(),
            config_layers: vec![],
            reload: Default::default(),
            registry_selector: Default::default(),
        },
    );
    Api::<LocalInstance>::namespaced(client.clone(), NS)
        .create(&PostParams::default(), &instance)
        .await
        .unwrap();
}

fn ctx(client: &Client, dependents: Arc<FakeDependents>) -> Arc<Ctx> {
    let instances = Arc::new(LocalInstanceDirectory::new(client.clone()));
    Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(HttpGatewayFactory::new(client.clone(), instances.clone())),
        instances: instances.clone(),
        registries: instances.clone(),
        dependents,
        workloads: Arc::new(application::test_support::FakeWorkloads::default()),
        operator_namespace: None,
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

/// `Ready`'s status, reason and message, once there is one.
fn ready(instance: &LocalInstance) -> Option<(String, String, String)> {
    let c = weebo_kit_api::status::ready(&instance.status.as_ref()?.conditions)?;
    Some((c.status.clone(), c.reason.clone(), c.message.clone()))
}

/// The condition of `type_`, once there is one.
fn condition(instance: &LocalInstance, type_: &str) -> Option<(String, String)> {
    let status = instance.status.as_ref()?;
    let c = status.conditions.iter().find(|c| c.type_ == type_)?;
    Some((c.status.clone(), c.reason.clone()))
}

async fn namespace(client: &Client) {
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
}

#[tokio::test]
async fn an_instance_is_ready_only_with_a_labelled_admin_token() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    namespace(&client).await;
    let admin = batlehub("admin-token", "admin").await;
    let user = batlehub("user-token", "user").await;

    token_secret(&client, "admin", "admin-token", true).await;
    token_secret(&client, "unlabelled", "admin-token", false).await;
    token_secret(&client, "user", "user-token", true).await;
    instance(&client, "ready", &admin.uri(), "admin").await;
    instance(&client, "unlabelled", &admin.uri(), "unlabelled").await;
    instance(&client, "user-role", &user.uri(), "user").await;
    instance(&client, "down", "http://127.0.0.1:9", "admin").await;
    instance(&client, "no-secret", &admin.uri(), "absent").await;
    let ca = |name: &str| LocalTlsOptions {
        insecure_skip_verify: false,
        ca_secret_ref: Some(LocalSecretKeyRef {
            name: name.into(),
            key: "ca.crt".into(),
        }),
    };
    instance_with_tls(&client, "no-ca", &admin.uri(), "admin", ca("absent")).await;
    let garbage = Secret {
        metadata: ObjectMeta {
            name: Some("garbage-ca".into()),
            ..Default::default()
        },
        string_data: Some(BTreeMap::from([("ca.crt".into(), "not a PEM".into())])),
        ..Default::default()
    };
    Api::<Secret>::namespaced(client.clone(), NS)
        .create(&PostParams::default(), &garbage)
        .await
        .unwrap();
    instance_with_tls(&client, "bad-ca", &admin.uri(), "admin", ca("garbage-ca")).await;

    let dependents = Arc::new(FakeDependents::default());
    tokio::spawn(controller::local_instance::run(
        client.clone(),
        ctx(&client, dependents),
    ));
    let instances: Api<LocalInstance> = Api::namespaced(client.clone(), NS);
    let wait =
        |name: &'static str| testkit::polling::wait_for(&instances, name, TIMEOUT, POLL, ready);

    let (status, reason, message) = wait("ready").await;
    assert_eq!((status.as_str(), reason.as_str()), ("True", "Reconciled"));
    assert!(message.contains("1.6.0"), "{message}");
    let ready_one = instances.get("ready").await.unwrap();
    let status = ready_one.status.as_ref().unwrap();
    assert_eq!(status.endpoint.as_deref(), Some(admin.uri().as_str()));
    assert_eq!(status.version.as_deref(), Some("1.6.0"));
    assert_eq!(status.warnings.len(), 1);
    assert_eq!(status.warnings[0].code, "audit.no-retention");
    assert_eq!(
        condition(&ready_one, "ConfigWarnings"),
        Some(("True".into(), "ConfigWarnings".into()))
    );
    assert!(ready_one.finalizers().contains(&FINALIZER.to_string()));

    let (status, reason, message) = wait("unlabelled").await;
    assert_eq!(
        (status.as_str(), reason.as_str()),
        ("False", "TokenSecretNotAllowed")
    );
    assert!(message.contains("instance-token"), "{message}");

    let (_, reason, message) = wait("user-role").await;
    assert_eq!(reason, "OperatorUnauthorized");
    assert!(message.contains("\"user\""), "{message}");

    let (_, reason, _) = wait("down").await;
    assert_eq!(reason, "InstanceUnreachable");
    let down = instances.get("down").await.unwrap();
    assert_eq!(down.status.as_ref().unwrap().version, None);

    let (_, reason, _) = wait("no-secret").await;
    assert_eq!(reason, "TokenSecretMissing");
    let (_, reason, message) = wait("no-ca").await;
    assert_eq!(reason, "InvalidSpec");
    assert!(message.contains("tls.caSecretRef"), "{message}");
    let (_, reason, message) = wait("bad-ca").await;
    assert_eq!(reason, "InvalidSpec");
    assert!(message.contains("tls.caSecretRef"), "{message}");
}

#[tokio::test]
async fn an_instance_in_use_waits_for_its_dependents_or_force_orphan() {
    let _ = tracing_subscriber::fmt().with_test_writer().try_init();
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    namespace(&client).await;
    let admin = batlehub("admin-token", "admin").await;
    token_secret(&client, "admin", "admin-token", true).await;
    instance(&client, "in-use", &admin.uri(), "admin").await;
    instance(&client, "orphaned", &admin.uri(), "admin").await;

    let dependents = Arc::new(FakeDependents::default());
    dependents.set(vec!["BatleHubRegistry/team-a/npm".into()]);
    tokio::spawn(controller::local_instance::run(
        client.clone(),
        ctx(&client, dependents.clone()),
    ));
    let instances: Api<LocalInstance> = Api::namespaced(client.clone(), NS);
    for name in ["in-use", "orphaned"] {
        let (status, _, _) =
            testkit::polling::wait_for(&instances, name, TIMEOUT, POLL, ready).await;
        assert_eq!(status, "True");
    }

    // Deleted while a CR is bound to it: held, Ready says why.
    instances
        .delete("in-use", &DeleteParams::default())
        .await
        .unwrap();
    let (status, _, message) =
        testkit::polling::wait_for(&instances, "in-use", TIMEOUT, POLL, |i| {
            ready(i).filter(|(_, reason, _)| reason == "InstanceInUse")
        })
        .await;
    assert_eq!(status, "False");
    assert!(message.contains("BatleHubRegistry/team-a/npm"), "{message}");
    assert!(instances.get("in-use").await.is_ok());

    // force-orphan releases it, dependents or not.
    instances
        .delete("orphaned", &DeleteParams::default())
        .await
        .unwrap();
    instances
        .patch(
            "orphaned",
            &PatchParams::default(),
            &Patch::Merge(json!({"metadata": {"annotations": {
                "batlehub.weebo.io/force-orphan": "true"
            }}})),
        )
        .await
        .unwrap();
    gone(&instances, "orphaned").await;

    // The last dependent gone, the instance goes (the next retry).
    dependents.set(Vec::new());
    gone(&instances, "in-use").await;
}

async fn gone(instances: &Api<LocalInstance>, name: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    while instances.get_opt(name).await.unwrap().is_some() {
        assert!(
            tokio::time::Instant::now() < deadline,
            "{name} is still there"
        );
        tokio::time::sleep(POLL).await;
    }
}
