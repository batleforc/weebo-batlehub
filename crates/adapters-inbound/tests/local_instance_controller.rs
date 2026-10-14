//! Integration tests: the `BatleHubLocalInstance` controller with the real
//! adapters — `LocalInstanceDirectory`, `HttpGatewayFactory` reading the
//! token Secret through the kit's opt-in check, `HttpAdminGateway` — against
//! a scripted BatleHub (`wiremock`) and a real control plane (envtest).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{HttpGatewayFactory, LocalInstanceDirectory, UnavailableConfigParser};
use api::LocalInstance;
use api::local_instance::{LocalInstanceSpec, LocalSecretKeyRef};
use k8s_openapi::api::core::v1::{Namespace, Secret};
use kube::Client;
use kube::api::{Api, ObjectMeta, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use serde_json::json;
use weebo_kit_runtime::{Health, WatchScope};
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TIMEOUT: Duration = Duration::from_secs(20);
const POLL: Duration = Duration::from_millis(200);
const NS: &str = "team-a";

/// A BatleHub answering `/livez` and `/api/v1/me` with `role` for `token`.
async fn batlehub(token: &str, role: &str) -> MockServer {
    let server = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/livez"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"ok": true, "version": "1.4.0"})),
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
    let instance = LocalInstance::new(
        name,
        LocalInstanceSpec {
            url: url.into(),
            token_secret_ref: LocalSecretKeyRef {
                name: secret.into(),
                key: "token".into(),
            },
        },
    );
    Api::<LocalInstance>::namespaced(client.clone(), NS)
        .create(&PostParams::default(), &instance)
        .await
        .unwrap();
}

fn ctx(client: &Client) -> Arc<Ctx> {
    let instances = Arc::new(LocalInstanceDirectory::new(client.clone()));
    Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(HttpGatewayFactory::new(client.clone(), instances.clone())),
        instances,
        config: Arc::new(UnavailableConfigParser),
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

#[tokio::test]
async fn an_instance_is_ready_only_with_a_labelled_admin_token() {
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
    let admin = batlehub("admin-token", "admin").await;
    let user = batlehub("user-token", "user").await;

    token_secret(&client, "admin", "admin-token", true).await;
    token_secret(&client, "unlabelled", "admin-token", false).await;
    token_secret(&client, "user", "user-token", true).await;
    instance(&client, "ready", &admin.uri(), "admin").await;
    instance(&client, "unlabelled", &admin.uri(), "unlabelled").await;
    instance(&client, "user-role", &user.uri(), "user").await;
    instance(&client, "down", "http://127.0.0.1:9", "admin").await;

    tokio::spawn(controller::local_instance::run(
        client.clone(),
        ctx(&client),
    ));
    let instances: Api<LocalInstance> = Api::namespaced(client.clone(), NS);
    let wait =
        |name: &'static str| testkit::polling::wait_for(&instances, name, TIMEOUT, POLL, ready);

    let (status, reason, message) = wait("ready").await;
    assert_eq!((status.as_str(), reason.as_str()), ("True", "Reconciled"));
    assert!(message.contains("1.4.0"), "{message}");

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
}
