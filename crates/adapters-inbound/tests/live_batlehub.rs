//! The `BatleHubLocalInstance` controller end to end, on envtest, against a
//! real BatleHub (`task test:live-batlehub`, ignored by default; see
//! `adapters-outbound/tests/live_batlehub.rs` for the variables).

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{
    ClusterDependents, HttpGatewayFactory, LocalInstanceDirectory, UnavailableConfigParser,
};
use api::LocalInstance;
use api::local_instance::{ExternalInstance, LocalInstanceSpec, LocalSecretKeyRef};
use k8s_openapi::api::core::v1::{Namespace, Secret};
use kube::Client;
use kube::api::{Api, ObjectMeta, PostParams};
use kube::runtime::events::{Recorder, Reporter};
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
            },
        },
    );
    create(client, &instance).await;
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

    let instances = Arc::new(LocalInstanceDirectory::new(client.clone()));
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(HttpGatewayFactory::new(client.clone(), instances.clone())),
        instances,
        dependents: Arc::new(ClusterDependents),
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
    });
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
