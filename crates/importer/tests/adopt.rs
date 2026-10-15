//! Adoption end to end on envtest: grants and policies written on the
//! instance by someone else are imported, adopted (created paused, their
//! status seeded, unpaused), and the operator's controllers then find
//! them theirs — `Reconciled`, nothing written again, no conflict. A
//! second run adopts nothing new.

use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{
    BatleHubConfigParser, ClusterDependents, KubeConfigSources, LocalInstanceDirectory,
};
use api::local_instance::{ExternalInstance, LocalInstanceSpec, LocalSecretKeyRef};
use api::{LocalInstance, PackageGrant, PackagePolicy};
use application::ports::{PackageNode, StoredGrant};
use application::use_cases::import::{Scope, import_governance};
use k8s_openapi::api::core::v1::Namespace;
use kube::Client;
use kube::api::{Api, ObjectMeta, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use serde_json::json;
use testkit::{FakeGateway, StaticGatewayFactory};
use weebo_kit_runtime::{Health, WatchScope};

const NS: &str = "infra";
const TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(200);

fn node(version: Option<&str>) -> PackageNode {
    PackageNode {
        registry: "npm".into(),
        package: "@acme/billing".into(),
        version: version.map(String::from),
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
        operator_namespace: None,
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
    })
}

fn reason(conditions: Option<&Vec<api::status::Condition>>) -> Option<String> {
    weebo_kit_api::status::ready(conditions?).map(|c| c.reason.clone())
}

#[tokio::test]
async fn imported_governance_is_adopted_and_reconciles_without_writing() {
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
    Api::<LocalInstance>::namespaced(client.clone(), NS)
        .create(
            &PostParams::default(),
            &LocalInstance::new(
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
                    config: serde_json::Value::Null,
                    config_layers: vec![],
                    reload: Default::default(),
                    registry_selector: Default::default(),
                },
            ),
        )
        .await
        .unwrap();

    // What the console wrote.
    let gateway = Arc::new(FakeGateway::default());
    gateway.serve(&["npm"]);
    gateway.allow_exemptions(true);
    gateway.put_grant_row(
        &node(None),
        StoredGrant {
            subject: "user:alice".into(),
            actions: vec!["releases:read".into(), "releases:list".into()],
            from_ownership: false,
            granted_by: Some("admin".into()),
        },
    );
    gateway.put_policy_row(
        &node(Some("1.0.0")),
        json!({"visibility": "team", "rules": [{"gate": "cve_gate", "settings": {
            "exempt": true, "exempt_until": "2099-01-01T00:00:00Z", "reason": "patched",
        }}]}),
    );

    let imported = import_governance(gateway.as_ref(), &Scope::default())
        .await
        .unwrap();
    let items = importer::governance(&imported, NS, Some("hub"));
    assert_eq!(items.len(), 2);
    let summary = importer::adopt_all(&client, NS, &items, false).await;
    assert_eq!((summary.adopted, summary.failed), (2, 0));

    let calls_before = gateway.calls().len();
    let ctx = ctx(&client, gateway.clone());
    tokio::spawn(controller::package_grant::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::package_policy::run(client.clone(), ctx));

    let grants: Api<PackageGrant> = Api::namespaced(client.clone(), NS);
    let policies: Api<PackagePolicy> = Api::namespaced(client.clone(), NS);
    let grant_name = importer::cr_name(&node(None));
    let policy_name = importer::cr_name(&node(Some("1.0.0")));
    testkit::polling::wait_for(&grants, &grant_name, TIMEOUT, POLL, |g: &PackageGrant| {
        (reason(g.status.as_ref().map(|s| &s.conditions)).as_deref() == Some("Reconciled"))
            .then_some(())
    })
    .await;
    testkit::polling::wait_for(
        &policies,
        &policy_name,
        TIMEOUT,
        POLL,
        |p: &PackagePolicy| {
            (reason(p.status.as_ref().map(|s| &s.conditions)).as_deref() == Some("Reconciled"))
                .then_some(())
        },
    )
    .await;
    // Adopted, not rewritten: only reads since the import.
    let writes: Vec<String> = gateway.calls()[calls_before..]
        .iter()
        .filter(|c| !matches!(c.as_str(), "grants" | "policy" | "registries"))
        .cloned()
        .collect();
    assert!(writes.is_empty(), "{writes:?}");
    let grant = grants.get(&grant_name).await.unwrap();
    assert!(
        !grant
            .metadata
            .annotations
            .unwrap_or_default()
            .contains_key("batlehub.weebo.io/import-pending")
    );

    // A second run: nothing new.
    let summary = importer::adopt_all(&client, NS, &items, false).await;
    assert_eq!(
        (summary.adopted, summary.skipped, summary.failed),
        (0, 2, 0)
    );
}
