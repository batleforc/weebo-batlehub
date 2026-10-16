//! The importer against a real BatleHub (`task test:live-batlehub`,
//! ignored by default): grants and a policy written straight through the
//! admin API (as the console would) are imported, adopted on envtest, and
//! the controllers — on that same BatleHub — find them theirs.

use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_outbound::{
    BatleHubConfigParser, ClusterDependents, HttpAdminGateway, KubeConfigSources,
    LocalInstanceDirectory,
};
use api::local_instance::{ExternalInstance, LocalInstanceSpec, LocalSecretKeyRef};
use api::{LocalInstance, PackageGrant, PackagePolicy};
use application::ports::{AdminGateway, PackageNode};
use application::use_cases::import::{Scope, import_governance};
use k8s_openapi::api::core::v1::Namespace;
use kube::api::{Api, DeleteParams, ObjectMeta, PostParams};
use kube::runtime::events::{Recorder, Reporter};
use serde_json::json;
use testkit::StaticGatewayFactory;
use weebo_kit_runtime::{Health, WatchScope};

const NS: &str = "imported";
const REGISTRY: &str = "import-npm";
const TIMEOUT: Duration = Duration::from_secs(30);
const POLL: Duration = Duration::from_millis(200);

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn gateway() -> HttpAdminGateway {
    HttpAdminGateway::new(
        &env("BATLEHUB_URL"),
        env("BATLEHUB_ADMIN_TOKEN"),
        HttpAdminGateway::client(None, false).unwrap(),
    )
    .unwrap()
}

/// The instance serves `REGISTRY`, added to its file if needed.
async fn serve_registry(batlehub: &HttpAdminGateway) {
    if batlehub
        .registry_names()
        .await
        .unwrap()
        .iter()
        .any(|r| r == REGISTRY)
    {
        return;
    }
    let current = batlehub.config_content().await.unwrap();
    let run = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let added = format!(
        "{current}\n[[registries]]\nname = \"{REGISTRY}\"\ntype = \"npm\"\nupstreams = [\"https://registry.npmjs.org\"]\n# {run}\n"
    );
    assert!(batlehub.stage_config(&added).await.unwrap());
    batlehub.apply_pending().await.unwrap();
}

fn reason(conditions: Option<&Vec<api::status::Condition>>) -> Option<String> {
    weebo_kit_api::status::ready(conditions?).map(|c| c.reason.clone())
}

#[tokio::test]
#[ignore = "needs a real BatleHub (task test:live-batlehub)"]
async fn governance_written_elsewhere_is_imported_and_adopted() {
    let batlehub = Arc::new(gateway());
    serve_registry(&batlehub).await;
    let run = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis();
    let package = format!("@import/billing-{run}");
    let node = PackageNode {
        registry: REGISTRY.into(),
        package: package.clone(),
        version: None,
    };
    // The console's grant and policy.
    batlehub
        .put_grant(&node, "user:imported", &["releases:*".to_string()])
        .await
        .unwrap();
    batlehub
        .put_policy(&node, &json!({"visibility": "team"}))
        .await
        .unwrap();
    // The catalogue reads, page after page.
    batlehub.packages(REGISTRY).await.unwrap();

    let imported = import_governance(
        batlehub.as_ref(),
        &Scope {
            registries: vec![REGISTRY.into()],
            packages: vec![package.clone()],
        },
    )
    .await
    .unwrap();
    let ours = |n: &PackageNode| n.package == package;
    assert_eq!(imported.grants.iter().filter(|g| ours(&g.node)).count(), 1);
    assert_eq!(
        imported.policies.iter().filter(|p| ours(&p.node)).count(),
        1
    );

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
                        url: env("BATLEHUB_URL"),
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
    let mut items = importer::governance(&imported, NS, Some("hub"));
    items.retain(|i| match i {
        importer::Adoptable::Grant(g, _) => g.spec.package == package,
        importer::Adoptable::Policy(p, _) => p.spec.package == package,
    });
    let summary = importer::adopt_all(&client, NS, &items, false).await;
    assert_eq!((summary.adopted, summary.failed), (2, 0));

    let instances = Arc::new(LocalInstanceDirectory::new(client.clone()));
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(StaticGatewayFactory::new(batlehub.clone())),
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
    });
    tokio::spawn(controller::package_grant::run(client.clone(), ctx.clone()));
    tokio::spawn(controller::package_policy::run(client.clone(), ctx));

    let grants: Api<PackageGrant> = Api::namespaced(client.clone(), NS);
    let policies: Api<PackagePolicy> = Api::namespaced(client.clone(), NS);
    let name = importer::cr_name(&node);
    // Theirs now: no GrantConflict, no PolicyConflict.
    testkit::polling::wait_for(&grants, &name, TIMEOUT, POLL, |g: &PackageGrant| {
        (reason(g.status.as_ref().map(|s| &s.conditions)).as_deref() == Some("Reconciled"))
            .then_some(())
    })
    .await;
    testkit::polling::wait_for(&policies, &name, TIMEOUT, POLL, |p: &PackagePolicy| {
        (reason(p.status.as_ref().map(|s| &s.conditions)).as_deref() == Some("Reconciled"))
            .then_some(())
    })
    .await;
    let grant = grants.get(&name).await.unwrap().status.unwrap();
    assert!(grant.last_sync_time.is_none(), "rewritten: {grant:?}");

    // And theirs to remove.
    grants
        .delete(&name, &DeleteParams::default())
        .await
        .unwrap();
    policies
        .delete(&name, &DeleteParams::default())
        .await
        .unwrap();
    let deadline = tokio::time::Instant::now() + TIMEOUT;
    while grants.get_opt(&name).await.unwrap().is_some()
        || policies.get_opt(&name).await.unwrap().is_some()
    {
        assert!(tokio::time::Instant::now() < deadline, "not released");
        tokio::time::sleep(POLL).await;
    }
    assert!(batlehub.grants(&node).await.unwrap().is_empty());
    assert_eq!(batlehub.policy(&node).await.unwrap(), None);
}
