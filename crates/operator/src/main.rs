//! The `weebo-batlehub-operator` binary: wires the adapters into the
//! controllers, then runs them on the kit's runtime (telemetry, health,
//! graceful shutdown, leader election, HTTPS probes).

use std::fmt::Debug;
use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::admission::{BatleHubAdmission, KubeSiblings};
use adapters_inbound::controller::{self, Ctx, Shutdown};
use adapters_inbound::webhook;
use adapters_outbound::{
    BatleHubConfigParser, ClusterDependents, HttpGatewayFactory, KubeConfigSources,
    LocalInstanceDirectory,
};
use api::{LocalInstance, Maintenance, NamespaceClaim, PackageGrant, PackagePolicy, Registry};
use futures::StreamExt;
use kube::api::Api;
use kube::runtime::events::{Recorder, Reporter};
use kube::runtime::reflector::Store;
use kube::runtime::{WatchStreamExt, reflector, watcher};
use kube::{Client, Resource};
use serde::de::DeserializeOwned;
use weebo_kit_runtime::{Health, WatchScope, leader, telemetry, webhook_server};

/// Default `LEASE_NAME`. Keep it across releases: old and new pods of a
/// rollout must compete for the same lease.
const DEFAULT_LEASE_NAME: &str = "weebo-batlehub-operator-leader";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let telemetry = telemetry::init(controller::FIELD_MANAGER)?;
    let result = match std::env::args().nth(1).as_deref() {
        // What the image's smoke run calls: no cluster needed.
        Some("--version") => {
            println!(
                "{} {}",
                controller::FIELD_MANAGER,
                env!("CARGO_PKG_VERSION")
            );
            Ok(())
        }
        Some(other) => Err(anyhow::anyhow!("unknown command {other:?}")),
        None => run(&telemetry).await,
    };
    if let Err(err) = &result {
        tracing::error!(error = %err, "operator failed");
    }
    telemetry.shutdown();
    result
}

/// A reflector on `api`, its watch errors reported to `health`: the store
/// serves every read from memory instead of a request per reconcile, and
/// watch errors back off exponentially instead of spinning.
fn spawn_reflector<K>(
    api: Api<K>,
    scope: &WatchScope,
    health: Arc<Health>,
    name: &'static str,
) -> Store<K>
where
    K: Resource<DynamicType = ()> + Clone + Debug + DeserializeOwned + Send + Sync + 'static,
{
    let (store, writer) = reflector::store::<K>();
    let stream = reflector::reflector(
        writer,
        watcher(api, scope.watcher_config()).default_backoff(),
    );
    tokio::spawn(async move {
        stream
            .for_each(|event| {
                match event {
                    Ok(_) => health.ok(name),
                    Err(err) => {
                        tracing::warn!(error = %err, "{name} watch error");
                        health.failed(name, err.to_string());
                    }
                }
                futures::future::ready(())
            })
            .await;
    });
    store
}

async fn run(telemetry: &telemetry::Telemetry) -> anyhow::Result<()> {
    // `ring` and `aws-lc-rs` are both linked transitively (`kube`'s rustls
    // vs. reqwest's); rustls refuses to pick a default provider when more
    // than one is present.
    let _ = rustls::crypto::ring::default_provider().install_default();

    telemetry.serve_metrics().await?;
    register_leader_gauge();

    let client = Client::try_default().await?;
    // The whole cluster, or one namespace (with or without the
    // cluster-scoped kinds) and/or a label selector (the chart's
    // `watch.*`): an invalid value stops the start here, as does a kind
    // the scope can't watch.
    let scope = WatchScope::from_env()?;
    scope.ensure::<LocalInstance>()?;
    scope.ensure::<Registry>()?;
    scope.ensure::<NamespaceClaim>()?;
    scope.ensure::<PackageGrant>()?;
    scope.ensure::<PackagePolicy>()?;
    scope.ensure::<Maintenance>()?;
    tracing::info!(
        namespace = ?scope.watched_namespace(),
        selector = ?scope.selector(),
        "watch scope"
    );

    // The binary is PID 1 in its container: without a handler, SIGTERM
    // would be ignored and every rollout would wait for the SIGKILL.
    let shutdown = Shutdown::on_termination()?;
    let health = Arc::new(Health::default());

    // Every resolution reads the instances: one reflector on the only
    // instance kind, namespaced.
    let store = spawn_reflector(
        scope.api::<LocalInstance>(client.clone()),
        &scope,
        health.clone(),
        "BatleHubLocalInstance reflector",
    );
    let instances = Arc::new(
        LocalInstanceDirectory::new(client.clone())
            .with_scope(
                scope.watched_namespace().map(String::from),
                scope.selector().cloned(),
            )
            .with_store(store),
    );

    let sources = Arc::new(
        KubeConfigSources::new(client.clone(), instances.clone()).with_scope(
            scope.watched_namespace().map(String::from),
            scope.selector().cloned(),
        ),
    );
    let parser = Arc::new(BatleHubConfigParser::default());

    let holder_id = std::env::var("HOSTNAME").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(HttpGatewayFactory::new(client.clone(), instances.clone())),
        instances: instances.clone(),
        registries: instances,
        dependents: Arc::new(
            ClusterDependents::new(client.clone(), scope.watched_namespace().map(String::from))
                .with_selector(scope.selector().cloned()),
        ),
        config: parser.clone(),
        sources: sources.clone(),
        recorder: Recorder::new(
            client.clone(),
            Reporter {
                controller: controller::FIELD_MANAGER.into(),
                instance: Some(holder_id.clone()),
            },
        ),
        shutdown: shutdown.clone(),
        health: health.clone(),
        scope: scope.clone(),
    });

    // The HTTPS server (probes, the scope guard, the admission webhook)
    // runs on every replica, before and regardless of leadership: a
    // standby must stay ready, and a leader-only webhook would turn every
    // failover into an outage. On shutdown it keeps answering while
    // endpoints drain.
    let admission = Arc::new(BatleHubAdmission {
        sources,
        config: parser,
        siblings: Arc::new(KubeSiblings(client.clone())),
    });
    let server = webhook_server::spawn(
        webhook::router(health.clone(), scope, admission),
        health,
        shutdown.clone(),
    )
    .await?;

    // The controllers, in contrast, run on one replica at a time: two
    // active reconcilers could both create the same remote object.
    let leadership = tokio::select! {
        leadership = leader::acquire_leadership(&client, holder_id, DEFAULT_LEASE_NAME) => leadership,
        () = shutdown.wait() => {
            server.stopped().await;
            return Ok(());
        }
    };

    tracing::info!("starting controllers");
    tokio::join!(
        controller::local_instance::run(client.clone(), ctx.clone()),
        controller::registry::run(client.clone(), ctx.clone()),
        controller::namespace_claim::run(client.clone(), ctx.clone()),
        controller::package_grant::run(client.clone(), ctx.clone()),
        controller::package_policy::run(client.clone(), ctx.clone()),
        controller::maintenance::run(client.clone(), ctx.clone()),
    );
    // Every controller returns once the shutdown signal arrived and its
    // in-flight reconciles finished: hand the lease over right away
    // instead of making the next leader wait out the TTL.
    leadership.release().await;
    // Bounded: the drain started with the signal, long before.
    let _ = tokio::time::timeout(Duration::from_secs(30), server.stopped()).await;
    Ok(())
}

/// `<prefix>_leader`: 1 on the replica holding the lease.
fn register_leader_gauge() {
    // The callback lives as long as the meter provider: the handle can go.
    let _ = opentelemetry::global::meter(controller::FIELD_MANAGER)
        .u64_observable_gauge(format!("{}_leader", controller::METRIC_PREFIX))
        .with_description("1 when this replica holds the leader lease")
        .with_callback(|observer| observer.observe(u64::from(leader::is_leader()), &[]))
        .build();
}
