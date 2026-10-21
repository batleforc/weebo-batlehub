//! The `weebo-batlehub-operator` binary: wires the adapters into the
//! controllers, then runs them on the kit's runtime (telemetry, health,
//! graceful shutdown, leader election, HTTPS probes).

use std::sync::Arc;
use std::time::Duration;

use adapters_inbound::admission::{BatleHubAdmission, KubeSiblings};
use adapters_inbound::controller::{self, Ctx, ImageDefaults, Shutdown};
use adapters_inbound::webhook;
use adapters_outbound::{
    BatleHubConfigParser, ClusterDependents, HttpGatewayFactory, KubeConfigSources, KubeWorkloads,
    LocalInstanceDirectory, MeteredFactory,
};
use api::{LocalInstance, Maintenance, NamespaceClaim, PackageGrant, PackagePolicy, Registry};
use application::workload::OperatorPod;
use kube::Client;
use kube::runtime::events::{Recorder, Reporter};
use weebo_kit_runtime::shared::{LISTED_TIMEOUT, SharedWatch};
use weebo_kit_runtime::{Health, WatchScope, leader, pod, telemetry, webhook_server};

/// Default `LEASE_NAME`. Keep it across releases: old and new pods of a
/// rollout must compete for the same lease.
const DEFAULT_LEASE_NAME: &str = "weebo-batlehub-operator-leader";

/// The kit's runtime: `WEEBO_WORKER_THREADS` workers (4 by default), not
/// tokio's one per core (`weebo_kit_runtime::runtime`).
fn main() -> anyhow::Result<()> {
    weebo_kit_runtime::runtime::build()?.block_on(operator())
}

async fn operator() -> anyhow::Result<()> {
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

async fn run(telemetry: &telemetry::Telemetry) -> anyhow::Result<()> {
    // `ring` and `aws-lc-rs` are both linked transitively (`kube`'s rustls
    // vs. reqwest's); rustls refuses to pick a default provider when more
    // than one is present.
    let _ = rustls::crypto::ring::default_provider().install_default();

    telemetry.serve_metrics().await?;
    leader::register_leader_gauge(controller::FIELD_MANAGER, controller::METRIC_PREFIX);

    // This operator's own settings: an invalid value stops the start.
    let settings = Settings::from_env()?;
    adapters_outbound::admin_gateway::set_request_timeout(settings.admin_timeout);

    let operator = operator_pod()?;

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

    // One watch per CR kind, shared by every controller and by the stores
    // read in place of a LIST (instances, registries, dependents). Spawned
    // now, before the lease: a standby keeps them warm, and the
    // controllers start from stores that already listed.
    let watches = controller::spawn_watches(&client, &scope, &health);
    let mut instances = LocalInstanceDirectory::new(client.clone()).with_scope(
        scope.watched_namespace().map(String::from),
        scope.selector().cloned(),
    );
    if let Some(shared) = watches.get::<LocalInstance>() {
        instances = instances.with_store(shared.store());
    }
    let instances = Arc::new(instances);

    let sources = Arc::new(
        KubeConfigSources::new(client.clone(), instances.clone())
            .with_scope(
                scope.watched_namespace().map(String::from),
                scope.selector().cloned(),
            )
            .with_store(watches.get::<Registry>().map(SharedWatch::store)),
    );
    let parser = Arc::new(BatleHubConfigParser::default());
    // What a managed instance's pods may run (the chart's
    // `managedInstances.allowedImages`): checked by the webhook and again
    // before every apply.
    let allowed_images = application::pod_safety::parse_allowed_images(
        std::env::var("WEEBO_BATLEHUB_ALLOWED_IMAGES")
            .ok()
            .as_deref(),
    );

    let holder_id = std::env::var("HOSTNAME").unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
    let ctx = Arc::new(Ctx {
        client: client.clone(),
        gateways: Arc::new(MeteredFactory::new(HttpGatewayFactory::new(
            client.clone(),
            instances.clone(),
        ))),
        instances: instances.clone(),
        registries: instances,
        dependents: Arc::new(
            ClusterDependents::new(client.clone(), scope.watched_namespace().map(String::from))
                .with_selector(scope.selector().cloned())
                .with_watches(watches.clone()),
        ),
        workloads: Arc::new(
            KubeWorkloads::new(client.clone()).with_allowed_images(allowed_images.clone()),
        ),
        operator,
        token_review_role: std::env::var("WEEBO_BATLEHUB_TOKENREVIEW_CLUSTERROLE")
            .ok()
            .filter(|r| !r.is_empty() && scope.watched_namespace().is_none()),
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
        images: settings.images,
        watches,
    });

    // The HTTPS server (probes, the scope guard, the admission webhook)
    // runs on every replica, before and regardless of leadership: a
    // standby must stay ready, and a leader-only webhook would turn every
    // failover into an outage. On shutdown it keeps answering while
    // endpoints drain.
    let admission = Arc::new(BatleHubAdmission {
        sources,
        config: parser,
        siblings: Arc::new(KubeSiblings {
            client: client.clone(),
            watches: ctx.watches.clone(),
        }),
        allowed_images,
    });
    let server = webhook_server::spawn(
        webhook::router(health.clone(), scope, admission),
        health,
        shutdown.clone(),
    )
    .await?;

    // The controllers, in contrast, run on one replica at a time: two
    // active reconcilers could both create the same remote object. A
    // replica campaigns once its shared watches listed (their LISTs done
    // before the lease, not in the leader's first minute), or after
    // LISTED_TIMEOUT: a watch that can't list is reported by /livez, not
    // waited for.
    let campaign = async {
        ctx.watches.wait_listed(LISTED_TIMEOUT).await;
        leader::acquire_leadership(&client, holder_id, DEFAULT_LEASE_NAME).await
    };
    let leadership = tokio::select! {
        leadership = campaign => leadership,
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

/// The default image of managed instances' proxy pods.
const DEFAULT_IMAGE_ENV: &str = "WEEBO_BATLEHUB_DEFAULT_IMAGE";
/// The default image of their worker pods.
const DEFAULT_WORKER_IMAGE_ENV: &str = "WEEBO_BATLEHUB_DEFAULT_WORKER_IMAGE";
/// The timeout of the admin calls, in seconds (maintenances have theirs).
const ADMIN_TIMEOUT_ENV: &str = "WEEBO_BATLEHUB_ADMIN_TIMEOUT_SECONDS";

/// The `WEEBO_BATLEHUB_*` settings (the chart's `defaults.*`).
#[derive(Debug, PartialEq)]
struct Settings {
    images: ImageDefaults,
    admin_timeout: Duration,
}

impl Settings {
    fn from_env() -> anyhow::Result<Self> {
        Self::from_values(|name| std::env::var(name).ok())
    }

    fn from_values(var: impl Fn(&str) -> Option<String>) -> anyhow::Result<Self> {
        let set = |name: &str| var(name).filter(|v| !v.trim().is_empty());
        let image = |name: &str| {
            set(name)
                .map(|v| ImageDefaults::parse(&v).map_err(|e| anyhow::anyhow!("{name}: {e}")))
                .transpose()
        };
        let admin_timeout = match set(ADMIN_TIMEOUT_ENV) {
            None => adapters_outbound::admin_gateway::REQUEST_TIMEOUT,
            Some(v) => match v.trim().parse::<u64>() {
                Ok(secs) if (1..=600).contains(&secs) => Duration::from_secs(secs),
                _ => anyhow::bail!(
                    "{ADMIN_TIMEOUT_ENV}: {v:?} is not a number of seconds in 1..=600"
                ),
            },
        };
        Ok(Self {
            images: ImageDefaults {
                proxy: image(DEFAULT_IMAGE_ENV)?,
                worker: image(DEFAULT_WORKER_IMAGE_ENV)?,
            },
            admin_timeout,
        })
    }
}

/// The operator's own pods, let in by a managed instance's
/// `NetworkPolicy`: the chart's selector labels
/// (`WEEBO_OPERATOR_POD_LABELS`; malformed = a broken chart, the start
/// stops). Unset (run outside the chart), the chart's default label —
/// said once, a `nameOverride` would leave the operator out.
fn operator_pod() -> anyhow::Result<OperatorPod> {
    pod::operator_pod(application::workload::OPERATOR_CHART).map_err(anyhow::Error::msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn settings_default_and_refuse_garbage() {
        let none = Settings::from_values(|_| None).unwrap();
        assert_eq!(none.images, ImageDefaults::default());
        assert_eq!(none.admin_timeout, Duration::from_secs(15));
        let set = Settings::from_values(|name| match name {
            DEFAULT_IMAGE_ENV => Some("mirror.local/batlehub:1.6.0".into()),
            ADMIN_TIMEOUT_ENV => Some("30".into()),
            _ => None,
        })
        .unwrap();
        assert_eq!(
            set.images.proxy.unwrap().repository.as_deref(),
            Some("mirror.local/batlehub")
        );
        assert_eq!(set.admin_timeout, Duration::from_secs(30));
        for (name, value) in [
            (ADMIN_TIMEOUT_ENV, "0"),
            (ADMIN_TIMEOUT_ENV, "soon"),
            (DEFAULT_IMAGE_ENV, "x@sha256:1"),
        ] {
            assert!(
                Settings::from_values(|n| (n == name).then(|| value.to_string())).is_err(),
                "{name}={value}"
            );
        }
    }
}
