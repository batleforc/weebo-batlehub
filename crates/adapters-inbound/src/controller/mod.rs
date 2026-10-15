//! One `kube::runtime::Controller` per CRD, on the kit's skeleton
//! (triggers, concurrency, requeue, finalizer, Events, metrics). The
//! reconcile bodies delegate to `application::use_cases`.

use std::fmt::Debug;
use std::sync::{Arc, OnceLock};
use std::time::Instant;

use api::status::Condition;
use application::ports::{
    BoundInstance, ConfigParser, ConfigSources, GatewayFactory, GatewayFactoryError,
    InstanceAccess, InstanceDependents, InstanceDirectory, InstanceError, InstanceRef, Ledger,
    RegistryResolver, ResolveError,
};
use application::use_cases::{Outcome, instance_failure};
use domain::Failure;
use domain::error::ReasonCode;
use kube::api::{Api, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::runtime::events::Recorder;
use kube::runtime::reflector::ObjectRef;
use kube::{Client, Resource, ResourceExt};
use serde::Serialize;
use serde::de::DeserializeOwned;
use weebo_kit_runtime::events;
use weebo_kit_runtime::metrics::ReconcileMetrics;
use weebo_kit_runtime::status::StatusUpdate;
use weebo_kit_runtime::{Health, WatchScope};

/// Resolves once the process is asked to stop: every controller then stops
/// taking new work, lets its in-flight reconciles finish, and its `run`
/// returns.
pub use weebo_kit_runtime::Shutdown;
/// The kit's controller skeleton: a watch filtered to what reconciling
/// acts on (never the CR's own status patches), bounded concurrency
/// (`WEEBO_RECONCILE_CONCURRENCY`), the result stream drained into the
/// liveness.
pub use weebo_kit_runtime::controller::{controller, drive};

pub mod local_instance;
pub mod maintenance;
pub mod namespace_claim;
pub mod package_grant;
pub mod package_policy;
pub mod registry;

/// Field manager of the status patches, meter and Event reporter name.
pub const FIELD_MANAGER: &str = "weebo-batlehub-operator";
pub const FINALIZER: &str = "batlehub.weebo.io/finalizer";
/// Prefix of every metric: `<prefix>_reconcile_total`, `<prefix>_leader`…
pub const METRIC_PREFIX: &str = "weebo_batlehub";

/// Shared across every controller. Concrete adapters are built and
/// injected once, in `operator::main` (tests inject fakes).
pub struct Ctx {
    pub client: Client,
    pub gateways: Arc<dyn GatewayFactory>,
    /// Which instance a CR lives on (`LocalInstanceDirectory`, on the
    /// watch scope).
    pub instances: Arc<dyn InstanceDirectory>,
    /// Which instance a `BatleHubRegistry` attaches to (another
    /// namespace's, when it consents).
    pub registries: Arc<dyn RegistryResolver>,
    /// The CRs bound to an instance, holding its deletion.
    pub dependents: Arc<dyn InstanceDependents>,
    /// BatleHub's own configuration parser (`batlehub-config`).
    pub config: Arc<dyn ConfigParser>,
    /// What an instance's configuration is rendered from, besides its
    /// spec: `ConfigMap`s, `Secret`s, registries.
    pub sources: Arc<dyn ConfigSources>,
    /// One recorder for the whole process: the kit folds repeated Events
    /// into a series only within a recorder.
    pub recorder: Recorder,
    pub shutdown: Shutdown,
    /// Liveness: controllers report their watch errors here.
    pub health: Arc<Health>,
    /// What the controllers watch (`WEEBO_WATCH_NAMESPACE`,
    /// `WEEBO_WATCH_LABEL_SELECTOR`): every watch goes through it.
    pub scope: WatchScope,
}

/// What stopped a reconcile before (or instead of) its status.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Kubernetes API error: {0}")]
    Kube(#[from] kube::Error),
    /// Anything the finalizer helper reports: the reconcile's own error
    /// (`ApplyFailed`/`CleanupFailed`) or adding/removing the finalizer.
    #[error("{0}")]
    Finalizer(Box<kube::runtime::finalizer::Error<Error>>),
    /// A cleanup that couldn't delete the remote object: the finalizer
    /// stays until it can (or the CR is force-orphaned).
    #[error("{0}")]
    Cleanup(Failure),
    /// A reconcile stopped before its status (a read through a port).
    #[error("{0}")]
    Failed(Failure),
    /// A deletion waiting for something (`InstanceInUse`), already
    /// published on `Ready` and announced: retried without another Event.
    #[error("{0}")]
    Waiting(Failure),
}

impl Error {
    /// A deletion waiting, already announced by its status publish.
    pub fn is_waiting(&self) -> bool {
        use kube::runtime::finalizer::Error as Finalizer;
        match self {
            Error::Waiting(_) => true,
            Error::Finalizer(err) => {
                matches!(err.as_ref(), Finalizer::CleanupFailed(inner) if inner.is_waiting())
            }
            _ => false,
        }
    }

    /// The reason code of the Event announcing this error, and whether it
    /// happened reconciling or cleaning up (the Event's `action`).
    pub fn reason(&self) -> (ReasonCode, &'static str) {
        use kube::runtime::finalizer::Error as Finalizer;
        match self {
            Error::Kube(_) => (ReasonCode::KubernetesApiError, events::RECONCILE),
            Error::Cleanup(failure) => (failure.reason, events::CLEANUP),
            Error::Failed(failure) => (failure.reason, events::RECONCILE),
            Error::Waiting(failure) => (failure.reason, events::CLEANUP),
            Error::Finalizer(err) => match err.as_ref() {
                Finalizer::ApplyFailed(inner) => inner.reason(),
                Finalizer::CleanupFailed(inner) => (inner.reason().0, events::CLEANUP),
                _ => (ReasonCode::KubernetesApiError, events::RECONCILE),
            },
        }
    }
}

/// Every reconcile that errors out is announced by a `Warning` Event on
/// its CR, then retried in ~30s (the kit's).
pub fn error_policy<K>(obj: Arc<K>, err: &Error, ctx: Arc<Ctx>) -> Action
where
    K: Resource<DynamicType = ()>,
{
    if err.is_waiting() {
        return weebo_kit_runtime::controller::requeue_after(false, None);
    }
    let (reason, action) = err.reason();
    weebo_kit_runtime::controller::retry_after_error(
        &ctx.recorder,
        obj.object_ref(&()),
        reason,
        action,
        err,
    )
}

/// Steady-state drift check after a success or a failure only a change of
/// the spec can clear, a quick retry after any other failure (both
/// jittered — the kit's).
pub fn requeue_after(outcome: &Outcome) -> Action {
    weebo_kit_runtime::controller::requeue_after(outcome.steady(), None)
}

/// `<prefix>_reconcile_total` / `_duration_seconds` (the kit's
/// `ReconcileMetrics`). A no-op until the telemetry installs a real
/// `MeterProvider`.
pub fn record_reconcile(kind: &'static str, started: Instant, outcome: &Outcome) {
    static METRICS: OnceLock<ReconcileMetrics> = OnceLock::new();
    METRICS
        .get_or_init(|| ReconcileMetrics::new(FIELD_MANAGER, METRIC_PREFIX))
        .record(kind, outcome.reason(), started.elapsed());
}

/// What [`publish`] needs of a CR's `status`.
pub trait HasStatus {
    /// The conditions of the last publish.
    fn conditions(&self) -> &[Condition];

    /// The instance recorded at the last resolution (the kinds that target
    /// an instance).
    fn bound_instance(&self) -> Option<&BoundInstance> {
        None
    }
}

impl HasStatus for api::LocalInstance {
    fn conditions(&self) -> &[Condition] {
        self.status
            .as_ref()
            .map(|s| s.conditions.as_slice())
            .unwrap_or_default()
    }
}

impl HasStatus for api::NamespaceClaim {
    fn conditions(&self) -> &[Condition] {
        self.status
            .as_ref()
            .map(|s| s.conditions.as_slice())
            .unwrap_or_default()
    }

    fn bound_instance(&self) -> Option<&BoundInstance> {
        self.status.as_ref().and_then(|s| s.instance.as_ref())
    }
}

impl HasStatus for api::PackageGrant {
    fn conditions(&self) -> &[Condition] {
        self.status
            .as_ref()
            .map(|s| s.conditions.as_slice())
            .unwrap_or_default()
    }

    fn bound_instance(&self) -> Option<&BoundInstance> {
        self.status.as_ref().and_then(|s| s.instance.as_ref())
    }
}

impl HasStatus for api::PackagePolicy {
    fn conditions(&self) -> &[Condition] {
        self.status
            .as_ref()
            .map(|s| s.conditions.as_slice())
            .unwrap_or_default()
    }

    fn bound_instance(&self) -> Option<&BoundInstance> {
        self.status.as_ref().and_then(|s| s.instance.as_ref())
    }
}

impl HasStatus for api::Maintenance {
    fn conditions(&self) -> &[Condition] {
        self.status
            .as_ref()
            .map(|s| s.conditions.as_slice())
            .unwrap_or_default()
    }

    fn bound_instance(&self) -> Option<&BoundInstance> {
        self.status.as_ref().and_then(|s| s.instance.as_ref())
    }
}

impl HasStatus for api::Registry {
    fn conditions(&self) -> &[Condition] {
        self.status
            .as_ref()
            .map(|s| s.conditions.as_slice())
            .unwrap_or_default()
    }

    fn bound_instance(&self) -> Option<&BoundInstance> {
        self.status.as_ref().and_then(|s| s.instance.as_ref())
    }
}

/// Publishes `outcome` on `obj` (read fresh from the API server: its
/// conditions are the previous ones). The kit's: one merge patch
/// (conditions with the advisories, `observedGeneration` on success, the
/// bound instance, the kind's own `fields`), retried while the apiserver
/// is unavailable, then a `Warning` on every failed reconcile and a
/// `Normal` for every condition change.
pub async fn publish<K>(
    api: &Api<K>,
    recorder: &Recorder,
    obj: &K,
    outcome: &Outcome,
    mut fields: serde_json::Map<String, serde_json::Value>,
) -> Result<(), kube::Error>
where
    K: Resource<DynamicType = ()> + HasStatus + Clone + Debug + DeserializeOwned + Serialize,
{
    let previous = obj.conditions();
    if let Some(instance) = &outcome.instance {
        let instance = serde_json::to_value(instance).expect("a BoundInstance serializes");
        fields.insert("instance".into(), instance);
    }
    weebo_kit_runtime::status::publish(
        api,
        recorder,
        FIELD_MANAGER,
        obj,
        previous,
        StatusUpdate {
            ready: &outcome.ready,
            advisories: &outcome.advisories,
            fields,
        },
    )
    .await
    .map(|_| ())
}

/// `controller`, also triggered for every CR of a namespace when one of
/// its `BatleHubLocalInstance`s appears, goes or changes (its token, its
/// readiness): the kinds bound to an instance of their own namespace.
pub fn with_instances<K>(
    controller: kube::runtime::Controller<K>,
    scope: &WatchScope,
    client: Client,
) -> kube::runtime::Controller<K>
where
    K: Resource<DynamicType = ()> + Clone + Debug + DeserializeOwned + Send + Sync + 'static,
{
    let store = controller.store();
    controller.watches(
        scope.api::<api::LocalInstance>(client),
        scope.watcher_config(),
        move |instance| {
            let namespace = instance.namespace();
            store
                .state()
                .iter()
                .filter(|o| o.namespace() == namespace)
                .map(|o| ObjectRef::from_obj(o.as_ref()))
                .collect::<Vec<_>>()
        },
    )
}

/// The instance of a CR bound to an instance of its own namespace, and
/// the gateway to it.
pub async fn local_access(
    ctx: &Ctx,
    namespace: &str,
    instance_ref: Option<&InstanceRef>,
    recorded: Option<&BoundInstance>,
) -> Result<(BoundInstance, Result<InstanceAccess, GatewayFactoryError>), InstanceError> {
    let bound = ctx
        .instances
        .resolve(Some(namespace), instance_ref, recorded)
        .await?;
    let access = ctx.gateways.gateway_for(&bound).await;
    Ok((bound, access))
}

/// The gateway a cleanup removes through; `None` when the instance is
/// gone (deleted with `force-orphan`): nothing is left to remove on, the
/// finalizer goes.
pub async fn cleanup_access(
    ctx: &Ctx,
    namespace: &str,
    instance_ref: Option<&InstanceRef>,
    recorded: Option<&BoundInstance>,
    what: &str,
) -> Result<Option<InstanceAccess>, Error> {
    match local_access(ctx, namespace, instance_ref, recorded).await {
        Ok((_, Ok(access))) => Ok(Some(access)),
        Err(InstanceError::Resolve(ResolveError::NotFound { .. } | ResolveError::NoInstance)) => {
            tracing::warn!("{what}: its instance is gone, nothing removed");
            Ok(None)
        }
        Ok((bound, Err(GatewayFactoryError::InstanceNotFound(_)))) => {
            tracing::warn!("{what}: {bound} is gone, nothing removed");
            Ok(None)
        }
        Ok((_, Err(err))) => Err(Error::Cleanup(err.into())),
        Err(err) => Err(Error::Cleanup(instance_failure(err))),
    }
}

/// A [`Ledger`] writing into the status of one CR, by merge patch: what a
/// governance reconcile wrote, recorded right after each write.
pub struct StatusLedger<K> {
    pub api: Api<K>,
    pub name: String,
    /// The `status` field written (`applied`…); `None`: the record's own
    /// fields, merged into `status`.
    pub field: Option<&'static str>,
}

#[async_trait::async_trait]
impl<K, T> Ledger<T> for StatusLedger<K>
where
    K: Resource<DynamicType = ()> + Clone + Debug + DeserializeOwned + Send + Sync,
    T: Serialize + Send + Sync,
{
    async fn record(&self, written: &T) -> Result<(), String> {
        let status = match self.field {
            Some(field) => serde_json::json!({ field: written }),
            None => serde_json::to_value(written).map_err(|e| e.to_string())?,
        };
        let patch = Patch::Merge(serde_json::json!({ "status": status }));
        self.api
            .patch_status(&self.name, &PatchParams::apply(FIELD_MANAGER), &patch)
            .await
            .map(|_| ())
            .map_err(|e| format!("recording the status: {e}"))
    }
}

/// A finalizer's cleanup — unless the CR carries
/// `batlehub.weebo.io/force-orphan: "true"`, the way out for
/// a CR whose cleanup can't succeed any more (its instance gone) — then a
/// `Released` Event (the kit's).
pub async fn finalize<K>(
    obj: &K,
    ctx: &Ctx,
    cleanup: impl Future<Output = Result<(), Error>>,
) -> Result<Action, Error>
where
    K: Resource<DynamicType = ()>,
{
    weebo_kit_runtime::controller::finalize(
        obj,
        &ctx.recorder,
        &api::ANNOTATIONS,
        ReasonCode::Released,
        cleanup,
    )
    .await
}

#[cfg(test)]
mod tests {
    use kube::runtime::finalizer::Error as Finalizer;

    use super::*;

    #[test]
    fn errors_map_to_a_reason_and_an_action() {
        let unreachable = || Error::Cleanup(Failure::new(ReasonCode::InstanceUnreachable, "x"));
        assert_eq!(
            unreachable().reason(),
            (ReasonCode::InstanceUnreachable, events::CLEANUP)
        );
        assert_eq!(
            Error::Finalizer(Box::new(Finalizer::CleanupFailed(unreachable()))).reason(),
            (ReasonCode::InstanceUnreachable, events::CLEANUP)
        );
        assert_eq!(
            Error::Finalizer(Box::new(Finalizer::UnnamedObject)).reason(),
            (ReasonCode::KubernetesApiError, events::RECONCILE)
        );
        let waiting = || Error::Waiting(Failure::new(ReasonCode::InstanceInUse, "x"));
        assert!(Error::Finalizer(Box::new(Finalizer::CleanupFailed(waiting()))).is_waiting());
        assert!(!unreachable().is_waiting());
    }
}
