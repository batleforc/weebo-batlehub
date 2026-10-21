//! `BatleHubMaintenance`: an admin action, run once or on a schedule
//! (`reconcile_maintenance`). The operator is the scheduler: a pass
//! decides from the object read from the API server, records the run as
//! `Running` by a status patch conditioned on that object's
//! `resourceVersion` (a conflict: nothing runs, the next pass reads
//! again), calls the instance, then publishes the result. The next run of
//! a schedule is the requeue (`requeue_after`'s `due_in`: no jitter).
//!
//! No finalizer: a maintenance writes nothing it would have to remove.
//! A pass is also triggered by any change of a `BatleHubLocalInstance` of
//! its namespace, and by the `batlehub.weebo.io/run-now` annotation.

use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};

use api::Maintenance;
use api::local_instance::ReloadStrategy;
use api::maintenance::{LastRun, MaintenanceAction};
use application::ports::{Approver, KubernetesError, RunGuard};
use application::use_cases::reconcile_maintenance::{
    Decision, Plan, Restarter, Target, decide, run_maintenance, settle,
};
use application::use_cases::{Outcome, instance_failure};
use domain::error::ReasonCode;
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, DeleteParams, Patch, PatchParams};
use kube::runtime::controller::Action;
use kube::{Client, Resource, ResourceExt};
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;
use serde_json::{Map, Value, json};
use weebo_kit_runtime::events;

use super::{Ctx, Error, FIELD_MANAGER, error_policy};

pub const KIND: &str = "BatleHubMaintenance";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller = ctx
        .watches
        .controller(ctx.scope.api::<Maintenance>(client.clone()), &ctx.scope);
    let results = super::with_instances(controller, &ctx, &client)
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

/// `<prefix>_maintenance_runs_total{action,result}`.
fn runs() -> &'static Counter<u64> {
    static RUNS: OnceLock<Counter<u64>> = OnceLock::new();
    RUNS.get_or_init(|| {
        opentelemetry::global::meter(FIELD_MANAGER)
            // Spelled out: the docs' Metrics page checks the name in the sources.
            .u64_counter("weebo_batlehub_maintenance_runs_total")
            .with_description("Maintenance runs, by action and result")
            .build()
    })
}

/// The run guard: the `Running` record, written only on the object as
/// read (its `resourceVersion` in the patch makes the API server refuse
/// it with a 409 when anything wrote since).
struct ConditionalStart<'a> {
    api: Api<Maintenance>,
    name: String,
    resource_version: String,
    /// Announces the start (`MaintenanceStarted`), once recorded.
    recorder: &'a kube::runtime::events::Recorder,
    object: k8s_openapi::api::core::v1::ObjectReference,
    action: String,
}

/// Records `run` in the status of `name`, only if its `resourceVersion`
/// is still `resource_version`: `Ok(false)` when anything wrote since (the
/// API server answers 409), nothing written.
pub async fn record_start(
    api: &Api<Maintenance>,
    name: &str,
    resource_version: &str,
    run: &LastRun,
    run_now: Option<&str>,
) -> Result<bool, KubernetesError> {
    let mut status = json!({ "lastRun": run });
    if let Some(token) = run_now {
        status["runNow"] = json!(token);
    }
    let patch = Patch::Merge(json!({
        "metadata": { "resourceVersion": resource_version },
        "status": status,
    }));
    match api
        .patch_status(name, &PatchParams::apply(FIELD_MANAGER), &patch)
        .await
    {
        Ok(_) => Ok(true),
        Err(kube::Error::Api(e)) if e.code == 409 => Ok(false),
        Err(e) => Err(KubernetesError::new("recording the run", e)),
    }
}

#[async_trait::async_trait]
impl RunGuard for ConditionalStart<'_> {
    async fn start(&self, run: &LastRun, run_now: Option<&str>) -> Result<bool, KubernetesError> {
        let started =
            record_start(&self.api, &self.name, &self.resource_version, run, run_now).await?;
        if started {
            events::announce_change(
                self.recorder,
                &self.object,
                ReasonCode::MaintenanceStarted,
                events::RECONCILE,
                &format!("{} started", self.action),
            )
            .await;
        }
        Ok(started)
    }
}

/// Approves a held configuration: the instance's
/// `batlehub.weebo.io/approved-config-hash`.
struct AnnotateInstance {
    api: Api<api::LocalInstance>,
    name: String,
}

#[async_trait::async_trait]
impl Approver for AnnotateInstance {
    async fn approve(&self, hash: &str) -> Result<(), KubernetesError> {
        let patch = Patch::Merge(json!({
            "metadata": { "annotations": { api::APPROVED_CONFIG_HASH: hash } }
        }));
        self.api
            .patch(&self.name, &PatchParams::default(), &patch)
            .await
            .map(|_| ())
            .map_err(|e| KubernetesError::new(format!("approving {hash}"), e))
    }
}

/// Restarts the Deployments of a managed instance: the proxy's onto the
/// configuration the instance renders.
struct WorkloadRestart<'a> {
    workloads: &'a dyn application::ports::Workloads,
    owner: application::ports::Owner,
    config_hash: Option<String>,
}

#[async_trait::async_trait]
impl Restarter for WorkloadRestart<'_> {
    async fn restart(&self) -> Result<Vec<String>, domain::Failure> {
        let names = api::managed::Names::new(&self.owner.name);
        let mut restarted = Vec::new();
        for (name, hash) in [
            (names.proxy(), self.config_hash.as_deref()),
            (names.worker(), None),
        ] {
            if self
                .workloads
                .restart(&self.owner, &name, hash)
                .await
                .map_err(|e| {
                    domain::Failure::new(application::ports::workload_reason(&e), e.to_string())
                })?
            {
                restarted.push(name);
            }
        }
        Ok(restarted)
    }
}

fn plan<'a>(m: &'a Maintenance) -> Plan<'a> {
    let created = m
        .metadata
        .creation_timestamp
        .as_ref()
        .map(|t| t.0)
        .unwrap_or_else(Timestamp::now);
    Plan {
        action: m.spec.action,
        params: &m.spec.params,
        schedule: m.spec.schedule.as_deref(),
        suspend: m.spec.suspend,
        ttl_seconds_after_finished: m.spec.ttl_seconds_after_finished,
        timeout: Duration::from_secs(m.spec.timeout_seconds.max(1) as u64),
        generation: m.metadata.generation.unwrap_or_default(),
        created,
        run_now: m.annotations().get(api::RUN_NOW).map(String::as_str),
    }
}

/// The status fields a pass publishes, besides the conditions.
fn fields(status: &api::MaintenanceStatus) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("lastRun".into(), json!(status.last_run));
    fields.insert("nextRunTime".into(), json!(status.next_run_time));
    fields.insert("runCount".into(), json!(status.run_count));
    fields.insert("failureCount".into(), json!(status.failure_count));
    fields.insert("runNow".into(), json!(status.run_now));
    fields.insert("suspendedTime".into(), json!(status.suspended_time));
    fields.insert("resumedTime".into(), json!(status.resumed_time));
    fields
}

async fn reconcile(obj: Arc<Maintenance>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    if api::ANNOTATIONS.import_pending(&obj.metadata) {
        return Ok(Action::await_change());
    }
    let started = Instant::now();
    let namespace = obj.namespace().unwrap_or_default();
    let api: Api<Maintenance> = Api::namespaced(ctx.client.clone(), &namespace);
    // Decided on the object as the API server has it, never the cache.
    let Some(m) = api.get_opt(&obj.name_any()).await? else {
        return Ok(Action::await_change());
    };
    let status = m.status.clone().unwrap_or_default();
    let plan = plan(&m);
    let now = Timestamp::now();
    let decision = decide(&plan, &status, now);
    let (outcome, status, wake) = match &decision {
        Decision::Delete => {
            api.delete(&m.name_any(), &DeleteParams::default()).await?;
            return Ok(Action::await_change());
        }
        Decision::Run => {
            let Some(report) = run_once(&api, &m, &plan, status.clone(), now, &ctx).await? else {
                // Changed meanwhile: decided again on the next read.
                return Ok(Action::requeue(Duration::from_secs(1)));
            };
            report
        }
        _ => {
            let (outcome, status) = settle(&decision, &plan, status, now);
            let wake = match &decision {
                Decision::Wait { wake, .. } => *wake,
                _ => None,
            };
            (outcome, status, wake)
        }
    };
    super::record_reconcile(KIND, started, &outcome);
    super::publish(&api, &ctx.recorder, &m, &outcome, fields(&status)).await?;
    Ok(next(&m, &outcome, wake, now))
}

/// The steady requeue, or sooner when the schedule (or a TTL) is due.
fn next(m: &Maintenance, outcome: &Outcome, wake: Option<Timestamp>, now: Timestamp) -> Action {
    let due_in = wake.map(|w| w.as_second().saturating_sub(now.as_second()).max(1) as u64);
    weebo_kit_runtime::controller::requeue_after(m, outcome.steady(), due_in)
}

/// A run: the instance resolved, the run recorded, the action called.
/// `None` when the object changed before the run was recorded.
async fn run_once(
    api: &Api<Maintenance>,
    m: &Maintenance,
    plan: &Plan<'_>,
    status: api::MaintenanceStatus,
    now: Timestamp,
    ctx: &Ctx,
) -> Result<Option<(Outcome, api::MaintenanceStatus, Option<Timestamp>)>, Error> {
    let namespace = m.namespace().unwrap_or_default();
    let (bound, access) = match super::local_access(
        ctx,
        &namespace,
        m.spec.instance_ref.as_ref(),
        status.instance.as_ref(),
    )
    .await
    {
        Err(err) => return Ok(Some((Outcome::failed(instance_failure(err)), status, None))),
        Ok((bound, Err(err))) => {
            return Ok(Some((Outcome::failed(err).on(bound), status, None)));
        }
        Ok((bound, Ok(access))) => (bound, access),
    };
    let Some(instance) = ctx
        .registries
        .instance(&bound)
        .await
        .map_err(|e| Error::Failed(domain::Failure::new(ReasonCode::KubernetesApiError, e)))?
    else {
        return Ok(Some((
            Outcome::failed(domain::Failure::new(
                ReasonCode::InstanceNotFound,
                format!("{bound} not found"),
            ))
            .on(bound),
            status,
            None,
        )));
    };
    let pods = ctx
        .gateways
        .pod_gateways(&bound)
        .await
        .map_err(|e| Error::Failed(e.into()))?;
    let held = (instance.spec.reload.strategy == ReloadStrategy::Manual)
        .then(|| instance.status.as_ref()?.pending_config_hash.clone())
        .flatten();
    let rendered =
        if plan.action == MaintenanceAction::ConfigValidate && instance.spec.manages_config() {
            let (rendered, _) = super::local_instance::render(&instance, &bound, ctx).await?;
            Some(rendered.map(|r| r.document))
        } else {
            None
        };
    let approver = AnnotateInstance {
        api: Api::namespaced(ctx.client.clone(), bound.namespace.as_deref().unwrap_or("")),
        name: bound.name.clone(),
    };
    let restart = instance.spec.managed.as_ref().map(|_| WorkloadRestart {
        workloads: ctx.workloads.as_ref(),
        owner: application::ports::Owner {
            namespace: bound.namespace.clone().unwrap_or_default(),
            name: bound.name.clone(),
            uid: instance.uid().unwrap_or_default(),
        },
        config_hash: instance.status.as_ref().and_then(|s| s.config_hash.clone()),
    });
    let target = Target {
        restarter: restart.as_ref().map(|r| r as &dyn Restarter),
        gateway: access.gateway.as_ref(),
        pods,
        manage_config: instance.spec.manages_config(),
        held,
        rendered,
        approver: &approver,
    };
    let action = plan.action.as_str();
    let guard = ConditionalStart {
        api: api.clone(),
        name: m.name_any(),
        resource_version: m.resource_version().unwrap_or_default(),
        recorder: &ctx.recorder,
        object: m.object_ref(&()),
        action: action.clone(),
    };
    let report = run_maintenance(plan, status, now, &target, &guard).await;
    if !report.started {
        return match report.outcome.ready {
            Ok(_) => Ok(None),
            Err(failure) => Err(Error::Failed(failure)),
        };
    }
    runs().add(
        1,
        &[
            KeyValue::new("action", action),
            KeyValue::new(
                "result",
                if report.outcome.ready.is_ok() {
                    "success"
                } else {
                    "failure"
                },
            ),
        ],
    );
    // The next run, or the end of a single run's TTL.
    let wake = match decide(plan, &report.status, now) {
        Decision::Wait { wake, .. } => wake,
        _ => None,
    };
    Ok(Some((report.outcome.on(bound), report.status, wake)))
}
