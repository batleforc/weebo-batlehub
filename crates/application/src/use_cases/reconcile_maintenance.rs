//! `BatleHubMaintenance`: an admin action run once or on a schedule, at
//! most once per run.
//!
//! [`decide`] says, from the object read from the API server, whether a
//! run is due. [`run_maintenance`] records the run as `Running` first —
//! through a [`RunGuard`], a status patch conditioned on the object's
//! `resourceVersion`: if anything wrote in between, nothing runs, the next
//! pass reads again — then calls the instance. A pass finding a run still
//! `Running` (the operator stopped during it) closes it as failed
//! (`MaintenanceInterrupted`) instead of replaying it: an import or a
//! purge must not run twice behind the user's back.

use std::time::Duration;

use api::maintenance::{
    LastRun, MaintenanceAction, MaintenanceParams, MaintenanceStatus, RunState,
};
use domain::Failure;
use domain::error::ReasonCode;
use jiff::{SignedDuration, Timestamp};
use serde_json::{Map, Value, json};

use super::Outcome;
use crate::cron::Schedule;
use crate::ports::{
    AdminGateway, AdminRequest, Approver, GatewayError, Method, PodGateway, RunGuard,
};

/// Beyond this, `lastRun.result` is replaced by a summary.
pub const RESULT_LIMIT: usize = 32 * 1024;

/// What a `BatleHubMaintenance` asks for, and where it stands.
#[derive(Debug, Clone, Copy)]
pub struct Plan<'a> {
    pub action: MaintenanceAction,
    pub params: &'a MaintenanceParams,
    pub schedule: Option<&'a str>,
    pub suspend: bool,
    pub ttl_seconds_after_finished: Option<i64>,
    pub timeout: Duration,
    pub generation: i64,
    /// `metadata.creationTimestamp`: a schedule's first run comes after.
    pub created: Timestamp,
    /// The `batlehub.weebo.io/run-now` annotation.
    pub run_now: Option<&'a str>,
}

/// What a pass does.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// Run now.
    Run,
    /// A run was left `Running`: close it as failed.
    Interrupted,
    /// Nothing due; `next_run` for an armed schedule, `wake` when to look
    /// again (the next run, or the end of a finished run's TTL).
    Wait {
        next_run: Option<Timestamp>,
        wake: Option<Timestamp>,
    },
    /// The schedule is suspended.
    Suspended,
    /// A single run finished more than `ttlSecondsAfterFinished` ago:
    /// delete the object.
    Delete,
    /// The schedule can't be read, or never runs.
    Invalid(Failure),
}

fn parse_time(text: &str) -> Option<Timestamp> {
    text.parse().ok()
}

pub fn decide(plan: &Plan<'_>, status: &MaintenanceStatus, now: Timestamp) -> Decision {
    let last = status.last_run.as_ref();
    if last.is_some_and(|r| r.state == RunState::Running) {
        return Decision::Interrupted;
    }
    if let Some(token) = plan.run_now
        && status.run_now.as_deref() != Some(token)
    {
        return Decision::Run;
    }
    let Some(schedule) = plan.schedule else {
        let Some(last) = last.filter(|r| r.generation >= plan.generation) else {
            return Decision::Run;
        };
        let finished = last.completion_time.as_deref().and_then(parse_time);
        return match (plan.ttl_seconds_after_finished, finished) {
            (Some(ttl), Some(finished)) => {
                let due = finished
                    .checked_add(SignedDuration::from_secs(ttl.max(0)))
                    .unwrap_or(Timestamp::MAX);
                if now >= due {
                    Decision::Delete
                } else {
                    Decision::Wait {
                        next_run: None,
                        wake: Some(due),
                    }
                }
            }
            _ => Decision::Wait {
                next_run: None,
                wake: None,
            },
        };
    };
    let schedule = match Schedule::parse(schedule) {
        Ok(schedule) => schedule,
        Err(why) => {
            return Decision::Invalid(Failure::new(
                ReasonCode::InvalidSpec,
                format!("schedule: {why}"),
            ));
        }
    };
    if plan.suspend {
        return Decision::Suspended;
    }
    let base = last
        .and_then(|r| parse_time(&r.start_time))
        .unwrap_or(plan.created);
    match schedule.next_after(base) {
        None => Decision::Invalid(Failure::new(
            ReasonCode::InvalidSpec,
            "schedule: never runs (no matching date within 5 years)",
        )),
        Some(next) if next <= now => Decision::Run,
        Some(next) => Decision::Wait {
            next_run: Some(next),
            wake: Some(next),
        },
    }
}

/// The status and outcome of a pass that runs nothing.
pub fn settle(
    decision: &Decision,
    plan: &Plan<'_>,
    mut status: MaintenanceStatus,
    now: Timestamp,
) -> (Outcome, MaintenanceStatus) {
    match decision {
        Decision::Interrupted => {
            let message =
                "the operator stopped during the run: closed as failed, not replayed".to_string();
            if let Some(run) = status.last_run.as_mut() {
                run.state = RunState::Failed;
                run.completion_time = Some(now.to_string());
                run.reason = Some(ReasonCode::MaintenanceInterrupted.as_str().to_string());
                run.message = Some(message.clone());
            }
            status.failure_count += 1;
            let outcome =
                Outcome::failed(Failure::new(ReasonCode::MaintenanceInterrupted, message));
            (outcome, status)
        }
        Decision::Invalid(failure) => {
            status.next_run_time = None;
            (Outcome::failed(failure.clone()), status)
        }
        Decision::Suspended => {
            status.next_run_time = None;
            let outcome = last_outcome(&status, plan).advise(
                ReasonCode::MaintenanceSuspended,
                "the schedule is suspended",
            );
            (outcome, status)
        }
        Decision::Wait { next_run, .. } => {
            status.next_run_time = next_run.map(|t| t.to_string());
            (last_outcome(&status, plan), status)
        }
        Decision::Run | Decision::Delete => (last_outcome(&status, plan), status),
    }
}

/// `Ready` from the last run: its failure, or a success / an armed
/// schedule.
fn last_outcome(status: &MaintenanceStatus, plan: &Plan<'_>) -> Outcome {
    let action = plan.action.as_str();
    match &status.last_run {
        Some(run) if run.state == RunState::Failed => {
            let reason = run
                .reason
                .as_deref()
                .and_then(|r| {
                    [
                        ReasonCode::MaintenanceTimeout,
                        ReasonCode::MaintenanceInterrupted,
                        ReasonCode::InvalidSpec,
                    ]
                    .into_iter()
                    .find(|c| c.as_str() == r)
                })
                .unwrap_or(ReasonCode::MaintenanceFailed);
            Outcome::failed(Failure::new(
                reason,
                format!(
                    "{action} failed: {}",
                    run.message.as_deref().unwrap_or("no message")
                ),
            ))
        }
        Some(run) => Outcome::synced(format!(
            "{action} succeeded{}",
            run.message
                .as_deref()
                .map(|m| format!(": {m}"))
                .unwrap_or_default()
        )),
        None => Outcome::synced(match &status.next_run_time {
            Some(next) => format!("{action} scheduled, next run at {next}"),
            None => format!("{action} waiting"),
        }),
    }
}

/// Where a run acts.
pub struct Target<'a> {
    pub gateway: &'a dyn AdminGateway,
    /// The proxy pods of `external.podSelector`, `None` without one.
    pub pods: Option<Vec<PodGateway>>,
    /// The instance's `external.manageConfig`.
    pub manage_config: bool,
    /// The configuration it holds (`reload.strategy: Manual`), by hash.
    pub held: Option<String>,
    /// What `configValidate` dry-runs on a `manageConfig` instance: the
    /// configuration rendered for it.
    pub rendered: Option<Result<String, Failure>>,
    pub approver: &'a dyn Approver,
    /// Restarts a managed instance's pods; `None` on an external one.
    pub restarter: Option<&'a dyn Restarter>,
}

/// Restarts the pods of a managed instance.
#[async_trait::async_trait]
pub trait Restarter: Send + Sync {
    /// The `Deployment`s restarted.
    async fn restart(&self) -> Result<Vec<String>, Failure>;
}

/// What a run ended on.
#[derive(Debug, Clone, PartialEq)]
pub struct RunReport {
    /// `false`: the object changed before the run was recorded, nothing
    /// ran.
    pub started: bool,
    pub outcome: Outcome,
    pub status: MaintenanceStatus,
}

pub async fn run_maintenance(
    plan: &Plan<'_>,
    mut status: MaintenanceStatus,
    now: Timestamp,
    target: &Target<'_>,
    guard: &dyn RunGuard,
) -> RunReport {
    let mut run = LastRun {
        state: RunState::Running,
        start_time: now.to_string(),
        completion_time: None,
        generation: plan.generation,
        reason: None,
        message: None,
        result: None,
    };
    match guard.start(&run, plan.run_now).await {
        Ok(true) => {}
        Ok(false) => {
            return RunReport {
                started: false,
                outcome: Outcome::synced("the object changed: the run is decided again"),
                status,
            };
        }
        Err(e) => {
            return RunReport {
                started: false,
                outcome: Outcome::failed(Failure::new(ReasonCode::KubernetesApiError, e)),
                status,
            };
        }
    }
    let result = match tokio::time::timeout(plan.timeout, execute(plan, target, now)).await {
        Ok(result) => result,
        Err(_) => Err(Failure::new(
            ReasonCode::MaintenanceTimeout,
            format!("no answer within {}s", plan.timeout.as_secs()),
        )),
    };
    let finished = Timestamp::now().max(now);
    run.completion_time = Some(finished.to_string());
    status.run_count += 1;
    status.run_now = plan.run_now.map(String::from).or(status.run_now);
    let outcome = match result {
        Ok(answer) => {
            let message = summary(&answer);
            run.state = RunState::Succeeded;
            run.message = (!message.is_empty()).then(|| message.clone());
            run.result = Some(bounded(answer, &message));
            Outcome::synced(format!(
                "{} succeeded{}",
                plan.action.as_str(),
                if message.is_empty() {
                    String::new()
                } else {
                    format!(": {message}")
                }
            ))
        }
        Err(failure) => {
            let reason = match failure.reason {
                ReasonCode::MaintenanceTimeout | ReasonCode::InvalidSpec => failure.reason,
                _ => ReasonCode::MaintenanceFailed,
            };
            run.state = RunState::Failed;
            run.reason = Some(reason.as_str().to_string());
            run.message = Some(failure.message.clone());
            status.failure_count += 1;
            Outcome::failed(Failure::new(
                reason,
                format!("{} failed: {}", plan.action.as_str(), failure.message),
            ))
        }
    };
    status.last_run = Some(run);
    status.next_run_time = plan
        .schedule
        .filter(|_| !plan.suspend)
        .and_then(|s| Schedule::parse(s).ok())
        .and_then(|s| s.next_after(now))
        .map(|t| t.to_string());
    RunReport {
        started: true,
        outcome,
        status,
    }
}

/// The scalar fields of an answer, `key=value`, or the answer itself when
/// it is a scalar.
pub fn summary(answer: &Value) -> String {
    let text = match answer {
        Value::Object(map) => map
            .iter()
            .filter_map(|(k, v)| match v {
                Value::String(s) => Some(format!("{k}={s}")),
                Value::Number(_) | Value::Bool(_) => Some(format!("{k}={v}")),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join(", "),
        Value::Null => String::new(),
        Value::String(s) => s.clone(),
        other if !other.is_array() => other.to_string(),
        Value::Array(items) => format!("{} item(s)", items.len()),
        _ => String::new(),
    };
    text.chars().take(1024).collect()
}

/// `answer`, or a summary of it beyond [`RESULT_LIMIT`].
fn bounded(answer: Value, summary: &str) -> Value {
    let size = answer.to_string().len();
    if size <= RESULT_LIMIT {
        return answer;
    }
    json!({"truncated": true, "bytes": size, "summary": summary})
}

fn missing(param: &str, action: MaintenanceAction) -> Failure {
    Failure::new(
        ReasonCode::InvalidSpec,
        format!("{} needs params.{param}", action.as_str()),
    )
}

fn segments(parts: &[&str]) -> Vec<String> {
    ["api", "v1", "admin"]
        .iter()
        .chain(parts)
        .map(|s| s.to_string())
        .collect()
}

/// `value` without its `null` fields.
fn object(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .filter(|(_, v)| !v.is_null())
                .collect::<Map<_, _>>(),
        ),
        other => other,
    }
}

/// The admin call of a plain action; `None` for the actions run
/// otherwise (configuration, health).
pub fn request(
    action: MaintenanceAction,
    params: &MaintenanceParams,
    now: Timestamp,
    timeout: Duration,
) -> Result<Option<AdminRequest>, Failure> {
    use MaintenanceAction::*;
    let need =
        |value: &Option<String>, name: &str| value.clone().ok_or_else(|| missing(name, action));
    let registry = || need(&params.registry, "registry");
    let dry_run = || {
        vec![(
            "dry_run".to_string(),
            params.dry_run.unwrap_or(true).to_string(),
        )]
    };
    let before = || -> Result<Option<String>, Failure> {
        match (&params.before, params.older_than_days) {
            (Some(before), _) => before
                .parse::<Timestamp>()
                .map(|t| Some(t.to_string()))
                .map_err(|e| Failure::new(ReasonCode::InvalidSpec, format!("params.before: {e}"))),
            (None, Some(days)) => Ok(Some(
                now.checked_sub(SignedDuration::from_hours(days.clamp(0, 365 * 100) * 24))
                    .unwrap_or(Timestamp::MIN)
                    .to_string(),
            )),
            (None, None) => Ok(None),
        }
    };
    let call = |method, path: Vec<String>, query, body: Option<Value>| {
        Ok(Some(AdminRequest {
            method,
            path,
            query,
            body: body.map(object),
            timeout: Some(timeout),
        }))
    };
    match action {
        ConfigReload | ConfigValidate | ConfigApplyPending | ConfigDiscardPending | HealthCheck
        | Restart => Ok(None),
        CacheWarm => {
            let r = registry()?;
            call(
                Method::Post,
                segments(&["registries", &r, "warm"]),
                vec![],
                Some(json!({
                    "package": params.package,
                    "packages": params.packages,
                    "path": params.path,
                    "paths": params.paths,
                    "versions": params.versions,
                })),
            )
        }
        CacheClearMetadata => {
            let r = registry()?;
            call(
                Method::Post,
                segments(&["registries", &r, "clear-cache"]),
                vec![],
                None,
            )
        }
        CacheClearArtifacts => {
            let r = registry()?;
            call(
                Method::Delete,
                segments(&["registries", &r, "cache"]),
                vec![],
                Some(
                    json!({"name": params.package, "version": params.version, "path": params.path}),
                ),
            )
        }
        CacheEvict => {
            let r = registry()?;
            call(
                Method::Post,
                segments(&["registries", &r, "evict"]),
                dry_run(),
                None,
            )
        }
        CacheCoherence => {
            let r = registry()?;
            call(
                Method::Post,
                segments(&["registries", &r, "coherence"]),
                dry_run(),
                None,
            )
        }
        RetentionRun => {
            let r = registry()?;
            call(
                Method::Post,
                segments(&["registries", &r, "retention"]),
                dry_run(),
                None,
            )
        }
        TombstonesCompact => {
            let r = registry()?;
            call(
                Method::Post,
                segments(&["registries", &r, "tombstones", "compact"]),
                dry_run(),
                None,
            )
        }
        PackageInvalidate => call(
            Method::Post,
            segments(&["packages", "invalidate"]),
            vec![],
            Some(json!({
                "registry": registry()?,
                "name": need(&params.package, "package")?,
                "version": need(&params.version, "version")?,
                "artifact": params.artifact,
            })),
        ),
        ExploreInvalidate => call(
            Method::Post,
            segments(&["explore", "invalidate"]),
            vec![],
            Some(json!({"registry": params.registry})),
        ),
        VulnerabilityRescan | VerdictBackfill => call(
            Method::Post,
            segments(&[
                "verdicts",
                if action == VulnerabilityRescan {
                    "rescan"
                } else {
                    "backfill"
                },
            ]),
            vec![],
            Some(json!({"registry": registry()?, "state": params.state})),
        ),
        UpstreamRecheck => call(
            Method::Post,
            segments(&["upstream", "recheck"]),
            vec![],
            Some(json!({
                "registry": registry()?,
                "package_name": need(&params.package, "package")?,
                "version": params.version,
            })),
        ),
        AuditLogPurge => {
            let before = before()?.ok_or_else(|| missing("before or olderThanDays", action))?;
            call(
                Method::Delete,
                segments(&["audit-log"]),
                vec![("before".into(), before)],
                None,
            )
        }
        AirGapMissingPurge => {
            let mut query = Vec::new();
            if let Some(before) = before()? {
                query.push(("before".to_string(), before));
            }
            if let Some(r) = &params.registry {
                query.push(("registry".to_string(), r.clone()));
            }
            call(
                Method::Delete,
                segments(&["air-gap", "missing"]),
                query,
                None,
            )
        }
        ReleaseImport => {
            let r = registry()?;
            call(
                Method::Post,
                segments(&["registries", &r, "import"]),
                vec![],
                Some(json!({"tag": params.tag, "repo": params.repo})),
            )
        }
        IpBlock => call(
            Method::Post,
            segments(&["ip-blocks"]),
            vec![],
            Some(json!({
                "ip": need(&params.ip, "ip")?,
                "reason": params.reason,
                "duration_secs": params.duration_seconds,
            })),
        ),
        IpUnblock => {
            let ip = need(&params.ip, "ip")?;
            call(Method::Delete, segments(&["ip-blocks", &ip]), vec![], None)
        }
        UserBlock => {
            let user = need(&params.user, "user")?;
            call(
                Method::Post,
                segments(&["users", &user, "block"]),
                vec![],
                Some(json!({"reason": params.reason})),
            )
        }
        UserUnblock => {
            let user = need(&params.user, "user")?;
            call(
                Method::Delete,
                segments(&["users", &user, "block"]),
                vec![],
                None,
            )
        }
        PackageBlock => call(
            Method::Post,
            segments(&["packages", "block"]),
            vec![],
            Some(json!({
                "registry": registry()?,
                "name": need(&params.package, "package")?,
                "version": need(&params.version, "version")?,
                "reason": need(&params.reason, "reason")?,
                "artifact": params.artifact,
            })),
        ),
        PackageUnblock => call(
            Method::Post,
            segments(&["packages", "unblock"]),
            vec![],
            Some(json!({
                "registry": registry()?,
                "name": need(&params.package, "package")?,
                "version": need(&params.version, "version")?,
                "artifact": params.artifact,
            })),
        ),
        QuotaReset => {
            let r = registry()?;
            let user = need(&params.user, "user")?;
            call(
                Method::Delete,
                segments(&["quota", &r, &user]),
                vec![],
                None,
            )
        }
        BannerSet => {
            let level = params.level.ok_or_else(|| missing("level", action))?;
            call(
                Method::Put,
                segments(&["banner"]),
                vec![],
                Some(json!({"message": need(&params.message, "message")?, "level": level})),
            )
        }
        BannerClear => call(Method::Delete, segments(&["banner"]), vec![], None),
    }
}

fn failed(err: GatewayError) -> Failure {
    Failure::new(ReasonCode::MaintenanceFailed, err.to_string())
}

/// Runs `call` on each pod (`podSelector`), or on the instance: one
/// answer per pod, failing when any pod failed (naming them).
async fn on_each<'a, F, Fut>(target: &'a Target<'a>, call: F) -> Result<Value, Failure>
where
    F: Fn(&'a dyn AdminGateway) -> Fut,
    Fut: Future<Output = Result<Value, GatewayError>>,
{
    let Some(pods) = &target.pods else {
        return call(target.gateway).await.map_err(failed);
    };
    if pods.is_empty() {
        return Err(Failure::new(
            ReasonCode::MaintenanceFailed,
            "no ready proxy pod matches external.podSelector",
        ));
    }
    let mut answers = Map::new();
    let mut failures = Vec::new();
    for pod in pods {
        match call(pod.gateway.as_ref()).await {
            Ok(answer) => {
                answers.insert(pod.name.clone(), answer);
            }
            Err(err) => {
                failures.push(format!("{}: {err}", pod.name));
                answers.insert(pod.name.clone(), json!({"error": err.to_string()}));
            }
        }
    }
    if failures.is_empty() {
        Ok(json!({ "pods": answers }))
    } else {
        Err(Failure::new(
            ReasonCode::MaintenanceFailed,
            failures.join("; "),
        ))
    }
}

async fn execute(plan: &Plan<'_>, target: &Target<'_>, now: Timestamp) -> Result<Value, Failure> {
    use MaintenanceAction::*;
    if let Some(request) = request(plan.action, plan.params, now, plan.timeout)? {
        return target.gateway.call(&request).await.map_err(failed);
    }
    match plan.action {
        ConfigReload => {
            if let Some(hash) = &target.held {
                target
                    .approver
                    .approve(hash)
                    .await
                    .map_err(|e| Failure::new(ReasonCode::MaintenanceFailed, e))?;
                return Ok(json!({"approved": hash}));
            }
            let request = AdminRequest {
                method: Method::Post,
                path: segments(&["config", "reload"]),
                query: vec![],
                body: None,
                timeout: Some(plan.timeout),
            };
            let request = &request;
            on_each(target, move |g| async move { g.call(request).await }).await
        }
        ConfigValidate => {
            let content = match &target.rendered {
                Some(rendered) => rendered.clone()?,
                None => target.gateway.config_content().await.map_err(failed)?,
            };
            let check = target
                .gateway
                .validate_config(&content)
                .await
                .map_err(failed)?;
            Ok(json!({"valid": true, "restart_required": check.restart_required}))
        }
        ConfigApplyPending => {
            if target.manage_config {
                return Err(Failure::new(
                    ReasonCode::InvalidSpec,
                    "configApplyPending is for an external instance without manageConfig: \
                     the operator approves its own configuration",
                ));
            }
            on_each(target, |g| async move {
                g.apply_pending().await.map(|()| json!({"applied": true}))
            })
            .await
        }
        ConfigDiscardPending => {
            on_each(target, |g| async move {
                g.discard_pending()
                    .await
                    .map(|()| json!({"discarded": true}))
            })
            .await
        }
        Restart => {
            let Some(restarter) = target.restarter else {
                return Err(Failure::new(
                    ReasonCode::InvalidSpec,
                    "restart needs a managed instance: the operator can't restart an instance \
                     it doesn't deploy",
                ));
            };
            let restarted = restarter.restart().await?;
            Ok(json!({ "restarted": restarted }))
        }
        HealthCheck => {
            let healthz = target
                .gateway
                .call(&AdminRequest {
                    method: Method::Get,
                    path: vec!["healthz".into()],
                    query: vec![],
                    body: None,
                    timeout: Some(plan.timeout),
                })
                .await
                .map_err(failed)?;
            let health = target
                .gateway
                .call(&AdminRequest {
                    method: Method::Get,
                    path: segments(&["health"]),
                    query: vec![],
                    body: None,
                    timeout: Some(plan.timeout),
                })
                .await
                .map_err(failed)?;
            Ok(json!({"healthz": healthz, "health": health}))
        }
        _ => unreachable!("a plain action has its request"),
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::test_support::FakeGateway;

    fn at(text: &str) -> Timestamp {
        text.parse().unwrap()
    }

    fn plan<'a>(
        action: MaintenanceAction,
        params: &'a MaintenanceParams,
        schedule: Option<&'a str>,
    ) -> Plan<'a> {
        Plan {
            action,
            params,
            schedule,
            suspend: false,
            ttl_seconds_after_finished: None,
            timeout: Duration::from_secs(5),
            generation: 1,
            created: at("2026-10-15T00:00:00Z"),
            run_now: None,
        }
    }

    fn finished(start: &str, state: RunState) -> MaintenanceStatus {
        MaintenanceStatus {
            last_run: Some(LastRun {
                state,
                start_time: start.into(),
                completion_time: Some(start.into()),
                generation: 1,
                reason: None,
                message: None,
                result: None,
            }),
            run_count: 1,
            ..Default::default()
        }
    }

    #[derive(Default)]
    struct Guard {
        refuse: bool,
        started: Mutex<Vec<LastRun>>,
    }

    #[async_trait::async_trait]
    impl RunGuard for Guard {
        async fn start(&self, run: &LastRun, _: Option<&str>) -> Result<bool, String> {
            if self.refuse {
                return Ok(false);
            }
            self.started.lock().unwrap().push(run.clone());
            Ok(true)
        }
    }

    #[derive(Default)]
    struct Approvals(Mutex<Vec<String>>);

    #[async_trait::async_trait]
    impl Approver for Approvals {
        async fn approve(&self, hash: &str) -> Result<(), String> {
            self.0.lock().unwrap().push(hash.into());
            Ok(())
        }
    }

    fn target<'a>(gateway: &'a FakeGateway, approver: &'a Approvals) -> Target<'a> {
        Target {
            gateway,
            pods: None,
            manage_config: false,
            held: None,
            rendered: None,
            approver,
            restarter: None,
        }
    }

    #[test]
    fn a_single_run_runs_once_per_generation_then_waits_for_its_ttl() {
        let params = MaintenanceParams::default();
        let mut p = plan(MaintenanceAction::BannerClear, &params, None);
        let now = at("2026-10-15T01:00:00Z");
        assert_eq!(
            decide(&p, &MaintenanceStatus::default(), now),
            Decision::Run
        );
        let done = finished("2026-10-15T00:30:00Z", RunState::Succeeded);
        assert_eq!(
            decide(&p, &done, now),
            Decision::Wait {
                next_run: None,
                wake: None
            }
        );
        p.ttl_seconds_after_finished = Some(3600);
        assert_eq!(
            decide(&p, &done, now),
            Decision::Wait {
                next_run: None,
                wake: Some(at("2026-10-15T01:30:00Z"))
            }
        );
        assert_eq!(
            decide(&p, &done, at("2026-10-15T01:30:00Z")),
            Decision::Delete
        );
        // A new spec is a new run.
        p.generation = 2;
        assert_eq!(decide(&p, &done, now), Decision::Run);
        // run-now, once per value.
        p.generation = 1;
        p.run_now = Some("a");
        assert_eq!(decide(&p, &done, now), Decision::Run);
        let mut answered = done.clone();
        answered.run_now = Some("a".into());
        p.ttl_seconds_after_finished = None;
        assert!(matches!(decide(&p, &answered, now), Decision::Wait { .. }));
    }

    #[test]
    fn a_schedule_runs_when_due_once_however_late() {
        let params = MaintenanceParams::default();
        let mut p = plan(MaintenanceAction::BannerClear, &params, Some("0 * * * *"));
        assert_eq!(
            decide(
                &p,
                &MaintenanceStatus::default(),
                at("2026-10-15T00:30:00Z")
            ),
            Decision::Wait {
                next_run: Some(at("2026-10-15T01:00:00Z")),
                wake: Some(at("2026-10-15T01:00:00Z"))
            }
        );
        assert_eq!(
            decide(
                &p,
                &MaintenanceStatus::default(),
                at("2026-10-15T01:00:00Z")
            ),
            Decision::Run
        );
        // Three slots missed: one run, then the next slot after it.
        let late = finished("2026-10-15T01:00:00Z", RunState::Succeeded);
        assert_eq!(decide(&p, &late, at("2026-10-15T04:10:00Z")), Decision::Run);
        p.suspend = true;
        assert_eq!(
            decide(&p, &late, at("2026-10-15T04:10:00Z")),
            Decision::Suspended
        );
        p.schedule = Some("nope");
        assert!(matches!(
            decide(&p, &late, at("2026-10-15T04:10:00Z")),
            Decision::Invalid(_)
        ));
    }

    #[test]
    fn a_run_left_running_is_closed_never_replayed() {
        let params = MaintenanceParams::default();
        let p = plan(MaintenanceAction::ReleaseImport, &params, None);
        let left = finished("2026-10-15T00:30:00Z", RunState::Running);
        let now = at("2026-10-15T01:00:00Z");
        let decision = decide(&p, &left, now);
        assert_eq!(decision, Decision::Interrupted);
        let (outcome, status) = settle(&decision, &p, left, now);
        assert_eq!(outcome.reason(), ReasonCode::MaintenanceInterrupted);
        assert_eq!(status.failure_count, 1);
        assert_eq!(status.last_run.as_ref().unwrap().state, RunState::Failed);
        // Next pass: closed, same generation, nothing runs.
        assert!(matches!(decide(&p, &status, now), Decision::Wait { .. }));
        let (outcome, _) = settle(&decide(&p, &status, now), &p, status, now);
        assert_eq!(outcome.reason(), ReasonCode::MaintenanceInterrupted);
    }

    #[tokio::test]
    async fn a_run_is_recorded_before_the_call_and_not_made_when_the_object_changed() {
        let gateway = FakeGateway::default();
        let approvals = Approvals::default();
        let params = MaintenanceParams {
            registry: Some("npm".into()),
            ..Default::default()
        };
        let p = plan(MaintenanceAction::CacheEvict, &params, None);
        let now = at("2026-10-15T01:00:00Z");
        let refused = Guard {
            refuse: true,
            ..Default::default()
        };
        let report = run_maintenance(
            &p,
            MaintenanceStatus::default(),
            now,
            &target(&gateway, &approvals),
            &refused,
        )
        .await;
        assert!(!report.started);
        assert!(gateway.requests().is_empty());

        let guard = Guard::default();
        gateway.answer(Some(Ok(
            json!({"evicted": 3, "dry_run": true, "items": [1, 2, 3]}),
        )));
        let report = run_maintenance(
            &p,
            MaintenanceStatus::default(),
            now,
            &target(&gateway, &approvals),
            &guard,
        )
        .await;
        assert!(report.started);
        assert_eq!(guard.started.lock().unwrap()[0].state, RunState::Running);
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        let run = report.status.last_run.unwrap();
        assert_eq!(run.state, RunState::Succeeded);
        assert_eq!(run.message.as_deref(), Some("dry_run=true, evicted=3"));
        assert_eq!(report.status.run_count, 1);
        // `dryRun` defaults to true.
        let request = &gateway.requests()[0];
        assert_eq!(request.path.join("/"), "api/v1/admin/registries/npm/evict");
        assert_eq!(request.query, [("dry_run".to_string(), "true".to_string())]);
    }

    #[tokio::test]
    async fn failures_and_timeouts_are_counted_and_reported() {
        let gateway = FakeGateway::default();
        let approvals = Approvals::default();
        let params = MaintenanceParams::default();
        let p = plan(MaintenanceAction::BannerClear, &params, Some("0 * * * *"));
        let now = at("2026-10-15T01:00:00Z");
        gateway.answer(Some(Err(GatewayError::NotFound("no banner".into()))));
        let report = run_maintenance(
            &p,
            MaintenanceStatus::default(),
            now,
            &target(&gateway, &approvals),
            &Guard::default(),
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::MaintenanceFailed);
        assert_eq!(report.status.failure_count, 1);
        assert_eq!(
            report.status.next_run_time.as_deref(),
            Some("2026-10-15T02:00:00Z")
        );
        let (outcome, _) = settle(
            &Decision::Wait {
                next_run: None,
                wake: None,
            },
            &p,
            report.status,
            now,
        );
        assert_eq!(outcome.reason(), ReasonCode::MaintenanceFailed);
    }

    #[tokio::test]
    async fn a_held_configuration_is_approved_rather_than_reloaded() {
        let gateway = FakeGateway::default();
        let approvals = Approvals::default();
        let params = MaintenanceParams::default();
        let p = plan(MaintenanceAction::ConfigReload, &params, None);
        let mut held = target(&gateway, &approvals);
        held.held = Some("abc".into());
        let report = run_maintenance(
            &p,
            MaintenanceStatus::default(),
            at("2026-10-15T01:00:00Z"),
            &held,
            &Guard::default(),
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        assert_eq!(*approvals.0.lock().unwrap(), ["abc"]);
        assert!(gateway.requests().is_empty());

        let mut managed = target(&gateway, &approvals);
        managed.manage_config = true;
        let p = plan(MaintenanceAction::ConfigApplyPending, &params, None);
        let report = run_maintenance(
            &p,
            MaintenanceStatus::default(),
            at("2026-10-15T01:00:00Z"),
            &managed,
            &Guard::default(),
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::InvalidSpec);
    }

    struct Pods;

    #[async_trait::async_trait]
    impl Restarter for Pods {
        async fn restart(&self) -> Result<Vec<String>, Failure> {
            Ok(vec!["hub".into(), "hub-worker".into()])
        }
    }

    #[tokio::test]
    async fn restart_needs_a_managed_instance() {
        let gateway = FakeGateway::default();
        let approvals = Approvals::default();
        let params = MaintenanceParams::default();
        let p = plan(MaintenanceAction::Restart, &params, None);
        let now = at("2026-10-15T01:00:00Z");
        let external = target(&gateway, &approvals);
        let report = run_maintenance(
            &p,
            MaintenanceStatus::default(),
            now,
            &external,
            &Guard::default(),
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::InvalidSpec);
        let mut managed = target(&gateway, &approvals);
        managed.restarter = Some(&Pods);
        let report = run_maintenance(
            &p,
            MaintenanceStatus::default(),
            now,
            &managed,
            &Guard::default(),
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        assert_eq!(
            report.status.last_run.unwrap().result.unwrap(),
            json!({"restarted": ["hub", "hub-worker"]})
        );
    }

    #[test]
    fn every_plain_action_builds_its_call() {
        let now = at("2026-10-15T00:00:00Z");
        let full = MaintenanceParams {
            registry: Some("npm".into()),
            package: Some("@acme/billing".into()),
            version: Some("1.0.0".into()),
            ip: Some("10.0.0.1".into()),
            user: Some("oidc:alice".into()),
            reason: Some("r".into()),
            message: Some("m".into()),
            level: Some(api::maintenance::BannerLevel::Warning),
            older_than_days: Some(30),
            ..Default::default()
        };
        for rule in MaintenanceAction::RULES {
            let built = request(rule.action, &full, now, Duration::from_secs(1)).unwrap();
            let configured = matches!(
                rule.action,
                MaintenanceAction::ConfigReload
                    | MaintenanceAction::ConfigValidate
                    | MaintenanceAction::ConfigApplyPending
                    | MaintenanceAction::ConfigDiscardPending
                    | MaintenanceAction::HealthCheck
                    | MaintenanceAction::Restart
            );
            assert_eq!(built.is_none(), configured, "{}", rule.action.as_str());
            // A missing required param is refused at run too.
            if !rule.required.is_empty() {
                assert!(
                    request(
                        rule.action,
                        &MaintenanceParams::default(),
                        now,
                        Duration::from_secs(1)
                    )
                    .is_err(),
                    "{}",
                    rule.action.as_str()
                );
            }
        }
        let purge = request(
            MaintenanceAction::AuditLogPurge,
            &full,
            now,
            Duration::from_secs(1),
        )
        .unwrap()
        .unwrap();
        assert_eq!(purge.query[0].1, "2026-09-15T00:00:00Z");
        let unblock = request(
            MaintenanceAction::IpUnblock,
            &full,
            now,
            Duration::from_secs(1),
        )
        .unwrap()
        .unwrap();
        assert_eq!(unblock.path.join("/"), "api/v1/admin/ip-blocks/10.0.0.1");
        let block = request(
            MaintenanceAction::PackageBlock,
            &full,
            now,
            Duration::from_secs(1),
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            block.body.unwrap(),
            json!({"registry": "npm", "name": "@acme/billing", "version": "1.0.0", "reason": "r"})
        );
    }

    #[test]
    fn a_large_answer_is_summarized() {
        let answer = json!({"count": 2, "items": vec!["x".repeat(100); 400]});
        let message = summary(&answer);
        assert_eq!(message, "count=2");
        let kept = bounded(answer, &message);
        assert_eq!(kept["truncated"], true);
        assert_eq!(kept["summary"], "count=2");
    }
}
