use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use weebo_kit_api::InstanceRef;

use crate::status::{BoundInstance, Condition};

/// The short names the rest of the workspace uses.
pub use self::BatleHubMaintenance as Maintenance;
pub use self::BatleHubMaintenanceSpec as MaintenanceSpec;
pub use self::BatleHubMaintenanceStatus as MaintenanceStatus;

/// An administrative action against the instance of this namespace, run
/// once or on a schedule: warming or clearing a cache, a retention pass, a
/// configuration reload, blocking an IP…
///
/// The operator is the scheduler (no Job, no pod): it calls BatleHub's
/// admin API at the time due, at most once per run — a run interrupted by
/// a restart of the operator is closed as failed, never replayed. Actions
/// that respect `params.dryRun` only report unless it is set to `false`.
#[derive(CustomResource, Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[kube(
    group = "batlehub.weebo.io",
    version = "v1alpha1",
    kind = "BatleHubMaintenance",
    plural = "batlehubmaintenances",
    namespaced,
    shortname = "bhm",
    status = "BatleHubMaintenanceStatus",
    printcolumn = r#"{"name":"Instance","type":"string","jsonPath":".status.instance.name"}"#,
    printcolumn = r#"{"name":"Action","type":"string","jsonPath":".spec.action"}"#,
    printcolumn = r#"{"name":"Schedule","type":"string","jsonPath":".spec.schedule"}"#,
    printcolumn = r#"{"name":"Last Run","type":"string","jsonPath":".status.lastRun.state"}"#,
    printcolumn = r#"{"name":"Runs","type":"integer","jsonPath":".status.runCount"}"#,
    printcolumn = r#"{"name":"Next","type":"date","jsonPath":".status.nextRunTime"}"#,
    printcolumn = r#"{"name":"Ready","type":"string","jsonPath":".status.conditions[?(@.type=='Ready')].status"}"#
)]
#[serde(rename_all = "camelCase")]
#[schemars(transform = action_rules)]
pub struct BatleHubMaintenanceSpec {
    /// The `BatleHubLocalInstance` of this namespace to act on; unset, the
    /// only one of this namespace. Immutable.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(schema_with = "crate::common::local_instance_ref")]
    pub instance_ref: Option<InstanceRef>,
    /// What to run (the guide lists each action's endpoint and params).
    pub action: MaintenanceAction,
    /// The action's parameters: which ones an action needs is checked
    /// when the object is written.
    #[serde(default)]
    pub params: MaintenanceParams,
    /// A 5-field cron expression (minute hour day-of-month month
    /// day-of-week, UTC; day-of-week 0-7 from Sunday). Unset: one run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 128))]
    pub schedule: Option<String>,
    /// Pauses the schedule.
    #[serde(default)]
    pub suspend: bool,
    /// Deletes a single run's object this long after it finished.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 0))]
    pub ttl_seconds_after_finished: Option<i64>,
    /// Bounds the run, and the request to BatleHub.
    #[serde(default = "default_timeout")]
    #[schemars(range(min = 1, max = 86400))]
    pub timeout_seconds: i64,
}

fn default_timeout() -> i64 {
    600
}

/// The actions, and the parameters each needs. One table: the CRD's
/// validation rules are generated from it, and the run checks it again.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, Hash, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum MaintenanceAction {
    /// `POST /admin/config/reload` on the instance, or on each pod of
    /// `external.podSelector`; on an instance holding a configuration
    /// (`reload.strategy: Manual`), approves the held one instead.
    ConfigReload,
    /// A dry run (`POST /admin/config/validate`) of the configuration the
    /// operator renders (`manageConfig`), or of the instance's own file.
    ConfigValidate,
    /// `POST /admin/config/pending/apply`: an external instance without
    /// `manageConfig` only (elsewhere the operator approves its own).
    ConfigApplyPending,
    /// `DELETE /admin/config/pending`, on each pod with a `podSelector`.
    ConfigDiscardPending,
    /// `POST /admin/registries/{registry}/warm`.
    CacheWarm,
    /// `POST /admin/registries/{registry}/clear-cache`.
    CacheClearMetadata,
    /// `DELETE /admin/registries/{registry}/cache`.
    CacheClearArtifacts,
    /// `POST /admin/registries/{registry}/evict` (`dryRun`).
    CacheEvict,
    /// `POST /admin/registries/{registry}/coherence` (`dryRun`).
    CacheCoherence,
    /// `POST /admin/packages/invalidate`.
    PackageInvalidate,
    /// `POST /admin/explore/invalidate`.
    ExploreInvalidate,
    /// `POST /admin/registries/{registry}/retention` (`dryRun`).
    RetentionRun,
    /// `POST /admin/registries/{registry}/tombstones/compact` (`dryRun`).
    TombstonesCompact,
    /// `POST /admin/verdicts/rescan`.
    VulnerabilityRescan,
    /// `POST /admin/verdicts/backfill`.
    VerdictBackfill,
    /// `POST /admin/upstream/recheck`.
    UpstreamRecheck,
    /// `DELETE /admin/audit-log?before=`.
    AuditLogPurge,
    /// `DELETE /admin/air-gap/missing`.
    AirGapMissingPurge,
    /// `POST /admin/registries/{registry}/import`.
    ReleaseImport,
    /// `POST /admin/ip-blocks`.
    IpBlock,
    /// `DELETE /admin/ip-blocks/{ip}`.
    IpUnblock,
    /// `POST /admin/users/{user}/block`.
    UserBlock,
    /// `DELETE /admin/users/{user}/block`.
    UserUnblock,
    /// `POST /admin/packages/block`.
    PackageBlock,
    /// `POST /admin/packages/unblock`.
    PackageUnblock,
    /// `DELETE /admin/quota/{registry}/{user}`.
    QuotaReset,
    /// `PUT /admin/banner`.
    BannerSet,
    /// `DELETE /admin/banner`.
    BannerClear,
    /// A managed instance's pods restarted, worker included (a rolling
    /// restart, or `Recreate`'s): what applies the keys BatleHub reads at
    /// startup under `reload.restart: Never`. Refused on an external
    /// instance.
    Restart,
    /// `GET /healthz` (database, storage, version) and `GET
    /// /admin/health` (each registry), both in the result.
    HealthCheck,
}

/// What an action needs.
pub struct ActionRule {
    pub action: MaintenanceAction,
    /// The `params` it needs, each of them.
    pub required: &'static [&'static str],
    /// At least one of these, when not empty.
    pub one_of: &'static [&'static str],
    /// Whether it respects `params.dryRun`.
    pub dry_run: bool,
}

const fn rule(
    action: MaintenanceAction,
    required: &'static [&'static str],
    dry_run: bool,
) -> ActionRule {
    ActionRule {
        action,
        required,
        one_of: &[],
        dry_run,
    }
}

impl MaintenanceAction {
    /// The table of every action.
    pub const RULES: &'static [ActionRule] = &{
        use MaintenanceAction::*;
        [
            rule(ConfigReload, &[], false),
            rule(ConfigValidate, &[], false),
            rule(ConfigApplyPending, &[], false),
            rule(ConfigDiscardPending, &[], false),
            rule(CacheWarm, &["registry"], false),
            rule(CacheClearMetadata, &["registry"], false),
            rule(CacheClearArtifacts, &["registry"], false),
            rule(CacheEvict, &["registry"], true),
            rule(CacheCoherence, &["registry"], true),
            rule(
                PackageInvalidate,
                &["registry", "package", "version"],
                false,
            ),
            rule(ExploreInvalidate, &[], false),
            rule(RetentionRun, &["registry"], true),
            rule(TombstonesCompact, &["registry"], true),
            rule(VulnerabilityRescan, &["registry"], false),
            rule(VerdictBackfill, &["registry"], false),
            rule(UpstreamRecheck, &["registry", "package"], false),
            ActionRule {
                action: AuditLogPurge,
                required: &[],
                one_of: &["before", "olderThanDays"],
                dry_run: false,
            },
            rule(AirGapMissingPurge, &[], false),
            rule(ReleaseImport, &["registry"], false),
            rule(IpBlock, &["ip"], false),
            rule(IpUnblock, &["ip"], false),
            rule(UserBlock, &["user"], false),
            rule(UserUnblock, &["user"], false),
            rule(
                PackageBlock,
                &["registry", "package", "version", "reason"],
                false,
            ),
            rule(PackageUnblock, &["registry", "package", "version"], false),
            rule(QuotaReset, &["registry", "user"], false),
            rule(BannerSet, &["message", "level"], false),
            rule(BannerClear, &[], false),
            rule(Restart, &[], false),
            rule(HealthCheck, &[], false),
        ]
    };

    pub fn rule(self) -> &'static ActionRule {
        Self::RULES
            .iter()
            .find(|r| r.action == self)
            .expect("every action has a rule")
    }

    /// Its name, as in the spec.
    pub fn as_str(self) -> String {
        serde_json::to_value(self)
            .ok()
            .and_then(|v| v.as_str().map(String::from))
            .unwrap_or_default()
    }
}

/// One CEL rule per action needing params, from [`MaintenanceAction::RULES`].
fn action_rules(schema: &mut schemars::Schema) {
    let mut rules: Vec<serde_json::Value> = Vec::new();
    for rule in MaintenanceAction::RULES {
        if rule.required.is_empty() && rule.one_of.is_empty() {
            continue;
        }
        let name = rule.action.as_str();
        let mut checks: Vec<String> = rule
            .required
            .iter()
            .map(|p| format!("has(self.params.{p})"))
            .collect();
        if !rule.one_of.is_empty() {
            let any: Vec<String> = rule
                .one_of
                .iter()
                .map(|p| format!("has(self.params.{p})"))
                .collect();
            checks.push(format!("({})", any.join(" || ")));
        }
        let needs = if rule.one_of.is_empty() {
            rule.required.join(", ")
        } else {
            format!("one of {}", rule.one_of.join(", "))
        };
        rules.push(serde_json::json!({
            "rule": format!(
                "self.action != '{name}' || (has(self.params) && {})",
                checks.join(" && ")
            ),
            "message": format!("{name} needs params {needs}"),
        }));
    }
    rules.push(serde_json::json!({
        "rule": "has(self.instanceRef) == has(oldSelf.instanceRef)",
        "message": "instanceRef is immutable",
    }));
    schema.insert(
        "x-kubernetes-validations".into(),
        serde_json::Value::Array(rules),
    );
}

/// An action's parameters (each action reads the ones it needs).
#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct MaintenanceParams {
    /// A registry's name on the instance.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 253))]
    pub registry: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 1024))]
    pub package: Option<String>,
    /// Packages to warm.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub packages: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 256))]
    pub version: Option<String>,
    /// `cacheWarm`: how many of the latest versions.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub versions: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    /// Paths to warm (registries addressed by path).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub paths: Vec<String>,
    /// Report only (default `true`) for the actions that respect it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dry_run: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1))]
    pub ip: Option<String>,
    /// A user id, as the instance stores it (`oidc:alice`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1))]
    pub user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// `ipBlock`: how long; unset, until unblocked.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub duration_seconds: Option<i64>,
    /// RFC 3339: purge what is older.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("format" = "date-time"))]
    pub before: Option<String>,
    /// Purge what is older than this many days (instead of `before`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(range(min = 1))]
    pub older_than_days: Option<i64>,
    /// `vulnerabilityRescan`, `verdictBackfill`: only the verdicts in this
    /// state.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state: Option<VerdictState>,
    /// `releaseImport`: the release tag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tag: Option<String>,
    /// `releaseImport`: the repository.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>,
    /// `bannerSet`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(length(min = 1, max = 2048))]
    pub message: Option<String>,
    /// `bannerSet`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub level: Option<BannerLevel>,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum VerdictState {
    Allowed,
    Warned,
    Quarantined,
    Denied,
}

#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub enum BannerLevel {
    Info,
    Warning,
    Error,
}

/// Where a run stands.
#[derive(Serialize, Deserialize, Clone, Copy, Debug, PartialEq, Eq, JsonSchema)]
pub enum RunState {
    Running,
    Succeeded,
    Failed,
}

/// The last run.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct LastRun {
    pub state: RunState,
    pub start_time: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub completion_time: Option<String>,
    /// The `metadata.generation` it ran for.
    #[serde(default)]
    pub generation: i64,
    /// Why it failed: a reason code (`MaintenanceFailed`,
    /// `MaintenanceTimeout`, `MaintenanceInterrupted`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// The scalar fields of the instance's answer, or the error.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    /// The instance's answer, replaced by a summary beyond 32 KiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    #[schemars(extend("x-kubernetes-preserve-unknown-fields" = true))]
    pub result: Option<serde_json::Value>,
}

/// The runs.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct BatleHubMaintenanceStatus {
    /// The `metadata.generation` the last successful reconcile applied.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub observed_generation: Option<i64>,
    /// The instance this object was resolved to and stays bound to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance: Option<BoundInstance>,
    /// `Ready`: `True` when the last run succeeded or the schedule is
    /// armed.
    #[serde(default)]
    pub conditions: Vec<Condition>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_run: Option<LastRun>,
    /// When the schedule runs next.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub next_run_time: Option<String>,
    #[serde(default)]
    pub run_count: i64,
    #[serde(default)]
    pub failure_count: i64,
    /// The last value of the `batlehub.weebo.io/run-now` annotation a run
    /// answered.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_now: Option<String>,
    /// When the schedule was first seen suspended; cleared once it runs
    /// again.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suspended_time: Option<String>,
    /// When the schedule was last seen running again after a suspension:
    /// it counts from there, the runs missed meanwhile are skipped.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resumed_time: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_action_has_one_rule_and_a_name() {
        for rule in MaintenanceAction::RULES {
            assert_eq!(rule.action.rule().action, rule.action);
            assert!(!rule.action.as_str().is_empty());
        }
        assert_eq!(MaintenanceAction::CacheWarm.as_str(), "cacheWarm");
    }
}
