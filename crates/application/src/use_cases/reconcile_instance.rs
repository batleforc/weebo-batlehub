//! A `BatleHubLocalInstance` in external mode: a connectivity and token
//! check (`/livez`, then the token's role on the admin API), BatleHub's
//! own warnings on its configuration and, with `external.manageConfig`,
//! the configuration rendered from the CR pushed to the instance (or to
//! each of its pods with `external.podSelector`). Every CR bound to it
//! depends on the result. Its deletion waits while CRs are bound to it.
//!
//! The push, on each target behind (its file on disk differs from the
//! rendered document):
//!
//! 1. one dry run (`POST …/config/validate`) — a configuration every pod
//!    would refuse reaches none, and one that changes a key needing a
//!    restart is held back (`RestartForbidden`: the operator can't
//!    restart what it doesn't deploy);
//! 2. on each target, `POST …/config/from-content` stages it, then
//!    `POST …/config/pending/apply` approves it — which writes it to the
//!    instance's disk. BatleHub stages nothing for bytes identical to its
//!    last load attempt (one that failed or expired): the reload nonce, a
//!    final comment outside the hash, makes them new;
//! 3. the file is read back: still different, the instance couldn't
//!    write it (`ConfigReadOnly`), the change would be lost on restart.
//!
//! A refusal is recorded (`rejectedConfigHash`, `lastRejectionTime`) and
//! the same configuration is pushed again at most every 10 minutes.
//! `reload.strategy: Manual` holds a configuration until its exact hash
//! is approved.

use std::sync::Arc;

use api::local_instance::{PodConfig, ReloadStrategy};
use domain::error::ReasonCode;
use domain::{Advisory, Failure};

use crate::ports::{AdminGateway, ConfigWarning, GatewayError, PendingSource};
use crate::use_cases::Outcome;
use crate::use_cases::render_config::{Rendered, sha256};

/// How many dependents, warnings or pods a message names.
const SHOWN: usize = 5;
/// How long a refused configuration waits before it is pushed again.
pub const REJECTION_BACKOFF_SECS: i64 = 600;
/// How soon a reload in progress is looked at again.
pub const PROPAGATION_RETRY_SECS: u64 = 15;
/// The first characters of the reload nonce's comment line.
pub const NONCE_COMMENT: &str = "# weebo-batlehub reload-nonce: ";

/// What a reconcile of the instance ends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceReport {
    pub outcome: Outcome,
    /// What the instance said about itself, when it answered.
    pub observed: Option<Observed>,
    /// The configuration fields of the status (with `manageConfig`).
    pub config: Option<ConfigStatus>,
    /// When the next pass is due, sooner than the requeue interval.
    pub due_in: Option<u64>,
    /// Whether this pass made the instance load a new configuration.
    pub reloaded: bool,
}

/// The instance's status fields, read from BatleHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub version: String,
    pub warnings: Vec<ConfigWarning>,
}

/// Where the configuration stands, from the status, and what the pass
/// needs to decide.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigState {
    pub applied_hash: Option<String>,
    pub nonce: u64,
    /// The last configuration the instance refused, or loaded without
    /// being able to write it ([`Self::unpersisted_hash`]), and when
    /// (Unix seconds): not pushed again for [`REJECTION_BACKOFF_SECS`].
    pub rejected_hash: Option<String>,
    pub rejected_at: Option<i64>,
    /// What the instance said when it refused it.
    pub rejection_message: Option<String>,
    /// A configuration the instance loaded but couldn't write to its file.
    pub unpersisted_hash: Option<String>,
    /// The pods behind, as last seen.
    pub pods: Vec<PodConfig>,
    pub strategy: ReloadStrategy,
    /// `batlehub.weebo.io/approved-config-hash`.
    pub approved_hash: Option<String>,
    /// Unix seconds.
    pub now: i64,
}

/// The configuration fields of the status after the pass.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ConfigStatus {
    pub config_hash: Option<String>,
    pub applied_hash: Option<String>,
    pub pending_hash: Option<String>,
    pub nonce: u64,
    pub rejected_hash: Option<String>,
    /// Unix seconds.
    pub rejected_at: Option<i64>,
    pub rejection_message: Option<String>,
    pub unpersisted_hash: Option<String>,
    pub restart_keys: Vec<String>,
    pub pods: Vec<PodConfig>,
    /// Unix seconds.
    pub reloaded_at: Option<i64>,
}

impl ConfigStatus {
    /// The status as the previous pass left it.
    fn from_state(state: &ConfigState) -> Self {
        Self {
            config_hash: None,
            applied_hash: state.applied_hash.clone(),
            pending_hash: None,
            nonce: state.nonce,
            rejected_hash: state.rejected_hash.clone(),
            rejected_at: state.rejected_at,
            rejection_message: state.rejection_message.clone(),
            unpersisted_hash: state.unpersisted_hash.clone(),
            restart_keys: Vec::new(),
            pods: state.pods.clone(),
            reloaded_at: None,
        }
    }
}

/// What `manageConfig` brings to a pass.
pub struct ManagedConfig {
    /// The configuration rendered from the CR (its token checked), or why
    /// it couldn't be.
    pub rendered: Result<Rendered, Failure>,
    pub state: ConfigState,
    /// Where to push: the instance's `url`, or each ready proxy pod.
    pub targets: Targets,
}

/// A proxy pod, by name, and its gateway.
pub type Pod = (String, Arc<dyn AdminGateway>);

pub enum Targets {
    /// No `podSelector`: the instance's `url`.
    Url,
    /// Its ready proxy pods; `Err` when they couldn't be listed.
    Pods(Result<Vec<Pod>, Failure>),
}

/// The pass of an instance. A configuration that can't be rendered
/// outranks what the instance answers (the spec's §5): it is reported
/// even when the instance is down, with what it said about itself when it
/// answered.
pub async fn reconcile_instance(
    gateway: &dyn AdminGateway,
    managed: Option<ManagedConfig>,
) -> InstanceReport {
    let answer = async {
        let info = gateway.ping().await?;
        let warnings = gateway.config_warnings().await?;
        Ok::<_, GatewayError>((info, warnings))
    }
    .await;
    let observed = answer.as_ref().ok().map(|(info, warnings)| Observed {
        version: info.version.clone(),
        warnings: warnings.clone(),
    });
    let mut report = InstanceReport {
        outcome: Outcome::synced(String::new()),
        observed,
        config: None,
        due_in: None,
        reloaded: false,
    };
    let warnings = match (answer, managed) {
        (
            _,
            Some(ManagedConfig {
                rendered: Err(failure),
                state,
                ..
            }),
        ) => {
            report.outcome = Outcome::failed(failure);
            report.config = Some(ConfigStatus::from_state(&state));
            return report;
        }
        (Err(e), _) => {
            report.outcome = Outcome::failed(e);
            return report;
        }
        (Ok((info, warnings)), managed) => {
            report.outcome = Outcome::synced(format!("BatleHub {} answers", info.version));
            if let Some(managed) = managed {
                let push = manage(gateway, managed).await;
                report.config = Some(push.status);
                report.due_in = push.due_in;
                report.reloaded = push.reloaded;
                report.outcome.ready = push.ready;
                report.outcome.advisories = push.advisories;
            }
            warnings
        }
    };
    if !warnings.is_empty() {
        report.outcome = report
            .outcome
            .advise(ReasonCode::ConfigWarnings, warnings_message(&warnings));
    }
    report
}

struct Push {
    ready: Result<String, Failure>,
    advisories: Vec<Advisory>,
    status: ConfigStatus,
    due_in: Option<u64>,
    reloaded: bool,
}

/// The document as written to a target: the nonce's comment last.
pub fn with_nonce(document: &str, nonce: u64) -> String {
    if nonce == 0 {
        return document.to_string();
    }
    let sep = if document.ends_with('\n') { "" } else { "\n" };
    format!("{document}{sep}{NONCE_COMMENT}{nonce}\n")
}

/// A target's file without the operator's nonce comment.
pub fn without_nonce(content: &str) -> &str {
    match content.rfind(NONCE_COMMENT) {
        Some(at)
            if (at == 0 || content[..at].ends_with('\n'))
                && content[at + NONCE_COMMENT.len()..]
                    .trim_end()
                    .bytes()
                    .all(|b| b.is_ascii_digit()) =>
        {
            &content[..at]
        }
        _ => content,
    }
}

/// Whether a target's file is `document` (its nonce comment, and the
/// line break before it, aside).
pub fn holds(content: &str, document: &str) -> bool {
    without_nonce(content).trim_end_matches('\n') == document.trim_end_matches('\n')
}

fn short(hash: &str) -> &str {
    &hash[..hash.len().min(12)]
}

fn names(list: &[String]) -> String {
    let shown: Vec<&str> = list.iter().take(SHOWN).map(String::as_str).collect();
    match list.len().saturating_sub(SHOWN) {
        0 => shown.join(", "),
        n => format!("{} and {n} more", shown.join(", ")),
    }
}

async fn manage(gateway: &dyn AdminGateway, managed: ManagedConfig) -> Push {
    let state = managed.state;
    let mut push = Push {
        ready: Ok(String::new()),
        advisories: Vec::new(),
        status: ConfigStatus::from_state(&state),
        due_in: None,
        reloaded: false,
    };
    let rendered = match managed.rendered {
        Ok(rendered) => rendered,
        Err(failure) => {
            push.ready = Err(failure);
            return push;
        }
    };
    push.status.config_hash = Some(rendered.hash.clone());
    push.advisories = rendered.advisories.clone();
    let hash = rendered.hash.as_str();

    if state.strategy == ReloadStrategy::Manual
        && state.approved_hash.as_deref() != Some(hash)
        && state.applied_hash.as_deref() != Some(hash)
    {
        push.status.pending_hash = Some(hash.to_string());
        push.ready = Ok(match &state.applied_hash {
            Some(applied) => format!("configuration {} applied", short(applied)),
            None => "no configuration applied yet".into(),
        });
        push.advisories.push(Advisory {
            reason: ReasonCode::ConfigHeld,
            message: format!(
                "configuration {hash} is held (reload.strategy: Manual): annotate the instance \
                 batlehub.weebo.io/approved-config-hash={hash} to apply it"
            ),
        });
        return push;
    }

    let pods;
    let targets: Vec<(String, &dyn AdminGateway)> = match managed.targets {
        Targets::Url => vec![("the instance".into(), gateway)],
        Targets::Pods(Err(failure)) => {
            push.ready = Err(failure);
            return push;
        }
        Targets::Pods(Ok(pods)) if pods.is_empty() => {
            push.ready = Err(Failure::new(
                ReasonCode::NoReadyPod,
                "no ready pod matches external.podSelector",
            ));
            push.due_in = Some(PROPAGATION_RETRY_SECS);
            return push;
        }
        Targets::Pods(Ok(list)) => {
            pods = list;
            pods.iter().map(|(n, g)| (n.clone(), g.as_ref())).collect()
        }
    };
    let mut loaded = false;
    let result = push_to(&targets, &rendered, &state, &mut push.status, &mut loaded).await;
    if loaded {
        push.reloaded = true;
        push.status.reloaded_at = Some(state.now);
    }
    match result {
        Ok(()) => {
            push.status.applied_hash = Some(hash.to_string());
            push.status.pods.clear();
            push.status.rejected_hash = None;
            push.status.rejected_at = None;
            push.status.rejection_message = None;
            push.status.unpersisted_hash = None;
            push.ready = Ok(format!("configuration {} applied", short(hash)));
        }
        Err((failure, due_in)) => {
            push.ready = Err(failure);
            push.due_in = due_in;
        }
    }
    push
}

type Stop = (Failure, Option<u64>);

/// Waiting out a refusal (or a configuration the instance couldn't
/// write): the same failure, in words that don't change from one pass to
/// the next, and the pods behind as last seen.
fn backoff(state: &ConfigState, hash: &str, status: &mut ConfigStatus) -> Option<Stop> {
    if state.rejected_hash.as_deref() != Some(hash) {
        return None;
    }
    let wait = REJECTION_BACKOFF_SECS - (state.now - state.rejected_at?);
    if wait <= 0 {
        return None;
    }
    status.pods = state.pods.clone();
    let retry = "pushed again 10 minutes after status.lastRejectionTime, or at once on a change \
                 of the spec";
    let failure = if state.unpersisted_hash.as_deref() == Some(hash) {
        Failure::new(
            ReasonCode::ConfigReadOnly,
            read_only_message("the instance", retry),
        )
    } else {
        let said = state
            .rejection_message
            .as_deref()
            .unwrap_or("the instance refused it");
        Failure::new(
            ReasonCode::ConfigRejected,
            format!("configuration {}: {said} ({retry})", short(hash)),
        )
    };
    Some((failure, Some(wait as u64)))
}

fn read_only_message(name: &str, then: &str) -> String {
    format!(
        "{name} loaded the configuration but couldn't write it to its first configuration \
         file: the change is lost on its next restart. Make that file writable (not a \
         ConfigMap mount); {then}"
    )
}

/// Brings every target to `rendered`; `loaded` tells whether one loaded
/// it, even when a later one fails.
async fn push_to(
    targets: &[(String, &dyn AdminGateway)],
    rendered: &Rendered,
    state: &ConfigState,
    status: &mut ConfigStatus,
    loaded: &mut bool,
) -> Result<(), Stop> {
    let fail = |e: GatewayError| (Failure::new(e.reason(), e.to_string()), None);
    let mut behind = Vec::new();
    let mut pods = Vec::new();
    for (name, target) in targets {
        let content = target.config_content().await.map_err(fail)?;
        if holds(&content, &rendered.document) {
            // In sync on disk. A reload its own watcher staged from that file
            // (another layer arrived late) is the desired state: approved
            // rather than left to expire.
            if target.pending().await.map_err(fail)? == Some(PendingSource::FileWatcher) {
                match target.apply_pending().await {
                    Ok(()) | Err(GatewayError::NoPending(_)) => {}
                    Err(e) => return Err(fail(e)),
                }
            }
        } else {
            pods.push(PodConfig {
                name: name.clone(),
                config_hash: Some(sha256(without_nonce(&content))),
            });
            behind.push((name, target));
        }
    }
    if behind.is_empty() {
        return Ok(());
    }
    if let Some(stop) = backoff(state, &rendered.hash, status) {
        return Err(stop);
    }
    status.pods = pods;
    let rejected = |status: &mut ConfigStatus, message: String| {
        status.rejected_hash = Some(rendered.hash.clone());
        status.rejected_at = Some(state.now);
        status.rejection_message = Some(message.clone());
        status.unpersisted_hash = None;
        (
            Failure::new(
                ReasonCode::ConfigRejected,
                format!(
                    "configuration {}: {message} (pushed again 10 minutes after \
                     status.lastRejectionTime, or at once on a change of the spec)",
                    short(&rendered.hash)
                ),
            ),
            Some(REJECTION_BACKOFF_SECS as u64),
        )
    };

    // One dry run for all: a configuration they'd all refuse reaches none.
    let check = match behind[0].1.validate_config(&rendered.document).await {
        Ok(check) => check,
        Err(GatewayError::Rejected(message)) => {
            return Err(rejected(
                status,
                format!("the instance refuses it: {message}"),
            ));
        }
        Err(e) => return Err(fail(e)),
    };
    if !check.restart_required.is_empty() {
        status.restart_keys = check.restart_required.clone();
        return Err((
            Failure::new(
                ReasonCode::RestartForbidden,
                format!(
                    "the configuration needs a restart the operator can't do (it doesn't deploy \
                     the instance) for {}: the push is held back. Revert these keys, or align \
                     the instance's configuration and restart it yourself",
                    names(&check.restart_required)
                ),
            ),
            None,
        ));
    }

    let mut done: Vec<String> = Vec::new();
    for (name, target) in behind {
        let partial = |done: &[String]| match done {
            [] => String::new(),
            done => format!(" ({} already loaded it)", names(done)),
        };
        let mut staged = target
            .stage_config(&with_nonce(&rendered.document, status.nonce))
            .await;
        if staged == Ok(false) {
            // Bytes BatleHub already tried once: new ones.
            status.nonce += 1;
            staged = target
                .stage_config(&with_nonce(&rendered.document, status.nonce))
                .await;
        }
        match staged {
            Ok(true) => {}
            Ok(false) => {
                return Err((
                    Failure::new(
                        ReasonCode::RemoteError,
                        format!("{name} staged nothing, twice{}", partial(&done)),
                    ),
                    None,
                ));
            }
            Err(GatewayError::Rejected(message)) => {
                return Err(rejected(
                    status,
                    format!("{name} refuses it: {message}{}", partial(&done)),
                ));
            }
            Err(e) => return Err(fail(e)),
        }
        match target.apply_pending().await {
            Ok(()) => *loaded = true,
            Err(GatewayError::NoPending(why)) => {
                return Err((
                    Failure::new(
                        ReasonCode::ConfigPropagating,
                        format!(
                            "{name}: the staged reload is gone ({why}){}",
                            partial(&done)
                        ),
                    ),
                    Some(PROPAGATION_RETRY_SECS),
                ));
            }
            Err(GatewayError::Rejected(message)) => {
                return Err(rejected(
                    status,
                    format!("{name} failed to load it: {message}{}", partial(&done)),
                ));
            }
            Err(e) => return Err(fail(e)),
        }
        let written = target.config_content().await.map_err(fail)?;
        if !holds(&written, &rendered.document) {
            // Loaded in memory, not written: pushing again would reload it
            // on every pass. Waited out like a refusal.
            status.rejected_hash = Some(rendered.hash.clone());
            status.rejected_at = Some(state.now);
            status.rejection_message = None;
            status.unpersisted_hash = Some(rendered.hash.clone());
            let then = format!(
                "pushed again 10 minutes after status.lastRejectionTime, or at once on a change \
                 of the spec{}",
                partial(&done)
            );
            return Err((
                Failure::new(ReasonCode::ConfigReadOnly, read_only_message(name, &then)),
                Some(REJECTION_BACKOFF_SECS as u64),
            ));
        }
        status.pods.retain(|p| p.name != *name);
        done.push(name.clone());
    }
    Ok(())
}

fn warnings_message(warnings: &[ConfigWarning]) -> String {
    let codes: Vec<&str> = warnings
        .iter()
        .take(SHOWN)
        .map(|w| w.code.as_str())
        .collect();
    let more = match warnings.len().saturating_sub(SHOWN) {
        0 => String::new(),
        n => format!(" and {n} more"),
    };
    format!(
        "BatleHub warns about its configuration: {}{more} (status.warnings)",
        codes.join(", ")
    )
}

/// Whether the instance may go: `Err(InstanceInUse)` while CRs are bound
/// to it (`dependents`, as `Kind/namespace/name`).
pub fn release_instance(instance: &str, dependents: &[String]) -> Result<(), Failure> {
    if dependents.is_empty() {
        return Ok(());
    }
    let shown: Vec<&str> = dependents.iter().take(SHOWN).map(String::as_str).collect();
    Err(Failure::new(
        ReasonCode::InstanceInUse,
        format!(
            "{} CR(s) still use {instance} (e.g. {}): delete them first, or annotate the \
             instance batlehub.weebo.io/force-orphan: \"true\" to leave them orphaned",
            dependents.len(),
            shown.join(", ")
        ),
    ))
}

#[cfg(test)]
mod tests {
    use domain::error::ReasonCode;

    use super::*;
    use crate::test_support::FakeGateway;

    const DOC: &str = "{\"server\":{\"port\":8080}}";

    fn warning(code: &str) -> ConfigWarning {
        ConfigWarning {
            code: code.into(),
            path: "server".into(),
            message: "m".into(),
        }
    }

    fn rendered(document: &str) -> Rendered {
        Rendered {
            document: document.into(),
            hash: sha256(document),
            advisories: vec![],
        }
    }

    fn managed(state: ConfigState) -> Option<ManagedConfig> {
        Some(ManagedConfig {
            rendered: Ok(rendered(DOC)),
            state,
            targets: Targets::Url,
        })
    }

    fn now() -> ConfigState {
        ConfigState {
            now: 1_000_000,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn a_reachable_instance_is_ready() {
        let report = reconcile_instance(&FakeGateway::default(), None).await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        assert_eq!(report.outcome.ready, Ok("BatleHub 1.6.0 answers".into()));
        assert!(report.outcome.advisories.is_empty());
        assert!(report.config.is_none());
        let observed = report.observed.unwrap();
        assert_eq!(observed.version, "1.6.0");
        assert!(observed.warnings.is_empty());
    }

    #[tokio::test]
    async fn warnings_are_an_advisory_next_to_ready() {
        let gateway = FakeGateway::default();
        gateway.warn_with((0..7).map(|i| warning(&format!("w{i}"))).collect());
        let report = reconcile_instance(&gateway, None).await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        let [advisory] = report.outcome.advisories.as_slice() else {
            panic!("{:?}", report.outcome.advisories);
        };
        assert_eq!(advisory.reason, ReasonCode::ConfigWarnings);
        assert!(
            advisory.message.contains("w0, w1, w2, w3, w4 and 2 more"),
            "{}",
            advisory.message
        );
        assert_eq!(report.observed.unwrap().warnings.len(), 7);
    }

    #[tokio::test]
    async fn an_unreachable_or_refusing_instance_is_not() {
        let gateway = FakeGateway::default();
        let reason = async |gateway: &FakeGateway| {
            let report = reconcile_instance(gateway, managed(now())).await;
            assert!(report.observed.is_none());
            report.outcome.reason()
        };
        gateway.fail_with(Some(GatewayError::Unreachable("dns".into())));
        assert_eq!(reason(&gateway).await, ReasonCode::InstanceUnreachable);
        gateway.fail_with(Some(GatewayError::Unauthorized("401".into())));
        assert_eq!(reason(&gateway).await, ReasonCode::OperatorUnauthorized);
        gateway.fail_with(Some(GatewayError::Remote("500".into())));
        assert_eq!(reason(&gateway).await, ReasonCode::RemoteError);
    }

    #[tokio::test]
    async fn warnings_that_cannot_be_read_fail_the_reconcile() {
        let gateway = FakeGateway::default();
        gateway.fail_warnings_with(Some(GatewayError::Unauthorized("403".into())));
        let report = reconcile_instance(&gateway, None).await;
        assert_eq!(report.outcome.reason(), ReasonCode::OperatorUnauthorized);
    }

    #[tokio::test]
    async fn a_new_configuration_is_validated_staged_applied_and_read_back() {
        let gateway = FakeGateway::default();
        gateway.write_file("old");
        let report = reconcile_instance(&gateway, managed(now())).await;
        assert_eq!(
            report.outcome.ready,
            Ok(format!("configuration {} applied", &sha256(DOC)[..12]))
        );
        assert!(report.reloaded);
        assert_eq!(gateway.file(), DOC);
        assert_eq!(gateway.loaded().as_deref(), Some(DOC));
        assert_eq!(
            gateway.calls(),
            ["content", "validate", "stage", "apply", "content"]
        );
        let status = report.config.unwrap();
        assert_eq!(status.applied_hash, Some(sha256(DOC)));
        assert_eq!(status.config_hash, Some(sha256(DOC)));
        assert_eq!(status.reloaded_at, Some(1_000_000));
        assert!(status.pods.is_empty());
    }

    #[tokio::test]
    async fn an_instance_in_sync_is_left_alone() {
        let gateway = FakeGateway::default();
        gateway.write_file(&with_nonce(DOC, 3));
        let state = ConfigState { nonce: 3, ..now() };
        let report = reconcile_instance(&gateway, managed(state)).await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        assert!(!report.reloaded);
        assert_eq!(gateway.calls(), ["content", "pending"]);
        assert_eq!(report.config.unwrap().applied_hash, Some(sha256(DOC)));
    }

    #[tokio::test]
    async fn a_reload_its_watcher_staged_from_our_file_is_approved() {
        let gateway = FakeGateway::default();
        gateway.write_file(DOC);
        gateway.stage(DOC, PendingSource::FileWatcher);
        let report = reconcile_instance(&gateway, managed(now())).await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        assert_eq!(gateway.calls(), ["content", "pending", "apply"]);
        assert_eq!(gateway.loaded().as_deref(), Some(DOC));
        // Someone else's is not.
        let gateway = FakeGateway::default();
        gateway.write_file(DOC);
        gateway.stage("theirs", PendingSource::AdminRequest);
        reconcile_instance(&gateway, managed(now())).await;
        assert_eq!(gateway.calls(), ["content", "pending"]);
    }

    #[tokio::test]
    async fn bytes_already_attempted_are_restaged_with_a_new_nonce() {
        let gateway = FakeGateway::default();
        gateway.write_file("old");
        gateway.attempted(DOC);
        let report = reconcile_instance(&gateway, managed(now())).await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        assert_eq!(gateway.file(), with_nonce(DOC, 1));
        let status = report.config.unwrap();
        assert_eq!(status.nonce, 1);
        // The nonce stays outside the hash.
        assert_eq!(status.applied_hash, Some(sha256(DOC)));
    }

    #[tokio::test]
    async fn a_refused_configuration_backs_off() {
        let gateway = FakeGateway::default();
        gateway.write_file("old");
        gateway.refuse(Some("8080"));
        let report = reconcile_instance(&gateway, managed(now())).await;
        assert_eq!(report.outcome.reason(), ReasonCode::ConfigRejected);
        assert_eq!(report.due_in, Some(600));
        let status = report.config.unwrap();
        assert_eq!(status.rejected_hash, Some(sha256(DOC)));
        assert_eq!(status.rejected_at, Some(1_000_000));
        assert_eq!(status.applied_hash, None);
        assert_eq!(gateway.calls(), ["content", "validate"]);
        let Err(first) = report.outcome.ready.clone() else {
            unreachable!()
        };
        assert!(first.message.contains("refused: 8080"), "{}", first.message);

        // Ten minutes later at the earliest, unless the spec changes: the
        // same words in the meantime (no status churn), the pods kept.
        let gateway = FakeGateway::default();
        gateway.write_file("old");
        let pods = vec![PodConfig {
            name: "hub-0".into(),
            config_hash: Some("x".into()),
        }];
        let state = ConfigState {
            rejected_hash: status.rejected_hash.clone(),
            rejected_at: Some(1_000_000),
            rejection_message: status.rejection_message.clone(),
            pods: pods.clone(),
            now: 1_000_100,
            ..Default::default()
        };
        let report = reconcile_instance(&gateway, managed(state.clone())).await;
        assert_eq!(report.outcome.ready, Err(first.clone()));
        assert_eq!(report.due_in, Some(500));
        assert_eq!(gateway.calls(), ["content"]);
        assert_eq!(report.config.unwrap().pods, pods);
        let report = reconcile_instance(
            &gateway,
            managed(ConfigState {
                now: 1_000_200,
                ..state.clone()
            }),
        )
        .await;
        assert_eq!(report.outcome.ready, Err(first));
        // An instance that already holds it is in sync: the refusal goes.
        let holding = FakeGateway::default();
        holding.write_file(DOC);
        let report = reconcile_instance(&holding, managed(state.clone())).await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        let cleared = report.config.unwrap();
        assert_eq!(cleared.rejected_hash, None);
        assert_eq!(cleared.rejection_message, None);
        let later = ConfigState {
            now: 1_000_600,
            ..state.clone()
        };
        let report = reconcile_instance(&gateway, managed(later)).await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        let other = Some(ManagedConfig {
            rendered: Ok(rendered("{}")),
            state,
            targets: Targets::Url,
        });
        let report = reconcile_instance(&gateway, other).await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
    }

    #[tokio::test]
    async fn a_restart_key_holds_the_push_back() {
        let gateway = FakeGateway::default();
        gateway.write_file("old");
        gateway.require_restart(&["database.url", "server.port"]);
        let report = reconcile_instance(&gateway, managed(now())).await;
        assert_eq!(report.outcome.reason(), ReasonCode::RestartForbidden);
        let Err(failure) = &report.outcome.ready else {
            unreachable!()
        };
        assert!(failure.message.contains("database.url, server.port"));
        assert_eq!(
            report.config.unwrap().restart_keys,
            ["database.url", "server.port"]
        );
        assert_eq!(gateway.file(), "old");
        assert!(report.outcome.steady());
    }

    #[tokio::test]
    async fn a_file_the_instance_cannot_write_is_reported_not_reloaded_again() {
        let gateway = FakeGateway::default();
        gateway.write_file("old");
        gateway.read_only(true);
        let report = reconcile_instance(&gateway, managed(now())).await;
        assert_eq!(report.outcome.reason(), ReasonCode::ConfigReadOnly);
        assert_eq!(gateway.loaded().as_deref(), Some(DOC));
        // It did load it: announced.
        assert!(report.reloaded);
        let status = report.config.unwrap();
        assert_eq!(status.unpersisted_hash, Some(sha256(DOC)));
        assert_eq!(status.reloaded_at, Some(1_000_000));

        // The next passes don't reload it again (only read the file).
        let next = ConfigState {
            rejected_hash: status.rejected_hash.clone(),
            rejected_at: status.rejected_at,
            unpersisted_hash: status.unpersisted_hash.clone(),
            nonce: status.nonce,
            now: 1_000_300,
            ..Default::default()
        };
        let calls = gateway.calls().len();
        let report = reconcile_instance(&gateway, managed(next)).await;
        assert_eq!(report.outcome.reason(), ReasonCode::ConfigReadOnly);
        assert!(!report.reloaded);
        assert_eq!(gateway.calls()[calls..], ["content"]);
    }

    #[tokio::test]
    async fn hot_reload_disabled_is_a_state() {
        let gateway = FakeGateway::default();
        gateway.write_file("old");
        gateway.disable_hot_reload();
        let report = reconcile_instance(&gateway, managed(now())).await;
        assert_eq!(report.outcome.reason(), ReasonCode::HotReloadDisabled);
        assert!(!report.outcome.steady());
        assert_eq!(gateway.file(), "old");
    }

    #[tokio::test]
    async fn a_rendering_failure_outranks_an_instance_that_doesn_t_answer() {
        let gateway = FakeGateway::default();
        gateway.fail_with(Some(GatewayError::Unreachable("dns".into())));
        let state = ConfigState {
            applied_hash: Some("before".into()),
            ..now()
        };
        let config = Some(ManagedConfig {
            rendered: Err(Failure::new(ReasonCode::ConfigInvalid, "bad")),
            state,
            targets: Targets::Url,
        });
        let report = reconcile_instance(&gateway, config).await;
        assert_eq!(report.outcome.reason(), ReasonCode::ConfigInvalid);
        assert!(report.observed.is_none());
        // What was applied stays in the status.
        assert_eq!(
            report.config.unwrap().applied_hash.as_deref(),
            Some("before")
        );
    }

    #[tokio::test]
    async fn manual_holds_until_the_exact_hash_is_approved() {
        let gateway = FakeGateway::default();
        gateway.write_file("old");
        let held = ConfigState {
            strategy: ReloadStrategy::Manual,
            applied_hash: Some("previous".into()),
            ..now()
        };
        let report = reconcile_instance(&gateway, managed(held.clone())).await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        assert_eq!(
            report.outcome.ready,
            Ok("configuration previous applied".into())
        );
        assert_eq!(report.outcome.advisories[0].reason, ReasonCode::ConfigHeld);
        assert!(report.outcome.advisories[0].message.contains(&sha256(DOC)));
        assert_eq!(report.config.unwrap().pending_hash, Some(sha256(DOC)));
        assert!(gateway.calls().is_empty());

        let wrong = ConfigState {
            approved_hash: Some("not-it".into()),
            ..held.clone()
        };
        let report = reconcile_instance(&gateway, managed(wrong)).await;
        assert_eq!(report.outcome.advisories[0].reason, ReasonCode::ConfigHeld);

        let approved = ConfigState {
            approved_hash: Some(sha256(DOC)),
            ..held
        };
        let report = reconcile_instance(&gateway, managed(approved)).await;
        assert!(report.outcome.advisories.is_empty());
        assert_eq!(gateway.file(), DOC);
        assert_eq!(report.config.unwrap().pending_hash, None);
    }

    #[tokio::test]
    async fn a_rendering_failure_blocks_after_observing() {
        let gateway = FakeGateway::default();
        gateway.warn_with(vec![warning("w")]);
        let config = Some(ManagedConfig {
            rendered: Err(Failure::new(ReasonCode::ConfigInvalid, "bad")),
            state: now(),
            targets: Targets::Url,
        });
        let report = reconcile_instance(&gateway, config).await;
        assert_eq!(report.outcome.reason(), ReasonCode::ConfigInvalid);
        assert_eq!(report.observed.unwrap().version, "1.6.0");
        assert!(gateway.calls().is_empty());
    }

    #[tokio::test]
    async fn every_pod_is_pushed_and_a_partial_refusal_names_those_done() {
        let pods: Vec<Arc<FakeGateway>> =
            (0..3).map(|_| Arc::new(FakeGateway::default())).collect();
        for pod in &pods {
            pod.write_file("old");
        }
        pods[1].write_file(DOC);
        let targets = |pods: &[Arc<FakeGateway>]| {
            Targets::Pods(Ok(pods
                .iter()
                .enumerate()
                .map(|(i, p)| (format!("hub-{i}"), p.clone() as Arc<dyn AdminGateway>))
                .collect()))
        };
        let url = FakeGateway::default();
        let config = Some(ManagedConfig {
            rendered: Ok(rendered(DOC)),
            state: now(),
            targets: targets(&pods),
        });
        let report = reconcile_instance(&url, config).await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        assert!(pods.iter().all(|p| p.file() == DOC));
        assert_eq!(pods[1].calls(), ["content", "pending"]);
        // Only the first pod behind runs the dry run.
        assert_eq!(pods[0].calls()[1], "validate");
        assert!(!pods[2].calls().contains(&"validate".to_string()));
        assert!(url.calls().is_empty());

        for pod in &pods {
            pod.write_file("old");
        }
        pods[2].refuse(Some("8080"));
        let config = Some(ManagedConfig {
            rendered: Ok(rendered(DOC)),
            state: now(),
            targets: targets(&pods),
        });
        let report = reconcile_instance(&url, config).await;
        assert_eq!(report.outcome.reason(), ReasonCode::ConfigRejected);
        let Err(failure) = &report.outcome.ready else {
            unreachable!()
        };
        assert!(
            failure.message.contains("(hub-0, hub-1 already loaded it)"),
            "{}",
            failure.message
        );
        // hub-0 and hub-1 did load it.
        assert!(report.reloaded);
        let pods_behind: Vec<String> = report
            .config
            .unwrap()
            .pods
            .into_iter()
            .map(|p| p.name)
            .collect();
        assert_eq!(pods_behind, ["hub-2"]);
    }

    #[tokio::test]
    async fn no_ready_pod_waits() {
        let config = Some(ManagedConfig {
            rendered: Ok(rendered(DOC)),
            state: now(),
            targets: Targets::Pods(Ok(vec![])),
        });
        let report = reconcile_instance(&FakeGateway::default(), config).await;
        assert_eq!(report.outcome.reason(), ReasonCode::NoReadyPod);
        assert_eq!(report.due_in, Some(PROPAGATION_RETRY_SECS));
    }

    #[test]
    fn the_nonce_comment_is_written_and_read_back() {
        assert_eq!(with_nonce("a\n", 0), "a\n");
        assert_eq!(
            with_nonce("a\n", 2),
            "a\n# weebo-batlehub reload-nonce: 2\n"
        );
        assert_eq!(with_nonce("a", 2), "a\n# weebo-batlehub reload-nonce: 2\n");
        assert_eq!(without_nonce(&with_nonce("a\n", 7)), "a\n");
        assert_eq!(without_nonce("a\n"), "a\n");
        assert!(holds(&with_nonce("a", 1), "a"));
        assert!(!holds("a\nb", "a"));
        // Only a final, well-formed comment is the operator's.
        let theirs = "a\n# weebo-batlehub reload-nonce: 2\nb = 1\n";
        assert_eq!(without_nonce(theirs), theirs);
    }

    #[test]
    fn an_instance_goes_once_nothing_is_bound_to_it() {
        assert_eq!(release_instance("ns/hub", &[]), Ok(()));
        let dependents: Vec<String> = (0..6).map(|i| format!("Kind/ns/cr{i}")).collect();
        let failure = release_instance("ns/hub", &dependents).unwrap_err();
        assert_eq!(failure.reason, ReasonCode::InstanceInUse);
        assert!(failure.message.starts_with("6 CR(s) still use ns/hub"));
        assert!(
            failure.message.contains("Kind/ns/cr4)"),
            "{}",
            failure.message
        );
        assert!(!failure.message.contains("cr5"), "{}", failure.message);
    }
}
