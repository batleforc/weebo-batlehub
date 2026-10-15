//! A `BatleHubLocalInstance` in managed mode: the operator deploys
//! BatleHub (`workload::objects`) and brings every proxy pod to the
//! configuration rendered from the CR.
//!
//! A pass:
//!
//! 1. the operator's token (generated once, `<name>-operator-token`) is
//!    added to the configuration's `[[auth]] type = "token"` provider,
//!    hashed; with the credentials layer merged over it the way BatleHub
//!    merges its `--config` files, the configuration must still accept it
//!    (`OperatorTokenShadowed` otherwise: nothing is applied);
//! 2. the credentials layer's hash is a final comment of the file: a
//!    rotation is a new configuration, reloaded;
//! 3. `reload.strategy: Manual` keeps the file the pods run until the new
//!    one's hash is approved;
//! 4. keys BatleHub reads at startup only, changed (its `reload_keys`),
//!    change the pod template's `batlehub.weebo.io/config-hash`: the pods
//!    roll (`reload.restart: Rollout`), or `RestartRequired` names them
//!    (`Never`). Every other change is a hot reload;
//! 5. the objects are applied; none is taken over (`OwnedObjectConflict`);
//! 6. once the rollout is complete and every ready proxy pod serves the
//!    file (the kubelet's sync of the `Secret`), one dry run, then
//!    `POST …/config/reload` on each pod — the approval. In steady state,
//!    a reload a pod's own watcher staged from the operator's files is
//!    approved too. A reload BatleHub let expire is re-staged under a new
//!    nonce.

use api::local_instance::{Reload, ReloadStrategy, RestartPolicy};
use api::managed::{CONFIG_KEY, ManagedInstance, Names, UpdateStrategy};
use domain::error::ReasonCode;
use domain::{Advisory, Failure};
use serde_json::{Value, json};

use super::Outcome;
use super::reconcile_instance::{
    ConfigState, ConfigStatus, InstanceReport, Observed, PROPAGATION_RETRY_SECS,
    REJECTION_BACKOFF_SECS, holds, with_nonce, without_nonce,
};
use super::render_config::{Rendered, sha256};
use crate::ports::{
    AdminGateway, ConfigParser, GatewayError, Owner, PendingSource, PodGateway, TokenCheck,
    WorkloadError, Workloads,
};
use crate::workload::{DocumentFacts, WorkloadInput, objects, removed, update_strategy};

/// The first characters of the credentials revision's comment line.
pub const CREDENTIALS_COMMENT: &str = "# weebo-batlehub credentials-revision: sha256:";

/// What a managed pass needs besides its ports.
pub struct ManagedPass<'a> {
    pub owner: Owner,
    pub spec: &'a ManagedInstance,
    pub reload: &'a Reload,
    /// The configuration rendered from the CR, before the operator's token.
    pub rendered: Result<Rendered, Failure>,
    /// The credentials layer's text, when `managed.credentials` is set.
    pub credentials: Option<Result<String, Failure>>,
    pub state: ConfigState,
    /// `status.restartKeys`: keys changed and not yet restarted.
    pub restart_keys: Vec<String>,
    pub operator_namespace: Option<String>,
}

/// The managed fields of the status, besides the configuration's.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct WorkloadStatus {
    pub credentials_hash: Option<String>,
    pub update_strategy: Option<String>,
    pub available_replicas: Option<i32>,
}

/// A rollout this pass started.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RolledOut {
    pub keys: Vec<String>,
    /// `Recreate`: the instance is down meanwhile.
    pub interrupts: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ManagedReport {
    pub instance: InstanceReport,
    pub workload: WorkloadStatus,
    pub rolled_out: Option<RolledOut>,
}

/// Where the managed pass reaches the instance once its objects exist.
#[async_trait::async_trait]
pub trait Reach: Send + Sync {
    /// The instance's `Service`, with the operator's token.
    async fn gateway(&self) -> Result<(std::sync::Arc<dyn AdminGateway>, String), Failure>;
    /// Its ready proxy pods.
    async fn pods(&self) -> Result<Vec<PodGateway>, Failure>;
}

fn short(hash: &str) -> &str {
    &hash[..hash.len().min(12)]
}

/// `document` with `token`'s hash added to its static-token provider
/// (one is added when there is none), unless it is there already.
pub fn with_operator_token(
    document: &str,
    hash: &str,
    user_id: &str,
    parser: &dyn ConfigParser,
) -> Result<String, Failure> {
    let invalid =
        |e: crate::ports::ConfigError| Failure::new(ReasonCode::ConfigInvalid, e.to_string());
    let config = parser.fragment(document).map_err(invalid)?;
    let mut auth = config
        .get("auth")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let entry = json!({"value": hash, "role": "admin", "user_id": user_id});
    match auth
        .iter_mut()
        .find(|p| p.get("type").and_then(Value::as_str) == Some("token"))
    {
        Some(provider) => {
            let tokens = provider
                .as_object_mut()
                .expect("an [[auth]] entry is a table")
                .entry("tokens")
                .or_insert_with(|| Value::Array(Vec::new()));
            match tokens.as_array_mut() {
                Some(list) if list.iter().any(|t| t.get("value") == entry.get("value")) => {
                    return Ok(document.to_string());
                }
                Some(list) => list.push(entry),
                None => *tokens = Value::Array(vec![entry]),
            }
        }
        None => auth.push(json!({"type": "token", "tokens": [entry]})),
    }
    // The whole `auth` array: on `type`, BatleHub merges the token
    // provider entry by entry, and its `tokens` list (no identity) is
    // replaced by this one — the existing tokens and the operator's.
    let overlay = parser.layer(&json!({ "auth": auth })).map_err(invalid)?;
    parser.merge(&[document, &overlay]).map_err(invalid)
}

/// `document` with the credentials revision as its final comment.
fn with_credentials(document: &str, credentials_hash: Option<&str>) -> String {
    match credentials_hash {
        None => document.to_string(),
        Some(hash) => {
            let sep = if document.ends_with('\n') { "" } else { "\n" };
            format!("{document}{sep}{CREDENTIALS_COMMENT}{hash}\n")
        }
    }
}

/// `document` without the credentials revision comment.
fn without_credentials(document: &str) -> &str {
    match document.rfind(CREDENTIALS_COMMENT) {
        Some(at) if at == 0 || document[..at].ends_with('\n') => &document[..at],
        _ => document,
    }
}

fn workload_failure(e: WorkloadError) -> Failure {
    Failure::new(e.reason(), e.to_string())
}

fn fail(e: GatewayError) -> Failure {
    Failure::new(e.reason(), e.to_string())
}

/// The pass. `None` gateway answers are read from `reach` only once the
/// objects exist.
pub async fn reconcile_managed(
    pass: ManagedPass<'_>,
    parser: &dyn ConfigParser,
    workloads: &dyn Workloads,
    reach: &dyn Reach,
) -> ManagedReport {
    let mut report = ManagedReport {
        instance: InstanceReport {
            outcome: Outcome::synced(String::new()),
            observed: None,
            config: Some(kept(&pass.state)),
            due_in: None,
            reloaded: false,
        },
        workload: WorkloadStatus::default(),
        rolled_out: None,
    };
    let result = run(&pass, parser, workloads, reach, &mut report).await;
    let advisories = std::mem::take(&mut report.instance.outcome.advisories);
    report.instance.outcome = match result {
        Ok(message) => Outcome::synced(message),
        Err(failure) => Outcome::failed(failure),
    };
    report.instance.outcome.advisories = advisories;
    report
}

fn kept(state: &ConfigState) -> ConfigStatus {
    ConfigStatus {
        config_hash: None,
        applied_hash: state.applied_hash.clone(),
        pending_hash: None,
        nonce: state.nonce,
        rejected_hash: state.rejected_hash.clone(),
        rejected_at: state.rejected_at,
        rejection_message: state.rejection_message.clone(),
        unpersisted_hash: None,
        restart_keys: Vec::new(),
        pods: state.pods.clone(),
        reloaded_at: None,
    }
}

async fn run(
    pass: &ManagedPass<'_>,
    parser: &dyn ConfigParser,
    workloads: &dyn Workloads,
    reach: &dyn Reach,
    report: &mut ManagedReport,
) -> Result<String, Failure> {
    let names = Names::new(&pass.owner.name);
    let spec = pass.spec;
    let state = &pass.state;
    let status = report.instance.config.as_mut().expect("set above");
    status.restart_keys = pass.restart_keys.clone();
    let rendered = pass.rendered.clone()?;
    let generated = spec.operator_access.generate_token;

    // 1. The operator's token, in the configuration it must stay in.
    let token = if generated {
        Some(
            workloads
                .operator_token(&pass.owner, &names.token())
                .await
                .map_err(workload_failure)?,
        )
    } else {
        None
    };
    let mut document = rendered.document.clone();
    if let Some(token) = &token {
        document = with_operator_token(
            &document,
            &parser.hash_token(token),
            &spec.operator_access.user_id,
            parser,
        )?;
    }
    let credentials = match &pass.credentials {
        Some(text) => Some(text.clone()?),
        None => None,
    };
    let token_for_check = match &token {
        Some(token) => Some(token.clone()),
        None => reach.gateway().await.ok().map(|(_, token)| token),
    };
    if let Some(token) = token_for_check {
        let effective = match &credentials {
            Some(layer) => parser.merge(&[&document, layer]).map_err(|e| {
                Failure::new(ReasonCode::ConfigInvalid, format!("credentials: {e}"))
            })?,
            None => document.clone(),
        };
        if parser.token_check(&effective, &token) == TokenCheck::Refused {
            return Err(Failure::new(
                ReasonCode::OperatorTokenShadowed,
                if generated {
                    "the credentials layer declares its own [[auth]] type = \"token\" provider, \
                     whose token list replaces the configuration's — the operator's included: \
                     applying it would lock the operator out. Add the operator's entry (its \
                     hash is in the rendered configuration) to the credentials layer"
                } else {
                    "the configuration doesn't accept the token of \
                     managed.operatorAccess.tokenSecretRef with the admin role: declare it in \
                     an [[auth]] type = \"token\" provider"
                },
            ));
        }
    }

    // 2. The credentials revision.
    let credentials_hash = credentials.as_deref().map(sha256);
    report.workload.credentials_hash = credentials_hash.clone();
    let document = with_credentials(&document, credentials_hash.as_deref());
    let hash = sha256(&document);
    status.config_hash = Some(hash.clone());
    report
        .instance
        .outcome
        .advisories
        .extend(rendered.advisories.clone());

    // 3. What the pods are to run: the new configuration, or under
    //    `Manual` the one they run until it is approved.
    let previous = workloads
        .secret_text(&pass.owner, &names.config(), CONFIG_KEY)
        .await
        .map_err(workload_failure)?;
    let held = pass.reload.strategy == ReloadStrategy::Manual
        && previous.is_some()
        && state.approved_hash.as_deref() != Some(hash.as_str())
        && state.applied_hash.as_deref() != Some(hash.as_str());
    let (target, target_hash, file) = if held {
        let file = previous.clone().expect("held only with a previous file");
        let doc = without_nonce(&file).to_string();
        let doc_hash = sha256(&doc);
        status.pending_hash = Some(hash.clone());
        report.instance.outcome.advisories.push(Advisory {
            reason: ReasonCode::ConfigHeld,
            message: format!(
                "configuration {hash} is held (reload.strategy: Manual): annotate the instance \
                 batlehub.weebo.io/approved-config-hash={hash} to apply it"
            ),
        });
        (doc, doc_hash, file)
    } else {
        let file = with_nonce(&document, status.nonce);
        (document.clone(), hash.clone(), file)
    };

    // 4. Restart or reload.
    let facts = DocumentFacts::of(
        &parser
            .fragment(without_credentials(&target))
            .map_err(|e| Failure::new(ReasonCode::ConfigInvalid, e.to_string()))?,
    );
    let strategy = update_strategy(spec, &facts);
    report.workload.update_strategy = Some(
        match strategy {
            UpdateStrategy::Recreate => "Recreate",
            UpdateStrategy::RollingUpdate => "RollingUpdate",
        }
        .into(),
    );
    let rollout = workloads
        .rollout(&pass.owner, &names.proxy())
        .await
        .map_err(workload_failure)?;
    let current = rollout.as_ref().and_then(|r| r.config_hash.clone());
    let changed_keys = match previous.as_deref().map(without_nonce) {
        Some(before) if before != target => parser
            .restart_keys(without_credentials(before), without_credentials(&target))
            .map_err(|e| Failure::new(ReasonCode::ConfigInvalid, e.to_string()))?,
        _ => Vec::new(),
    };
    let restart_hash = match current {
        None => target_hash.clone(),
        Some(_) if !spec.hot_reload => target_hash.clone(),
        Some(current) if changed_keys.is_empty() => current,
        Some(current) => match pass.reload.restart {
            RestartPolicy::Rollout => {
                if current != target_hash {
                    report.rolled_out = Some(RolledOut {
                        keys: changed_keys.clone(),
                        interrupts: strategy == UpdateStrategy::Recreate,
                    });
                }
                status.restart_keys.clear();
                target_hash.clone()
            }
            RestartPolicy::Never => {
                for key in changed_keys {
                    if !status.restart_keys.contains(&key) {
                        status.restart_keys.push(key);
                    }
                }
                current
            }
        },
    };
    if !status.restart_keys.is_empty() {
        report.instance.outcome.advisories.push(Advisory {
            reason: ReasonCode::RestartRequired,
            message: format!(
                "keys BatleHub reads at startup changed and the pods won't restart \
                 (reload.restart: Never): {}",
                status.restart_keys.join(", ")
            ),
        });
    }

    // 5. The objects.
    let input = WorkloadInput {
        name: &pass.owner.name,
        namespace: &pass.owner.namespace,
        spec,
        file: &file,
        facts: &facts,
        restart_hash: &restart_hash,
        config_hash: &target_hash,
        operator_namespace: pass.operator_namespace.as_deref(),
    };
    workloads
        .apply(&pass.owner, &objects(&input))
        .await
        .map_err(workload_failure)?;
    for (api_version, kind, name) in removed(&input) {
        workloads
            .remove(&pass.owner, api_version, kind, &name)
            .await
            .map_err(workload_failure)?;
    }
    let rollout = workloads
        .rollout(&pass.owner, &names.proxy())
        .await
        .map_err(workload_failure)?
        .unwrap_or_default();
    report.workload.available_replicas = Some(rollout.available);
    if !rollout.complete() {
        report.instance.due_in = Some(PROPAGATION_RETRY_SECS);
        return Err(Failure::new(
            ReasonCode::WorkloadNotReady,
            format!(
                "{} of {} proxy pod(s) updated, {} available",
                rollout.updated, rollout.replicas, rollout.available
            ),
        ));
    }

    // 6. Every pod on the file, then approved.
    let (gateway, _) = reach.gateway().await?;
    let pods = reach.pods().await?;
    if pods.is_empty() {
        report.instance.due_in = Some(PROPAGATION_RETRY_SECS);
        return Err(Failure::new(
            ReasonCode::NoReadyPod,
            "no proxy pod is ready",
        ));
    }
    let status = report.instance.config.as_mut().expect("set above");
    let mut behind = Vec::new();
    for pod in &pods {
        let content = pod.gateway.config_content().await.map_err(fail)?;
        if !holds(&content, &target) {
            behind.push(api::local_instance::PodConfig {
                name: pod.name.clone(),
                config_hash: Some(sha256(without_nonce(&content))),
            });
        }
    }
    if !behind.is_empty() {
        let names: Vec<&str> = behind.iter().map(|p| p.name.as_str()).collect();
        status.pods = behind.clone();
        report.instance.due_in = Some(PROPAGATION_RETRY_SECS);
        return Err(Failure::new(
            ReasonCode::ConfigPropagating,
            format!(
                "the configuration Secret hasn't reached {} yet (the kubelet syncs it)",
                names.join(", ")
            ),
        ));
    }
    status.pods.clear();
    if spec.hot_reload && status.applied_hash.as_deref() != Some(target_hash.as_str()) {
        approve(
            &pods,
            gateway.as_ref(),
            &target,
            &target_hash,
            state,
            report,
        )
        .await?;
    } else if spec.hot_reload {
        // Steady state: a reload a pod's watcher staged from the operator's
        // files (the credentials arriving late) is the desired state.
        for pod in &pods {
            if pod.gateway.pending().await.map_err(fail)? == Some(PendingSource::FileWatcher) {
                match pod.gateway.apply_pending().await {
                    Ok(()) | Err(GatewayError::NoPending(_)) => {}
                    Err(e) => return Err(fail(e)),
                }
            }
        }
    }
    let status = report.instance.config.as_mut().expect("set above");
    status.applied_hash = Some(target_hash.clone());
    status.rejected_hash = None;
    status.rejected_at = None;
    status.rejection_message = None;

    // The instance itself: its version, its token's role, its warnings.
    let info = gateway.ping().await.map_err(fail)?;
    let warnings = gateway.config_warnings().await.map_err(fail)?;
    if !warnings.is_empty() {
        report.instance.outcome.advisories.push(Advisory {
            reason: ReasonCode::ConfigWarnings,
            message: format!(
                "BatleHub warns about its configuration: {} (status.warnings)",
                warnings
                    .iter()
                    .take(5)
                    .map(|w| w.code.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        });
    }
    report.instance.observed = Some(Observed {
        version: info.version.clone(),
        warnings,
    });
    Ok(format!(
        "BatleHub {} runs configuration {} on {} pod(s)",
        info.version,
        short(&target_hash),
        pods.len()
    ))
}

/// The approval of a new configuration every pod serves: one dry run,
/// then a reload on each pod.
async fn approve(
    pods: &[PodGateway],
    gateway: &dyn AdminGateway,
    target: &str,
    hash: &str,
    state: &ConfigState,
    report: &mut ManagedReport,
) -> Result<(), Failure> {
    let status = report.instance.config.as_mut().expect("set above");
    if status.rejected_hash.as_deref() == Some(hash)
        && let Some(at) = status.rejected_at
        && state.now - at < REJECTION_BACKOFF_SECS
    {
        report.instance.due_in = Some((REJECTION_BACKOFF_SECS - (state.now - at)) as u64);
        return Err(Failure::new(
            ReasonCode::ConfigRejected,
            format!(
                "configuration {}: {} (reloaded again 10 minutes after \
                 status.lastRejectionTime, or at once on a change of the spec)",
                short(hash),
                status
                    .rejection_message
                    .as_deref()
                    .unwrap_or("the instance refused it")
            ),
        ));
    }
    let rejected = |message: String, status: &mut ConfigStatus| {
        status.rejected_hash = Some(hash.to_string());
        status.rejected_at = Some(state.now);
        status.rejection_message = Some(message.clone());
        Failure::new(
            ReasonCode::ConfigRejected,
            format!(
                "configuration {}: {message} (reloaded again 10 minutes after \
                 status.lastRejectionTime, or at once on a change of the spec)",
                short(hash)
            ),
        )
    };
    match gateway.validate_config(target).await {
        Ok(_) => {}
        Err(GatewayError::Rejected(message)) => {
            let failure = rejected(format!("the instance refuses it: {message}"), status);
            report.instance.due_in = Some(REJECTION_BACKOFF_SECS as u64);
            return Err(failure);
        }
        Err(e) => return Err(fail(e)),
    }
    let mut done: Vec<String> = Vec::new();
    for pod in pods {
        let partial = |done: &[String]| match done {
            [] => String::new(),
            done => format!(" ({} already loaded it)", done.join(", ")),
        };
        match pod.gateway.reload().await {
            Ok(loaded) => {
                if loaded {
                    report.instance.reloaded = true;
                    status.reloaded_at = Some(state.now);
                }
            }
            Err(GatewayError::NoPending(why)) => {
                // BatleHub let its pending expire: new bytes, staged by the
                // watcher on the next sync.
                status.nonce += 1;
                report.instance.due_in = Some(PROPAGATION_RETRY_SECS);
                return Err(Failure::new(
                    ReasonCode::ConfigPropagating,
                    format!(
                        "{}: {why}; written again under nonce {}{}",
                        pod.name,
                        status.nonce,
                        partial(&done)
                    ),
                ));
            }
            Err(GatewayError::Rejected(message)) => {
                let failure = rejected(
                    format!(
                        "{} failed to load it: {message}{}",
                        pod.name,
                        partial(&done)
                    ),
                    status,
                );
                report.instance.due_in = Some(REJECTION_BACKOFF_SECS as u64);
                return Err(failure);
            }
            Err(GatewayError::HotReloadDisabled(why)) => {
                return Err(Failure::new(
                    ReasonCode::HotReloadDisabled,
                    format!(
                        "{}: {why}. Hot reload is disabled by the pods' environment: set \
                         managed.hotReload: false, every change then restarts the pods",
                        pod.name
                    ),
                ));
            }
            Err(e) => return Err(fail(e)),
        }
        done.push(pod.name.clone());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use api::managed::CONFIG_HASH_ANNOTATION;
    use serde_json::json;

    use super::*;
    use crate::test_support::{FakeConfigParser, FakeGateway, FakeWorkloads};

    struct FakeReach {
        service: Arc<FakeGateway>,
        pods: Vec<(String, Arc<FakeGateway>)>,
    }

    impl FakeReach {
        fn new(pods: usize) -> Self {
            Self {
                service: Arc::new(FakeGateway::default()),
                pods: (0..pods)
                    .map(|i| (format!("hub-{i}"), Arc::new(FakeGateway::default())))
                    .collect(),
            }
        }

        /// The kubelet syncs the config Secret to every pod.
        fn sync(&self, workloads: &FakeWorkloads) {
            let file = workloads.config_file("hub").unwrap();
            for (_, pod) in &self.pods {
                pod.write_file(&file);
            }
        }
    }

    #[async_trait::async_trait]
    impl Reach for FakeReach {
        async fn gateway(&self) -> Result<(Arc<dyn AdminGateway>, String), Failure> {
            Ok((self.service.clone(), "token-of-hub-operator-token".into()))
        }

        async fn pods(&self) -> Result<Vec<PodGateway>, Failure> {
            Ok(self
                .pods
                .iter()
                .map(|(name, g)| PodGateway {
                    name: name.clone(),
                    gateway: g.clone(),
                })
                .collect())
        }
    }

    fn rendered(config: Value) -> Rendered {
        let document = config.to_string();
        Rendered {
            hash: sha256(&document),
            document,
            advisories: vec![],
        }
    }

    struct World {
        spec: ManagedInstance,
        reload: Reload,
        workloads: FakeWorkloads,
        reach: FakeReach,
        state: ConfigState,
        restart_keys: Vec<String>,
        credentials: Option<String>,
    }

    impl World {
        fn new() -> Self {
            Self {
                spec: ManagedInstance::default(),
                reload: Reload::default(),
                workloads: FakeWorkloads::default(),
                reach: FakeReach::new(2),
                state: ConfigState {
                    now: 1_000,
                    ..Default::default()
                },
                restart_keys: vec![],
                credentials: None,
            }
        }

        async fn pass(&mut self, config: Value) -> ManagedReport {
            let pass = ManagedPass {
                owner: Owner {
                    namespace: "team".into(),
                    name: "hub".into(),
                    uid: "u-1".into(),
                },
                spec: &self.spec,
                reload: &self.reload,
                rendered: Ok(rendered(config)),
                credentials: self.credentials.clone().map(Ok),
                state: self.state.clone(),
                restart_keys: self.restart_keys.clone(),
                operator_namespace: None,
            };
            let report =
                reconcile_managed(pass, &FakeConfigParser, &self.workloads, &self.reach).await;
            // What the next pass reads from the status.
            if let Some(config) = &report.instance.config {
                self.state.applied_hash = config.applied_hash.clone();
                self.state.nonce = config.nonce;
                self.state.rejected_hash = config.rejected_hash.clone();
                self.state.rejected_at = config.rejected_at;
                self.state.rejection_message = config.rejection_message.clone();
                self.restart_keys = config.restart_keys.clone();
            }
            report
        }

        fn annotation(&self) -> String {
            self.workloads.object("Deployment", "hub").unwrap().manifest["spec"]["template"]
                ["metadata"]["annotations"][CONFIG_HASH_ANNOTATION]
                .as_str()
                .unwrap()
                .to_string()
        }
    }

    fn reason(report: &ManagedReport) -> ReasonCode {
        report.instance.outcome.reason()
    }

    #[tokio::test]
    async fn a_new_instance_is_deployed_then_approved_on_each_pod() {
        let mut world = World::new();
        let config = json!({"server": {"port": 8080}, "auth": [{"type": "token", "tokens": [
            {"value": "theirs", "role": "user"},
        ]}]});
        let report = world.pass(config.clone()).await;
        // Deployed; the kubelet hasn't synced the Secret yet.
        assert_eq!(reason(&report), ReasonCode::ConfigPropagating);
        assert!(world.workloads.object("Deployment", "hub").is_some());
        let file = world.workloads.config_file("hub").unwrap();
        // The operator's token added, the user's kept.
        assert!(
            file.contains("hashed:token-of-hub-operator-token"),
            "{file}"
        );
        assert!(file.contains("theirs"), "{file}");

        world.reach.sync(&world.workloads);
        let report = world.pass(config.clone()).await;
        assert_eq!(
            reason(&report),
            ReasonCode::Reconciled,
            "{:?}",
            report.instance.outcome
        );
        assert!(report.instance.reloaded);
        let config_status = report.instance.config.clone().unwrap();
        assert_eq!(config_status.applied_hash, config_status.config_hash);
        for (_, pod) in &world.reach.pods {
            assert_eq!(pod.loaded().as_deref(), Some(file.as_str()));
        }
        assert_eq!(
            world.reach.pods[0].1.calls(),
            ["content", "content", "reload"]
        );
        assert_eq!(report.workload.update_strategy.as_deref(), Some("Recreate"));

        // In sync: nothing reloaded.
        let report = world.pass(config).await;
        assert_eq!(reason(&report), ReasonCode::Reconciled);
        assert!(!report.instance.reloaded);
    }

    #[tokio::test]
    async fn a_restart_key_rolls_the_pods_or_is_reported() {
        let mut world = World::new();
        world.pass(json!({"restart": 1})).await;
        world.reach.sync(&world.workloads);
        world.pass(json!({"restart": 1})).await;
        let first = world.annotation();

        // A hot key: reloaded, the template unchanged.
        world.pass(json!({"restart": 1, "hot": 2})).await;
        assert_eq!(world.annotation(), first);

        // A restart key: the template changes.
        let report = world.pass(json!({"restart": 2, "hot": 2})).await;
        assert_ne!(world.annotation(), first);
        assert_eq!(
            report.rolled_out,
            Some(RolledOut {
                keys: vec!["restart".into()],
                interrupts: true
            })
        );

        // `Never`: the template kept, the keys reported.
        world.reload.restart = RestartPolicy::Never;
        let second = world.annotation();
        let report = world.pass(json!({"restart": 3, "hot": 2})).await;
        assert_eq!(world.annotation(), second);
        assert_eq!(report.rolled_out, None);
        assert_eq!(world.restart_keys, ["restart"]);
        assert!(
            report
                .instance
                .outcome
                .advisories
                .iter()
                .any(|a| a.reason == ReasonCode::RestartRequired)
        );
    }

    #[tokio::test]
    async fn an_object_of_someone_else_is_never_taken_over() {
        let mut world = World::new();
        world.workloads.foreign("Service", "hub");
        let report = world.pass(json!({})).await;
        assert_eq!(reason(&report), ReasonCode::OwnedObjectConflict);
        assert!(world.workloads.object("Deployment", "hub").is_none());

        let mut world = World::new();
        world.workloads.foreign("Secret", "hub-operator-token");
        let report = world.pass(json!({})).await;
        assert_eq!(reason(&report), ReasonCode::OwnedObjectConflict);
    }

    #[tokio::test]
    async fn credentials_shadowing_the_operator_token_are_refused() {
        let mut world = World::new();
        world.credentials = Some(json!({"auth": [{"type": "token", "tokens": []}]}).to_string());
        let report = world.pass(json!({})).await;
        assert_eq!(reason(&report), ReasonCode::OperatorTokenShadowed);
        assert!(world.workloads.object("Secret", "hub-config").is_none());

        // Credentials that don't touch `auth`: their hash is a comment.
        world.credentials = Some(json!({"database": {"url": "x"}}).to_string());
        let report = world.pass(json!({})).await;
        assert_eq!(reason(&report), ReasonCode::ConfigPropagating);
        let file = world.workloads.config_file("hub").unwrap();
        assert!(file.contains(CREDENTIALS_COMMENT), "{file}");
        let first = report.workload.credentials_hash.clone().unwrap();
        world.credentials = Some(json!({"database": {"url": "y"}}).to_string());
        let rotated = world.pass(json!({})).await;
        assert_ne!(rotated.workload.credentials_hash.unwrap(), first);
        assert_ne!(
            rotated.instance.config.unwrap().config_hash,
            report.instance.config.unwrap().config_hash
        );
    }

    #[tokio::test]
    async fn manual_holds_the_new_configuration() {
        let mut world = World::new();
        world.reload.strategy = ReloadStrategy::Manual;
        // The first configuration has nothing to be held against.
        world.pass(json!({"a": 1})).await;
        world.reach.sync(&world.workloads);
        let report = world.pass(json!({"a": 1})).await;
        assert_eq!(reason(&report), ReasonCode::Reconciled);
        let applied = world.workloads.config_file("hub").unwrap();

        let report = world.pass(json!({"a": 2})).await;
        assert_eq!(reason(&report), ReasonCode::Reconciled);
        assert_eq!(world.workloads.config_file("hub").unwrap(), applied);
        let held = report.instance.config.unwrap().pending_hash.unwrap();
        assert!(
            report
                .instance
                .outcome
                .advisories
                .iter()
                .any(|a| a.reason == ReasonCode::ConfigHeld)
        );

        world.state.approved_hash = Some(held);
        world.pass(json!({"a": 2})).await;
        assert_ne!(world.workloads.config_file("hub").unwrap(), applied);
    }

    #[tokio::test]
    async fn a_rollout_in_progress_waits() {
        let mut world = World::new();
        world.workloads.hold_rollout(true);
        let report = world.pass(json!({})).await;
        assert_eq!(reason(&report), ReasonCode::WorkloadNotReady);
        assert_eq!(report.instance.due_in, Some(PROPAGATION_RETRY_SECS));
    }

    #[tokio::test]
    async fn a_refused_configuration_waits_and_an_expired_one_is_restaged() {
        let mut world = World::new();
        world.pass(json!({"a": 1})).await;
        world.reach.sync(&world.workloads);
        world.reach.service.refuse(Some("invalid"));
        let report = world.pass(json!({"a": "invalid"})).await;
        assert_eq!(reason(&report), ReasonCode::ConfigPropagating);
        world.reach.sync(&world.workloads);
        let report = world.pass(json!({"a": "invalid"})).await;
        assert_eq!(reason(&report), ReasonCode::ConfigRejected);
        let again = world.pass(json!({"a": "invalid"})).await;
        assert_eq!(reason(&again), ReasonCode::ConfigRejected);
        // Waited out: nothing reloaded.
        assert!(!world.reach.pods[0].1.calls().iter().any(|c| c == "reload"));
    }
}
