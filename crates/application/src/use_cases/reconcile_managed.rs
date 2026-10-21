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

use api::local_instance::{PartialPolicy, Reload, ReloadStrategy, RestartPolicy};
use api::managed::{CONFIG_HASH_ANNOTATION, CONFIG_KEY, ManagedInstance, Names, UpdateStrategy};
use domain::error::ReasonCode;
use domain::{Advisory, Failure};
use serde_json::{Value, json};

use super::Outcome;
use super::reconcile_instance::{
    ConfigState, ConfigStatus, InstanceReport, Observed, PROPAGATION_RETRY_SECS,
    REJECTION_BACKOFF_SECS, with_nonce, without_nonce,
};
use super::render_config::{Rendered, sha256};
use crate::ports::{
    AdminGateway, ConfigParser, GatewayError, KeyChanges, Owner, PendingSource, PodGateway,
    Reloaded, TokenCheck, WorkloadError, Workloads,
};
use crate::workload::{
    DocumentFacts, OperatorPod, WorkloadInput, objects, removed, update_strategy,
};

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
    /// `status.partialKeys`: keys partially applied since the pods
    /// started.
    pub partial_keys: Vec<String>,
    /// The operator's pods, let in by the `NetworkPolicy`.
    pub operator: OperatorPod,
    /// The chart's TokenReview `ClusterRole`; `None` when the operator may
    /// not bind it (limited to one namespace).
    pub token_review_role: Option<String>,
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
    match auth.iter_mut().find_map(|p| {
        p.as_object_mut()
            .filter(|p| p.get("type").and_then(Value::as_str) == Some("token"))
    }) {
        Some(provider) => {
            let tokens = provider
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
    Failure::new(crate::ports::workload_reason(&e), e.to_string())
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
    // The pass's `status.config`, filled as it goes, then reported.
    let mut status = kept(&pass.state);
    let mut report = ManagedReport {
        instance: InstanceReport {
            outcome: Outcome::synced(String::new()),
            observed: None,
            config: None,
            due_in: None,
            reloaded: false,
        },
        workload: WorkloadStatus::default(),
        rolled_out: None,
    };
    let result = run(&pass, parser, workloads, reach, &mut report, &mut status).await;
    let mut advisories = std::mem::take(&mut report.instance.outcome.advisories);
    // What the pods still lack, as the pass left it.
    if pass.spec.hot_reload {
        if pass.reload.restart == RestartPolicy::Never && !status.restart_keys.is_empty() {
            advisories.push(Advisory {
                reason: ReasonCode::RestartRequired,
                message: format!(
                    "keys BatleHub reads at startup changed and the pods won't restart \
                     (reload.restart: Never): {}",
                    status.restart_keys.join(", ")
                ),
            });
        }
        if !status.partial_keys.is_empty() {
            advisories.push(Advisory {
                reason: ReasonCode::PartiallyApplied,
                message: format!(
                    "hot-reloaded, but what BatleHub built at startup (warming, release \
                     imports, the scan worker) keeps the old values until the proxy pods \
                     restart: {} (reload.partial: Restart rolls them instead)",
                    status.partial_keys.join(", ")
                ),
            });
        }
    }
    advisories.extend(cache_not_resized(&pass, workloads).await);
    report.instance.outcome = match result {
        Ok(message) => Outcome::synced(message),
        Err(failure) => Outcome::failed(failure),
    };
    report.instance.outcome.advisories = advisories;
    report.instance.config = Some(status);
    report
}

/// The cache's claim the operator created, against `persistence.size`
/// (a claim it can't read says nothing: the pass reports its own errors).
async fn cache_not_resized(pass: &ManagedPass<'_>, workloads: &dyn Workloads) -> Option<Advisory> {
    let persistence = &pass.spec.persistence;
    if !persistence.enabled || persistence.existing_claim.is_some() {
        return None;
    }
    let name = Names::new(&pass.owner.name).cache();
    let current = workloads.claim_size(&pass.owner, &name).await.ok()??;
    crate::cache_volume::not_resized(pass.spec, &current)
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
        partial_keys: Vec::new(),
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
    status: &mut ConfigStatus,
) -> Result<String, Failure> {
    let names = Names::new(&pass.owner.name);
    let spec = pass.spec;
    let state = &pass.state;
    status.restart_keys = pass.restart_keys.clone();
    status.partial_keys = pass.partial_keys.clone();
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
        let hash = parser.hash_token(token).await.map_err(|e| {
            Failure::new(
                ReasonCode::ConfigInvalid,
                format!("hashing the operator's token: {e}"),
            )
        })?;
        document = with_operator_token(&document, &hash, &spec.operator_access.user_id, parser)?;
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
                Failure::new(
                    ReasonCode::ConfigInvalid,
                    format!(
                        "managed.credentials: {}",
                        crate::redact::values(&e.to_string())
                    ),
                )
            })?,
            None => document.clone(),
        };
        if parser.token_check(&effective, &token).await == TokenCheck::Refused {
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
    let held = previous.as_ref().filter(|_| {
        pass.reload.strategy == ReloadStrategy::Manual
            && state.approved_hash.as_deref() != Some(hash.as_str())
            && state.applied_hash.as_deref() != Some(hash.as_str())
    });
    let (target, target_hash, file) = if let Some(file) = held {
        let file = file.clone();
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

    // 4. Restart or reload. Restart-only keys stay owed
    //    (`status.restartKeys`) until the proxy pods start on the
    //    configuration — a pass that fails half-way, or `Never` turned
    //    into `Rollout`, still rolls them.
    let facts = DocumentFacts::of(
        &parser
            .fragment(without_credentials(&target))
            .map_err(|e| Failure::new(ReasonCode::ConfigInvalid, e.to_string()))?,
    );
    let strategy = update_strategy(spec, &facts);
    report
        .instance
        .outcome
        .advisories
        .extend(crate::cache_volume::single_writer(spec, &facts));
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
    let current = rollout
        .as_ref()
        .and_then(|r| r.annotation(CONFIG_HASH_ANNOTATION))
        .map(String::from);
    let changes = match previous.as_deref().map(without_nonce) {
        Some(before) if before != target => parser
            .classify(without_credentials(before), without_credentials(&target))
            .map_err(|e| Failure::new(ReasonCode::ConfigInvalid, e.to_string()))?,
        _ => KeyChanges::default(),
    };
    // Pods that started on the configuration run every key of it.
    if current.as_deref() == Some(target_hash.as_str()) || !spec.hot_reload {
        status.restart_keys.clear();
        status.partial_keys.clear();
    }
    let policy = Policy {
        rollout: pass.reload.restart == RestartPolicy::Rollout,
        partial_restarts: pass.reload.partial == PartialPolicy::Restart,
    };
    if spec.hot_reload {
        policy.owe(status, changes.restart, changes.partial);
    }
    let restart_hash = match current.as_deref() {
        None => target_hash.clone(),
        Some(_) if !spec.hot_reload => target_hash.clone(),
        Some(current) if status.restart_keys.is_empty() || !policy.rollout => current.to_string(),
        Some(_) => target_hash.clone(),
    };

    // 5. The objects.
    let deploy = Deploy {
        pass,
        file: &file,
        facts: &facts,
        target_hash: &target_hash,
    };
    let advisory = deploy.apply(workloads, &restart_hash).await?;
    report.instance.outcome.advisories.extend(advisory);
    if spec.hot_reload
        && let Some(current) = current.as_deref()
        && current != restart_hash
    {
        report.rolled_out = Some(RolledOut {
            keys: status.restart_keys.clone(),
            interrupts: strategy == UpdateStrategy::Recreate,
        });
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

    // 6. Every pod on the file — its exact bytes, nonce included: a reload
    //    of the bytes before a re-stage would find them tried already —
    //    then approved.
    let (gateway, _) = reach.gateway().await?;
    let pods = reach.pods().await?;
    if pods.is_empty() {
        report.instance.due_in = Some(PROPAGATION_RETRY_SECS);
        return Err(Failure::new(
            ReasonCode::NoReadyPod,
            "no proxy pod is ready",
        ));
    }
    let mut behind = Vec::new();
    for pod in &pods {
        let content = pod.gateway.config_content().await.map_err(fail)?;
        if content.trim_end_matches('\n') != file.trim_end_matches('\n') {
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
        let approval = Approval {
            pods: &pods,
            gateway: gateway.as_ref(),
            target: &target,
            hash: &target_hash,
            state,
            policy,
            // BatleHub merges the credentials layer, and expands the
            // environment, before it quotes a value.
            sensitive: rendered.sensitive || credentials.is_some(),
            // Pods that started on it owe it nothing, whatever BatleHub
            // compares (`*` when a placeholder names an entry).
            may_owe: restart_hash != target_hash,
        };
        if approval.run(report, status).await? == Approved::Roll {
            // Restart-only keys the dry run or a pod reported (the
            // credentials layer's, a pod's environment): the pods restart
            // onto the configuration.
            let keys = status.restart_keys.clone();
            deploy.apply(workloads, &target_hash).await?;
            report.rolled_out = Some(RolledOut {
                keys: keys.clone(),
                interrupts: strategy == UpdateStrategy::Recreate,
            });
            report.instance.due_in = Some(PROPAGATION_RETRY_SECS);
            return Err(Failure::new(
                ReasonCode::WorkloadNotReady,
                format!(
                    "keys BatleHub reads at startup changed ({}): the proxy pods restart onto \
                     configuration {}",
                    keys.join(", "),
                    short(&target_hash)
                ),
            ));
        }
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

/// `keys` added to `list`, each once, in order.
fn merge_into(list: &mut Vec<String>, keys: impl IntoIterator<Item = String>) {
    for key in keys {
        if !list.contains(&key) {
            list.push(key);
        }
    }
}

/// What `reload.restart` and `reload.partial` make of changed keys.
#[derive(Debug, Clone, Copy)]
struct Policy {
    /// `reload.restart: Rollout`.
    rollout: bool,
    /// `reload.partial: Restart`: the `Partial` tier counts as restart.
    partial_restarts: bool,
}

impl Policy {
    /// Records keys a reload doesn't fully apply: owed a restart
    /// (`status.restartKeys`), or partially applied
    /// (`status.partialKeys`).
    fn owe(self, status: &mut ConfigStatus, restart: Vec<String>, partial: Vec<String>) {
        merge_into(&mut status.restart_keys, restart);
        if self.partial_restarts {
            merge_into(&mut status.restart_keys, partial);
        } else {
            merge_into(&mut status.partial_keys, partial);
        }
    }
}

/// The objects of the pass, applied with a pod template hash.
struct Deploy<'a> {
    pass: &'a ManagedPass<'a>,
    file: &'a str,
    facts: &'a DocumentFacts,
    target_hash: &'a str,
}

impl Deploy<'_> {
    /// Applies every object, the proxy pods' template carrying
    /// `restart_hash`; then the TokenReview binding and what the spec no
    /// longer asks for.
    async fn apply(
        &self,
        workloads: &dyn Workloads,
        restart_hash: &str,
    ) -> Result<Option<Advisory>, Failure> {
        let pass = self.pass;
        let spec = pass.spec;
        let input = WorkloadInput {
            name: &pass.owner.name,
            namespace: &pass.owner.namespace,
            spec,
            file: self.file,
            facts: self.facts,
            restart_hash,
            config_hash: self.target_hash,
            operator: &pass.operator,
        };
        workloads
            .apply(&pass.owner, &objects(&input))
            .await
            .map_err(workload_failure)?;
        let mut advisory = None;
        // TokenReview, for a `kubernetes` auth provider.
        let token_review = self.facts.kubernetes_auth && spec.service_account.auto_token_review;
        match (&pass.token_review_role, token_review) {
            (Some(role), true) => {
                let account = spec
                    .service_account
                    .name
                    .clone()
                    .unwrap_or_else(|| pass.owner.name.clone());
                workloads
                    .bind_token_review(&pass.owner, &account, role)
                    .await
                    .map_err(workload_failure)?;
            }
            (None, true) => {
                advisory = Some(Advisory {
                    reason: ReasonCode::TokenReviewUnavailable,
                    message: "the configuration has a kubernetes auth provider, and the operator \
                              (limited to one namespace) binds no ClusterRole: bind TokenReview \
                              (create) to the instance's ServiceAccount yourself"
                        .into(),
                })
            }
            // No role (limited to one namespace, `tokenReview.enabled:
            // false`): the operator binds nothing, so has nothing to unbind
            // — nor the right to read a cluster-scoped binding.
            (Some(role), false) => workloads
                .unbind_token_review(&pass.owner, role)
                .await
                .map_err(workload_failure)?,
            (None, false) => {}
        }
        for (api_version, kind, name) in removed(&input) {
            workloads
                .remove(&pass.owner, api_version, kind, &name)
                .await
                .map_err(workload_failure)?;
        }
        Ok(advisory)
    }
}

/// How an approval ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Approved {
    /// Every pod loaded the configuration.
    Done,
    /// Keys read at startup only are owed and `reload.restart: Rollout`:
    /// the pods restart onto it.
    Roll,
}

/// The approval of a new configuration every pod serves: one dry run,
/// then a reload on each pod.
struct Approval<'a> {
    pods: &'a [PodGateway],
    gateway: &'a dyn AdminGateway,
    target: &'a str,
    hash: &'a str,
    state: &'a ConfigState,
    policy: Policy,
    /// BatleHub's messages keep key paths and positions only.
    sensitive: bool,
    /// The pods didn't start on the configuration: the restart-only keys
    /// BatleHub reports are owed.
    may_owe: bool,
}

impl Approval<'_> {
    async fn run(
        &self,
        report: &mut ManagedReport,
        status: &mut ConfigStatus,
    ) -> Result<Approved, Failure> {
        let (hash, state) = (self.hash, self.state);
        let retry = "reloaded again 10 minutes after status.lastRejectionTime, or at once on a \
                     change of the spec";
        if status.rejected_hash.as_deref() == Some(hash)
            && let Some(at) = status.rejected_at
        {
            let wait = REJECTION_BACKOFF_SECS.saturating_sub(state.now.saturating_sub(at));
            if wait > 0 {
                report.instance.due_in = u64::try_from(wait).ok();
                return Err(Failure::new(
                    ReasonCode::ConfigRejected,
                    format!(
                        "configuration {}: {} ({retry})",
                        short(hash),
                        status
                            .rejection_message
                            .as_deref()
                            .unwrap_or("the instance refused it")
                    ),
                ));
            }
            // Waited out. The pods tried these bytes already (a reload of
            // them stages nothing — it would read as loaded): new ones
            // first, and a pod staging nothing for them refused them.
            status.nonce = status.nonce.wrapping_add(1);
            status.rejected_at = None;
            report.instance.due_in = Some(PROPAGATION_RETRY_SECS);
            return Err(Failure::new(
                ReasonCode::ConfigPropagating,
                format!(
                    "configuration {} was refused 10 minutes ago: written again under nonce {} to \
                     be retried",
                    short(hash),
                    status.nonce
                ),
            ));
        }
        // Retried under fresh bytes: a pod that had tried them already
        // refused them, or let their pending reload expire.
        let fresh = status.rejected_hash.as_deref() == Some(hash) && status.rejected_at.is_none();
        let said = |message: String| {
            if self.sensitive {
                crate::redact::values(&message)
            } else {
                message
            }
        };
        let rejected = |message: String, status: &mut ConfigStatus| {
            status.rejected_hash = Some(hash.to_string());
            status.rejected_at = Some(state.now);
            status.rejection_message = Some(message.clone());
            Failure::new(
                ReasonCode::ConfigRejected,
                format!("configuration {}: {message} ({retry})", short(hash)),
            )
        };
        let check = match self.gateway.validate_config(self.target).await {
            Ok(check) => check,
            Err(GatewayError::Rejected(message)) => {
                let failure = rejected(
                    format!("the instance refuses it: {}", said(message)),
                    status,
                );
                report.instance.due_in = Some(REJECTION_BACKOFF_SECS as u64);
                return Err(failure);
            }
            Err(e) => return Err(fail(e)),
        };
        if self.may_owe && !check.restart_required.is_empty() {
            merge_into(&mut status.restart_keys, check.restart_required);
            if self.policy.rollout {
                return Ok(Approved::Roll);
            }
        }
        let mut done: Vec<String> = Vec::new();
        for pod in self.pods {
            let partial = |done: &[String]| match done {
                [] => String::new(),
                done => format!(" ({} already loaded it)", done.join(", ")),
            };
            // Stopped half-way, some pods loaded it: those would find these
            // bytes tried next time. New ones, and a pod staging nothing
            // for them refused them.
            let restage = |status: &mut ConfigStatus, done: &[String]| {
                if !done.is_empty() {
                    status.nonce = status.nonce.wrapping_add(1);
                    if status.rejected_hash.as_deref() != Some(hash) {
                        status.rejected_hash = Some(hash.to_string());
                        status.rejected_at = None;
                    }
                }
            };
            match pod.gateway.reload().await {
                Ok(Reloaded::Loaded {
                    restart_required,
                    partially_applied,
                }) => {
                    report.instance.reloaded = true;
                    status.reloaded_at = Some(state.now);
                    let restart = if self.may_owe {
                        restart_required
                    } else {
                        Vec::new()
                    };
                    self.policy.owe(status, restart, partially_applied);
                }
                Ok(Reloaded::AlreadyTried) if fresh => {
                    let failure = rejected(
                        format!(
                            "{} staged nothing for bytes written for it anew: it refused them \
                             (its file watcher tried them first) or let their reload expire{}",
                            pod.name,
                            partial(&done)
                        ),
                        status,
                    );
                    report.instance.due_in = Some(REJECTION_BACKOFF_SECS as u64);
                    return Err(failure);
                }
                Ok(Reloaded::AlreadyTried) => {
                    // These bytes were tried before — run, refused, or let
                    // expire: BatleHub doesn't say. Never read as loaded.
                    status.nonce = status.nonce.wrapping_add(1);
                    status.rejected_hash = Some(hash.to_string());
                    status.rejected_at = None;
                    report.instance.due_in = Some(PROPAGATION_RETRY_SECS);
                    return Err(Failure::new(
                        ReasonCode::ConfigPropagating,
                        format!(
                            "{} had already tried these bytes and doesn't say it runs them: \
                             written again under nonce {}{}",
                            pod.name,
                            status.nonce,
                            partial(&done)
                        ),
                    ));
                }
                Err(GatewayError::NoPending(why)) => {
                    // BatleHub let its pending expire: new bytes, staged by
                    // the watcher on the next sync.
                    status.nonce = status.nonce.wrapping_add(1);
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
                            "{} failed to load it: {}{}",
                            pod.name,
                            said(message),
                            partial(&done)
                        ),
                        status,
                    );
                    report.instance.due_in = Some(REJECTION_BACKOFF_SECS as u64);
                    return Err(failure);
                }
                Err(GatewayError::HotReloadDisabled(why)) => {
                    restage(status, &done);
                    return Err(Failure::new(
                        ReasonCode::HotReloadDisabled,
                        format!(
                            "{}: {why}. Hot reload is disabled by the pods' environment: set \
                             managed.hotReload: false, every change then restarts the pods",
                            pod.name
                        ),
                    ));
                }
                Err(e) => {
                    restage(status, &done);
                    return Err(fail(e));
                }
            }
            done.push(pod.name.clone());
        }
        if self.policy.rollout && self.may_owe && !status.restart_keys.is_empty() {
            return Ok(Approved::Roll);
        }
        Ok(Approved::Done)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

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
            sensitive: false,
        }
    }

    struct World {
        spec: ManagedInstance,
        reload: Reload,
        workloads: FakeWorkloads,
        reach: FakeReach,
        state: ConfigState,
        restart_keys: Vec<String>,
        partial_keys: Vec<String>,
        credentials: Option<String>,
        token_review_role: Option<String>,
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
                partial_keys: vec![],
                credentials: None,
                token_review_role: Some("weebo-batlehub-tokenreview".into()),
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
                partial_keys: self.partial_keys.clone(),
                operator: OperatorPod::named(crate::workload::OPERATOR_CHART),
                token_review_role: self.token_review_role.clone(),
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
                self.partial_keys = config.partial_keys.clone();
            }
            report
        }

        fn advised(report: &ManagedReport, reason: ReasonCode) -> bool {
            report
                .instance
                .outcome
                .advisories
                .iter()
                .any(|a| a.reason == reason)
        }

        /// Deployed, every pod on `config`.
        async fn running(&mut self, config: Value) {
            self.pass(config.clone()).await;
            self.reach.sync(&self.workloads);
            let report = self.pass(config).await;
            assert_eq!(
                reason(&report),
                ReasonCode::Reconciled,
                "{:?}",
                report.instance.outcome
            );
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

        // Restarted onto the configuration (the `restart` maintenance):
        // nothing left to restart for.
        let hash = report.instance.config.unwrap().config_hash.unwrap();
        let owner = Owner {
            namespace: "team".into(),
            name: "hub".into(),
            uid: "u-1".into(),
        };
        world
            .workloads
            .restart(&owner, "hub", Some(&hash))
            .await
            .unwrap();
        world.reach.sync(&world.workloads);
        let report = world.pass(json!({"restart": 3, "hot": 2})).await;
        assert!(world.restart_keys.is_empty(), "{:?}", world.restart_keys);
        assert!(
            !report
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
    async fn a_kubernetes_provider_binds_token_review_and_unbinds_without() {
        let mut world = World::new();
        world.pass(json!({"auth": [{"type": "kubernetes"}]})).await;
        assert!(
            world
                .workloads
                .removed()
                .contains(&"bound team/hub to weebo-batlehub-tokenreview".to_string())
        );
        let pod = &world
            .workloads
            .object("Deployment", "hub")
            .unwrap()
            .manifest;
        assert_eq!(
            pod["spec"]["template"]["spec"]["automountServiceAccountToken"],
            true
        );
        world.pass(json!({})).await;
        assert!(
            world
                .workloads
                .removed()
                .contains(&"unbound hub".to_string())
        );
    }

    #[tokio::test]
    async fn a_cache_claim_is_never_resized_but_said_so() {
        let mut world = World::new();
        let report = world.pass(json!({})).await;
        assert!(
            world
                .workloads
                .object("PersistentVolumeClaim", "hub-cache")
                .is_some()
        );
        assert!(
            !report
                .instance
                .outcome
                .advisories
                .iter()
                .any(|a| a.reason == ReasonCode::CacheVolumeNotResized)
        );
        world.spec.persistence.size =
            k8s_openapi::apimachinery::pkg::api::resource::Quantity("20Gi".into());
        world.spec.replicas = 2;
        let report = world.pass(json!({})).await;
        let reasons: Vec<ReasonCode> = report
            .instance
            .outcome
            .advisories
            .iter()
            .map(|a| a.reason)
            .collect();
        assert!(
            reasons.contains(&ReasonCode::CacheVolumeNotResized),
            "{reasons:?}"
        );
        assert!(
            reasons.contains(&ReasonCode::CacheVolumeSingleWriter),
            "{reasons:?}"
        );
    }

    #[tokio::test]
    async fn without_a_token_review_role_nothing_is_bound_nor_unbound() {
        let mut world = World::new();
        world.token_review_role = None;
        let report = world.pass(json!({"auth": [{"type": "kubernetes"}]})).await;
        assert!(
            report
                .instance
                .outcome
                .advisories
                .iter()
                .any(|a| a.reason == ReasonCode::TokenReviewUnavailable)
        );
        world.pass(json!({})).await;
        // No cluster-scoped call at all: it would be forbidden.
        assert!(
            world.workloads.removed().is_empty(),
            "{:?}",
            world.workloads.removed()
        );
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

    #[tokio::test]
    async fn restart_keys_stay_owed_until_the_pods_start_on_the_configuration() {
        let mut world = World::new();
        world.running(json!({"restart": 1})).await;
        let first = world.annotation();
        // The Secret is written, then an object after it can't be: the
        // Deployment keeps its template.
        world.workloads.foreign("Service", "hub");
        let report = world.pass(json!({"restart": 2})).await;
        assert_eq!(reason(&report), ReasonCode::OwnedObjectConflict);
        assert_eq!(report.rolled_out, None);
        assert_eq!(world.restart_keys, ["restart"]);
        // Fixed: the file is already the new one, the keys are still owed.
        world.workloads.unforeign("Service", "hub");
        let report = world.pass(json!({"restart": 2})).await;
        assert_ne!(world.annotation(), first);
        assert_eq!(
            report.rolled_out,
            Some(RolledOut {
                keys: vec!["restart".into()],
                interrupts: true
            })
        );
        // Started on it: nothing owed any more, nothing rolled again.
        world.reach.sync(&world.workloads);
        let report = world.pass(json!({"restart": 2})).await;
        assert_eq!(reason(&report), ReasonCode::Reconciled);
        assert!(world.restart_keys.is_empty());
        assert_eq!(report.rolled_out, None);
    }

    #[tokio::test]
    async fn never_turned_into_rollout_rolls_the_keys_held_back() {
        let mut world = World::new();
        world.reload.restart = RestartPolicy::Never;
        world.running(json!({"restart": 1})).await;
        let first = world.annotation();
        world.pass(json!({"restart": 2})).await;
        world.reach.sync(&world.workloads);
        let report = world.pass(json!({"restart": 2})).await;
        assert_eq!(reason(&report), ReasonCode::Reconciled);
        assert!(World::advised(&report, ReasonCode::RestartRequired));
        assert_eq!(world.annotation(), first);

        world.reload.restart = RestartPolicy::Rollout;
        let report = world.pass(json!({"restart": 2})).await;
        assert_ne!(world.annotation(), first);
        assert!(report.rolled_out.is_some());
        assert!(!World::advised(&report, ReasonCode::RestartRequired));
    }

    #[tokio::test]
    async fn a_restart_key_only_batlehub_sees_rolls_the_pods_too() {
        // A key of the credentials layer, or one an environment sets: the
        // operator's documents don't show it, the dry run does.
        let mut world = World::new();
        world.running(json!({"a": 1})).await;
        let first = world.annotation();
        world.reach.service.require_restart(&["database.url"]);
        world.pass(json!({"a": 2})).await;
        world.reach.sync(&world.workloads);
        let reloads = world.reach.pods[0].1.calls().len();
        let report = world.pass(json!({"a": 2})).await;
        assert_eq!(reason(&report), ReasonCode::WorkloadNotReady);
        assert_eq!(
            report.rolled_out.as_ref().map(|r| r.keys.clone()),
            Some(vec!["database.url".to_string()])
        );
        assert_ne!(world.annotation(), first);
        // Not reloaded: the pods restart onto it.
        assert!(
            !world.reach.pods[0].1.calls()[reloads..]
                .iter()
                .any(|c| c == "reload")
        );
        // Once they did, BatleHub's comparison against their startup
        // configuration owes nothing.
        let report = world.pass(json!({"a": 2})).await;
        assert_eq!(
            reason(&report),
            ReasonCode::Reconciled,
            "{:?}",
            report.instance.outcome
        );
        assert!(world.restart_keys.is_empty());

        // `Never`: reloaded, the keys reported.
        let mut world = World::new();
        world.reload.restart = RestartPolicy::Never;
        world.running(json!({"a": 1})).await;
        for (_, pod) in &world.reach.pods {
            pod.require_restart(&["database.url"]);
        }
        world.pass(json!({"a": 2})).await;
        world.reach.sync(&world.workloads);
        let report = world.pass(json!({"a": 2})).await;
        assert_eq!(reason(&report), ReasonCode::Reconciled);
        assert_eq!(world.restart_keys, ["database.url"]);
        assert!(World::advised(&report, ReasonCode::RestartRequired));
    }

    #[tokio::test]
    async fn bytes_a_pod_already_tried_never_read_as_loaded() {
        // A pod that staged nothing — it may run them, have refused them,
        // or let them expire: written again, then a refusal.
        let mut world = World::new();
        world.running(json!({"a": 1})).await;
        world.pass(json!({"a": 2})).await;
        world.reach.sync(&world.workloads);
        let file = world.workloads.config_file("hub").unwrap();
        world.reach.pods[1].1.attempted(&file);
        let report = world.pass(json!({"a": 2})).await;
        assert_eq!(reason(&report), ReasonCode::ConfigPropagating);
        let status = report.instance.config.clone().unwrap();
        assert_eq!(status.nonce, 1);
        assert_ne!(status.applied_hash, status.config_hash);
        // New bytes, not synced yet: nothing is reloaded meanwhile.
        let report = world.pass(json!({"a": 2})).await;
        assert_eq!(reason(&report), ReasonCode::ConfigPropagating);
        world.reach.sync(&world.workloads);
        let file = world.workloads.config_file("hub").unwrap();
        // Its watcher tried the new bytes first and refused them.
        world.reach.pods[1].1.attempted(&file);
        let report = world.pass(json!({"a": 2})).await;
        assert_eq!(reason(&report), ReasonCode::ConfigRejected);
        let status = report.instance.config.clone().unwrap();
        assert_ne!(status.applied_hash, status.config_hash);
        assert_eq!(status.rejected_at, Some(world.state.now));
    }

    #[tokio::test]
    async fn a_refusal_waited_out_is_retried_under_new_bytes() {
        let mut world = World::new();
        world.running(json!({"a": 1})).await;
        // Every pod refuses it at load time.
        for (_, pod) in &world.reach.pods {
            pod.refuse(Some("bad"));
        }
        world.pass(json!({"a": "bad"})).await;
        world.reach.sync(&world.workloads);
        let report = world.pass(json!({"a": "bad"})).await;
        assert_eq!(reason(&report), ReasonCode::ConfigRejected);
        // Fixed on the pods' side (a database back), ten minutes later.
        for (_, pod) in &world.reach.pods {
            pod.refuse(None);
        }
        world.state.now += REJECTION_BACKOFF_SECS;
        // The bytes they tried would stage nothing: new ones first.
        let report = world.pass(json!({"a": "bad"})).await;
        assert_eq!(reason(&report), ReasonCode::ConfigPropagating);
        assert!(
            !report
                .instance
                .config
                .as_ref()
                .unwrap()
                .applied_hash
                .as_ref()
                .is_some_and(|h| Some(h)
                    == report
                        .instance
                        .config
                        .as_ref()
                        .unwrap()
                        .config_hash
                        .as_ref())
        );
        // Written under the new nonce, then synced.
        let report = world.pass(json!({"a": "bad"})).await;
        assert_eq!(reason(&report), ReasonCode::ConfigPropagating);
        world.reach.sync(&world.workloads);
        let report = world.pass(json!({"a": "bad"})).await;
        assert_eq!(
            reason(&report),
            ReasonCode::Reconciled,
            "{:?}",
            report.instance.outcome
        );
        let status = report.instance.config.unwrap();
        assert_eq!(status.applied_hash, status.config_hash);
        assert_eq!(status.rejected_hash, None);
        let file = world.workloads.config_file("hub").unwrap();
        for (_, pod) in &world.reach.pods {
            assert_eq!(pod.loaded().as_deref(), Some(file.as_str()));
        }
    }

    #[tokio::test]
    async fn partial_keys_are_reported_or_rolled() {
        let mut world = World::new();
        world.running(json!({"partial": 1})).await;
        let first = world.annotation();
        world.pass(json!({"partial": 2})).await;
        world.reach.sync(&world.workloads);
        let report = world.pass(json!({"partial": 2})).await;
        assert_eq!(reason(&report), ReasonCode::Reconciled);
        assert_eq!(world.annotation(), first);
        assert_eq!(world.partial_keys, ["partial"]);
        assert!(World::advised(&report, ReasonCode::PartiallyApplied));

        world.reload.partial = PartialPolicy::Restart;
        let report = world.pass(json!({"partial": 3})).await;
        assert_ne!(world.annotation(), first);
        assert_eq!(
            report.rolled_out.map(|r| r.keys),
            Some(vec!["partial".to_string()])
        );
        // Started on it: neither list is kept.
        world.reach.sync(&world.workloads);
        let report = world.pass(json!({"partial": 3})).await;
        assert_eq!(reason(&report), ReasonCode::Reconciled);
        assert!(world.partial_keys.is_empty() && world.restart_keys.is_empty());
        assert!(!World::advised(&report, ReasonCode::PartiallyApplied));
    }
}
