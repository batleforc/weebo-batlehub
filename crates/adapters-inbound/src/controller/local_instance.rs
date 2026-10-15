//! `BatleHubLocalInstance` in external mode: a connectivity and token
//! check, BatleHub's warnings on its configuration and, with
//! `external.manageConfig`, the configuration rendered from the CR and
//! its registries pushed to the instance (`reconcile_instance`), with the
//! token of its own namespace. It then writes the status of every
//! `BatleHubRegistry` bound to it. Its finalizer holds the deletion while
//! CRs are still bound to it (`InstanceInUse`).
//!
//! The causes come in the order of the spec's §5: the configuration is
//! rendered before the token is read and the instance called, so a spec
//! the operator can't render says so even when the instance is down.
//!
//! Besides its own changes, a pass is triggered by any `BatleHubRegistry`
//! change (each may attach to any instance), by a change of a `ConfigMap`
//! a `configLayers` or a registry's `configFrom` names (metadata only), and
//! — cluster-wide, for `registrySelector.namespaces.from: Selector` — by a
//! change of a Namespace's labels. Secrets are not watched (it would grant
//! reading all of them): they are read again on every pass, at the latest
//! on the steady resync.

use std::sync::Arc;
use std::time::Instant;

use api::local_instance::NamespacesFrom;
use api::{LocalInstance, Registry};
use application::ports::{BoundInstance, InstanceAccess};
use application::use_cases::Outcome;
use application::use_cases::reconcile_instance::{
    ConfigState, ConfigStatus, InstanceReport, ManagedConfig, Targets, reconcile_instance,
    release_instance,
};
use application::use_cases::reconcile_registry::rendered_outcome;
use application::use_cases::render_config::{
    RegistryDecision, Rendered, base_layers, check_token, render_config, render_registries,
    static_registry_names,
};
use domain::Failure;
use domain::error::ReasonCode;
use k8s_openapi::api::core::v1::{ConfigMap, Namespace};
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, PartialObjectMeta};
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::runtime::reflector::{self, ObjectRef};
use kube::runtime::{WatchStreamExt, watcher};
use kube::{Client, ResourceExt};
use serde_json::{Map, Value, json};
use weebo_kit_runtime::events;

use super::{Ctx, Error, FINALIZER, error_policy};

const KIND: &str = "BatleHubLocalInstance";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller = super::controller(ctx.scope.api::<LocalInstance>(client.clone()), &ctx.scope);
    let instances = controller.store();
    let all = {
        let instances = instances.clone();
        move || {
            instances
                .state()
                .iter()
                .map(|i| ObjectRef::from_obj(i.as_ref()))
                .collect::<Vec<_>>()
        }
    };

    // A registry may attach to any instance: every one renders again
    // (requests for one instance collapse in the queue). Its store tells
    // which ConfigMaps the registries read.
    let (registries, writer) = reflector::store::<Registry>();
    let registry_changes = watcher(
        ctx.scope.api::<Registry>(client.clone()),
        ctx.scope.watcher_config(),
    )
    .default_backoff()
    .reflect(writer)
    .touched_objects();
    let on_registry = all.clone();
    let controller = controller.watches_stream(registry_changes, move |_| on_registry());

    // Without cluster kinds the chart renders no ClusterRole, so no
    // `clusterRules`: no ConfigMap nor Namespace watch, layers are read
    // again on the steady resync only (spec §7.1).
    if !ctx.scope.cluster_kinds() {
        let results =
            controller
                .graceful_shutdown_on(ctx.shutdown.wait())
                .run(reconcile, error_policy, ctx);
        super::drive(KIND, health, results).await;
        return;
    }

    // Metadata only: no ConfigMap data in memory.
    let configmaps: Api<PartialObjectMeta<ConfigMap>> = match ctx.scope.watched_namespace() {
        Some(namespace) => Api::namespaced(client.clone(), namespace),
        None => Api::all(client.clone()),
    };
    let configmap_changes = watcher(configmaps, watcher::Config::default())
        .default_backoff()
        .touched_objects();
    let by_configmap = instances.clone();
    let on_configmap = all.clone();
    let controller = controller.watches_stream(configmap_changes, move |cm| {
        let namespace = cm.namespace();
        let name = cm.name_any();
        let names_it =
            |r: &Option<api::config::ConfigKeyRef>| r.as_ref().is_some_and(|r| r.name == name);
        // A registry's fragment: every instance renders again, as on any
        // registry change.
        if registries.state().iter().any(|r| {
            r.namespace() == namespace
                && r.spec
                    .config_from
                    .iter()
                    .any(|s| names_it(&s.config_map_ref))
        }) {
            return on_configmap();
        }
        by_configmap
            .state()
            .iter()
            .filter(|i| {
                i.namespace() == namespace
                    && i.spec
                        .config_layers
                        .iter()
                        .any(|l| names_it(&l.config_map_ref))
            })
            .map(|i| ObjectRef::from_obj(i.as_ref()))
            .collect::<Vec<_>>()
    });

    // A namespace's labels decide whether its registries attach to the
    // instances that accept namespaces by selector (cluster-wide only:
    // limited to one namespace, none attach from elsewhere).
    let controller = if ctx.scope.watched_namespace().is_none() {
        let namespaces: Api<PartialObjectMeta<Namespace>> = Api::all(client);
        let namespace_changes = watcher(namespaces, watcher::Config::default())
            .default_backoff()
            .touched_objects()
            .predicate_filter(kube::runtime::predicates::labels, Default::default());
        let by_namespace = instances.clone();
        controller.watches_stream(namespace_changes, move |_| {
            by_namespace
                .state()
                .iter()
                .filter(|i| i.spec.registry_selector.namespaces.from == NamespacesFrom::Selector)
                .map(|i| ObjectRef::from_obj(i.as_ref()))
                .collect::<Vec<_>>()
        })
    } else {
        controller
    };
    let results =
        controller
            .graceful_shutdown_on(ctx.shutdown.wait())
            .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<LocalInstance>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let namespace = obj.namespace().unwrap_or_default();
    let api: Api<LocalInstance> = Api::namespaced(ctx.client.clone(), &namespace);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(instance) => apply(&api, instance, &ctx).await,
            FinalizerEvent::Cleanup(instance) => {
                super::finalize(instance.as_ref(), &ctx, cleanup(&api, &instance, &ctx)).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

fn bound(instance: &LocalInstance) -> BoundInstance {
    BoundInstance::local(
        instance.namespace().unwrap_or_default(),
        instance.name_any(),
    )
}

fn unix(time: &Option<String>) -> Option<i64> {
    time.as_deref()?
        .parse::<Timestamp>()
        .ok()
        .map(|t| t.as_second())
}

fn rfc3339(secs: Option<i64>) -> Value {
    secs.and_then(|s| Timestamp::from_second(s).ok())
        .map_or(Value::Null, |t| json!(t.to_string()))
}

/// What the status says of the configuration, and the approval.
fn config_state(obj: &LocalInstance) -> ConfigState {
    let status = obj.status.clone().unwrap_or_default();
    ConfigState {
        applied_hash: status.applied_config_hash,
        nonce: status.reload_nonce,
        rejected_hash: status.rejected_config_hash,
        rejected_at: unix(&status.last_rejection_time),
        rejection_message: status.rejection_message,
        unpersisted_hash: status.unpersisted_config_hash,
        pods: status.pods,
        strategy: obj.spec.reload.strategy,
        approved_hash: obj.annotations().get(api::APPROVED_CONFIG_HASH).cloned(),
        now: Timestamp::now().as_second(),
    }
}

/// The configuration fields as the status has them: kept when the pass
/// stops before the instance.
fn config_status_kept(obj: &LocalInstance) -> ConfigStatus {
    let previous = obj.status.clone().unwrap_or_default();
    ConfigStatus {
        config_hash: previous.config_hash,
        applied_hash: previous.applied_config_hash,
        pending_hash: previous.pending_config_hash,
        nonce: previous.reload_nonce,
        rejected_hash: previous.rejected_config_hash,
        rejected_at: unix(&previous.last_rejection_time),
        rejection_message: previous.rejection_message,
        unpersisted_hash: previous.unpersisted_config_hash,
        restart_keys: previous.restart_keys,
        pods: previous.pods,
        reloaded_at: unix(&previous.last_reload_time),
    }
}

/// The configuration of a `manageConfig` instance, rendered from its spec
/// and the registries bound to it (their fate in the decisions), before
/// the token is known.
pub(crate) async fn render(
    obj: &LocalInstance,
    bound: &BoundInstance,
    ctx: &Ctx,
) -> Result<(Result<Rendered, Failure>, Vec<RegistryDecision>), Error> {
    let namespace = bound.namespace.clone().unwrap_or_default();
    let registries = ctx
        .sources
        .registries()
        .await
        .map_err(|e| Error::Failed(Failure::new(ReasonCode::KubernetesApiError, e)))?;
    let base = base_layers(obj, &namespace, ctx.sources.as_ref(), ctx.config.as_ref()).await;
    let statics = match &base {
        Ok(base) => static_registry_names(base, ctx.config.as_ref()),
        Err(_) => Vec::new(),
    };
    let (decisions, entries) = render_registries(
        obj,
        bound,
        registries,
        &statics,
        ctx.sources.as_ref(),
        ctx.config.as_ref(),
    )
    .await;
    let rendered = base.and_then(|base| render_config(obj, &base, entries, ctx.config.as_ref()));
    Ok((rendered, decisions))
}

/// The rendered configuration with the token checked against it, and
/// where to push it.
async fn managed_config(
    obj: &LocalInstance,
    bound: &BoundInstance,
    access: &InstanceAccess,
    rendered: Result<Rendered, Failure>,
    ctx: &Ctx,
) -> ManagedConfig {
    let rendered = rendered.and_then(|rendered| {
        check_token(&rendered, &access.token, ctx.config.as_ref()).map(|()| rendered)
    });
    let targets = match ctx.gateways.pod_gateways(bound).await {
        Ok(None) => Targets::Url,
        Ok(Some(pods)) => {
            Targets::Pods(Ok(pods.into_iter().map(|p| (p.name, p.gateway)).collect()))
        }
        Err(e) => Targets::Pods(Err(e.into())),
    };
    ManagedConfig {
        rendered,
        state: config_state(obj),
        targets,
    }
}

async fn apply(
    api: &Api<LocalInstance>,
    obj: Arc<LocalInstance>,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let started = Instant::now();
    let bound = bound(&obj);
    let (rendered, decisions) = match obj.spec.external.manage_config {
        true => {
            let (rendered, decisions) = render(&obj, &bound, ctx).await?;
            (Some(rendered), decisions)
        }
        false => (None, Vec::new()),
    };
    let report = match (ctx.gateways.gateway_for(&bound).await, rendered) {
        // A configuration that can't be rendered outranks a token that
        // can't be read.
        (Err(_), Some(Err(failure))) => InstanceReport {
            outcome: Outcome::failed(failure),
            observed: None,
            config: Some(config_status_kept(&obj)),
            due_in: None,
            reloaded: false,
        },
        (Err(e), _) => InstanceReport {
            outcome: Outcome::failed(e),
            observed: None,
            config: None,
            due_in: None,
            reloaded: false,
        },
        (Ok(access), rendered) => {
            let managed = match rendered {
                Some(rendered) => Some(managed_config(&obj, &bound, &access, rendered, ctx).await),
                None => None,
            };
            reconcile_instance(access.gateway.as_ref(), managed).await
        }
    };
    let mut outcome = report.outcome.clone();
    let from = obj.spec.registry_selector.namespaces.from;
    if ctx.scope.watched_namespace().is_some() && from != NamespacesFrom::Same {
        outcome = outcome.advise(
            ReasonCode::RegistrySelectorIgnored,
            "the operator is limited to one namespace: registries of other namespaces are \
             not seen (registrySelector.namespaces.from)",
        );
    }
    super::record_reconcile(KIND, started, &outcome);
    super::publish(
        api,
        &ctx.recorder,
        obj.as_ref(),
        &outcome,
        fields(&obj, &report),
    )
    .await?;
    if report.reloaded {
        let hash = report
            .config
            .as_ref()
            .and_then(|c| c.config_hash.as_deref())
            .unwrap_or_default();
        events::announce_change(
            &ctx.recorder,
            &kube::Resource::object_ref(obj.as_ref(), &()),
            ReasonCode::ConfigReloaded,
            events::RECONCILE,
            &format!("the instance loaded configuration {hash}"),
        )
        .await;
    }
    let config = report.config.as_ref();
    let hash = config.and_then(|c| c.config_hash.clone());
    let held = config.is_some_and(|c| c.pending_hash.is_some());
    for decision in &decisions {
        publish_registry(
            ctx,
            decision,
            &outcome.ready,
            hash.as_deref(),
            held,
            started,
        )
        .await?;
    }
    Ok(weebo_kit_runtime::controller::requeue_after(
        outcome.steady(),
        report.due_in,
    ))
}

/// `endpoint` always; `version` and `warnings` as last read — kept while
/// the instance doesn't answer; the configuration's fields with
/// `manageConfig` (all cleared without it).
fn fields(obj: &LocalInstance, report: &InstanceReport) -> Map<String, Value> {
    let mut fields = Map::new();
    fields.insert("endpoint".into(), json!(obj.spec.external.url));
    if let Some(observed) = &report.observed {
        fields.insert("version".into(), json!(observed.version));
        fields.insert(
            "warnings".into(),
            serde_json::to_value(&observed.warnings).expect("warnings serialize"),
        );
    }
    let config = match (&report.config, obj.spec.external.manage_config) {
        (Some(config), true) => {
            let mut config = config.clone();
            // A pass that loaded nothing keeps the last load's time.
            if config.reloaded_at.is_none() {
                config.reloaded_at = obj.status.as_ref().and_then(|s| unix(&s.last_reload_time));
            }
            config
        }
        // The instance didn't answer: what was known stays.
        (None, true) => config_status_kept(obj),
        (_, false) => ConfigStatus::default(),
    };
    let or_null = |v: Option<String>| v.map_or(Value::Null, Value::String);
    let list_or_null = |v: Value| match &v {
        Value::Array(items) if items.is_empty() => Value::Null,
        _ => v,
    };
    fields.insert("configHash".into(), or_null(config.config_hash));
    fields.insert("appliedConfigHash".into(), or_null(config.applied_hash));
    fields.insert("pendingConfigHash".into(), or_null(config.pending_hash));
    fields.insert(
        "reloadNonce".into(),
        if config.nonce == 0 {
            Value::Null
        } else {
            json!(config.nonce)
        },
    );
    fields.insert("rejectedConfigHash".into(), or_null(config.rejected_hash));
    fields.insert("lastRejectionTime".into(), rfc3339(config.rejected_at));
    fields.insert("rejectionMessage".into(), or_null(config.rejection_message));
    fields.insert(
        "unpersistedConfigHash".into(),
        or_null(config.unpersisted_hash),
    );
    fields.insert(
        "restartKeys".into(),
        list_or_null(json!(config.restart_keys)),
    );
    fields.insert(
        "pods".into(),
        list_or_null(serde_json::to_value(&config.pods).expect("pods serialize")),
    );
    fields.insert("lastReloadTime".into(), rfc3339(config.reloaded_at));
    fields
}

/// The status of a registry bound to the instance, read fresh: its
/// conditions are the previous ones. Gone meanwhile: nothing to write.
async fn publish_registry(
    ctx: &Ctx,
    decision: &RegistryDecision,
    instance_ready: &Result<String, Failure>,
    config_hash: Option<&str>,
    held: bool,
    started: Instant,
) -> Result<(), Error> {
    let api: Api<Registry> = Api::namespaced(ctx.client.clone(), &decision.namespace);
    let Some(registry) = api.get_opt(&decision.name).await? else {
        return Ok(());
    };
    let outcome = rendered_outcome(decision, instance_ready, held);
    let mut fields = Map::new();
    fields.insert("registryName".into(), json!(decision.registry_name));
    fields.insert(
        "instanceConfigHash".into(),
        match (&decision.rendered, config_hash) {
            (Ok(true), Some(hash)) => json!(hash),
            _ => Value::Null,
        },
    );
    // Rendered by the instance's pass: its duration is the registry's.
    super::record_reconcile(super::registry::KIND, started, &outcome);
    super::publish(&api, &ctx.recorder, &registry, &outcome, fields).await?;
    Ok(())
}

/// Released once no CR is bound to the instance any more.
async fn cleanup(
    api: &Api<LocalInstance>,
    instance: &LocalInstance,
    ctx: &Ctx,
) -> Result<(), Error> {
    // Bound by default too when it is the only one of its namespace (in
    // the operator's scope).
    let default = api.list(&ctx.scope.list_params()).await?.items.len() == 1;
    let bound = bound(instance);
    let dependents = ctx
        .dependents
        .dependents(&bound, default)
        .await
        .map_err(|e| Error::Cleanup(Failure::new(ReasonCode::KubernetesApiError, e)))?;
    let Err(in_use) = release_instance(&bound.to_string(), &dependents) else {
        return Ok(());
    };
    // `InstanceInUse` replaces whatever `Ready` said while the deletion
    // waits; that publish announces it (`error_policy` doesn't again).
    let outcome = Outcome::failed(in_use.clone());
    super::publish(api, &ctx.recorder, instance, &outcome, Map::new()).await?;
    Err(Error::Waiting(in_use))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_round_trip_as_rfc3339() {
        let text = rfc3339(Some(1_700_000_000));
        assert_eq!(text, json!("2023-11-14T22:13:20Z"));
        assert_eq!(
            unix(&Some(text.as_str().unwrap().to_string())),
            Some(1_700_000_000)
        );
        assert_eq!(rfc3339(None), Value::Null);
        assert_eq!(unix(&Some("garbage".into())), None);
    }
}
