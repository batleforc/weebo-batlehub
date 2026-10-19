//! `BatleHubRegistry`: the instance it attaches to renders it and writes
//! its status (`local_instance`). This controller only reports what no
//! instance ever renders (`unrendered_outcome`): no instance to attach
//! to, one that doesn't consent, or one that renders no configuration
//! (`InstanceConfigUnmanaged`). No finalizer: the instance renders again
//! without it once it is gone.

use std::sync::Arc;
use std::time::Instant;

use api::{LocalInstance, Registry};
use application::use_cases::reconcile_registry::unrendered_outcome;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::reflector::ObjectRef;
use kube::{Client, ResourceExt};
use serde_json::Map;
use weebo_kit_runtime::shared::WatchesIn;

use super::{Ctx, Error, error_policy};

pub const KIND: &str = "BatleHubRegistry";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller = ctx
        .watches
        .controller(ctx.scope.api::<Registry>(client.clone()), &ctx.scope);
    let store = controller.store();
    let results = controller
        // An instance appearing, going, or switching `manageConfig` changes
        // which registries no instance renders.
        .watches_in(
            &ctx.watches,
            &ctx.scope,
            &client,
            move |_: LocalInstance| {
                store
                    .state()
                    .iter()
                    .map(|r| ObjectRef::from_obj(r.as_ref()))
                    .collect::<Vec<_>>()
            },
        )
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<Registry>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    let namespace = obj.namespace().unwrap_or_default();
    let recorded = obj.status.as_ref().and_then(|s| s.instance.as_ref());
    let resolved = ctx
        .registries
        .resolve_registry(&namespace, obj.spec.instance_ref.as_ref(), recorded)
        .await;
    let instance = match &resolved {
        Ok(bound) => ctx.registries.instance(bound).await.map_err(|e| {
            Error::Failed(domain::Failure::new(
                domain::error::ReasonCode::KubernetesApiError,
                e,
            ))
        })?,
        Err(_) => None,
    };
    let Some(outcome) = unrendered_outcome(resolved, instance.as_ref()) else {
        // Its instance renders it, and publishes its status.
        return Ok(weebo_kit_runtime::controller::requeue_after(true, None));
    };
    let started = Instant::now();
    super::record_reconcile(KIND, started, &outcome);
    let api: Api<Registry> = Api::namespaced(ctx.client.clone(), &namespace);
    let mut fields = Map::new();
    fields.insert(
        "registryName".into(),
        serde_json::json!(obj.spec.registry_name(&obj.name_any())),
    );
    fields.insert("instanceConfigHash".into(), serde_json::Value::Null);
    super::publish(&api, &ctx.recorder, obj.as_ref(), &outcome, fields).await?;
    Ok(super::requeue_after(&outcome))
}
