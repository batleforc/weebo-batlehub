//! `BatleHubLocalInstance` in external mode: a connectivity and token
//! check, BatleHub's warnings on its configuration
//! (`reconcile_instance`), with the token of its own namespace. Its
//! finalizer holds the deletion while CRs are still bound to it
//! (`InstanceInUse`).

use std::sync::Arc;
use std::time::Instant;

use api::LocalInstance;
use application::ports::BoundInstance;
use application::use_cases::Outcome;
use application::use_cases::reconcile_instance::{
    InstanceReport, reconcile_instance, release_instance,
};
use domain::Failure;
use domain::error::ReasonCode;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::{Client, ResourceExt};
use serde_json::{Map, Value, json};

use super::{Ctx, Error, FINALIZER, error_policy};

const KIND: &str = "BatleHubLocalInstance";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let results = super::controller(ctx.scope.api::<LocalInstance>(client), &ctx.scope)
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

async fn apply(
    api: &Api<LocalInstance>,
    obj: Arc<LocalInstance>,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let started = Instant::now();
    let report = match ctx.gateways.gateway_for(&bound(&obj)).await {
        Ok(gateway) => reconcile_instance(gateway.as_ref()).await,
        Err(e) => InstanceReport {
            outcome: Outcome::failed(e),
            observed: None,
        },
    };
    super::record_reconcile(KIND, started, &report.outcome);
    super::publish(
        api,
        &ctx.recorder,
        obj.as_ref(),
        &report.outcome,
        fields(&obj, &report),
    )
    .await?;
    Ok(super::requeue_after(&report.outcome))
}

/// `endpoint` always; `version` and `warnings` as last read — kept while
/// the instance doesn't answer.
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
    fields
}

/// Released once no CR is bound to the instance any more.
async fn cleanup(
    api: &Api<LocalInstance>,
    instance: &LocalInstance,
    ctx: &Ctx,
) -> Result<(), Error> {
    // Bound by default too when it is the only one of its namespace.
    let default = api.list(&Default::default()).await?.items.len() == 1;
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
    // waits.
    let outcome = Outcome::failed(in_use.clone());
    super::publish(api, &ctx.recorder, instance, &outcome, Map::new()).await?;
    Err(Error::Cleanup(in_use))
}
