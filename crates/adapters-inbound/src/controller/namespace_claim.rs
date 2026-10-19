//! `BatleHubNamespaceClaim`: a team namespace of a registry, claimed on
//! the instance of its namespace through the admin API
//! (`reconcile_namespace_claim`), checked again on every pass (the steady
//! requeue is the drift check), released by the finalizer unless
//! `deletionPolicy: Orphan`.
//!
//! Besides its own changes, a pass is triggered by any change of a
//! `BatleHubLocalInstance` of its namespace (it appears, goes, or its
//! token changes).

use std::sync::Arc;
use std::time::Instant;

use api::NamespaceClaim;
use api::namespace_claim::DeletionPolicy;
use application::ports::{BoundInstance, GatewayFactoryError, InstanceAccess, InstanceError};
use application::use_cases::reconcile_namespace_claim::{
    Claim, marker, reconcile_namespace_claim, release_namespace_claim,
};
use application::use_cases::{Outcome, instance_failure};
use domain::error::ReasonCode;
use k8s_openapi::jiff::Timestamp;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::{Client, Resource, ResourceExt};
use serde_json::{Map, Value, json};
use weebo_kit_runtime::events;

use super::{Ctx, Error, FINALIZER, error_policy};

pub const KIND: &str = "BatleHubNamespaceClaim";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller = ctx
        .watches
        .controller(ctx.scope.api::<NamespaceClaim>(client.clone()), &ctx.scope);
    let results = super::with_instances(controller, &ctx, &client)
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<NamespaceClaim>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    // Created by an importer, its status not seeded yet.
    if api::ANNOTATIONS.import_pending(&obj.metadata) {
        return Ok(Action::await_change());
    }
    let namespace = obj.namespace().unwrap_or_default();
    let api: Api<NamespaceClaim> = Api::namespaced(ctx.client.clone(), &namespace);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(claim) => apply(&api, &claim, &ctx).await,
            FinalizerEvent::Cleanup(claim) => {
                super::finalize(claim.as_ref(), &ctx, cleanup(&claim, &ctx)).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

/// The instance of the claim, and the gateway to it.
async fn access(
    claim: &NamespaceClaim,
    ctx: &Ctx,
) -> Result<(BoundInstance, Result<InstanceAccess, GatewayFactoryError>), InstanceError> {
    let recorded = claim.status.as_ref().and_then(|s| s.instance.as_ref());
    super::local_access(
        ctx,
        &claim.namespace().unwrap_or_default(),
        claim.spec.instance_ref.as_ref(),
        recorded,
    )
    .await
}

async fn apply(
    api: &Api<NamespaceClaim>,
    claim: &NamespaceClaim,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let started = Instant::now();
    let mut fields = Map::new();
    let outcome = match access(claim, ctx).await {
        Err(err) => Outcome::failed(instance_failure(err)),
        Ok((bound, Err(err))) => Outcome::failed(err).on(bound),
        Ok((bound, Ok(access))) => {
            let marker = marker(&claim.namespace().unwrap_or_default(), &claim.name_any());
            let report = reconcile_namespace_claim(
                &Claim {
                    registry: &claim.spec.registry,
                    prefix: &claim.spec.prefix,
                    group: &claim.spec.group,
                    marker: &marker,
                },
                access.gateway.as_ref(),
            )
            .await;
            if let Some(state) = report.state {
                fields.insert("claimedGroup".into(), json!(state.group));
                fields.insert("packageCount".into(), json!(state.package_count));
            }
            if report.changed {
                fields.insert(
                    "lastSyncTime".into(),
                    Value::String(Timestamp::now().to_string()),
                );
            }
            report.outcome.on(bound)
        }
    };
    super::record_reconcile(KIND, started, &outcome);
    super::publish(api, &ctx.recorder, claim, &outcome, fields).await?;
    Ok(super::requeue_after(&outcome))
}

/// Releases the prefix when the claim in place is this CR's. An instance
/// already gone (deleted with `force-orphan`) has nothing left to release
/// on.
async fn cleanup(claim: &NamespaceClaim, ctx: &Ctx) -> Result<(), Error> {
    if claim.spec.deletion_policy == DeletionPolicy::Orphan {
        return Ok(());
    }
    let Some(access) = super::cleanup_access(
        ctx,
        &claim.namespace().unwrap_or_default(),
        claim.spec.instance_ref.as_ref(),
        claim.status.as_ref().and_then(|s| s.instance.as_ref()),
        &format!("BatleHubNamespaceClaim {}", claim.name_any()),
    )
    .await?
    else {
        return Ok(());
    };
    let marker = marker(&claim.namespace().unwrap_or_default(), &claim.name_any());
    let released = release_namespace_claim(
        &Claim {
            registry: &claim.spec.registry,
            prefix: &claim.spec.prefix,
            group: &claim.spec.group,
            marker: &marker,
        },
        access.gateway.as_ref(),
    )
    .await
    .map_err(Error::Cleanup)?;
    if released {
        events::announce_change(
            &ctx.recorder,
            &claim.object_ref(&()),
            ReasonCode::Revoked,
            events::CLEANUP,
            &format!(
                "released {:?} on registry {:?}",
                claim.spec.prefix, claim.spec.registry
            ),
        )
        .await;
    }
    Ok(())
}
