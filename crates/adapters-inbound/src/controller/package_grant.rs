//! `BatleHubPackageGrant`: the grants of a package or version node,
//! written on the instance of its namespace through the admin API
//! (`reconcile_package_grant`), read again on every pass (the steady
//! requeue is the drift check), revoked by the finalizer unless
//! `deletionPolicy: Orphan`.
//!
//! What the operator wrote is in `status.applied`, patched after each
//! write: every pass starts from the object read from the API server, not
//! the cache, so a write recorded by the previous pass is never taken for
//! someone else's.
//!
//! Besides its own changes, a pass is triggered by any change of a
//! `BatleHubLocalInstance` of its namespace.

use std::sync::Arc;
use std::time::Instant;

use api::PackageGrant;
use api::common::DeletionPolicy;
use application::ports::PackageNode;
use application::use_cases::reconcile_package_grant::{
    reconcile_package_grant, revoke_package_grant,
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

use super::{Ctx, Error, FINALIZER, StatusLedger, error_policy};

pub const KIND: &str = "BatleHubPackageGrant";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller = ctx
        .watches
        .controller(ctx.scope.api::<PackageGrant>(client.clone()), &ctx.scope);
    let results = super::with_instances(controller, &ctx, &client)
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<PackageGrant>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    // Created by the importer, its status not seeded yet.
    if api::ANNOTATIONS.import_pending(&obj.metadata) {
        return Ok(Action::await_change());
    }
    let namespace = obj.namespace().unwrap_or_default();
    let api: Api<PackageGrant> = Api::namespaced(ctx.client.clone(), &namespace);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(grant) => apply(&api, &grant, &ctx).await,
            FinalizerEvent::Cleanup(grant) => {
                super::finalize(grant.as_ref(), &ctx, cleanup(&api, &grant, &ctx)).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

fn node(grant: &PackageGrant) -> PackageNode {
    PackageNode {
        registry: grant.spec.registry.clone(),
        package: grant.spec.package.clone(),
        version: grant.spec.version.clone(),
    }
}

/// The object as the API server has it: its `status.applied` is the
/// last write recorded, whatever the cache holds.
async fn fresh(api: &Api<PackageGrant>, grant: &PackageGrant) -> Result<PackageGrant, Error> {
    Ok(api.get(&grant.name_any()).await?)
}

async fn apply(api: &Api<PackageGrant>, grant: &PackageGrant, ctx: &Ctx) -> Result<Action, Error> {
    let started = Instant::now();
    let grant = fresh(api, grant).await?;
    let status = grant.status.clone().unwrap_or_default();
    let mut fields = Map::new();
    let outcome = match super::local_access(
        ctx,
        &grant.namespace().unwrap_or_default(),
        grant.spec.instance_ref.as_ref(),
        status.instance.as_ref(),
    )
    .await
    {
        Err(err) => Outcome::failed(instance_failure(err)),
        Ok((bound, Err(err))) => Outcome::failed(err).on(bound),
        Ok((bound, Ok(access))) => {
            let ledger = StatusLedger {
                api: api.clone(),
                name: grant.name_any(),
                field: Some("applied"),
            };
            let report = reconcile_package_grant(
                &node(&grant),
                &grant.spec.grants,
                status.applied,
                access.gateway.as_ref(),
                &ledger,
            )
            .await;
            fields.insert("applied".into(), json!(report.applied));
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
    super::publish(api, &ctx.recorder, &grant, &outcome, fields).await?;
    Ok(super::requeue_after(&outcome))
}

/// Revokes what the object wrote (`status.applied`, read fresh).
async fn cleanup(api: &Api<PackageGrant>, grant: &PackageGrant, ctx: &Ctx) -> Result<(), Error> {
    if grant.spec.deletion_policy == DeletionPolicy::Orphan {
        return Ok(());
    }
    let grant = fresh(api, grant).await?;
    let status = grant.status.clone().unwrap_or_default();
    if status.applied.is_empty() {
        return Ok(());
    }
    let Some(access) = super::cleanup_access(
        ctx,
        &grant.namespace().unwrap_or_default(),
        grant.spec.instance_ref.as_ref(),
        status.instance.as_ref(),
        &format!("{KIND} {}", grant.name_any()),
    )
    .await?
    else {
        return Ok(());
    };
    let node = node(&grant);
    let revoked = revoke_package_grant(&node, &status.applied, access.gateway.as_ref())
        .await
        .map_err(Error::Cleanup)?;
    if revoked > 0 {
        events::announce_change(
            &ctx.recorder,
            &grant.object_ref(&()),
            ReasonCode::Revoked,
            events::CLEANUP,
            &format!("revoked {revoked} grant(s) on {node}"),
        )
        .await;
    }
    Ok(())
}
