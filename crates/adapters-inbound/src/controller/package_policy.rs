//! `BatleHubPackagePolicy`: the policy of a package or version node and a
//! version's exemptions, written on the instance of its namespace through
//! the admin API (`reconcile_package_policy`), read again on every pass
//! (the steady requeue is the drift check), cleared by the finalizer
//! unless `deletionPolicy: Orphan`.
//!
//! What the operator wrote is in `status` (`appliedPolicyHash`,
//! `observedPolicyHash`, `appliedExemptions`), patched after each write:
//! every pass starts from the object read from the API server, not the
//! cache, so a write recorded by the previous pass is never taken for
//! someone else's.
//!
//! Besides its own changes, a pass is triggered by any change of a
//! `BatleHubLocalInstance` of its namespace.

use std::sync::Arc;
use std::time::Instant;

use api::PackagePolicy;
use api::common::DeletionPolicy;
use api::package_policy::PolicyRecord;
use application::ports::PackageNode;
use application::use_cases::reconcile_package_policy::{
    PolicySpec, clear_package_policy, reconcile_package_policy,
};
use application::use_cases::{Outcome, instance_failure};
use domain::error::ReasonCode;
use k8s_openapi::jiff::Timestamp;
use kube::api::Api;
use kube::runtime::controller::Action;
use kube::runtime::finalizer::{Event as FinalizerEvent, finalizer};
use kube::{Client, Resource, ResourceExt};
use serde_json::{Map, Value};
use weebo_kit_runtime::events;

use super::{Ctx, Error, FINALIZER, StatusLedger, error_policy};

pub const KIND: &str = "BatleHubPackagePolicy";

pub async fn run(client: Client, ctx: Arc<Ctx>) {
    let health = ctx.health.clone();
    let controller = ctx
        .watches
        .controller(ctx.scope.api::<PackagePolicy>(client.clone()), &ctx.scope);
    let results = super::with_instances(controller, &ctx, &client)
        .graceful_shutdown_on(ctx.shutdown.wait())
        .run(reconcile, error_policy, ctx);
    super::drive(KIND, health, results).await;
}

async fn reconcile(obj: Arc<PackagePolicy>, ctx: Arc<Ctx>) -> Result<Action, Error> {
    // Created by the importer, its status not seeded yet.
    if api::ANNOTATIONS.import_pending(&obj.metadata) {
        return Ok(Action::await_change());
    }
    let namespace = obj.namespace().unwrap_or_default();
    let api: Api<PackagePolicy> = Api::namespaced(ctx.client.clone(), &namespace);
    finalizer(&api, FINALIZER, obj, |event| async {
        match event {
            FinalizerEvent::Apply(policy) => apply(&api, &policy, &ctx).await,
            FinalizerEvent::Cleanup(policy) => {
                super::finalize(policy.as_ref(), &ctx, cleanup(&api, &policy, &ctx)).await
            }
        }
    })
    .await
    .map_err(|e| Error::Finalizer(Box::new(e)))
}

fn node(policy: &PackagePolicy) -> PackageNode {
    PackageNode {
        registry: policy.spec.registry.clone(),
        package: policy.spec.package.clone(),
        version: policy.spec.version.clone(),
    }
}

/// The object as the API server has it: its `status.applied` is the
/// last write recorded, whatever the cache holds.
async fn fresh(api: &Api<PackagePolicy>, policy: &PackagePolicy) -> Result<PackagePolicy, Error> {
    Ok(api.get(&policy.name_any()).await?)
}

async fn apply(
    api: &Api<PackagePolicy>,
    policy: &PackagePolicy,
    ctx: &Ctx,
) -> Result<Action, Error> {
    let started = Instant::now();
    let policy = fresh(api, policy).await?;
    let status = policy.status.clone().unwrap_or_default();
    let mut fields = Map::new();
    let outcome = match super::local_access(
        ctx,
        &policy.namespace().unwrap_or_default(),
        policy.spec.instance_ref.as_ref(),
        status.instance.as_ref(),
    )
    .await
    {
        Err(err) => Outcome::failed(instance_failure(err)),
        Ok((bound, Err(err))) => Outcome::failed(err).on(bound),
        Ok((bound, Ok(access))) => {
            let ledger = StatusLedger {
                api: api.clone(),
                name: policy.name_any(),
                field: None,
            };
            let node = node(&policy);
            let report = reconcile_package_policy(
                PolicySpec {
                    node: &node,
                    policy: policy.spec.policy.as_ref(),
                    exemptions: &policy.spec.exemptions,
                },
                PolicyRecord::from(&status),
                Timestamp::now(),
                access.gateway.as_ref(),
                &ledger,
            )
            .await;
            fields.extend(match serde_json::to_value(&report.record) {
                Ok(Value::Object(record)) => record,
                _ => Map::new(),
            });
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
    super::publish(api, &ctx.recorder, &policy, &outcome, fields).await?;
    Ok(super::requeue_after(&outcome))
}

/// Clears what the object wrote (its status, read fresh).
async fn cleanup(api: &Api<PackagePolicy>, policy: &PackagePolicy, ctx: &Ctx) -> Result<(), Error> {
    if policy.spec.deletion_policy == DeletionPolicy::Orphan {
        return Ok(());
    }
    let policy = fresh(api, policy).await?;
    let status = policy.status.clone().unwrap_or_default();
    let record = PolicyRecord::from(&status);
    if record.applied_policy_hash.is_none() && record.applied_exemptions.is_empty() {
        return Ok(());
    }
    let Some(access) = super::cleanup_access(
        ctx,
        &policy.namespace().unwrap_or_default(),
        policy.spec.instance_ref.as_ref(),
        status.instance.as_ref(),
        &format!("{KIND} {}", policy.name_any()),
    )
    .await?
    else {
        return Ok(());
    };
    let node = node(&policy);
    let cleared = clear_package_policy(&node, &record, access.gateway.as_ref())
        .await
        .map_err(Error::Cleanup)?;
    if cleared > 0 {
        events::announce_change(
            &ctx.recorder,
            &policy.object_ref(&()),
            ReasonCode::Revoked,
            events::CLEANUP,
            &format!("cleared the policy and exemptions written on {node}"),
        )
        .await;
    }
    Ok(())
}
