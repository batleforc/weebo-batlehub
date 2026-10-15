//! The HTTPS router the kit's `webhook_server` serves on every replica
//! (`WEBHOOK_PORT`, default 8443): the probes — `/readyz`, `/livez`,
//! `/healthz` —, `/scope`, the kit's `ScopeGuard` (the chart's
//! `scope.<group>` webhook, rendered with a `watch.labelSelector`), and
//! `/validate`, the admission webhook (`BatleHubAdmission`, through the
//! kit's `admission::router`: failing closed, `DELETE` and `UPDATE`s
//! leaving `spec` alone always accepted).

use std::sync::Arc;

use axum::Router;
use domain::error::ReasonCode;
use weebo_kit_runtime::admission::{ScopeGuard, scope_router};
use weebo_kit_runtime::{Health, WatchScope};

use crate::admission::BatleHubAdmission;
use crate::controller::{FIELD_MANAGER, FINALIZER, METRIC_PREFIX};

pub fn router(health: Arc<Health>, scope: WatchScope, admission: Arc<BatleHubAdmission>) -> Router {
    let guard = ScopeGuard {
        scope,
        finalizer: FINALIZER,
        annotations: api::ANNOTATIONS,
        reason: ReasonCode::LeavesWatchScope,
    };
    weebo_kit_runtime::admission::router(admission, health, FIELD_MANAGER, METRIC_PREFIX)
        .merge(scope_router(Arc::new(guard)))
}
