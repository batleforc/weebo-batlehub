//! What the operator costs a cluster (weebo-kit-perf): the release binary
//! against envtest and a fake BatleHub (wiremock, grants in memory). A
//! warm-up cycle, an idle baseline, then a measured cycle — a burst of
//! `BatleHubPackageGrant`s on an external instance, an idle window with
//! all of them in place, a spec churn on all of them, their deletion
//! (revocation) — and a final idle window, checked against the kit's
//! small-cluster budget.
//!
//! `task perf` runs it. Tunable: `PERF_OBJECTS` (default 200),
//! `PERF_IDLE_SECS` (default 30); `WEEBO_PERF_REPORT_ONLY=1` reports
//! without failing; `WEEBO_PERF_BASELINE=<previous json>` adds the change
//! from a previous run. The report lands in `target/perf/`.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use api::{LocalInstance, PackageGrant};
use kube::api::{Api, PostParams};
use serde_json::{Value, json};
use testkit::envtest::EnvTestCluster;
use weebo_kit_perf::{BASELINE, Budget, FINAL, OperatorMetrics, PerfRun, Workload, names};
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, Request, Respond, ResponseTemplate};

const TOKEN: &str = "perf-admin-token";

/// The grants of the fake BatleHub: `(package, subject) → actions`.
#[derive(Default)]
struct Grants(Mutex<BTreeMap<(String, String), Vec<String>>>);

struct Grant(Arc<Grants>);

impl Respond for Grant {
    fn respond(&self, request: &Request) -> ResponseTemplate {
        let mut grants = self.0.0.lock().unwrap();
        match request.method.as_str() {
            "GET" => {
                let package = request
                    .url
                    .query_pairs()
                    .find(|(k, _)| k == "package")
                    .map(|(_, v)| v.to_string())
                    .unwrap_or_default();
                let rows: Vec<Value> = grants
                    .iter()
                    .filter(|((p, _), _)| *p == package)
                    .map(|((p, s), a)| {
                        json!({"node_kind": "package", "node_key": p, "subject": s,
                               "actions": a, "from_ownership": false})
                    })
                    .collect();
                ResponseTemplate::new(200).set_body_json(json!({ "grants": rows }))
            }
            "PUT" => {
                let body: Value = serde_json::from_slice(&request.body).unwrap_or_default();
                let key = (
                    body["package"].as_str().unwrap_or_default().to_string(),
                    body["subject"].as_str().unwrap_or_default().to_string(),
                );
                let actions: Vec<String> =
                    serde_json::from_value(body["actions"].clone()).unwrap_or_default();
                grants.insert(key, actions.clone());
                ResponseTemplate::new(200)
                    .set_body_json(json!({"actions": actions, "warnings": []}))
            }
            "DELETE" => {
                let body: Value = serde_json::from_slice(&request.body).unwrap_or_default();
                let key = (
                    body["package"].as_str().unwrap_or_default().to_string(),
                    body["subject"].as_str().unwrap_or_default().to_string(),
                );
                let removed = grants.remove(&key).is_some();
                ResponseTemplate::new(200).set_body_json(json!({ "removed": removed }))
            }
            _ => ResponseTemplate::new(405),
        }
    }
}

async fn fake_batlehub() -> MockServer {
    let server = MockServer::start().await;
    let ok = |body: Value| ResponseTemplate::new(200).set_body_json(body);
    for (p, body) in [
        ("/livez", json!({"ok": true, "version": "1.6.0"})),
        (
            "/api/v1/me",
            json!({"role": "admin", "groups": [], "has_registry_access": true,
                   "user_id": "weebo-batlehub-operator"}),
        ),
        ("/api/v1/admin/config/warnings", json!({"warnings": []})),
    ] {
        Mock::given(method("GET"))
            .and(path(p))
            .respond_with(ok(body))
            .mount(&server)
            .await;
    }
    Mock::given(path("/api/v1/admin/registries/npm/grants"))
        .respond_with(Grant(Arc::new(Grants::default())))
        .mount(&server)
        .await;
    server
}

fn env_or(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn grant(name: &str, actions: &[&str]) -> PackageGrant {
    serde_json::from_value(json!({
        "apiVersion": "batlehub.weebo.io/v1alpha1", "kind": "BatleHubPackageGrant",
        "metadata": {"name": name},
        "spec": {"registry": "npm", "package": format!("@perf/{name}"),
                 "grants": [{"subject": "group:oidc:perf", "actions": actions}]},
    }))
    .unwrap()
}

/// `Ready: True` for the current generation.
fn converged(g: &PackageGrant) -> bool {
    let Some(status) = &g.status else {
        return false;
    };
    status.observed_generation == g.metadata.generation
        && status
            .conditions
            .iter()
            .any(|c| c.type_ == "Ready" && c.status == "True")
}

async fn burst(grants: &Workload<PackageGrant>, names: &[String], timeout: Duration) -> Duration {
    let objects: Vec<_> = names.iter().map(|n| grant(n, &["releases:read"])).collect();
    let started = Instant::now();
    grants.create(&objects).await;
    grants.wait_all(names, timeout, converged).await;
    started.elapsed()
}

async fn churn(grants: &Workload<PackageGrant>, names: &[String], timeout: Duration) -> Duration {
    let started = Instant::now();
    grants
        .patch_all(names, |_| {
            json!({"spec": {"grants": [
                {"subject": "group:oidc:perf", "actions": ["releases:read", "releases:list"]},
            ]}})
        })
        .await;
    grants.wait_all(names, timeout, converged).await;
    started.elapsed()
}

async fn delete(grants: &Workload<PackageGrant>, names: &[String], timeout: Duration) -> Duration {
    let started = Instant::now();
    grants.delete_all(names).await;
    grants.wait_gone(names, timeout).await;
    started.elapsed()
}

/// Creates every grant, idles with them in place (`loaded`, when `idle` is
/// set), changes every spec, deletes them all.
async fn cycle(
    run: &mut PerfRun,
    grants: &Workload<PackageGrant>,
    all: &[String],
    label: &str,
    idle: Option<Duration>,
    timeout: Duration,
) {
    let n = all.len();
    run.load(&format!("{label} burst"), n, burst(grants, all, timeout))
        .await;
    if let Some(idle) = idle {
        run.idle(&format!("{label} loaded"), idle).await;
    }
    run.load(&format!("{label} churn"), n, churn(grants, all, timeout))
        .await;
    run.load(&format!("{label} delete"), n, delete(grants, all, timeout))
        .await;
}

#[tokio::test]
#[ignore = "a perf run (minutes, release build): `task perf`"]
async fn the_operator_fits_a_small_cluster() {
    let objects = env_or("PERF_OBJECTS", 200) as usize;
    let idle = Duration::from_secs(env_or("PERF_IDLE_SECS", 30));
    let timeout = Duration::from_secs(300);

    let cluster: EnvTestCluster = testkit::envtest::start().await;
    let batlehub = fake_batlehub().await;
    let client = cluster.client();

    Api::<k8s_openapi::api::core::v1::Secret>::namespaced(client.clone(), "default")
        .create(
            &PostParams::default(),
            &serde_json::from_value(json!({
                "metadata": {"name": "batlehub-admin",
                             "labels": {"batlehub.weebo.io/instance-token": "true"}},
                "stringData": {"token": TOKEN},
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    Api::<LocalInstance>::namespaced(client.clone(), "default")
        .create(
            &PostParams::default(),
            &serde_json::from_value(json!({
                "apiVersion": "batlehub.weebo.io/v1alpha1", "kind": "BatleHubLocalInstance",
                "metadata": {"name": "hub"},
                "spec": {"external": {
                    "url": batlehub.uri(),
                    "adminTokenSecretRef": {"name": "batlehub-admin", "key": "token"},
                }},
            }))
            .unwrap(),
        )
        .await
        .unwrap();

    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_weebo-batlehub-operator"));
    command.env("RUST_LOG", "warn");
    let mut run = PerfRun::start(
        "weebo-batlehub",
        &cluster,
        command,
        OperatorMetrics::new("weebo_batlehub"),
    )
    .await;
    let grants = run.workload(Api::<PackageGrant>::namespaced(client.clone(), "default"));

    run.idle("startup", idle).await;
    // The warm-up is a whole cycle at full size: the baseline must follow a
    // process that already filled its caches, pools and allocator arenas to
    // what this load needs, or the next cycle's fill reads as a leak.
    let all = names("grant", objects);
    cycle(&mut run, &grants, &all, "warm-up", None, timeout).await;
    run.idle(BASELINE, idle).await;
    cycle(&mut run, &grants, &all, "cycle", Some(idle), timeout).await;
    run.idle(FINAL, idle).await;

    run.finish().await.assert_within(&Budget::small_cluster());
}
