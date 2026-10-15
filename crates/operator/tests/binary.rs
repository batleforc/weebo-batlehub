//! The real operator binary on envtest, against a scripted BatleHub: it
//! serves its HTTPS endpoints on every replica, takes the leader lease,
//! reconciles, and exits as soon as the lease is lost.

use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use api::LocalInstance;
use k8s_openapi::api::coordination::v1::Lease;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::MicroTime;
use k8s_openapi::jiff::Timestamp;
use kube::api::{Api, Patch, PatchParams, PostParams};
use serde_json::json;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const LEASE: &str = "weebo-batlehub-operator-leader";

/// Kills the operator if the test fails before it exits on its own.
struct Operator(Child);

impl Drop for Operator {
    fn drop(&mut self) {
        let _ = self.0.kill();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

async fn eventually<F, Fut>(what: &str, timeout: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let start = Instant::now();
    while !check().await {
        assert!(start.elapsed() < timeout, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

#[tokio::test]
async fn binary_serves_the_webhook_leads_reconciles_and_exits_on_lease_loss() {
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    let dir = std::env::temp_dir().join(format!("operator-bin-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let kubeconfig = dir.join("kubeconfig.yaml");
    cluster.write_kubeconfig(&kubeconfig);

    let cert =
        rcgen::generate_simple_self_signed(vec!["127.0.0.1".into(), "localhost".into()]).unwrap();
    let (cert_file, key_file) = (dir.join("tls.crt"), dir.join("tls.key"));
    std::fs::write(&cert_file, cert.cert.pem()).unwrap();
    std::fs::write(&key_file, cert.signing_key.serialize_pem()).unwrap();

    let batlehub = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/livez"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"ok": true, "version": "1.6.0"})),
        )
        .mount(&batlehub)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/me"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"role": "admin", "groups": [], "has_registry_access": true})),
        )
        .mount(&batlehub)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/config/warnings"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"warnings": []})))
        .mount(&batlehub)
        .await;

    let secrets: Api<k8s_openapi::api::core::v1::Secret> =
        Api::namespaced(client.clone(), "default");
    secrets
        .create(
            &PostParams::default(),
            &serde_json::from_value(json!({
                "metadata": {"name": "batlehub-admin",
                             "labels": {"batlehub.weebo.io/instance-token": "true"}},
                "stringData": {"token": "t0ken"},
            }))
            .unwrap(),
        )
        .await
        .unwrap();
    let instances: Api<LocalInstance> = Api::namespaced(client.clone(), "default");
    instances
        .create(
            &PostParams::default(),
            &serde_json::from_value(json!({
                "apiVersion": "batlehub.weebo.io/v1alpha1", "kind": "BatleHubLocalInstance",
                "metadata": {"name": "main"},
                "spec": {"external": {"url": batlehub.uri(),
                         "adminTokenSecretRef": {"name": "batlehub-admin", "key": "token"}}},
            }))
            .unwrap(),
        )
        .await
        .unwrap();

    let port = free_port();
    let mut op = Operator(
        Command::new(env!("CARGO_BIN_EXE_weebo-batlehub-operator"))
            .env("KUBECONFIG", &kubeconfig)
            .env("POD_NAMESPACE", "default")
            .env("HOSTNAME", "operator-under-test")
            .env("WEBHOOK_TLS_CERT_FILE", &cert_file)
            .env("WEBHOOK_TLS_KEY_FILE", &key_file)
            .env("WEBHOOK_PORT", port.to_string())
            // Exercises the OTLP branch; nothing listens, exports just fail.
            .env("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:9")
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("operator starts"),
    );

    // The webhook answers over TLS with the mounted certificate.
    let https = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let healthz = format!("https://127.0.0.1:{port}/healthz");
    eventually("the webhook /healthz", Duration::from_secs(30), || {
        let req = https.get(&healthz).send();
        async move { req.await.is_ok_and(|r| r.status().is_success()) }
    })
    .await;

    // It leads, and reconciles.
    let leases: Api<Lease> = Api::namespaced(client.clone(), "default");
    eventually("the leader lease", Duration::from_secs(30), || {
        let get = leases.get_opt(LEASE);
        async move {
            get.await
                .ok()
                .flatten()
                .and_then(|l| l.spec?.holder_identity)
                .as_deref()
                == Some("operator-under-test")
        }
    })
    .await;
    eventually(
        "BatleHubLocalInstance Ready",
        Duration::from_secs(30),
        || {
            let get = instances.get("main");
            async move {
                get.await.ok().and_then(|i| i.status).is_some_and(|s| {
                    s.conditions
                        .iter()
                        .any(|c| c.type_ == "Ready" && c.status == "True")
                })
            }
        },
    )
    .await;

    // Losing the lease ends the process (exit 1): a deposed leader must
    // never keep reconciling.
    leases
        .patch(
            LEASE,
            &PatchParams::default(),
            &Patch::Merge(json!({"spec": {
                "holderIdentity": "someone-else",
                "renewTime": MicroTime(Timestamp::now()),
            }})),
        )
        .await
        .unwrap();
    let start = Instant::now();
    let status = loop {
        if let Some(status) = op.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(30),
            "the operator kept running after losing the lease"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    assert_eq!(status.code(), Some(1));
    std::fs::remove_dir_all(&dir).unwrap();
}

/// SIGTERM (what the kubelet sends on a rollout) stops the operator
/// cleanly — it is PID 1 in its container, so an unhandled SIGTERM would be
/// ignored until the SIGKILL — and hands the lease over at once.
#[tokio::test]
async fn binary_stops_on_sigterm_and_releases_the_lease() {
    let metrics_port = free_port();
    let cluster = testkit::envtest::start().await;
    let client = cluster.client();
    let dir = std::env::temp_dir().join(format!("operator-sigterm-{}", std::process::id()));
    std::fs::create_dir_all(&dir).unwrap();
    let kubeconfig = dir.join("kubeconfig.yaml");
    cluster.write_kubeconfig(&kubeconfig);

    let mut op = Operator(
        Command::new(env!("CARGO_BIN_EXE_weebo-batlehub-operator"))
            .env("KUBECONFIG", &kubeconfig)
            .env("POD_NAMESPACE", "default")
            .env("HOSTNAME", "operator-under-test")
            // No certificate: the webhook is skipped.
            .env("WEBHOOK_TLS_CERT_FILE", dir.join("absent.crt"))
            .env("WEEBO_METRICS_ADDR", format!("127.0.0.1:{metrics_port}"))
            .env("RUST_LOG", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("operator starts"),
    );

    let leases: Api<Lease> = Api::namespaced(client.clone(), "default");
    let holder = || {
        let get = leases.get_opt(LEASE);
        async move {
            get.await
                .ok()
                .flatten()
                .and_then(|l| l.spec?.holder_identity)
        }
    };
    eventually("the leader lease", Duration::from_secs(30), || async {
        holder().await.as_deref() == Some("operator-under-test")
    })
    .await;
    // Prometheus metrics, the leader gauge included.
    let metrics = format!("http://127.0.0.1:{metrics_port}/metrics");
    eventually("the leader gauge at 1", Duration::from_secs(15), || {
        let get = reqwest::get(metrics.clone());
        async move {
            match get.await {
                Ok(r) => r.text().await.is_ok_and(|body| {
                    body.lines()
                        .any(|l| l.starts_with("weebo_batlehub_leader") && l.ends_with(" 1"))
                }),
                Err(_) => false,
            }
        }
    })
    .await;

    let killed = Command::new("kill")
        .args(["-TERM", &op.0.id().to_string()])
        .status()
        .unwrap();
    assert!(killed.success());
    let start = Instant::now();
    let status = loop {
        if let Some(status) = op.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            start.elapsed() < Duration::from_secs(20),
            "the operator ignored SIGTERM"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    };
    assert_eq!(status.code(), Some(0));
    assert_eq!(holder().await.as_deref(), Some(""));
    std::fs::remove_dir_all(&dir).unwrap();
}
