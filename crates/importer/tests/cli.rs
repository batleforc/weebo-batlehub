//! The real `weebo-batlehub-importer` binary: a release's values on stdin,
//! the instance on stdout; a refusal exits non-zero.

#![expect(
    clippy::unwrap_used,
    reason = "an integration test: a failure panics with its message, fixtures are known"
)]

use std::io::Write;
use std::process::{Command, Stdio};

const VALUES: &str = r#"
replicaCount: 1
service: {type: ClusterIP, port: 8080}
config:
  server: {host: 0.0.0.0, port: 8080}
  storage: {type: filesystem, path: /var/cache/batlehub}
"#;

fn run(args: &[&str]) -> std::process::Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_weebo-batlehub-importer"))
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(VALUES.as_bytes())
        .unwrap();
    child.wait_with_output().unwrap()
}

#[test]
fn a_release_is_printed_as_an_instance() {
    let out = run(&[
        "instance",
        "--values",
        "-",
        "--release",
        "registry",
        "-n",
        "infra",
        "--mode",
        "managed",
    ]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8(out.stdout).unwrap();
    let doc: serde_json::Value = serde_norway::from_str(text.trim_start_matches("---\n")).unwrap();
    assert_eq!(doc["kind"], "BatleHubLocalInstance");
    assert_eq!(doc["metadata"]["name"], "registry");
    assert_eq!(doc["metadata"]["namespace"], "infra");
    assert_eq!(doc["spec"]["managed"]["replicas"], 1);
    assert_eq!(doc["spec"]["config"]["storage"]["type"], "filesystem");
}

#[test]
fn external_without_a_token_secret_is_refused() {
    let out = run(&["instance", "--values", "-", "--release", "registry"]);
    assert!(!out.status.success());
    assert!(String::from_utf8_lossy(&out.stderr).contains("--token-secret"));
}
