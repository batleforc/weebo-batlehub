//! What a managed instance's pods may be: the spec's §2.11 opt-in holds
//! for what reaches a pod too. Creating a `BatleHubLocalInstance` must not
//! give more than BatleHub itself:
//!
//! - images from an allow-list of repositories only (the operator's
//!   `WEEBO_BATLEHUB_ALLOWED_IMAGES`, BatleHub's own by default);
//! - no `hostPath` volume, no privileged container, no privilege
//!   escalation, no added capability, no host namespace;
//! - every `Secret` the pods read (`env[].valueFrom.secretKeyRef`,
//!   `envFrom[].secretRef`, a `secret` or projected volume) labelled
//!   `batlehub.weebo.io/credential: "true"` — the operator writes the
//!   pods, so it would otherwise hand any `Secret` of the namespace to a
//!   pod the CR's author configures.
//!
//! Pure: checked on the pod templates the operator is about to apply (the
//! webhook builds them from the spec, the apply checks them again).

use std::collections::BTreeSet;

use api::managed::{DEFAULT_IMAGE_REPOSITORY, DEFAULT_WORKER_REPOSITORY, ManagedInstance};
use domain::Failure;
use domain::error::ReasonCode;
use k8s_openapi::api::core::v1::{PodSpec, SecurityContext};

use crate::ports::OwnedObject;
use crate::workload::{DocumentFacts, WorkloadInput, objects};

/// How many problems a message names.
const SHOWN: usize = 5;

/// The repositories a managed instance may run without the operator's
/// setting: BatleHub's proxy and worker images.
pub fn default_allowed_images() -> Vec<String> {
    vec![
        DEFAULT_IMAGE_REPOSITORY.to_string(),
        DEFAULT_WORKER_REPOSITORY.to_string(),
    ]
}

/// The allow-list as the operator's setting writes it: comma- or
/// space-separated repositories; empty or unset, the default.
pub fn parse_allowed_images(setting: Option<&str>) -> Vec<String> {
    let list: Vec<String> = setting
        .unwrap_or_default()
        .split([',', ' ', '\n'])
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect();
    if list.is_empty() {
        default_allowed_images()
    } else {
        list
    }
}

/// The repository of an image reference: without its digest and tag.
pub fn repository(image: &str) -> &str {
    let image = image.split_once('@').map_or(image, |(name, _)| name);
    match image.rfind(':') {
        // A colon after the last slash is the tag's, before it a port's.
        Some(at) if !image[at..].contains('/') => &image[..at],
        _ => image,
    }
}

fn container_violations(
    out: &mut Vec<String>,
    container: &str,
    image: Option<&str>,
    security: Option<&SecurityContext>,
    allowed: &[String],
) {
    match image {
        Some(image) if allowed.iter().any(|a| a == repository(image)) => {}
        Some(image) => out.push(format!(
            "container {container}: image {image} is not from an allowed repository ({})",
            allowed.join(", ")
        )),
        None => out.push(format!("container {container}: no image")),
    }
    let Some(sc) = security else {
        return;
    };
    if sc.privileged == Some(true) {
        out.push(format!("container {container}: privileged"));
    }
    if sc.allow_privilege_escalation == Some(true) {
        out.push(format!("container {container}: allowPrivilegeEscalation"));
    }
    if sc
        .capabilities
        .as_ref()
        .and_then(|c| c.add.as_ref())
        .is_some_and(|add| !add.is_empty())
    {
        out.push(format!("container {container}: capabilities.add"));
    }
    if sc
        .windows_options
        .as_ref()
        .and_then(|w| w.host_process)
        .unwrap_or(false)
    {
        out.push(format!("container {container}: windowsOptions.hostProcess"));
    }
    if sc.proc_mount.as_deref().is_some_and(|m| m != "Default") {
        out.push(format!("container {container}: procMount"));
    }
}

/// What `pod` may not do, in words (empty: nothing).
pub fn violations(pod: &PodSpec, allowed: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for c in pod
        .containers
        .iter()
        .chain(pod.init_containers.iter().flatten())
    {
        container_violations(
            &mut out,
            &c.name,
            c.image.as_deref(),
            c.security_context.as_ref(),
            allowed,
        );
    }
    for c in pod.ephemeral_containers.iter().flatten() {
        container_violations(
            &mut out,
            &c.name,
            c.image.as_deref(),
            c.security_context.as_ref(),
            allowed,
        );
    }
    for v in pod.volumes.iter().flatten() {
        if v.host_path.is_some() {
            out.push(format!("volume {}: hostPath", v.name));
        }
    }
    for (set, what) in [
        (pod.host_network, "hostNetwork"),
        (pod.host_pid, "hostPID"),
        (pod.host_ipc, "hostIPC"),
    ] {
        if set == Some(true) {
            out.push(what.to_string());
        }
    }
    if pod
        .security_context
        .as_ref()
        .and_then(|s| s.windows_options.as_ref())
        .and_then(|w| w.host_process)
        .unwrap_or(false)
    {
        out.push("podSecurityContext.windowsOptions.hostProcess".into());
    }
    out
}

/// The `Secret`s `pod` reads (`imagePullSecrets` aside: the kubelet only
/// presents them to the image's registry, an allowed one).
pub fn secret_names(pod: &PodSpec) -> BTreeSet<String> {
    let mut names = BTreeSet::new();
    for c in pod
        .containers
        .iter()
        .chain(pod.init_containers.iter().flatten())
    {
        for env in c.env.iter().flatten() {
            if let Some(r) = env
                .value_from
                .as_ref()
                .and_then(|v| v.secret_key_ref.as_ref())
            {
                names.insert(r.name.clone());
            }
        }
        for from in c.env_from.iter().flatten() {
            if let Some(r) = &from.secret_ref {
                names.insert(r.name.clone());
            }
        }
    }
    for v in pod.volumes.iter().flatten() {
        if let Some(name) = v.secret.as_ref().and_then(|s| s.secret_name.as_ref()) {
            names.insert(name.clone());
        }
        for source in v
            .projected
            .as_ref()
            .and_then(|p| p.sources.as_ref())
            .into_iter()
            .flatten()
        {
            if let Some(s) = &source.secret {
                names.insert(s.name.clone());
            }
        }
    }
    names
}

/// The pod templates among `objects`: `(Deployment name, pod spec)`.
pub fn pod_templates(objects: &[OwnedObject]) -> Vec<(String, PodSpec)> {
    objects
        .iter()
        .filter(|o| o.kind == "Deployment")
        .filter_map(|o| {
            let spec = o.manifest.pointer("/spec/template/spec")?.clone();
            Some((o.name.clone(), serde_json::from_value(spec).ok()?))
        })
        .collect()
}

/// `Err(InvalidSpec)` naming what the pods of `objects` may not do.
pub fn check(objects: &[OwnedObject], allowed: &[String]) -> Result<(), Failure> {
    let problems: Vec<String> = pod_templates(objects)
        .iter()
        .flat_map(|(deployment, pod)| {
            violations(pod, allowed)
                .into_iter()
                .map(move |v| format!("{deployment}: {v}"))
        })
        .collect();
    if problems.is_empty() {
        return Ok(());
    }
    let more = match problems.len().saturating_sub(SHOWN) {
        0 => String::new(),
        n => format!(" and {n} more"),
    };
    Err(Failure::new(
        ReasonCode::InvalidSpec,
        format!(
            "spec.managed asks for pods the operator doesn't run: {}{more}. A managed instance \
             runs BatleHub's images (the operator's allow-list), without hostPath, privilege or \
             added capability",
            problems
                .iter()
                .take(SHOWN)
                .cloned()
                .collect::<Vec<_>>()
                .join("; ")
        ),
    ))
}

/// The `Secret`s the pods of `objects` read that `objects` doesn't write
/// itself (the operator's own configuration `Secret`): each must consent.
pub fn secrets_to_check(objects: &[OwnedObject]) -> BTreeSet<String> {
    let written: BTreeSet<&str> = objects
        .iter()
        .filter(|o| o.kind == "Secret")
        .map(|o| o.name.as_str())
        .collect();
    pod_templates(objects)
        .iter()
        .flat_map(|(_, pod)| secret_names(pod))
        .filter(|name| !written.contains(name.as_str()))
        .collect()
}

/// The refusal of a `Secret` a pod would read without its consent.
pub fn secret_not_allowed(namespace: &str, name: &str) -> Failure {
    Failure::new(
        ReasonCode::SecretNotAllowed,
        format!(
            "spec.managed mounts or reads secret {namespace}/{name}, which lacks the label {}=\"true\": \
             the operator writes the pods, so every Secret they read must opt in (kubectl label \
             secret -n {namespace} {name} {}=true)",
            api::CREDENTIAL_LABEL,
            api::CREDENTIAL_LABEL
        ),
    )
}

/// The objects of a managed instance `name` as the webhook sees them: its
/// spec alone, the configuration not rendered yet (what the pods are
/// checked on doesn't depend on it).
pub fn sketch(name: &str, namespace: &str, spec: &ManagedInstance) -> Vec<OwnedObject> {
    let facts = DocumentFacts {
        port: 8080,
        cache_path: None,
        kubernetes_auth: false,
    };
    objects(&WorkloadInput {
        name,
        namespace,
        spec,
        file: "",
        facts: &facts,
        restart_hash: "",
        config_hash: "",
        operator_namespace: None,
    })
}

#[cfg(test)]
mod tests {
    use k8s_openapi::api::core::v1::{
        Capabilities, EnvFromSource, EnvVar, EnvVarSource, HostPathVolumeSource,
        ProjectedVolumeSource, SecretEnvSource, SecretKeySelector, SecretProjection,
        SecretVolumeSource, Volume, VolumeProjection,
    };
    use serde_json::json;

    use super::*;

    fn spec(value: serde_json::Value) -> ManagedInstance {
        serde_json::from_value(value).unwrap()
    }

    fn reasons(spec: &ManagedInstance) -> Result<(), ReasonCode> {
        check(&sketch("hub", "team", spec), &default_allowed_images()).map_err(|f| f.reason)
    }

    #[test]
    fn repositories_are_read_without_tag_or_digest() {
        assert_eq!(
            repository("ghcr.io/batlehub/batlehub:1.6.0"),
            "ghcr.io/batlehub/batlehub"
        );
        assert_eq!(
            repository("ghcr.io/batlehub/batlehub@sha256:ab"),
            "ghcr.io/batlehub/batlehub"
        );
        assert_eq!(
            repository("registry:5000/batlehub:1.6.0@sha256:ab"),
            "registry:5000/batlehub"
        );
        assert_eq!(
            repository("registry:5000/batlehub"),
            "registry:5000/batlehub"
        );
        assert_eq!(parse_allowed_images(None), default_allowed_images());
        assert_eq!(parse_allowed_images(Some(" ")), default_allowed_images());
        assert_eq!(
            parse_allowed_images(Some("a/b, c/d")),
            vec!["a/b".to_string(), "c/d".to_string()]
        );
    }

    #[test]
    fn the_default_pods_are_allowed() {
        assert_eq!(reasons(&ManagedInstance::default()), Ok(()));
        // The worker's own default image too.
        assert_eq!(reasons(&spec(json!({"worker": {}}))), Ok(()));
        assert_eq!(
            reasons(&spec(
                json!({"image": {"tag": "1.7.0"}, "worker": {"image": {"tag": "x"}}})
            )),
            Ok(())
        );
    }

    #[test]
    fn foreign_images_and_privileges_are_refused() {
        let refused = [
            json!({"image": {"repository": "docker.io/evil/miner"}}),
            json!({"worker": {"image": {"repository": "docker.io/evil/miner"}}}),
            json!({"securityContext": {"privileged": true}}),
            json!({"securityContext": {"allowPrivilegeEscalation": true}}),
            json!({"securityContext": {"capabilities": {"add": ["SYS_ADMIN"]}}}),
            json!({"podSecurityContext": {"windowsOptions": {"hostProcess": true}}}),
            json!({"extraVolumes": [{"name": "root", "hostPath": {"path": "/"}}]}),
        ];
        for value in refused {
            assert_eq!(
                reasons(&spec(value.clone())),
                Err(ReasonCode::InvalidSpec),
                "{value}"
            );
        }
        // Dropping capabilities is fine.
        assert_eq!(
            reasons(&spec(
                json!({"securityContext": {"capabilities": {"drop": ["ALL"]}}})
            )),
            Ok(())
        );
        let failure = check(
            &sketch(
                "hub",
                "team",
                &spec(json!({"image": {"repository": "evil/x"}})),
            ),
            &default_allowed_images(),
        )
        .unwrap_err();
        assert!(
            failure.message.contains("evil/x:1.6.0"),
            "{}",
            failure.message
        );
    }

    #[test]
    fn every_secret_the_pods_read_is_listed_but_the_operator_s_own() {
        let mut managed = spec(json!({
            "credentials": {"name": "creds", "key": "credentials.toml"},
            "env": [{"name": "A", "valueFrom": {"secretKeyRef": {"name": "env-secret", "key": "a"}}}],
            "envFrom": [{"secretRef": {"name": "from-secret"}}],
            "extraVolumes": [
                {"name": "v", "secret": {"secretName": "volume-secret"}},
                {"name": "p", "projected": {"sources": [{"secret": {"name": "projected-secret"}}]}},
            ],
            "worker": {},
        }));
        let names = secrets_to_check(&sketch("hub", "team", &managed));
        assert_eq!(
            names.into_iter().collect::<Vec<_>>(),
            [
                "creds",
                "env-secret",
                "from-secret",
                "projected-secret",
                "volume-secret"
            ]
        );
        managed.extra_volumes.clear();
        managed.env.clear();
        managed.env_from.clear();
        managed.credentials = None;
        assert!(secrets_to_check(&sketch("hub", "team", &managed)).is_empty());
    }

    #[test]
    fn a_pod_spec_is_judged_whole() {
        let pod = PodSpec {
            containers: vec![k8s_openapi::api::core::v1::Container {
                name: "c".into(),
                image: Some("ghcr.io/batlehub/batlehub:1".into()),
                security_context: Some(SecurityContext {
                    capabilities: Some(Capabilities {
                        add: Some(vec![]),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                env: Some(vec![EnvVar {
                    name: "X".into(),
                    value_from: Some(EnvVarSource {
                        secret_key_ref: Some(SecretKeySelector {
                            name: "s1".into(),
                            key: "k".into(),
                            ..Default::default()
                        }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                env_from: Some(vec![EnvFromSource {
                    secret_ref: Some(SecretEnvSource {
                        name: "s2".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                }]),
                ..Default::default()
            }],
            volumes: Some(vec![
                Volume {
                    name: "h".into(),
                    host_path: Some(HostPathVolumeSource {
                        path: "/var/run".into(),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                Volume {
                    name: "s".into(),
                    secret: Some(SecretVolumeSource {
                        secret_name: Some("s3".into()),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
                Volume {
                    name: "p".into(),
                    projected: Some(ProjectedVolumeSource {
                        sources: Some(vec![VolumeProjection {
                            secret: Some(SecretProjection {
                                name: "s4".into(),
                                ..Default::default()
                            }),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            ]),
            host_network: Some(true),
            ..Default::default()
        };
        assert_eq!(
            violations(&pod, &default_allowed_images()),
            ["volume h: hostPath", "hostNetwork"]
        );
        assert_eq!(
            secret_names(&pod).into_iter().collect::<Vec<_>>(),
            ["s1", "s2", "s3", "s4"]
        );
    }
}
