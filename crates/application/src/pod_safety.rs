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

use api::managed::{DEFAULT_IMAGE_REPOSITORY, DEFAULT_WORKER_REPOSITORY, ManagedInstance};
use domain::Failure;
use domain::error::ReasonCode;
pub use weebo_kit_application::pod_safety::{
    pod_templates, repository, secret_names, secrets_to_check, violations,
};

use crate::ports::OwnedObject;
use crate::workload::{DocumentFacts, OPERATOR_CHART, OperatorPod, WorkloadInput, objects};

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
    weebo_kit_application::pod_safety::parse_allowed_images(
        setting,
        &[DEFAULT_IMAGE_REPOSITORY, DEFAULT_WORKER_REPOSITORY],
    )
}

/// `Err(InvalidSpec)` naming what the pods of `objects` may not do.
pub fn check(objects: &[OwnedObject], allowed: &[String]) -> Result<(), Failure> {
    let problems = weebo_kit_application::pod_safety::problems(objects, allowed);
    if problems.is_empty() {
        return Ok(());
    }
    Err(Failure::new(
        ReasonCode::InvalidSpec,
        format!(
            "spec.managed asks for pods the operator doesn't run: {}. A managed instance \
             runs BatleHub's images (the operator's allow-list), without hostPath, privilege or \
             added capability",
            weebo_kit_application::pod_safety::summary(&problems)
        ),
    ))
}

/// The refusal of a `Secret` a pod would read without its consent.
pub fn secret_not_allowed(namespace: &str, name: &str) -> Failure {
    Failure::new(
        ReasonCode::SecretNotAllowed,
        format!(
            "spec.managed: {}",
            weebo_kit_application::pod_safety::secret_not_labelled(
                namespace,
                name,
                api::CREDENTIAL_LABEL
            )
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
        operator: &OperatorPod::named(OPERATOR_CHART),
    })
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    fn spec(value: serde_json::Value) -> ManagedInstance {
        serde_json::from_value(value).unwrap()
    }

    fn reasons(spec: &ManagedInstance) -> Result<(), ReasonCode> {
        check(&sketch("hub", "team", spec), &default_allowed_images()).map_err(|f| f.reason)
    }

    #[test]
    fn the_allow_list_defaults_to_batlehub_s_images() {
        assert_eq!(parse_allowed_images(None), default_allowed_images());
        assert_eq!(parse_allowed_images(Some("a/b")), ["a/b"]);
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
}
