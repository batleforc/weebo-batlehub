//! A `BatleHubRegistry`: rendered by the instance it attaches to (the
//! instance's reconcile writes its status, [`rendered_outcome`]); its own
//! controller only reports what no instance ever renders
//! ([`unrendered_outcome`]) — no instance to attach to, or one that
//! renders no configuration.

use api::LocalInstance;
use domain::error::ReasonCode;

use crate::ports::{BoundInstance, InstanceError};
use crate::use_cases::render_config::RegistryDecision;
use crate::use_cases::{Outcome, instance_failure};

/// The status of a registry no instance renders, `None` when its instance
/// does (its reconcile publishes it).
pub fn unrendered_outcome(
    resolved: Result<BoundInstance, InstanceError>,
    instance: Option<&LocalInstance>,
) -> Option<Outcome> {
    let bound = match resolved {
        Ok(bound) => bound,
        Err(err) => return Some(Outcome::failed(instance_failure(err))),
    };
    let Some(instance) = instance else {
        return Some(
            Outcome::failed(domain::Failure::new(
                ReasonCode::InstanceNotFound,
                format!("{bound} not found"),
            ))
            .on(bound),
        );
    };
    if !instance.spec.manages_config() {
        return Some(
            Outcome::failed(domain::Failure::new(
                ReasonCode::InstanceConfigUnmanaged,
                format!(
                    "{bound} doesn't manage its configuration (external.manageConfig is false): \
                     the operator renders no registry there"
                ),
            ))
            .on(bound),
        );
    }
    None
}

/// The status of a registry the instance rendered (or left out), given
/// how the instance's own reconcile ended. `held`: the configuration
/// containing it waits for approval (`reload.strategy: Manual`).
pub fn rendered_outcome(
    decision: &RegistryDecision,
    instance_ready: &Result<String, domain::Failure>,
    held: bool,
) -> Outcome {
    let bound = decision.bound.clone();
    match &decision.rendered {
        Err(failure) => Outcome::failed(failure.clone()).on(bound),
        Ok(false) => Outcome::synced(format!("suspended: not rendered into {bound}"))
            .advise(
                ReasonCode::RegistrySuspended,
                "spec.suspend is true: the registry is left out of the configuration",
            )
            .on(bound),
        Ok(true) => match instance_ready {
            Ok(_) if held => Outcome::synced(format!(
                "rendered into {bound}'s configuration, which is held"
            ))
            .advise(
                ReasonCode::ConfigHeld,
                format!(
                    "{bound} holds the configuration containing this registry \
                     (reload.strategy: Manual): BatleHub doesn't serve it until it is approved"
                ),
            )
            .on(bound),
            Ok(_) => Outcome::synced(format!("{bound} serves it as {:?}", decision.registry_name))
                .on(bound),
            Err(failure) => {
                let reason = match failure.reason {
                    ReasonCode::ConfigRejected => ReasonCode::InstanceRejected,
                    ReasonCode::ConfigInvalid => ReasonCode::ConfigInvalid,
                    _ => ReasonCode::InstanceNotReady,
                };
                Outcome::failed(domain::Failure::new(
                    reason,
                    format!("{bound}: {}: {}", failure.reason, failure.message),
                ))
                .on(bound)
            }
        },
    }
}

#[cfg(test)]
mod tests {
    use api::local_instance::{ExternalInstance, LocalInstanceSpec, LocalSecretKeyRef};
    use domain::Failure;

    use super::*;
    use crate::ports::ResolveError;

    fn instance(manage_config: bool) -> LocalInstance {
        LocalInstance::new(
            "hub",
            LocalInstanceSpec {
                external: Some(ExternalInstance {
                    url: "http://hub".into(),
                    admin_token_secret_ref: LocalSecretKeyRef {
                        name: "t".into(),
                        key: "token".into(),
                    },
                    tls: Default::default(),
                    manage_config,
                    pod_selector: None,
                }),
                managed: None,
                config: Default::default(),
                config_layers: vec![],
                reload: Default::default(),
                registry_selector: Default::default(),
            },
        )
    }

    fn bound() -> BoundInstance {
        BoundInstance::local("ns", "hub")
    }

    #[test]
    fn only_a_managed_instance_renders_registries() {
        let unresolved =
            unrendered_outcome(Err(InstanceError::Resolve(ResolveError::NoInstance)), None)
                .unwrap();
        assert_eq!(unresolved.reason(), ReasonCode::InstanceNotFound);
        let gone = unrendered_outcome(Ok(bound()), None).unwrap();
        assert_eq!(gone.reason(), ReasonCode::InstanceNotFound);
        assert_eq!(gone.instance, Some(bound()));
        let unmanaged = unrendered_outcome(Ok(bound()), Some(&instance(false))).unwrap();
        assert_eq!(unmanaged.reason(), ReasonCode::InstanceConfigUnmanaged);
        assert!(unmanaged.steady());
        assert_eq!(unrendered_outcome(Ok(bound()), Some(&instance(true))), None);
    }

    #[test]
    fn a_rendered_registry_follows_its_instance() {
        let decision = |rendered| RegistryDecision {
            namespace: "ns".into(),
            name: "npm".into(),
            registry_name: "npm".into(),
            bound: bound(),
            rendered,
        };
        let ready = Ok("applied".to_string());
        let rendered = decision(Ok(true));
        assert_eq!(
            rendered_outcome(&rendered, &ready, false).reason(),
            ReasonCode::Reconciled
        );
        let refused = Err(Failure::new(ReasonCode::ConfigRejected, "no"));
        assert_eq!(
            rendered_outcome(&rendered, &refused, false).reason(),
            ReasonCode::InstanceRejected
        );
        let invalid = Err(Failure::new(ReasonCode::ConfigInvalid, "no"));
        assert_eq!(
            rendered_outcome(&rendered, &invalid, false).reason(),
            ReasonCode::ConfigInvalid
        );
        let down = Err(Failure::new(ReasonCode::InstanceUnreachable, "dns"));
        let outcome = rendered_outcome(&rendered, &down, false);
        assert_eq!(outcome.reason(), ReasonCode::InstanceNotReady);
        let Err(failure) = &outcome.ready else {
            unreachable!()
        };
        assert!(failure.message.contains("InstanceUnreachable: dns"));

        let held = rendered_outcome(&rendered, &ready, true);
        assert_eq!(held.reason(), ReasonCode::Reconciled);
        assert_eq!(held.advisories[0].reason, ReasonCode::ConfigHeld);
        let suspended = rendered_outcome(&decision(Ok(false)), &down, false);
        assert_eq!(suspended.reason(), ReasonCode::Reconciled);
        assert_eq!(
            suspended.advisories[0].reason,
            ReasonCode::RegistrySuspended
        );
        let duplicate = Failure::new(ReasonCode::DuplicateRegistryName, "x");
        assert_eq!(
            rendered_outcome(&decision(Err(duplicate)), &ready, false).reason(),
            ReasonCode::DuplicateRegistryName
        );
    }
}
