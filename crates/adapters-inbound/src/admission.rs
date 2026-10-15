//! The admission webhook's decision (`POST /validate`, the kit's
//! `admission::router`): refusals the reconcilers would make anyway,
//! moved from the status to `kubectl apply`. Only what is certain is
//! refused — a layer not created yet, an instance absent, may appear on
//! their own and are left to the status.
//!
//! - `BatleHubLocalInstance` with `external.manageConfig`: no
//!   configuration at all, or a `spec.config` that isn't one
//!   (`InvalidSpec`, `ConfigInvalid`), and — when it has no
//!   `configLayers` — a `spec.config` BatleHub's parser refuses
//!   (`reload.validation: Strict`). A layer (a ConfigMap may be fixed
//!   without touching the CR) or a registry (another team's) that breaks
//!   the configuration never blocks the instance's own edits: the status
//!   says so.
//! - `BatleHubRegistry`: a `configFrom` fragment that is not TOML, or that
//!   sets `type`/`name` (`ConfigInvalid`); a `${` in a registry naming an
//!   instance of another namespace (`NamespaceNotAllowed`).

use std::sync::Arc;

use api::{LocalInstance, Registry};
use application::ports::{ConfigParser, ConfigSources, SourceError};
use application::use_cases::render_config::{base_layers, render_config};
use domain::error::ReasonCode;
use kube::core::DynamicObject;
use weebo_kit_runtime::admission::{Admission, Denial, typed};

pub struct BatleHubAdmission {
    pub sources: Arc<dyn ConfigSources>,
    pub config: Arc<dyn ConfigParser>,
}

/// The reasons a rendering refusal is certain for.
fn certain(reason: ReasonCode) -> bool {
    matches!(reason, ReasonCode::ConfigInvalid | ReasonCode::InvalidSpec)
}

impl BatleHubAdmission {
    async fn instance(
        &self,
        namespace: &str,
        instance: LocalInstance,
    ) -> Result<(), Denial<ReasonCode>> {
        if !instance.spec.external.manage_config {
            return Ok(());
        }
        let deny = |failure: domain::Failure| Denial::new(failure.reason, failure.message);
        let base = match base_layers(
            &instance,
            namespace,
            self.sources.as_ref(),
            self.config.as_ref(),
        )
        .await
        {
            Ok(base) => base,
            Err(failure) if certain(failure.reason) => return Err(deny(failure)),
            // A layer missing or not labelled yet: the status says so.
            Err(_) => return Ok(()),
        };
        if !instance.spec.config_layers.is_empty() {
            return Ok(());
        }
        match render_config(&instance, &base, Vec::new(), self.config.as_ref()) {
            Err(failure) if certain(failure.reason) => Err(deny(failure)),
            _ => Ok(()),
        }
    }

    async fn registry(
        &self,
        namespace: &str,
        registry: Registry,
    ) -> Result<(), Denial<ReasonCode>> {
        let foreign = registry
            .spec
            .instance_ref
            .as_ref()
            .and_then(|r| r.namespace.as_deref())
            .is_some_and(|ns| ns != namespace);
        if foreign && registry.spec.config.to_string().contains("${") {
            return Err(Denial::new(
                ReasonCode::NamespaceNotAllowed,
                "a registry attaching to an instance of another namespace may not contain `${`: \
                 placeholders resolve from the instance's environment",
            ));
        }
        for (i, source) in registry.spec.config_from.iter().enumerate() {
            let text = match self.sources.read(namespace, source).await {
                Ok(text) => text,
                // Missing or not labelled yet: the status says so.
                Err(SourceError::Missing(_) | SourceError::NotAllowed(_)) => continue,
                Err(SourceError::Kubernetes(_)) => continue,
            };
            let fragment = self.config.fragment(&text).map_err(|e| {
                Denial::new(
                    ReasonCode::ConfigInvalid,
                    format!("spec.configFrom[{i}] is not TOML: {e}"),
                )
            })?;
            if let Some(key) = ["type", "name"]
                .iter()
                .find(|k| fragment.get(**k).is_some())
            {
                return Err(Denial::new(
                    ReasonCode::ConfigInvalid,
                    format!("spec.configFrom[{i}] may not set {key:?}"),
                ));
            }
            if foreign && text.contains("${") {
                return Err(Denial::new(
                    ReasonCode::NamespaceNotAllowed,
                    format!(
                        "spec.configFrom[{i}] contains `${{`, refused in a registry attaching to \
                         an instance of another namespace"
                    ),
                ));
            }
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl Admission for BatleHubAdmission {
    type Reason = ReasonCode;

    async fn admit(
        &self,
        kind: &str,
        namespace: &str,
        object: &DynamicObject,
    ) -> Result<(), Denial<ReasonCode>> {
        let invalid = |e: String| Denial::new(ReasonCode::InvalidSpec, e);
        match kind {
            "BatleHubLocalInstance" => {
                self.instance(namespace, typed(object).map_err(invalid)?)
                    .await
            }
            "BatleHubRegistry" => {
                self.registry(namespace, typed(object).map_err(invalid)?)
                    .await
            }
            other => Err(Denial::new(
                ReasonCode::InvalidSpec,
                format!("{other} is not a kind this webhook decides on"),
            )),
        }
    }

    fn undecidable(&self) -> ReasonCode {
        ReasonCode::InvalidSpec
    }
}

#[cfg(test)]
mod tests {
    use api::config::ConfigSource;
    use api::local_instance::{ExternalInstance, LocalInstanceSpec, LocalSecretKeyRef};
    use api::registry::RegistrySpec;
    use application::test_support::{FakeConfigParser, FakeSources};
    use serde_json::json;
    use weebo_kit_api::InstanceRef;

    use super::*;

    fn admission() -> (Arc<FakeSources>, BatleHubAdmission) {
        let sources = Arc::new(FakeSources::default());
        let admission = BatleHubAdmission {
            sources: sources.clone(),
            config: Arc::new(FakeConfigParser),
        };
        (sources, admission)
    }

    fn object<K: serde::Serialize>(k: &K) -> DynamicObject {
        serde_json::from_value(serde_json::to_value(k).unwrap()).unwrap()
    }

    fn instance(manage_config: bool, config: serde_json::Value) -> LocalInstance {
        LocalInstance::new(
            "hub",
            LocalInstanceSpec {
                external: ExternalInstance {
                    url: "http://hub".into(),
                    admin_token_secret_ref: LocalSecretKeyRef {
                        name: "t".into(),
                        key: "token".into(),
                    },
                    tls: Default::default(),
                    manage_config,
                    pod_selector: None,
                },
                config,
                config_layers: vec![],
                reload: Default::default(),
                registry_selector: Default::default(),
            },
        )
    }

    fn registry(instance_ref: Option<InstanceRef>, config: serde_json::Value) -> Registry {
        Registry::new(
            "npm",
            RegistrySpec {
                instance_ref,
                r#type: "npm".into(),
                name: None,
                config,
                config_from: vec![],
                suspend: false,
            },
        )
    }

    #[tokio::test]
    async fn an_instance_is_refused_only_for_certain() {
        let (sources, admission) = admission();
        let decide = async |i: &LocalInstance| {
            admission
                .admit("BatleHubLocalInstance", "ns", &object(i))
                .await
                .map_err(|d| d.reason)
        };
        assert_eq!(
            decide(&instance(false, json!({"invalid": 1}))).await,
            Ok(())
        );
        assert_eq!(decide(&instance(true, json!({"server": {}}))).await, Ok(()));
        assert_eq!(
            decide(&instance(true, json!({"invalid": 1}))).await,
            Err(ReasonCode::ConfigInvalid)
        );
        assert_eq!(
            decide(&instance(true, serde_json::Value::Null)).await,
            Err(ReasonCode::InvalidSpec)
        );
        // A layer, created or not, valid or not, never blocks the
        // instance's own edits: it may be fixed without touching the CR.
        let mut later = instance(true, json!({"invalid": 1}));
        later.spec.config_layers = vec![ConfigSource::config_map("later", "config.toml")];
        assert_eq!(decide(&later).await, Ok(()));
        sources.put("ns", "later", "not json");
        assert_eq!(decide(&later).await, Ok(()));
        // Nor does another team's registry.
        sources.set_registries(vec![application::ports::RegistryView {
            namespace: "team".into(),
            name: "bad".into(),
            created: "1".into(),
            labels: Default::default(),
            spec: api::registry::RegistrySpec {
                instance_ref: None,
                r#type: "invalid".into(),
                name: None,
                config: json!({}),
                config_from: vec![],
                suspend: false,
            },
            bound: Ok(application::ports::BoundInstance::local("ns", "hub")),
        }]);
        assert_eq!(decide(&instance(true, json!({"server": {}}))).await, Ok(()));
    }

    #[tokio::test]
    async fn a_registry_is_refused_for_bad_fragments_and_foreign_placeholders() {
        let (sources, admission) = admission();
        let decide = async |r: &Registry| {
            admission
                .admit("BatleHubRegistry", "team", &object(r))
                .await
                .map_err(|d| d.reason)
        };
        let foreign = Some(InstanceRef {
            namespace: Some("infra".into()),
            ..InstanceRef::named("hub")
        });
        assert_eq!(decide(&registry(None, json!({"t": "${X}"}))).await, Ok(()));
        assert_eq!(
            decide(&registry(foreign.clone(), json!({"t": "${X}"}))).await,
            Err(ReasonCode::NamespaceNotAllowed)
        );
        sources.put("team", "frag", r#"{"name": "x"}"#);
        let mut renaming = registry(None, json!({}));
        renaming.spec.config_from = vec![ConfigSource::config_map("frag", "config.toml")];
        assert_eq!(decide(&renaming).await, Err(ReasonCode::ConfigInvalid));
        sources.put("team", "frag", "not json");
        assert_eq!(decide(&renaming).await, Err(ReasonCode::ConfigInvalid));
        sources.put("team", "frag", r#"{"token": "${T}"}"#);
        assert_eq!(decide(&renaming).await, Ok(()));
        renaming.spec.instance_ref = foreign;
        assert_eq!(
            decide(&renaming).await,
            Err(ReasonCode::NamespaceNotAllowed)
        );
        let mut absent = registry(None, json!({}));
        absent.spec.config_from = vec![ConfigSource::secret("absent", "config.toml")];
        assert_eq!(decide(&absent).await, Ok(()));
        assert!(
            admission
                .admit("Other", "team", &object(&absent))
                .await
                .is_err()
        );
    }
}
