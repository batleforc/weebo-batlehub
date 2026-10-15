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
//! - `BatleHubPackageGrant`: a subject another grant of the namespace
//!   already writes on the same node of the same instance
//!   (`GrantConflict`): the second would only ever be in conflict.
//! - `BatleHubPackagePolicy`: a node another policy of the namespace
//!   already writes (`PolicyConflict`), a gate both set in `policy.rules`
//!   and exempted (`InvalidSpec`).
//! - `BatleHubMaintenance`: a `schedule` or a `params.before` that can't
//!   be read (`InvalidSpec`).

use std::sync::Arc;

use api::{LocalInstance, Maintenance, PackageGrant, PackagePolicy, Registry};
use application::ports::{ConfigParser, ConfigSources, SourceError};
use application::use_cases::render_config::{base_layers, render_config};
use domain::error::ReasonCode;
use kube::api::{Api, ListParams};
use kube::core::DynamicObject;
use weebo_kit_runtime::admission::{Admission, Denial, typed};

pub struct BatleHubAdmission {
    pub sources: Arc<dyn ConfigSources>,
    pub config: Arc<dyn ConfigParser>,
    pub siblings: Arc<dyn Siblings>,
}

/// The other governance objects of a namespace, which a new one may
/// collide with.
#[async_trait::async_trait]
pub trait Siblings: Send + Sync {
    async fn grants(&self, namespace: &str) -> Result<Vec<PackageGrant>, String>;
    async fn policies(&self, namespace: &str) -> Result<Vec<PackagePolicy>, String>;
}

/// [`Siblings`] read from the API server.
pub struct KubeSiblings(pub kube::Client);

#[async_trait::async_trait]
impl Siblings for KubeSiblings {
    async fn grants(&self, namespace: &str) -> Result<Vec<PackageGrant>, String> {
        Api::<PackageGrant>::namespaced(self.0.clone(), namespace)
            .list(&ListParams::default())
            .await
            .map(|l| l.items)
            .map_err(|e| e.to_string())
    }

    async fn policies(&self, namespace: &str) -> Result<Vec<PackagePolicy>, String> {
        Api::<PackagePolicy>::namespaced(self.0.clone(), namespace)
            .list(&ListParams::default())
            .await
            .map(|l| l.items)
            .map_err(|e| e.to_string())
    }
}

/// The instance, by name, a governance object of the namespace targets
/// (`None`: the namespace's only one).
fn target(instance_ref: Option<&application::ports::InstanceRef>) -> Option<&str> {
    instance_ref.map(|r| r.name.as_str())
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
        if !instance.spec.manages_config() {
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

impl BatleHubAdmission {
    async fn grant(&self, namespace: &str, grant: PackageGrant) -> Result<(), Denial<ReasonCode>> {
        // Not listed: nothing certain, the status will say.
        let Ok(siblings) = self.siblings.grants(namespace).await else {
            return Ok(());
        };
        let name = kube::ResourceExt::name_any(&grant);
        let spec = &grant.spec;
        for other in siblings
            .iter()
            .filter(|o| kube::ResourceExt::name_any(*o) != name)
            .filter(|o| {
                o.spec.registry == spec.registry
                    && o.spec.package == spec.package
                    && o.spec.version == spec.version
                    && target(o.spec.instance_ref.as_ref()) == target(spec.instance_ref.as_ref())
            })
        {
            if let Some(subject) = spec
                .grants
                .iter()
                .map(|g| &g.subject)
                .find(|s| other.spec.grants.iter().any(|g| &g.subject == *s))
            {
                return Err(Denial::new(
                    ReasonCode::GrantConflict,
                    format!(
                        "BatleHubPackageGrant {} already grants {subject} on that node",
                        kube::ResourceExt::name_any(other)
                    ),
                ));
            }
        }
        Ok(())
    }
}

impl BatleHubAdmission {
    async fn policy(
        &self,
        namespace: &str,
        policy: PackagePolicy,
    ) -> Result<(), Denial<ReasonCode>> {
        let spec = &policy.spec;
        let rules = spec
            .policy
            .as_ref()
            .and_then(|p| p.get("rules"))
            .and_then(|r| r.as_array());
        if let Some(gate) = spec.exemptions.iter().map(|e| e.gate.as_str()).find(|g| {
            rules.is_some_and(|rules| {
                rules
                    .iter()
                    .any(|r| r.get("gate").and_then(|v| v.as_str()) == Some(g))
            })
        }) {
            return Err(Denial::new(
                ReasonCode::InvalidSpec,
                format!("gate {gate} is both set in policy.rules and exempted"),
            ));
        }
        let Ok(siblings) = self.siblings.policies(namespace).await else {
            return Ok(());
        };
        let name = kube::ResourceExt::name_any(&policy);
        if let Some(other) = siblings.iter().find(|o| {
            kube::ResourceExt::name_any(*o) != name
                && o.spec.registry == spec.registry
                && o.spec.package == spec.package
                && o.spec.version == spec.version
                && target(o.spec.instance_ref.as_ref()) == target(spec.instance_ref.as_ref())
        }) {
            return Err(Denial::new(
                ReasonCode::PolicyConflict,
                format!(
                    "BatleHubPackagePolicy {} already writes the policy of that node",
                    kube::ResourceExt::name_any(other)
                ),
            ));
        }
        Ok(())
    }
}

fn maintenance(maintenance: Maintenance) -> Result<(), Denial<ReasonCode>> {
    let invalid = |why: String| Denial::new(ReasonCode::InvalidSpec, why);
    if let Some(schedule) = &maintenance.spec.schedule {
        application::cron::Schedule::parse(schedule)
            .map_err(|why| invalid(format!("spec.schedule: {why}")))?;
    }
    if let Some(before) = &maintenance.spec.params.before {
        before
            .parse::<k8s_openapi::jiff::Timestamp>()
            .map_err(|e| invalid(format!("spec.params.before: {e}")))?;
    }
    Ok(())
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
            "BatleHubPackageGrant" => self.grant(namespace, typed(object).map_err(invalid)?).await,
            "BatleHubMaintenance" => maintenance(typed(object).map_err(invalid)?),
            "BatleHubPackagePolicy" => {
                self.policy(namespace, typed(object).map_err(invalid)?)
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

    #[derive(Default)]
    struct FakeSiblings {
        grants: std::sync::Mutex<Vec<PackageGrant>>,
        policies: std::sync::Mutex<Vec<PackagePolicy>>,
    }

    #[async_trait::async_trait]
    impl Siblings for FakeSiblings {
        async fn grants(&self, _: &str) -> Result<Vec<PackageGrant>, String> {
            Ok(self.grants.lock().unwrap().clone())
        }

        async fn policies(&self, _: &str) -> Result<Vec<PackagePolicy>, String> {
            Ok(self.policies.lock().unwrap().clone())
        }
    }

    fn policy(name: &str, rules: serde_json::Value, exempt: bool) -> PackagePolicy {
        PackagePolicy::new(
            name,
            api::package_policy::PackagePolicySpec {
                instance_ref: None,
                registry: "npm".into(),
                package: "@acme/billing".into(),
                version: Some("1.0.0".into()),
                policy: Some(json!({ "rules": rules })),
                exemptions: if exempt {
                    vec![api::package_policy::GateExemption {
                        gate: api::package_policy::Gate::CveGate,
                        exempt_until: "2099-01-01T00:00:00Z".into(),
                        reason: "r".into(),
                    }]
                } else {
                    vec![]
                },
                deletion_policy: Default::default(),
            },
        )
    }

    #[tokio::test]
    async fn a_maintenance_is_refused_for_a_schedule_or_date_it_cant_read() {
        let (_, admission) = admission();
        let decide = async |schedule: Option<&str>, before: Option<&str>| {
            let m = Maintenance::new(
                "m",
                api::maintenance::MaintenanceSpec {
                    instance_ref: None,
                    action: api::maintenance::MaintenanceAction::AuditLogPurge,
                    params: api::maintenance::MaintenanceParams {
                        before: before.map(String::from),
                        ..Default::default()
                    },
                    schedule: schedule.map(String::from),
                    suspend: false,
                    ttl_seconds_after_finished: None,
                    timeout_seconds: 600,
                },
            );
            admission
                .admit("BatleHubMaintenance", "team", &object(&m))
                .await
                .map_err(|d| d.reason)
        };
        assert_eq!(
            decide(Some("0 3 * * *"), Some("2026-01-01T00:00:00Z")).await,
            Ok(())
        );
        assert_eq!(
            decide(Some("0 3 * *"), None).await,
            Err(ReasonCode::InvalidSpec)
        );
        assert_eq!(
            decide(None, Some("yesterday")).await,
            Err(ReasonCode::InvalidSpec)
        );
    }

    #[tokio::test]
    async fn a_policy_is_refused_on_a_node_another_writes_or_a_gate_set_and_exempted() {
        let siblings = Arc::new(FakeSiblings::default());
        *siblings.policies.lock().unwrap() = vec![policy("first", json!([]), false)];
        let (_, admission) = admission_with(siblings);
        let decide = async |p: &PackagePolicy| {
            admission
                .admit("BatleHubPackagePolicy", "team", &object(p))
                .await
                .map_err(|d| d.reason)
        };
        assert_eq!(
            decide(&policy("second", json!([]), false)).await,
            Err(ReasonCode::PolicyConflict)
        );
        assert_eq!(decide(&policy("first", json!([]), true)).await, Ok(()));
        assert_eq!(
            decide(&policy(
                "first",
                json!([{"gate": "cve_gate", "settings": {}}]),
                true
            ))
            .await,
            Err(ReasonCode::InvalidSpec)
        );
    }

    fn admission() -> (Arc<FakeSources>, BatleHubAdmission) {
        admission_with(Arc::new(FakeSiblings::default()))
    }

    fn admission_with(siblings: Arc<FakeSiblings>) -> (Arc<FakeSources>, BatleHubAdmission) {
        let sources = Arc::new(FakeSources::default());
        let admission = BatleHubAdmission {
            sources: sources.clone(),
            config: Arc::new(FakeConfigParser),
            siblings,
        };
        (sources, admission)
    }

    fn grant(name: &str, version: Option<&str>, subjects: &[&str]) -> PackageGrant {
        PackageGrant::new(
            name,
            api::package_grant::PackageGrantSpec {
                instance_ref: None,
                registry: "npm".into(),
                package: "@acme/billing".into(),
                version: version.map(String::from),
                grants: subjects
                    .iter()
                    .map(|s| api::package_grant::SubjectGrant {
                        subject: s.to_string(),
                        actions: vec!["releases:read".into()],
                    })
                    .collect(),
                deletion_policy: Default::default(),
            },
        )
    }

    #[tokio::test]
    async fn a_grant_is_refused_on_a_subject_another_writes_on_the_node() {
        let siblings = Arc::new(FakeSiblings::default());
        *siblings.grants.lock().unwrap() = vec![grant("first", None, &["user:alice"])];
        let (_, admission) = admission_with(siblings);
        let decide = async |g: &PackageGrant| {
            admission
                .admit("BatleHubPackageGrant", "team", &object(g))
                .await
                .map_err(|d| d.reason)
        };
        assert_eq!(
            decide(&grant("second", None, &["user:bob", "user:alice"])).await,
            Err(ReasonCode::GrantConflict)
        );
        assert_eq!(decide(&grant("second", None, &["user:bob"])).await, Ok(()));
        assert_eq!(
            decide(&grant("second", Some("1.0.0"), &["user:alice"])).await,
            Ok(())
        );
        // Itself, updated.
        assert_eq!(decide(&grant("first", None, &["user:alice"])).await, Ok(()));
    }

    fn object<K: serde::Serialize>(k: &K) -> DynamicObject {
        serde_json::from_value(serde_json::to_value(k).unwrap()).unwrap()
    }

    fn instance(manage_config: bool, config: serde_json::Value) -> LocalInstance {
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
