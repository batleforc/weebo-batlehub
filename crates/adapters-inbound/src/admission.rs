//! The admission webhook's decision (`POST /validate`, the kit's
//! `admission::router`): refusals the reconcilers would make anyway,
//! moved from the status to `kubectl apply`. Only what is certain is
//! refused — a layer not created yet, an instance absent, may appear on
//! their own and are left to the status.
//!
//! - `BatleHubLocalInstance` whose configuration the operator renders
//!   (`external.manageConfig`, `managed`): no configuration at all, or a
//!   `spec.config` that isn't one (`InvalidSpec`, `ConfigInvalid`), and —
//!   when it has no `configLayers` and names no registry a
//!   `BatleHubRegistry` could provide or complete — a `spec.config`
//!   BatleHub's parser refuses (`reload.validation: Strict`). A layer (a
//!   ConfigMap may be fixed without touching the CR) or a registry
//!   (another team's, or one not created yet) that breaks or completes the
//!   configuration never decides: the status says so. `managed` with a
//!   generated token: a credentials layer whose `[[auth]] type = "token"`
//!   provider lists tokens without the operator's entry
//!   (`OperatorTokenShadowed`).
//! - `BatleHubLocalInstance` with `managed`: pods the operator doesn't run
//!   (`InvalidSpec`: an image off the operator's allow-list, a `hostPath`,
//!   a privileged container, privilege escalation, an added capability),
//!   or reading an existing `Secret` that lacks
//!   `batlehub.weebo.io/credential: "true"` (`SecretNotAllowed`; one not
//!   created yet is left to the status).
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
//!   be read, `restart` on an external instance (`InvalidSpec`).
//!
//! A governance object or maintenance without `instanceRef` targets the
//! namespace's only instance: it collides with one naming it.

use std::sync::Arc;

use api::config::ConfigSource;
use api::{LocalInstance, Maintenance, PackageGrant, PackagePolicy, Registry};
use application::ports::{ConfigParser, ConfigSources, SourceError};
use application::use_cases::render_config::{base_layers, instance_env, render_config};
use domain::error::ReasonCode;
use kube::api::{Api, ListParams};
use kube::core::DynamicObject;
use weebo_kit_runtime::admission::{Admission, Denial, typed};

pub struct BatleHubAdmission {
    pub sources: Arc<dyn ConfigSources>,
    pub config: Arc<dyn ConfigParser>,
    pub siblings: Arc<dyn Siblings>,
    /// The image repositories a managed instance may run
    /// (`WEEBO_BATLEHUB_ALLOWED_IMAGES`).
    pub allowed_images: Vec<String>,
}

/// The other governance objects of a namespace, which a new one may
/// collide with.
#[async_trait::async_trait]
pub trait Siblings: Send + Sync {
    async fn grants(&self, namespace: &str) -> Result<Vec<PackageGrant>, String>;
    async fn policies(&self, namespace: &str) -> Result<Vec<PackagePolicy>, String>;
    async fn instances(&self, namespace: &str) -> Result<Vec<LocalInstance>, String>;
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

    async fn instances(&self, namespace: &str) -> Result<Vec<LocalInstance>, String> {
        Api::<LocalInstance>::namespaced(self.0.clone(), namespace)
            .list(&ListParams::default())
            .await
            .map(|l| l.items)
            .map_err(|e| e.to_string())
    }
}

/// The instance, by name, a governance object of the namespace targets:
/// the one `instanceRef` names, else the namespace's only one (`None`:
/// none or several, unresolved).
fn target(
    instance_ref: Option<&application::ports::InstanceRef>,
    only: Option<&str>,
) -> Option<String> {
    instance_ref
        .map(|r| r.name.clone())
        .or_else(|| only.map(String::from))
}

/// Whether `value` has a key `key` at any depth.
fn mentions(value: &serde_json::Value, key: &str) -> bool {
    match value {
        serde_json::Value::Object(map) => map.iter().any(|(k, v)| k == key || mentions(v, key)),
        serde_json::Value::Array(items) => items.iter().any(|v| mentions(v, key)),
        _ => false,
    }
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
        let deny = |failure: domain::Failure| Denial::new(failure.reason, failure.message);
        if let Some(managed) = &instance.spec.managed {
            self.managed_pods(namespace, &kube::ResourceExt::name_any(&instance), managed)
                .await
                .map_err(deny)?;
        }
        let deny = |failure: domain::Failure| Denial::new(failure.reason, failure.message);
        if let Some(managed) = &instance.spec.managed {
            self.managed_pods(namespace, &kube::ResourceExt::name_any(&instance), managed)
                .await
                .map_err(deny)?;
        }
        if !instance.spec.manages_config() {
            return Ok(());
        }
        self.token_shadowed(namespace, &instance).await?;
        // With layers, only `spec.config` itself is certain: nothing read.
        if !instance.spec.config_layers.is_empty() {
            return match &instance.spec.config {
                serde_json::Value::Null => Ok(()),
                object @ serde_json::Value::Object(_) => match self.config.layer(object) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(Denial::new(
                        ReasonCode::ConfigInvalid,
                        format!("spec.config: {e}"),
                    )),
                },
                _ => Err(Denial::new(
                    ReasonCode::InvalidSpec,
                    "spec.config must be an object",
                )),
            };
        }
        let base = base_layers(
            &instance,
            namespace,
            self.sources.as_ref(),
            self.config.as_ref(),
        )
        .await
        .map_err(deny)?;
        let layers: Vec<&str> = base.iter().map(String::as_str).collect();
        if let Err(e) = self.config.merge(&layers) {
            return Err(Denial::new(
                ReasonCode::ConfigInvalid,
                format!("merging the configuration: {e}"),
            ));
        }
        // A `BatleHubRegistry` may complete a `[[registries]]` entry, or be
        // the registry a key names (`[worker] registries`, imports…) — one
        // not created yet too: the parser's verdict without it is not
        // certain.
        if mentions(&instance.spec.config, "registries") {
            return Ok(());
        }
        let env = instance_env(&instance, namespace, self.sources.as_ref()).await;
        match render_config(
            &instance,
            &base,
            Vec::new(),
            false,
            &env,
            self.config.as_ref(),
        ) {
            Err(failure) if certain(failure.reason) => Err(deny(failure)),
            _ => Ok(()),
        }
    }

    /// `managed` with a generated token: the credentials layer is merged
    /// last, and a `[[auth]] type = "token"` provider there replaces the
    /// configuration's token list — the operator's entry included, unless
    /// it lists it (its `user_id`), or a `${VAR}` value the operator can't
    /// judge.
    async fn token_shadowed(
        &self,
        namespace: &str,
        instance: &LocalInstance,
    ) -> Result<(), Denial<ReasonCode>> {
        let Some(managed) = &instance.spec.managed else {
            return Ok(());
        };
        let (Some(credentials), true) =
            (&managed.credentials, managed.operator_access.generate_token)
        else {
            return Ok(());
        };
        // Missing or not labelled yet: the status says so.
        let Ok(text) = self
            .sources
            .read(
                namespace,
                &ConfigSource::secret(&credentials.name, &credentials.key),
            )
            .await
        else {
            return Ok(());
        };
        let Ok(layer) = self.config.fragment(&text) else {
            return Ok(());
        };
        let user_id = managed.operator_access.user_id.as_str();
        let shadowing = layer
            .get("auth")
            .and_then(|a| a.as_array())
            .into_iter()
            .flatten()
            .filter(|p| p.get("type").and_then(|t| t.as_str()) == Some("token"))
            .filter_map(|p| p.get("tokens")?.as_array())
            .any(|tokens| {
                !tokens.iter().any(|t| {
                    t.get("user_id").and_then(|u| u.as_str()) == Some(user_id)
                        || t.get("value")
                            .and_then(|v| v.as_str())
                            .is_some_and(|v| v.contains("${"))
                })
            });
        if shadowing {
            return Err(Denial::new(
                ReasonCode::OperatorTokenShadowed,
                format!(
                    "the credentials layer (managed.credentials) declares an [[auth]] type = \
                     \"token\" provider whose token list replaces the configuration's, without \
                     the operator's entry (user_id = \"{user_id}\"): the operator would lock \
                     itself out. Add the entry from the rendered configuration (Secret \
                     <instance>-config) to that list"
                ),
            ));
        }
        Ok(())
    }

    /// The pods a managed instance asks for: what the operator would
    /// refuse to apply.
    async fn managed_pods(
        &self,
        namespace: &str,
        name: &str,
        managed: &api::managed::ManagedInstance,
    ) -> Result<(), domain::Failure> {
        use application::pod_safety;
        let objects = pod_safety::sketch(name, namespace, managed);
        pod_safety::check(&objects, &self.allowed_images)?;
        for secret in pod_safety::secrets_to_check(&objects) {
            // Absent or unreadable: nothing certain, the status says.
            if let Ok(Some(false)) = self.sources.secret_consents(namespace, &secret).await {
                return Err(pod_safety::secret_not_allowed(namespace, &secret));
            }
        }
        Ok(())
    }

    /// The namespace's only instance, when it has exactly one.
    async fn only_instance(&self, namespace: &str) -> Option<LocalInstance> {
        match self.siblings.instances(namespace).await {
            Ok(mut instances) if instances.len() == 1 => instances.pop(),
            _ => None,
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
        let only = self
            .only_instance(namespace)
            .await
            .map(|i| kube::ResourceExt::name_any(&i));
        let only = only.as_deref();
        for other in siblings
            .iter()
            .filter(|o| kube::ResourceExt::name_any(*o) != name)
            .filter(|o| {
                o.spec.registry == spec.registry
                    && o.spec.package == spec.package
                    && o.spec.version == spec.version
                    && target(o.spec.instance_ref.as_ref(), only)
                        == target(spec.instance_ref.as_ref(), only)
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
        let only = self
            .only_instance(namespace)
            .await
            .map(|i| kube::ResourceExt::name_any(&i));
        let only = only.as_deref();
        if let Some(other) = siblings.iter().find(|o| {
            kube::ResourceExt::name_any(*o) != name
                && o.spec.registry == spec.registry
                && o.spec.package == spec.package
                && o.spec.version == spec.version
                && target(o.spec.instance_ref.as_ref(), only)
                    == target(spec.instance_ref.as_ref(), only)
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

impl BatleHubAdmission {
    /// `restart` restarts what the operator deploys: refused on an
    /// external instance (the one `instanceRef` names, or the namespace's
    /// only one). An instance not found yet is left to the run.
    async fn maintenance(
        &self,
        namespace: &str,
        maintenance: Maintenance,
    ) -> Result<(), Denial<ReasonCode>> {
        if maintenance.spec.action == api::maintenance::MaintenanceAction::Restart {
            let instance = match &maintenance.spec.instance_ref {
                Some(r) => self
                    .siblings
                    .instances(namespace)
                    .await
                    .ok()
                    .and_then(|all| {
                        all.into_iter()
                            .find(|i| kube::ResourceExt::name_any(i) == r.name)
                    }),
                None => self.only_instance(namespace).await,
            };
            if let Some(instance) = instance
                && instance.spec.managed.is_none()
            {
                return Err(Denial::new(
                    ReasonCode::InvalidSpec,
                    format!(
                        "restart restarts the pods the operator deploys: {} is external",
                        kube::ResourceExt::name_any(&instance)
                    ),
                ));
            }
        }
        maintenance_fields(maintenance)
    }
}

fn maintenance_fields(maintenance: Maintenance) -> Result<(), Denial<ReasonCode>> {
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
            "BatleHubMaintenance" => {
                self.maintenance(namespace, typed(object).map_err(invalid)?)
                    .await
            }
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
        instances: std::sync::Mutex<Vec<LocalInstance>>,
    }

    #[async_trait::async_trait]
    impl Siblings for FakeSiblings {
        async fn grants(&self, _: &str) -> Result<Vec<PackageGrant>, String> {
            Ok(self.grants.lock().unwrap().clone())
        }

        async fn policies(&self, _: &str) -> Result<Vec<PackagePolicy>, String> {
            Ok(self.policies.lock().unwrap().clone())
        }

        async fn instances(&self, _: &str) -> Result<Vec<LocalInstance>, String> {
            Ok(self.instances.lock().unwrap().clone())
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
            allowed_images: application::pod_safety::default_allowed_images(),
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

    fn managed(value: serde_json::Value) -> LocalInstance {
        let mut instance = instance(false, json!({"storage": {}}));
        instance.spec.external = None;
        instance.spec.managed = Some(serde_json::from_value(value).unwrap());
        instance
    }

    #[tokio::test]
    async fn a_managed_instance_is_refused_pods_the_operator_doesn_t_run() {
        let (sources, admission) = admission();
        let decide = async |i: &LocalInstance| {
            admission
                .admit("BatleHubLocalInstance", "ns", &object(i))
                .await
                .map_err(|d| d.reason)
        };
        assert_eq!(decide(&managed(json!({"worker": {}}))).await, Ok(()));
        for refused in [
            json!({"image": {"repository": "docker.io/evil/miner"}}),
            json!({"securityContext": {"privileged": true}}),
            json!({"securityContext": {"capabilities": {"add": ["NET_ADMIN"]}}}),
            json!({"extraVolumes": [{"name": "root", "hostPath": {"path": "/"}}]}),
        ] {
            assert_eq!(
                decide(&managed(refused.clone())).await,
                Err(ReasonCode::InvalidSpec),
                "{refused}"
            );
        }
        // A Secret read by the pods: refused only once it exists unlabelled.
        let reading = managed(json!({
            "env": [{"name": "A", "valueFrom": {"secretKeyRef": {"name": "db", "key": "url"}}}],
            "envFrom": [{"secretRef": {"name": "more"}}],
        }));
        assert_eq!(decide(&reading).await, Ok(()));
        sources.put("ns", "db", "labelled");
        assert_eq!(decide(&reading).await, Ok(()));
        sources.refuse("ns", "more");
        assert_eq!(decide(&reading).await, Err(ReasonCode::SecretNotAllowed));
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

    fn managed_named(name: &str, config: serde_json::Value) -> LocalInstance {
        let mut i = instance(true, config);
        i.metadata.name = Some(name.into());
        i.spec.external = None;
        i.spec.managed = Some(Default::default());
        i
    }

    #[tokio::test]
    async fn a_configuration_a_registry_may_complete_is_not_refused() {
        let (_, admission) = admission();
        let decide = async |i: &LocalInstance| {
            admission
                .admit("BatleHubLocalInstance", "ns", &object(i))
                .await
                .map_err(|d| d.reason)
        };
        // An entry without `type` a BatleHubRegistry named npm completes.
        assert_eq!(
            decide(&instance(
                true,
                json!({"invalid": 1, "registries": [{"name": "npm"}]})
            ))
            .await,
            Ok(())
        );
        // Nothing to complete: certain.
        assert_eq!(
            decide(&managed_named("hub", json!({"invalid": 1}))).await,
            Err(ReasonCode::ConfigInvalid)
        );
        assert_eq!(
            decide(&managed_named("hub", serde_json::Value::Null)).await,
            Err(ReasonCode::InvalidSpec)
        );
    }

    #[tokio::test]
    async fn credentials_dropping_the_operator_s_entry_are_refused() {
        let (sources, admission) = admission();
        let decide = async |i: &LocalInstance| {
            admission
                .admit("BatleHubLocalInstance", "ns", &object(i))
                .await
                .map_err(|d| d.reason)
        };
        let mut hub = managed_named("hub", json!({"server": {}}));
        hub.spec.managed.as_mut().unwrap().credentials = Some(LocalSecretKeyRef {
            name: "creds".into(),
            key: "credentials.toml".into(),
        });
        // Not created yet: the status will say.
        assert_eq!(decide(&hub).await, Ok(()));
        sources.put(
            "ns",
            "creds",
            r#"{"auth": [{"type": "token", "tokens": [{"value": "theirs", "role": "admin"}]}]}"#,
        );
        assert_eq!(decide(&hub).await, Err(ReasonCode::OperatorTokenShadowed));
        sources.put(
            "ns",
            "creds",
            r#"{"auth": [{"type": "token", "tokens": [{"value": "x", "role": "admin", "user_id": "weebo-batlehub-operator"}]}]}"#,
        );
        assert_eq!(decide(&hub).await, Ok(()));
        sources.put("ns", "creds", r#"{"database": {"url": "x"}}"#);
        assert_eq!(decide(&hub).await, Ok(()));
    }

    #[tokio::test]
    async fn restart_is_refused_on_an_external_instance_and_the_default_instance_is_named() {
        let siblings = Arc::new(FakeSiblings::default());
        *siblings.instances.lock().unwrap() = vec![instance(true, json!({}))];
        *siblings.grants.lock().unwrap() = vec![grant("first", None, &["user:alice"])];
        let (_, admission) = admission_with(siblings.clone());
        let restart = |instance_ref: Option<InstanceRef>| {
            Maintenance::new(
                "m",
                api::maintenance::MaintenanceSpec {
                    instance_ref,
                    action: api::maintenance::MaintenanceAction::Restart,
                    params: Default::default(),
                    schedule: None,
                    suspend: false,
                    ttl_seconds_after_finished: None,
                    timeout_seconds: 600,
                },
            )
        };
        let decide = async |m: &Maintenance| {
            admission
                .admit("BatleHubMaintenance", "ns", &object(m))
                .await
                .map_err(|d| d.reason)
        };
        assert_eq!(decide(&restart(None)).await, Err(ReasonCode::InvalidSpec));
        assert_eq!(
            decide(&restart(Some(InstanceRef::named("hub")))).await,
            Err(ReasonCode::InvalidSpec)
        );
        // Not found yet: left to the run.
        assert_eq!(
            decide(&restart(Some(InstanceRef::named("other")))).await,
            Ok(())
        );
        // A grant naming the only instance collides with one naming none.
        let mut named = grant("second", None, &["user:alice"]);
        named.spec.instance_ref = Some(InstanceRef::named("hub"));
        assert_eq!(
            admission
                .admit("BatleHubPackageGrant", "ns", &object(&named))
                .await
                .map_err(|d| d.reason),
            Err(ReasonCode::GrantConflict)
        );
        *siblings.instances.lock().unwrap() = vec![managed_named("hub", json!({}))];
        assert_eq!(decide(&restart(None)).await, Ok(()));
    }
}
