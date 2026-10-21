//! `weebo-batlehub-importer`: what exists already, as the CRs that
//! describe it.
//!
//! - **An instance** from the values of a Helm release of BatleHub's chart
//!   (`helm get values --all`): kept as is and piloted (`external`, its pods
//!   by the chart's labels), or taken over (`managed`, every value mapped to
//!   its field — the plan's §8).
//! - **The governance** of a live instance: its package and version grants
//!   and policies as `BatleHubPackageGrant`s and `BatleHubPackagePolicy`s,
//!   adopted (the kit's `Adopter`: created paused, their status seeded with
//!   what they hold, unpaused) — the only adoption path: the operator never
//!   takes over a grant or a policy it didn't write.

use std::collections::BTreeMap;

use api::local_instance::LocalInstanceSpec;
use api::package_grant::{PackageGrantSpec, PackageGrantStatus};
use api::package_policy::{PackagePolicySpec, PackagePolicyStatus};
use api::{LocalInstance, PackageGrant, PackagePolicy};
use application::ports::PackageNode;
use application::use_cases::import::{Imported, Owned, OwningCr};
use kube::api::{Api, ObjectMeta};
use kube::{Client, Resource, ResourceExt};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use weebo_kit_adapters::adopt::{Adopter, Summary};
use weebo_kit_api::InstanceRef;

pub use weebo_kit_adapters::adopt::to_yaml;

/// The importer's field manager.
pub const FIELD_MANAGER: &str = "weebo-batlehub-importer";

/// How the instance of a Helm release is described.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// The release stays, the operator pilots it (`external` +
    /// `podSelector`).
    External,
    /// The operator deploys it instead (`managed`).
    Managed,
}

/// What `instance` needs besides the values.
#[derive(Debug, Clone)]
pub struct ChartOptions {
    pub release: String,
    /// The release's namespace: the instance's.
    pub namespace: String,
    pub mode: Mode,
    /// The instance's name; default: the release's.
    pub name: Option<String>,
    /// External: the Secret (labelled `instance-token`) holding an admin
    /// token, `name/key`.
    pub token_secret: Option<(String, String)>,
    /// External: push the configuration (`manageConfig`).
    pub manage_config: bool,
}

/// The chart's `batlehub.fullname`.
pub fn chart_fullname(release: &str, values: &Value) -> String {
    if let Some(name) = values["fullnameOverride"]
        .as_str()
        .filter(|s| !s.is_empty())
    {
        return trunc63(name);
    }
    let name = chart_name(values);
    if release.contains(&name) {
        trunc63(release)
    } else {
        trunc63(&format!("{release}-{name}"))
    }
}

fn chart_name(values: &Value) -> String {
    values["nameOverride"]
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("batlehub")
        .to_string()
}

fn trunc63(s: &str) -> String {
    s.chars()
        .take(63)
        .collect::<String>()
        .trim_end_matches('-')
        .to_string()
}

/// The value at `pointer` (`/a/b`) in `values`, `null` when absent — as
/// `values["a"]["b"]` reads, without indexing.
fn at<'a>(values: &'a Value, pointer: &str) -> &'a Value {
    static NULL: Value = Value::Null;
    values.pointer(pointer).unwrap_or(&NULL)
}

/// `value` when it is set and not an empty map, list or string.
fn set(value: &Value) -> Option<Value> {
    match value {
        Value::Null => None,
        Value::Object(m) if m.is_empty() => None,
        Value::Array(a) if a.is_empty() => None,
        Value::String(s) if s.is_empty() => None,
        other => Some(other.clone()),
    }
}

fn copy(from: &Value, key: &str, to: &mut Map<String, Value>, as_key: &str) {
    if let Some(v) = set(&from[key]) {
        to.insert(as_key.into(), v);
    }
}

/// The `BatleHubLocalInstance` describing a release of BatleHub's chart,
/// and what it couldn't carry over.
pub fn chart_instance(
    values: &Value,
    options: &ChartOptions,
) -> Result<(LocalInstance, Vec<String>), String> {
    let mut warnings = Vec::new();
    let fullname = chart_fullname(&options.release, values);
    let name = options
        .name
        .clone()
        .unwrap_or_else(|| options.release.clone());
    let config = values["config"].clone();
    let credentials_secret = match at(values, "/credentials/enabled").as_bool() {
        Some(true) => Some(
            at(values, "/credentials/existingSecret")
                .as_str()
                .filter(|s| !s.is_empty())
                .map(String::from)
                .unwrap_or_else(|| format!("{fullname}-credentials")),
        ),
        _ => None,
    };
    let credentials_key = credentials_key(values);
    let credentials_copied = credentials_copy(values, options);
    if values["externalManifest"]
        .as_array()
        .is_some_and(|a| !a.is_empty())
    {
        warnings.push(
            "externalManifest isn't carried over: TOML layers become spec.configLayers, \
             mounted files managed.extraVolumes/extraVolumeMounts"
                .into(),
        );
    }
    if at(values, "/trivy/enabled").as_bool() == Some(true) {
        warnings.push(
            "trivy.enabled is out of scope: install Trivy yourself and point \
             config.scanners.trivy.endpoint at it"
                .into(),
        );
    }
    let spec = match options.mode {
        Mode::External => {
            let (secret, key) = options.token_secret.clone().ok_or(
                "--token-secret name/key is required with --mode external: a Secret of the \
                 release's namespace holding an admin token, labelled \
                 batlehub.weebo.io/instance-token=true",
            )?;
            let port = at(values, "/service/port").as_i64().unwrap_or(8080);
            if credentials_secret.is_some() && options.manage_config {
                warnings.push(
                    "the release mounts a credentials layer the operator can't see: it may \
                     shadow the admin token in the configuration it pushes"
                        .into(),
                );
            }
            json!({
                "external": {
                    "url": format!("http://{fullname}.{}.svc:{port}", options.namespace),
                    "adminTokenSecretRef": {"name": secret, "key": key},
                    "manageConfig": options.manage_config,
                    // The chart's proxy pods: its workers carry
                    // `app.kubernetes.io/component: worker`.
                    "podSelector": {
                        "matchLabels": {
                            "app.kubernetes.io/name": chart_name(values),
                            "app.kubernetes.io/instance": options.release,
                        },
                        "matchExpressions": [
                            {"key": "app.kubernetes.io/component", "operator": "DoesNotExist"},
                        ],
                    },
                },
                "config": if options.manage_config { config } else { Value::Null },
            })
        }
        Mode::Managed => {
            let mut managed = Map::new();
            if let Some(n) = values["replicaCount"].as_i64() {
                managed.insert("replicas".into(), json!(n));
            }
            let mut image = Map::new();
            copy(&values["image"], "repository", &mut image, "repository");
            copy(&values["image"], "tag", &mut image, "tag");
            copy(&values["image"], "pullPolicy", &mut image, "pullPolicy");
            // The chart's own default repository is an older name.
            if image.get("repository") == Some(&json!("ghcr.io/batleforc/batlehub")) {
                image.remove("repository");
            }
            if !image.is_empty() {
                managed.insert("image".into(), Value::Object(image));
            }
            copy(values, "imagePullSecrets", &mut managed, "imagePullSecrets");
            copy(values, "resources", &mut managed, "resources");
            copy(values, "env", &mut managed, "env");
            copy(values, "envFrom", &mut managed, "envFrom");
            copy(values, "podAnnotations", &mut managed, "podAnnotations");
            copy(values, "nodeSelector", &mut managed, "nodeSelector");
            copy(values, "tolerations", &mut managed, "tolerations");
            copy(values, "affinity", &mut managed, "affinity");
            copy(
                values,
                "podSecurityContext",
                &mut managed,
                "podSecurityContext",
            );
            copy(values, "securityContext", &mut managed, "securityContext");
            let mut service = Map::new();
            copy(&values["service"], "type", &mut service, "type");
            copy(&values["service"], "port", &mut service, "port");
            if !service.is_empty() {
                managed.insert("service".into(), Value::Object(service));
            }
            let sa = &values["serviceAccount"];
            let mut account = Map::new();
            copy(sa, "create", &mut account, "create");
            copy(sa, "name", &mut account, "name");
            copy(sa, "annotations", &mut account, "annotations");
            copy(
                &sa["rbac"],
                "autoTokenReview",
                &mut account,
                "autoTokenReview",
            );
            if !account.is_empty() {
                managed.insert("serviceAccount".into(), Value::Object(account));
            }
            let ingress = &values["ingress"];
            if ingress["enabled"].as_bool() == Some(true) {
                let mut out = Map::new();
                copy(ingress, "host", &mut out, "host");
                copy(ingress, "extraHosts", &mut out, "extraHosts");
                copy(ingress, "className", &mut out, "className");
                copy(ingress, "annotations", &mut out, "annotations");
                copy(ingress, "tls", &mut out, "tls");
                managed.insert("ingress".into(), Value::Object(out));
            }
            let persistence = &values["persistence"];
            let mut out = Map::new();
            for key in [
                "enabled",
                "size",
                "storageClass",
                "accessMode",
                "existingClaim",
                "ephemeralSizeLimit",
            ] {
                copy(persistence, key, &mut out, key);
            }
            if !out.is_empty() {
                managed.insert("persistence".into(), Value::Object(out));
            }
            let budget = &values["podDisruptionBudget"];
            if budget["enabled"].as_bool() == Some(true) {
                let mut out = Map::new();
                copy(budget, "minAvailable", &mut out, "minAvailable");
                copy(budget, "maxUnavailable", &mut out, "maxUnavailable");
                if !out.is_empty() {
                    managed.insert("podDisruptionBudget".into(), Value::Object(out));
                }
            }
            let policy = &values["networkPolicy"];
            if policy["enabled"].as_bool() == Some(true) {
                let mut out = Map::new();
                copy(policy, "ingressFrom", &mut out, "ingressFrom");
                copy(policy, "egressTo", &mut out, "egressTo");
                managed.insert("networkPolicy".into(), Value::Object(out));
            }
            let worker = &values["worker"];
            if worker["enabled"].as_bool() == Some(true) {
                let mut out = Map::new();
                copy(worker, "replicaCount", &mut out, "replicas");
                copy(worker, "resources", &mut out, "resources");
                copy(worker, "runtimeClassName", &mut out, "runtimeClassName");
                copy(worker, "nodeSelector", &mut out, "nodeSelector");
                copy(worker, "tolerations", &mut out, "tolerations");
                copy(
                    &worker["scratch"],
                    "sizeLimit",
                    &mut out,
                    "scratchSizeLimit",
                );
                let mut image = Map::new();
                copy(&worker["image"], "repository", &mut image, "repository");
                copy(&worker["image"], "tag", &mut image, "tag");
                copy(&worker["image"], "pullPolicy", &mut image, "pullPolicy");
                if image.get("repository") == Some(&json!("ghcr.io/batleforc/batlehub-worker")) {
                    image.remove("repository");
                }
                if !image.is_empty() {
                    out.insert("image".into(), Value::Object(image));
                }
                let autoscaling = &worker["autoscaling"];
                if autoscaling["enabled"].as_bool() == Some(true) {
                    let mut a = Map::new();
                    for key in ["minReplicas", "maxReplicas", "targetQueued", "metricName"] {
                        copy(autoscaling, key, &mut a, key);
                    }
                    out.insert("autoscaling".into(), Value::Object(a));
                }
                if set(at(worker, "/yaraRules/configMap")).is_some() {
                    warnings.push(
                        "worker.yaraRules.configMap isn't carried over: mount it with \
                         managed.extraVolumes/extraVolumeMounts"
                            .into(),
                    );
                }
                managed.insert("worker".into(), Value::Object(out));
            }
            match (&credentials_copied, &credentials_secret) {
                // The chart's own Secret goes with the release: a copy.
                (Some(copy), _) => {
                    managed.insert(
                        "credentials".into(),
                        json!({"name": copy.to, "key": copy.key}),
                    );
                }
                // `existingSecret`: something else manages it, it stays.
                (None, Some(secret)) => {
                    managed.insert(
                        "credentials".into(),
                        json!({"name": secret, "key": credentials_key}),
                    );
                    warnings.push(format!(
                        "label the credentials Secret for the operator: kubectl -n {} label \
                         secret {secret} batlehub.weebo.io/credential=true",
                        options.namespace
                    ));
                }
                (None, None) => {}
            }
            if fullname == name {
                warnings.push(format!(
                    "the instance's objects take the names of the release's ({name}, \
                     {name}-config…): uninstall the release first, or the operator refuses \
                     them (OwnedObjectConflict) — or name the instance otherwise (--name)"
                ));
            }
            json!({"managed": Value::Object(managed), "config": config})
        }
    };
    let spec: LocalInstanceSpec =
        serde_json::from_value(spec).map_err(|e| format!("the values don't map: {e}"))?;
    let mut instance = LocalInstance::new(&name, spec);
    instance.metadata.namespace = Some(options.namespace.clone());
    Ok((instance, warnings))
}

fn credentials_key(values: &Value) -> String {
    at(values, "/credentials/key")
        .as_str()
        .filter(|s| !s.is_empty())
        .unwrap_or("credentials.toml")
        .to_string()
}

/// The credentials layer of a release taken over (`managed`), when the
/// chart renders it into its own Secret (`credentials.config`, no
/// `existingSecret`): that Secret belongs to the release and goes with
/// it, so the instance reads a copy the importer makes, labelled
/// `batlehub.weebo.io/credential=true`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CredentialsCopy {
    /// The chart's Secret, `<fullname>-credentials`.
    pub from: String,
    /// The copy, `<instance>-credentials` (`-copy` appended when that is
    /// the chart's own name).
    pub to: String,
    pub key: String,
}

/// See [`CredentialsCopy`]; `None` in external mode, without a
/// credentials layer, or with `existingSecret`.
pub fn credentials_copy(values: &Value, options: &ChartOptions) -> Option<CredentialsCopy> {
    let credentials = &values["credentials"];
    if options.mode != Mode::Managed
        || credentials["enabled"].as_bool() != Some(true)
        || credentials["existingSecret"]
            .as_str()
            .is_some_and(|s| !s.is_empty())
    {
        return None;
    }
    let from = format!("{}-credentials", chart_fullname(&options.release, values));
    let name = options.name.as_deref().unwrap_or(&options.release);
    let mut to = format!("{name}-credentials");
    if to == from {
        to.push_str("-copy");
    }
    Some(CredentialsCopy {
        from,
        to,
        key: credentials_key(values),
    })
}

/// The commands that make the copy by hand (print mode: the importer
/// writes no secret value to its output).
pub fn credentials_commands(copy: &CredentialsCopy, namespace: &str) -> String {
    format!(
        "kubectl -n {namespace} get secret {from} -o go-template='{{{{index .data \"{key}\"}}}}' \
         | base64 -d > {key} && kubectl -n {namespace} create secret generic {to} \
         --from-file={key}={key} && kubectl -n {namespace} label secret {to} \
         {label}=true && rm {key}",
        from = copy.from,
        to = copy.to,
        key = copy.key,
        label = api::CREDENTIAL_LABEL,
    )
}

/// Copies the release's credentials Secret (see [`CredentialsCopy`]):
/// the same bytes under the copy's name, labelled for the operator. A copy
/// already there with the same content is fine; another is an error.
pub async fn copy_credentials(
    client: &Client,
    namespace: &str,
    copy: &CredentialsCopy,
) -> Result<(), String> {
    use k8s_openapi::api::core::v1::Secret;
    let secrets: Api<Secret> = Api::namespaced(client.clone(), namespace);
    let source = secrets
        .get_opt(&copy.from)
        .await
        .map_err(|e| format!("reading Secret {namespace}/{}: {e}", copy.from))?
        .ok_or_else(|| format!("Secret {namespace}/{} not found", copy.from))?;
    let data = source
        .data
        .as_ref()
        .and_then(|d| d.get(&copy.key))
        .cloned()
        .ok_or_else(|| format!("Secret {namespace}/{} has no key {}", copy.from, copy.key))?;
    if let Some(existing) = secrets
        .get_opt(&copy.to)
        .await
        .map_err(|e| format!("reading Secret {namespace}/{}: {e}", copy.to))?
    {
        let same = existing.data.as_ref().and_then(|d| d.get(&copy.key)) == Some(&data);
        let labelled = existing
            .metadata
            .labels
            .as_ref()
            .and_then(|l| l.get(api::CREDENTIAL_LABEL))
            .is_some_and(|v| v == "true");
        return match (same, labelled) {
            (true, true) => Ok(()),
            _ => Err(format!(
                "Secret {namespace}/{} exists already and isn't the labelled copy of {}",
                copy.to, copy.from
            )),
        };
    }
    let secret = Secret {
        metadata: ObjectMeta {
            name: Some(copy.to.clone()),
            namespace: Some(namespace.into()),
            labels: Some(BTreeMap::from([
                (api::CREDENTIAL_LABEL.to_string(), "true".to_string()),
                (
                    "app.kubernetes.io/managed-by".to_string(),
                    FIELD_MANAGER.to_string(),
                ),
            ])),
            ..Default::default()
        },
        data: Some(BTreeMap::from([(copy.key.clone(), data)])),
        type_: Some("Opaque".into()),
        ..Default::default()
    };
    secrets
        .create(&kube::api::PostParams::default(), &secret)
        .await
        .map_err(|e| format!("creating Secret {namespace}/{}: {e}", copy.to))?;
    Ok(())
}

/// A Kubernetes name for a node's CR: readable, unique (a digest of the
/// coordinate), at most 63 characters.
pub fn cr_name(node: &PackageNode) -> String {
    let coordinate = coordinate(node);
    let digest = Sha256::digest(coordinate.as_bytes());
    let hash: String = digest.iter().take(4).map(|b| format!("{b:02x}")).collect();
    let mut slug = String::new();
    for c in format!(
        "{}-{}{}",
        node.registry,
        node.package,
        node.version
            .as_deref()
            .map(|v| format!("-{v}"))
            .unwrap_or_default()
    )
    .to_lowercase()
    .chars()
    {
        let c = if c.is_ascii_alphanumeric() { c } else { '-' };
        if c == '-' && (slug.is_empty() || slug.ends_with('-')) {
            continue;
        }
        slug.push(c);
    }
    let slug: String = slug.chars().take(54).collect();
    format!("{}-{hash}", slug.trim_end_matches('-'))
}

/// What a CR of a node is bound to: `registry/package[@version]`.
pub fn coordinate(node: &PackageNode) -> String {
    match &node.version {
        Some(v) => format!("{}/{}@{v}", node.registry, node.package),
        None => format!("{}/{}", node.registry, node.package),
    }
}

/// A CR to adopt, and the status it starts from.
#[derive(Debug, Clone)]
pub enum Adoptable {
    Grant(PackageGrant, Value),
    Policy(PackagePolicy, Value),
}

impl Adoptable {
    pub fn name(&self) -> String {
        match self {
            Adoptable::Grant(g, _) => format!("BatleHubPackageGrant/{}", g.name_any()),
            Adoptable::Policy(p, _) => format!("BatleHubPackagePolicy/{}", p.name_any()),
        }
    }
}

fn meta(name: String, namespace: &str) -> ObjectMeta {
    ObjectMeta {
        name: Some(name),
        namespace: Some(namespace.into()),
        ..Default::default()
    }
}

/// The CRs of what was imported, in `namespace`, bound to `instance_ref`
/// (its only instance when `None`).
pub fn governance(
    imported: &Imported,
    namespace: &str,
    instance_ref: Option<&str>,
) -> Vec<Adoptable> {
    let instance_ref = instance_ref.map(InstanceRef::named);
    let mut out = Vec::new();
    for grant in &imported.grants {
        let node = &grant.node;
        let cr = PackageGrant {
            metadata: meta(cr_name(node), namespace),
            spec: PackageGrantSpec {
                instance_ref: instance_ref.clone(),
                registry: node.registry.clone(),
                package: node.package.clone(),
                version: node.version.clone(),
                grants: grant.grants.clone(),
                deletion_policy: Default::default(),
            },
            status: None,
        };
        #[expect(
            clippy::expect_used,
            reason = "a status of plain fields: serde_json has nothing to refuse in it"
        )]
        let seed = serde_json::to_value(PackageGrantStatus {
            applied: grant.applied.clone(),
            ..Default::default()
        })
        .expect("a status serializes");
        out.push(Adoptable::Grant(with_kind(cr), seed));
    }
    for policy in &imported.policies {
        let node = &policy.node;
        let cr = PackagePolicy {
            metadata: meta(cr_name(node), namespace),
            spec: PackagePolicySpec {
                instance_ref: instance_ref.clone(),
                registry: node.registry.clone(),
                package: node.package.clone(),
                version: node.version.clone(),
                policy: policy.policy.clone(),
                exemptions: policy.exemptions.clone(),
                deletion_policy: Default::default(),
            },
            status: None,
        };
        #[expect(
            clippy::expect_used,
            reason = "a status of plain fields: serde_json has nothing to refuse in it"
        )]
        let seed = serde_json::to_value(PackagePolicyStatus {
            applied_policy_hash: policy.applied_policy_hash.clone(),
            observed_policy_hash: policy.observed_policy_hash.clone(),
            applied_exemptions: policy.applied_exemptions.clone(),
            ..Default::default()
        })
        .expect("a status serializes");
        out.push(Adoptable::Policy(with_kind(cr), seed));
    }
    out
}

/// `cr` with its `apiVersion` and `kind`, as printed or applied.
#[expect(
    clippy::expect_used,
    reason = "one of this crate's CRs, built above: it serializes to an object and reads back"
)]
fn with_kind<K: Resource<DynamicType = ()> + serde::Serialize + serde::de::DeserializeOwned>(
    cr: K,
) -> K {
    let mut value = serde_json::to_value(&cr).expect("a CR serializes");
    if let Some(object) = value.as_object_mut() {
        object.insert("apiVersion".into(), json!(K::api_version(&())));
        object.insert("kind".into(), json!(K::kind(&())));
    }
    serde_json::from_value(value).expect("a CR deserializes")
}

/// The CRs, printable: with their seeded status, as they will be.
pub fn manifests(items: &[Adoptable]) -> Vec<Value> {
    items
        .iter()
        .map(|item| {
            #[expect(
                clippy::expect_used,
                reason = "this crate's CRs: serde_json has nothing to refuse in them"
            )]
            let (mut value, seed) = match item {
                Adoptable::Grant(g, s) => (serde_json::to_value(g).expect("a CR serializes"), s),
                Adoptable::Policy(p, s) => (serde_json::to_value(p).expect("a CR serializes"), s),
            };
            if let Some(object) = value.as_object_mut() {
                object.insert("status".into(), seed.clone());
            }
            value
        })
        .collect()
}

fn grant_bound(cr: &PackageGrant) -> Option<String> {
    let applied = cr.status.as_ref().is_some_and(|s| !s.applied.is_empty());
    applied.then(|| {
        coordinate(&PackageNode {
            registry: cr.spec.registry.clone(),
            package: cr.spec.package.clone(),
            version: cr.spec.version.clone(),
        })
    })
}

fn policy_bound(cr: &PackagePolicy) -> Option<String> {
    let written = cr
        .status
        .as_ref()
        .is_some_and(|s| s.applied_policy_hash.is_some() || !s.applied_exemptions.is_empty());
    written.then(|| {
        coordinate(&PackageNode {
            registry: cr.spec.registry.clone(),
            package: cr.spec.package.clone(),
            version: cr.spec.version.clone(),
        })
    })
}

fn node_of(registry: &str, package: &str, version: &Option<String>) -> PackageNode {
    PackageNode {
        registry: registry.to_string(),
        package: package.to_string(),
        version: version.clone(),
    }
}

/// Whether a CR naming `theirs` may write on the instance `ours` names:
/// either left empty (the namespace's only instance) is taken as the same.
fn same_instance(theirs: Option<&InstanceRef>, ours: Option<&str>) -> bool {
    match (theirs, ours) {
        (Some(theirs), Some(ours)) => theirs.name == ours,
        _ => true,
    }
}

/// What the governance CRs of the namespace already hold on the instance
/// `instance_ref` names: the subjects a grant lists or recorded as written,
/// the nodes a policy writes.
pub fn owned(
    grants: &[PackageGrant],
    policies: &[PackagePolicy],
    instance_ref: Option<&str>,
) -> Owned {
    let mut owned = Owned::default();
    for cr in grants
        .iter()
        .filter(|cr| same_instance(cr.spec.instance_ref.as_ref(), instance_ref))
    {
        let mut subjects: Vec<String> = cr.spec.grants.iter().map(|g| g.subject.clone()).collect();
        if let Some(status) = &cr.status {
            subjects.extend(status.applied.iter().map(|a| a.subject.clone()));
        }
        subjects.sort();
        subjects.dedup();
        owned
            .grants
            .entry(node_of(
                &cr.spec.registry,
                &cr.spec.package,
                &cr.spec.version,
            ))
            .or_default()
            .push(OwningCr {
                name: cr.name_any(),
                subjects,
                observed_policy_hash: None,
            });
    }
    for cr in policies
        .iter()
        .filter(|cr| same_instance(cr.spec.instance_ref.as_ref(), instance_ref))
    {
        owned
            .policies
            .entry(node_of(
                &cr.spec.registry,
                &cr.spec.package,
                &cr.spec.version,
            ))
            .or_default()
            .push(OwningCr {
                name: cr.name_any(),
                subjects: Vec::new(),
                observed_policy_hash: cr
                    .status
                    .as_ref()
                    .and_then(|s| s.observed_policy_hash.clone()),
            });
    }
    owned
}

/// The governance CRs of `namespace`, for [`owned`].
pub async fn existing(
    client: &Client,
    namespace: &str,
) -> Result<(Vec<PackageGrant>, Vec<PackagePolicy>), kube::Error> {
    let grants: Api<PackageGrant> = Api::namespaced(client.clone(), namespace);
    let policies: Api<PackagePolicy> = Api::namespaced(client.clone(), namespace);
    let params = kube::api::ListParams::default();
    Ok((
        grants.list(&params).await?.items,
        policies.list(&params).await?.items,
    ))
}

/// Adopts every CR, each reported on stderr as it happens.
pub async fn adopt_all(
    client: &Client,
    namespace: &str,
    items: &[Adoptable],
    force: bool,
) -> Summary {
    let adopter = Adopter {
        field_manager: FIELD_MANAGER,
        annotations: api::ANNOTATIONS,
    };
    let grants: Api<PackageGrant> = Api::namespaced(client.clone(), namespace);
    let policies: Api<PackagePolicy> = Api::namespaced(client.clone(), namespace);
    let mut summary = Summary::default();
    for item in items {
        let result = match item {
            Adoptable::Grant(cr, seed) => {
                let id = grant_id(cr);
                adopter
                    .adopt(&grants, cr, &id, seed.clone(), grant_bound, force)
                    .await
            }
            Adoptable::Policy(cr, seed) => {
                let id = policy_id(cr);
                adopter
                    .adopt(&policies, cr, &id, seed.clone(), policy_bound, force)
                    .await
            }
        };
        if let Err(e) = &result {
            eprintln!("{}: {e}", item.name());
        }
        summary.record(&result);
    }
    summary
}

fn grant_id(cr: &PackageGrant) -> String {
    coordinate(&PackageNode {
        registry: cr.spec.registry.clone(),
        package: cr.spec.package.clone(),
        version: cr.spec.version.clone(),
    })
}

fn policy_id(cr: &PackagePolicy) -> String {
    coordinate(&PackageNode {
        registry: cr.spec.registry.clone(),
        package: cr.spec.package.clone(),
        version: cr.spec.version.clone(),
    })
}

/// The values of a release, as `helm get values --all -o yaml` writes them.
pub fn read_values(text: &str) -> Result<Value, String> {
    serde_norway::from_str::<Value>(text).map_err(|e| format!("reading the values: {e}"))
}

/// Labels of a document, sorted, for stable output.
pub fn sorted(value: Value) -> Value {
    match value {
        Value::Object(map) => Value::Object(
            map.into_iter()
                .map(|(k, v)| (k, sorted(v)))
                .collect::<BTreeMap<_, _>>()
                .into_iter()
                .collect(),
        ),
        Value::Array(items) => Value::Array(items.into_iter().map(sorted).collect()),
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn options(mode: Mode) -> ChartOptions {
        ChartOptions {
            release: "registry".into(),
            namespace: "infra".into(),
            mode,
            name: None,
            token_secret: Some(("batlehub-admin".into(), "token".into())),
            manage_config: true,
        }
    }

    fn values() -> Value {
        read_values(
            r#"
replicaCount: 2
image: {repository: ghcr.io/batleforc/batlehub, tag: "1.6.0", pullPolicy: IfNotPresent}
service: {type: ClusterIP, port: 8080}
serviceAccount: {create: true, name: "", annotations: {}, rbac: {autoTokenReview: true}}
ingress: {enabled: true, host: hub.example.com, className: nginx, extraHosts: [], tls: []}
persistence: {enabled: true, accessMode: ReadWriteOnce, size: 20Gi, storageClass: ""}
podDisruptionBudget: {enabled: true, minAvailable: 1}
networkPolicy: {enabled: false, ingressFrom: [], egressTo: []}
credentials: {enabled: true, existingSecret: "", key: credentials.toml}
worker:
  enabled: true
  replicaCount: 1
  image: {repository: ghcr.io/batleforc/batlehub-worker, tag: ""}
  autoscaling: {enabled: true, minReplicas: 1, maxReplicas: 4, targetQueued: 20, metricName: batlehub_scan_jobs_queued}
  scratch: {sizeLimit: 4Gi}
env: [{name: DATABASE_URL, valueFrom: {secretKeyRef: {name: db, key: url}}}]
config:
  server: {host: 0.0.0.0, port: 8080}
  database: {type: postgresql, url: "${DATABASE_URL}"}
  storage: {type: filesystem, path: /var/cache/batlehub}
"#,
        )
        .unwrap()
    }

    #[test]
    fn the_chart_names_its_objects_as_helm_does() {
        assert_eq!(chart_fullname("registry", &json!({})), "registry-batlehub");
        assert_eq!(chart_fullname("my-batlehub", &json!({})), "my-batlehub");
        assert_eq!(
            chart_fullname("x", &json!({"fullnameOverride": "hub"})),
            "hub"
        );
        assert_eq!(chart_fullname("x", &json!({"nameOverride": "x"})), "x");
    }

    #[test]
    fn a_release_piloted_as_is_is_an_external_instance_on_its_pods() {
        let (instance, _) = chart_instance(&values(), &options(Mode::External)).unwrap();
        let external = instance.spec.external.unwrap();
        assert_eq!(external.url, "http://registry-batlehub.infra.svc:8080");
        assert!(external.manage_config);
        let selector = external.pod_selector.unwrap();
        assert_eq!(
            selector.match_labels.unwrap()["app.kubernetes.io/instance"],
            "registry"
        );
        assert_eq!(instance.spec.config["database"]["url"], "${DATABASE_URL}");
        let mut no_token = options(Mode::External);
        no_token.token_secret = None;
        assert!(chart_instance(&values(), &no_token).is_err());
    }

    #[test]
    fn a_release_taken_over_maps_every_value() {
        let (instance, warnings) = chart_instance(&values(), &options(Mode::Managed)).unwrap();
        let managed = instance.spec.managed.unwrap();
        assert_eq!(managed.replicas, 2);
        assert_eq!(managed.image.tag.as_deref(), Some("1.6.0"));
        // The chart's old default repository: the operator's own default.
        assert_eq!(managed.image.repository, None);
        assert_eq!(managed.ingress.unwrap().host, "hub.example.com");
        assert_eq!(managed.persistence.size.0, "20Gi");
        let worker = managed.worker.unwrap();
        assert_eq!(worker.autoscaling.unwrap().max_replicas, 4);
        assert_eq!(worker.image, None);
        assert!(managed.pod_disruption_budget.is_some());
        assert!(managed.network_policy.is_none());
        assert_eq!(managed.env[0].name, "DATABASE_URL");
        // The chart's own credentials Secret goes with the release: the
        // instance reads the importer's copy.
        let credentials = managed.credentials.unwrap();
        assert_eq!(credentials.name, "registry-credentials");
        assert_eq!(credentials.key, "credentials.toml");
        assert!(
            !warnings.iter().any(|w| w.contains("credential=true")),
            "{warnings:?}"
        );
        assert_eq!(
            credentials_copy(&values(), &options(Mode::Managed)),
            Some(CredentialsCopy {
                from: "registry-batlehub-credentials".into(),
                to: "registry-credentials".into(),
                key: "credentials.toml".into(),
            })
        );
    }

    #[test]
    fn credentials_are_copied_only_from_the_chart_s_own_secret() {
        // external: the release keeps its Secret.
        assert_eq!(credentials_copy(&values(), &options(Mode::External)), None);
        // existingSecret: managed by something else, referenced as is.
        let mut existing = values();
        existing["credentials"]["existingSecret"] = json!("vault-creds");
        assert_eq!(credentials_copy(&existing, &options(Mode::Managed)), None);
        let (instance, warnings) = chart_instance(&existing, &options(Mode::Managed)).unwrap();
        assert_eq!(
            instance.spec.managed.unwrap().credentials.unwrap().name,
            "vault-creds"
        );
        assert!(
            warnings
                .iter()
                .any(|w| w.contains("label secret vault-creds"))
        );
        // An instance named as the release's fullname: never the chart's name.
        let mut named = options(Mode::Managed);
        named.name = Some("registry-batlehub".into());
        let copy = credentials_copy(&values(), &named).unwrap();
        assert_eq!(copy.to, "registry-batlehub-credentials-copy");
        let commands = credentials_commands(&copy, "infra");
        assert!(
            commands.contains("get secret registry-batlehub-credentials "),
            "{commands}"
        );
        assert!(
            commands.contains("batlehub.weebo.io/credential=true"),
            "{commands}"
        );
    }

    #[test]
    fn existing_crs_own_what_they_list_on_their_instance() {
        let grant = |name: &str, instance: Option<&str>, subjects: &[&str]| {
            let mut cr = PackageGrant::new(
                name,
                PackageGrantSpec {
                    instance_ref: instance.map(InstanceRef::named),
                    registry: "npm".into(),
                    package: "a".into(),
                    version: None,
                    grants: subjects
                        .iter()
                        .map(|s| api::package_grant::SubjectGrant {
                            subject: s.to_string(),
                            actions: vec!["releases:read".into()],
                        })
                        .collect(),
                    deletion_policy: Default::default(),
                },
            );
            cr.status = Some(PackageGrantStatus {
                applied: vec![api::package_grant::AppliedGrant {
                    subject: "user:written".into(),
                    requested: vec![],
                    stored: vec![],
                    warnings: vec![],
                }],
                ..Default::default()
            });
            cr
        };
        let crs = [
            grant("mine", Some("hub"), &["user:alice"]),
            grant("default", None, &["user:bob"]),
            grant("other-instance", Some("other"), &["user:carol"]),
        ];
        let owned = owned(&crs, &[], Some("hub"));
        let node = PackageNode {
            registry: "npm".into(),
            package: "a".into(),
            version: None,
        };
        let names: Vec<_> = owned.grants[&node]
            .iter()
            .map(|c| c.name.as_str())
            .collect();
        assert_eq!(names, ["mine", "default"]);
        assert_eq!(
            owned.grants[&node][0].subjects,
            ["user:alice", "user:written"]
        );
    }

    #[test]
    fn cr_names_are_valid_and_unique() {
        let node = |p: &str, v: Option<&str>| PackageNode {
            registry: "npm".into(),
            package: p.into(),
            version: v.map(String::from),
        };
        let a = cr_name(&node("@Acme/Billing", None));
        assert!(a.starts_with("npm-acme-billing-"), "{a}");
        let b = cr_name(&node("@acme/billing", Some("1.0.0")));
        assert!(b.starts_with("npm-acme-billing-1-0-0-"), "{b}");
        assert_ne!(cr_name(&node("a.b", None)), cr_name(&node("a-b", None)));
        let long = cr_name(&node(&"x".repeat(300), None));
        assert!(long.len() <= 63, "{long}");
    }
}
