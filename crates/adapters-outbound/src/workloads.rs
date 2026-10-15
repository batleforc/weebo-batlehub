//! [`Workloads`] on the Kubernetes API: the objects of a managed instance,
//! applied by server-side apply (field manager `weebo-batlehub-operator`,
//! forced: the operator owns every field it writes), each read first.
//!
//! **No implicit adoption**: an object of the same name that carries
//! neither an owner reference to the instance nor the labels
//! `app.kubernetes.io/managed-by: weebo-batlehub` and
//! `app.kubernetes.io/instance: <instance>` is a conflict — server-side
//! apply would take it over silently. Labelling it hands it over. An
//! object another instance controls (its controller owner reference) is a
//! conflict whatever its labels: two instances never take one object from
//! each other.
//!
//! **What the pods may be** (`application::pod_safety`): before anything
//! is written, the pod templates are checked against the image allow-list
//! and the privileges the operator refuses, and every `Secret` they read
//! must carry `batlehub.weebo.io/credential: "true"` — the webhook refuses
//! the same, this is the check of what is actually applied.

use std::collections::BTreeMap;

use api::managed::MANAGED_BY;
use application::ports::{OwnedObject, Owner, Rollout, WorkloadError, Workloads};
use k8s_openapi::ByteString;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use kube::api::{
    Api, ApiResource, DeleteParams, DynamicObject, GroupVersionKind, Patch, PatchParams, PostParams,
};
use kube::{Client, ResourceExt};
use serde_json::json;

/// The field manager of every apply.
pub const FIELD_MANAGER: &str = "weebo-batlehub-operator";

pub struct KubeWorkloads {
    client: Client,
    /// The image repositories a pod may run.
    allowed_images: Vec<String>,
}

impl KubeWorkloads {
    pub fn new(client: Client) -> Self {
        Self {
            client,
            allowed_images: application::pod_safety::default_allowed_images(),
        }
    }

    /// The image repositories a pod may run (`WEEBO_BATLEHUB_ALLOWED_IMAGES`).
    pub fn with_allowed_images(mut self, allowed: Vec<String>) -> Self {
        self.allowed_images = allowed;
        self
    }

    /// The pods of `objects` checked, and the `Secret`s they read: nothing
    /// is written when one is refused.
    async fn check_pods(
        &self,
        owner: &Owner,
        objects: &[OwnedObject],
    ) -> Result<(), WorkloadError> {
        use application::pod_safety;
        pod_safety::check(objects, &self.allowed_images)
            .map_err(|f| WorkloadError::Refused(f.message))?;
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &owner.namespace);
        for name in pod_safety::secrets_to_check(objects) {
            let meta = api
                .get_metadata_opt(&name)
                .await
                .map_err(|e| kube_error(&format!("Secret {name}"), e))?;
            // Absent: the pod waits for it (the kubelet says so); present,
            // it must consent.
            if let Some(meta) = meta
                && meta.labels().get(api::CREDENTIAL_LABEL).map(String::as_str) != Some("true")
            {
                return Err(WorkloadError::SecretNotAllowed(
                    pod_safety::secret_not_allowed(&owner.namespace, &name).message,
                ));
            }
        }
        Ok(())
    }

    fn dynamic(&self, owner: &Owner, api_version: &str, kind: &str) -> Api<DynamicObject> {
        let (group, version) = match api_version.split_once('/') {
            Some((group, version)) => (group, version),
            None => ("", api_version),
        };
        let resource = ApiResource::from_gvk(&GroupVersionKind::gvk(group, version, kind));
        Api::namespaced_with(self.client.clone(), &owner.namespace, &resource)
    }
}

impl KubeWorkloads {
    /// Edits the instances of the TokenReview binding named after
    /// `cluster_role` (the chart grants `get`/`patch` on that name only),
    /// its subjects derived from them. Created on the first need, owned by
    /// the chart's `ClusterRole` (gone with the release); never deleted by
    /// the operator, an empty subject list binds no one. Every patch is
    /// conditioned on the `resourceVersion` read (subjects are one atomic
    /// list): two instances editing at once retry instead of dropping each
    /// other's account.
    async fn edit_token_review(
        &self,
        cluster_role: &str,
        edit: impl Fn(&mut BTreeMap<String, String>) + Send + Sync,
    ) -> Result<(), WorkloadError> {
        use k8s_openapi::api::rbac::v1::{ClusterRole, ClusterRoleBinding, RoleRef};
        let api: Api<ClusterRoleBinding> = Api::all(self.client.clone());
        let what = format!("ClusterRoleBinding {cluster_role}");
        for _ in 0..BINDING_RETRIES {
            let Some(existing) = api
                .get_opt(cluster_role)
                .await
                .map_err(|e| kube_error(&what, e))?
            else {
                let mut instances = BTreeMap::new();
                edit(&mut instances);
                if instances.is_empty() {
                    return Ok(());
                }
                let role: Api<ClusterRole> = Api::all(self.client.clone());
                let role = role
                    .get(cluster_role)
                    .await
                    .map_err(|e| kube_error(&format!("ClusterRole {cluster_role}"), e))?;
                let binding = ClusterRoleBinding {
                    metadata: ObjectMeta {
                        name: Some(cluster_role.into()),
                        labels: Some(BTreeMap::from([(
                            "app.kubernetes.io/managed-by".into(),
                            MANAGED_BY.into(),
                        )])),
                        annotations: Some(BTreeMap::from([(
                            TOKEN_REVIEW_INSTANCES.into(),
                            serde_json::to_string(&instances).expect("a map serializes"),
                        )])),
                        owner_references: Some(vec![OwnerReference {
                            api_version: "rbac.authorization.k8s.io/v1".into(),
                            kind: "ClusterRole".into(),
                            name: cluster_role.into(),
                            uid: role.metadata.uid.unwrap_or_default(),
                            ..Default::default()
                        }]),
                        ..Default::default()
                    },
                    role_ref: RoleRef {
                        api_group: Some("rbac.authorization.k8s.io".into()),
                        kind: "ClusterRole".into(),
                        name: cluster_role.into(),
                    },
                    subjects: Some(token_review_subjects(&instances)),
                };
                match api.create(&PostParams::default(), &binding).await {
                    Ok(_) => return Ok(()),
                    // Created meanwhile: edited on the next round.
                    Err(kube::Error::Api(e)) if e.code == 409 => continue,
                    Err(e) => return Err(kube_error(&what, e)),
                }
            };
            let ours = existing
                .labels()
                .get("app.kubernetes.io/managed-by")
                .is_some_and(|v| v == MANAGED_BY)
                && existing.role_ref.kind == "ClusterRole"
                && existing.role_ref.name == cluster_role;
            if !ours {
                return Err(WorkloadError::Conflict(format!(
                    "{what} exists and isn't the operator's TokenReview binding: never taken over"
                )));
            }
            let recorded: BTreeMap<String, String> = existing
                .annotations()
                .get(TOKEN_REVIEW_INSTANCES)
                .and_then(|text| serde_json::from_str(text).ok())
                .unwrap_or_default();
            let mut instances = recorded.clone();
            edit(&mut instances);
            let subjects = token_review_subjects(&instances);
            if instances == recorded && existing.subjects.clone().unwrap_or_default() == subjects {
                return Ok(());
            }
            let patch = json!({
                "metadata": {
                    "resourceVersion": existing.resource_version(),
                    "annotations": {
                        TOKEN_REVIEW_INSTANCES:
                            serde_json::to_string(&instances).expect("a map serializes"),
                    },
                },
                "subjects": subjects,
            });
            match api
                .patch(
                    cluster_role,
                    &PatchParams {
                        field_manager: Some(FIELD_MANAGER.into()),
                        ..Default::default()
                    },
                    &Patch::Merge(patch),
                )
                .await
            {
                Ok(_) => return Ok(()),
                // Written by someone else since read: read again.
                Err(kube::Error::Api(e)) if e.code == 409 => continue,
                Err(e) => return Err(kube_error(&what, e)),
            }
        }
        Err(WorkloadError::Kubernetes(format!(
            "{what}: changed by another writer {BINDING_RETRIES} times in a row"
        )))
    }
}

fn kube_error(what: &str, e: kube::Error) -> WorkloadError {
    WorkloadError::Kubernetes(format!("{what}: {e}"))
}

/// The owner reference every object carries.
fn owner_reference(owner: &Owner) -> OwnerReference {
    OwnerReference {
        api_version: format!("{}/v1alpha1", api::GROUP),
        kind: "BatleHubLocalInstance".into(),
        name: owner.name.clone(),
        uid: owner.uid.clone(),
        controller: Some(true),
        block_owner_deletion: Some(true),
    }
}

/// Whether `meta` is an object the operator may write over for `owner`:
/// owned by it, or labelled for it (`managed-by` and `instance`) and
/// controlled by no other object.
pub fn is_ours(meta: &ObjectMeta, owner: &Owner) -> bool {
    let references = meta.owner_references.iter().flatten();
    if references.clone().any(|r| r.uid == owner.uid) {
        return true;
    }
    if references
        .clone()
        .any(|r| r.controller == Some(true) && r.uid != owner.uid)
    {
        return false;
    }
    let label = |key: &str| meta.labels.as_ref().and_then(|l| l.get(key));
    label("app.kubernetes.io/managed-by").is_some_and(|v| v == MANAGED_BY)
        && label("app.kubernetes.io/instance").is_some_and(|v| *v == owner.name)
}

fn conflict(kind: &str, name: &str, namespace: &str) -> WorkloadError {
    WorkloadError::Conflict(format!(
        "{kind} {namespace}/{name} exists and isn't this instance's (no owner reference to it, \
         nor the labels app.kubernetes.io/managed-by={MANAGED_BY} and \
         app.kubernetes.io/instance=<instance> without another controller): never taken over. \
         Delete or rename it, or label it to hand it over"
    ))
}

/// The annotation of the TokenReview binding recording, per instance
/// (`<namespace>/<name>`), the account it binds: what the subjects are
/// derived from, so an account two instances share stays bound while one
/// still needs it.
pub const TOKEN_REVIEW_INSTANCES: &str = "batlehub.weebo.io/token-review-instances";

/// How many times an edit of the shared binding is retried when another
/// write got in between (its `resourceVersion` changed).
const BINDING_RETRIES: usize = 5;

/// The subjects of the TokenReview binding: one per distinct account.
pub fn token_review_subjects(
    instances: &BTreeMap<String, String>,
) -> Vec<k8s_openapi::api::rbac::v1::Subject> {
    let accounts: std::collections::BTreeSet<(String, String)> = instances
        .iter()
        .filter_map(|(instance, account)| {
            let (namespace, _) = instance.split_once('/')?;
            Some((namespace.to_string(), account.clone()))
        })
        .collect();
    accounts
        .into_iter()
        .map(|(namespace, name)| k8s_openapi::api::rbac::v1::Subject {
            kind: "ServiceAccount".into(),
            name,
            namespace: Some(namespace),
            ..Default::default()
        })
        .collect()
}

fn instance_key(owner: &Owner) -> String {
    format!("{}/{}", owner.namespace, owner.name)
}

#[async_trait::async_trait]
impl Workloads for KubeWorkloads {
    async fn bind_token_review(
        &self,
        owner: &Owner,
        service_account: &str,
        cluster_role: &str,
    ) -> Result<(), WorkloadError> {
        let account = service_account.to_string();
        self.edit_token_review(cluster_role, |instances| {
            instances.insert(instance_key(owner), account.clone());
        })
        .await
    }

    async fn unbind_token_review(
        &self,
        owner: &Owner,
        cluster_role: &str,
    ) -> Result<(), WorkloadError> {
        self.edit_token_review(cluster_role, |instances| {
            instances.remove(&instance_key(owner));
        })
        .await
    }

    async fn apply(&self, owner: &Owner, objects: &[OwnedObject]) -> Result<(), WorkloadError> {
        self.check_pods(owner, objects).await?;
        let params = PatchParams::apply(FIELD_MANAGER).force();
        for object in objects {
            let api = self.dynamic(owner, &object.api_version, &object.kind);
            let what = format!("{} {}", object.kind, object.name);
            if let Some(existing) = api
                .get_opt(&object.name)
                .await
                .map_err(|e| kube_error(&what, e))?
            {
                if !is_ours(&existing.metadata, owner) {
                    return Err(conflict(&object.kind, &object.name, &owner.namespace));
                }
                if object.create_only {
                    continue;
                }
            }
            let mut manifest = object.manifest.clone();
            manifest["metadata"]["ownerReferences"] = json!([owner_reference(owner)]);
            api.patch(&object.name, &params, &Patch::Apply(manifest))
                .await
                .map_err(|e| kube_error(&what, e))?;
        }
        Ok(())
    }

    async fn remove(
        &self,
        owner: &Owner,
        api_version: &str,
        kind: &str,
        name: &str,
    ) -> Result<(), WorkloadError> {
        let api = self.dynamic(owner, api_version, kind);
        let what = format!("{kind} {name}");
        match api.get_opt(name).await {
            Ok(Some(existing)) if is_ours(&existing.metadata, owner) => api
                .delete(name, &DeleteParams::background())
                .await
                .map(|_| ())
                .map_err(|e| kube_error(&what, e)),
            Ok(_) => Ok(()),
            // A kind the cluster doesn't serve (no autoscaling/v2…): nothing
            // of it to remove.
            Err(kube::Error::Api(e)) if e.code == 404 => Ok(()),
            Err(e) => Err(kube_error(&what, e)),
        }
    }

    async fn operator_token(&self, owner: &Owner, name: &str) -> Result<String, WorkloadError> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &owner.namespace);
        let what = format!("Secret {name}");
        let read = |secret: &Secret| -> Result<String, WorkloadError> {
            let bytes = secret
                .data
                .as_ref()
                .and_then(|d| d.get(api::managed::TOKEN_KEY))
                .ok_or_else(|| {
                    WorkloadError::Kubernetes(format!(
                        "{what} has no key {:?}: delete it to generate a new token",
                        api::managed::TOKEN_KEY
                    ))
                })?;
            String::from_utf8(bytes.0.clone())
                .map(|t| t.trim().to_string())
                .map_err(|_| WorkloadError::Kubernetes(format!("{what}: the token is not UTF-8")))
        };
        if let Some(existing) = api.get_opt(name).await.map_err(|e| kube_error(&what, e))? {
            if !is_ours(&existing.metadata, owner) {
                return Err(conflict("Secret", name, &owner.namespace));
            }
            return read(&existing);
        }
        // Generated once, never applied again: a token is never rotated
        // under a running instance.
        let token = format!(
            "{}{}",
            uuid::Uuid::new_v4().simple(),
            uuid::Uuid::new_v4().simple()
        );
        let secret = Secret {
            metadata: ObjectMeta {
                name: Some(name.to_string()),
                namespace: Some(owner.namespace.clone()),
                labels: Some(BTreeMap::from([
                    ("app.kubernetes.io/managed-by".into(), MANAGED_BY.into()),
                    ("app.kubernetes.io/instance".into(), owner.name.clone()),
                    (
                        api::ANNOTATIONS.key(weebo_kit_api::annotations::INSTANCE_TOKEN),
                        "true".into(),
                    ),
                ])),
                owner_references: Some(vec![owner_reference(owner)]),
                ..Default::default()
            },
            data: Some(BTreeMap::from([(
                api::managed::TOKEN_KEY.into(),
                ByteString(token.clone().into_bytes()),
            )])),
            ..Default::default()
        };
        match api.create(&PostParams::default(), &secret).await {
            Ok(_) => Ok(token),
            // Created meanwhile: whoever did, read it back (its owner checked).
            Err(kube::Error::Api(e)) if e.code == 409 => {
                let existing = api.get(name).await.map_err(|e| kube_error(&what, e))?;
                if !is_ours(&existing.metadata, owner) {
                    return Err(conflict("Secret", name, &owner.namespace));
                }
                read(&existing)
            }
            Err(e) => Err(kube_error(&what, e)),
        }
    }

    async fn secret_text(
        &self,
        owner: &Owner,
        name: &str,
        key: &str,
    ) -> Result<Option<String>, WorkloadError> {
        let api: Api<Secret> = Api::namespaced(self.client.clone(), &owner.namespace);
        let Some(secret) = api
            .get_opt(name)
            .await
            .map_err(|e| kube_error(&format!("Secret {name}"), e))?
        else {
            return Ok(None);
        };
        if !is_ours(&secret.metadata, owner) {
            return Ok(None);
        }
        Ok(secret
            .data
            .as_ref()
            .and_then(|d| d.get(key))
            .and_then(|b| String::from_utf8(b.0.clone()).ok()))
    }

    async fn restart(
        &self,
        owner: &Owner,
        name: &str,
        config_hash: Option<&str>,
    ) -> Result<bool, WorkloadError> {
        let api: Api<Deployment> = Api::namespaced(self.client.clone(), &owner.namespace);
        let what = format!("Deployment {name}");
        let Some(existing) = api.get_opt(name).await.map_err(|e| kube_error(&what, e))? else {
            return Ok(false);
        };
        if !is_ours(&existing.metadata, owner) {
            return Err(conflict("Deployment", name, &owner.namespace));
        }
        let mut annotations = serde_json::Map::new();
        annotations.insert(
            "kubectl.kubernetes.io/restartedAt".into(),
            json!(k8s_openapi::jiff::Timestamp::now().to_string()),
        );
        if let Some(hash) = config_hash {
            annotations.insert(api::managed::CONFIG_HASH_ANNOTATION.into(), json!(hash));
        }
        // A merge patch under its own manager: the operator's next apply
        // leaves `restartedAt` alone, and agrees on the hash.
        api.patch(
            name,
            &PatchParams {
                field_manager: Some(format!("{FIELD_MANAGER}-restart")),
                ..Default::default()
            },
            &Patch::Merge(json!({
                "spec": {"template": {"metadata": {"annotations": annotations}}}
            })),
        )
        .await
        .map_err(|e| kube_error(&what, e))?;
        Ok(true)
    }

    async fn rollout(&self, owner: &Owner, name: &str) -> Result<Option<Rollout>, WorkloadError> {
        let api: Api<Deployment> = Api::namespaced(self.client.clone(), &owner.namespace);
        let Some(deployment) = api
            .get_opt(name)
            .await
            .map_err(|e| kube_error(&format!("Deployment {name}"), e))?
        else {
            return Ok(None);
        };
        let spec = deployment.spec.as_ref();
        let status = deployment.status.clone().unwrap_or_default();
        Ok(Some(Rollout {
            replicas: spec.and_then(|s| s.replicas).unwrap_or(1),
            updated: status.updated_replicas.unwrap_or(0),
            available: status.available_replicas.unwrap_or(0),
            observed: status.observed_generation >= deployment.metadata.generation
                && deployment.metadata.generation.is_some(),
            config_hash: spec
                .and_then(|s| s.template.metadata.as_ref())
                .and_then(|m| m.annotations.as_ref())
                .and_then(|a| a.get(api::managed::CONFIG_HASH_ANNOTATION))
                .cloned(),
        }))
    }

    async fn claim_size(&self, owner: &Owner, name: &str) -> Result<Option<String>, WorkloadError> {
        let api: Api<k8s_openapi::api::core::v1::PersistentVolumeClaim> =
            Api::namespaced(self.client.clone(), &owner.namespace);
        let claim = api
            .get_opt(name)
            .await
            .map_err(|e| kube_error(&format!("PersistentVolumeClaim {name}"), e))?;
        Ok(claim
            .and_then(|c| c.spec)
            .and_then(|s| s.resources)
            .and_then(|r| r.requests)
            .and_then(|r| r.get("storage").map(|q| q.0.clone())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> Owner {
        Owner {
            namespace: "team".into(),
            name: "hub".into(),
            uid: "u-1".into(),
        }
    }

    #[test]
    fn an_account_two_instances_share_is_one_subject() {
        let instances = BTreeMap::from([
            ("team/a".to_string(), "hub".to_string()),
            ("team/b".to_string(), "hub".to_string()),
            ("other/c".to_string(), "hub".to_string()),
        ]);
        let subjects = token_review_subjects(&instances);
        let names: Vec<(String, String)> = subjects
            .iter()
            .map(|s| (s.namespace.clone().unwrap(), s.name.clone()))
            .collect();
        assert_eq!(
            names,
            [
                ("other".to_string(), "hub".to_string()),
                ("team".to_string(), "hub".to_string())
            ]
        );
        assert!(subjects.iter().all(|s| s.kind == "ServiceAccount"));
        assert!(token_review_subjects(&BTreeMap::new()).is_empty());
    }

    #[test]
    fn only_owned_or_labelled_objects_are_ours() {
        let mut meta = ObjectMeta::default();
        assert!(!is_ours(&meta, &owner()));
        meta.owner_references = Some(vec![owner_reference(&owner())]);
        assert!(is_ours(&meta, &owner()));
        meta.owner_references = Some(vec![OwnerReference {
            uid: "other".into(),
            ..owner_reference(&owner())
        }]);
        assert!(!is_ours(&meta, &owner()));
        // Labelled for it, but controlled by another instance: never.
        meta.labels = Some(BTreeMap::from([
            ("app.kubernetes.io/managed-by".into(), MANAGED_BY.into()),
            ("app.kubernetes.io/instance".into(), "hub".into()),
        ]));
        assert!(!is_ours(&meta, &owner()));
        // A non-controller reference doesn't hold it.
        meta.owner_references = Some(vec![OwnerReference {
            uid: "other".into(),
            controller: None,
            ..owner_reference(&owner())
        }]);
        assert!(is_ours(&meta, &owner()));
        meta.owner_references = None;
        assert!(is_ours(&meta, &owner()));
        // `managed-by` alone, or another instance's name: not this one's
        // (instance `hub` and `hub-worker` share names).
        meta.labels = Some(BTreeMap::from([(
            "app.kubernetes.io/managed-by".into(),
            MANAGED_BY.into(),
        )]));
        assert!(!is_ours(&meta, &owner()));
        meta.labels = Some(BTreeMap::from([
            ("app.kubernetes.io/managed-by".into(), MANAGED_BY.into()),
            ("app.kubernetes.io/instance".into(), "hub-worker".into()),
        ]));
        assert!(!is_ours(&meta, &owner()));
    }
}
