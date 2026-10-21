//! [`Workloads`] on the Kubernetes API: the kit's `KubeOwnedObjects`
//! (server-side apply under `weebo-batlehub-operator`, no implicit
//! adoption, the pods checked against the image allow-list and the
//! `batlehub.weebo.io/credential` label before anything is written) for
//! `BatleHubLocalInstance`, plus what only BatleHub needs: the operator's
//! token `Secret` and the shared TokenReview binding.

use std::collections::BTreeMap;

use api::managed::MANAGED_BY;
use application::ports::{OwnedObject, OwnedObjects, Owner, Rollout, WorkloadError, Workloads};
use k8s_openapi::ByteString;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use kube::api::{Api, Patch, PatchParams, PostParams};
use kube::{Client, ResourceExt};
use serde_json::json;
use weebo_kit_adapters::{KubeOwnedObjects, WorkloadSettings};
use weebo_kit_application::workload::{Listed, PodState};

/// The field manager of every apply.
pub const FIELD_MANAGER: &str = "weebo-batlehub-operator";

/// The kit's [`KubeOwnedObjects`] for BatleHub's instances, plus the
/// operator's token and the TokenReview binding.
pub struct KubeWorkloads {
    client: Client,
    objects: KubeOwnedObjects,
}

fn settings(allowed_images: Vec<String>) -> WorkloadSettings {
    WorkloadSettings {
        field_manager: FIELD_MANAGER.into(),
        managed_by: MANAGED_BY.into(),
        owner_api_version: format!("{}/v1alpha1", api::GROUP),
        owner_kind: "BatleHubLocalInstance".into(),
        credential_label: api::CREDENTIAL_LABEL.into(),
        allowed_images,
    }
}

impl KubeWorkloads {
    pub fn new(client: Client) -> Self {
        Self {
            objects: KubeOwnedObjects::new(
                client.clone(),
                settings(application::pod_safety::default_allowed_images()),
            ),
            client,
        }
    }

    /// The image repositories a pod may run (`WEEBO_BATLEHUB_ALLOWED_IMAGES`).
    pub fn with_allowed_images(mut self, allowed: Vec<String>) -> Self {
        self.objects = KubeOwnedObjects::new(self.client.clone(), settings(allowed));
        self
    }

    fn is_ours(&self, meta: &ObjectMeta, owner: &Owner) -> bool {
        self.objects.is_ours(meta, owner)
    }

    fn conflict(&self, kind: &str, name: &str, namespace: &str) -> WorkloadError {
        self.objects.conflict(kind, name, namespace)
    }

    fn owner_reference(&self, owner: &Owner) -> OwnerReference {
        self.objects.owner_reference(owner)
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
                #[expect(
                    clippy::expect_used,
                    reason = "a map of strings: serde_json has nothing to refuse in it"
                )]
                let recorded = serde_json::to_string(&instances).expect("a map serializes");
                let binding = ClusterRoleBinding {
                    metadata: ObjectMeta {
                        name: Some(cluster_role.into()),
                        labels: Some(BTreeMap::from([(
                            "app.kubernetes.io/managed-by".into(),
                            MANAGED_BY.into(),
                        )])),
                        annotations: Some(BTreeMap::from([(
                            TOKEN_REVIEW_INSTANCES.into(),
                            recorded,
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
            #[expect(
                clippy::expect_used,
                reason = "a map of strings: serde_json has nothing to refuse in it"
            )]
            let text = serde_json::to_string(&instances).expect("a map serializes");
            let patch = json!({
                "metadata": {
                    "resourceVersion": existing.resource_version(),
                    "annotations": { TOKEN_REVIEW_INSTANCES: text },
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

use weebo_kit_adapters::workloads::kube_error;

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
impl OwnedObjects for KubeWorkloads {
    async fn apply(&self, owner: &Owner, objects: &[OwnedObject]) -> Result<(), WorkloadError> {
        self.objects.apply(owner, objects).await
    }

    async fn remove(
        &self,
        owner: &Owner,
        api_version: &str,
        kind: &str,
        name: &str,
    ) -> Result<(), WorkloadError> {
        self.objects.remove(owner, api_version, kind, name).await
    }

    async fn list(
        &self,
        owner: &Owner,
        api_version: &str,
        kind: &str,
        labels: &BTreeMap<String, String>,
    ) -> Result<Vec<Listed>, WorkloadError> {
        self.objects.list(owner, api_version, kind, labels).await
    }

    async fn secret_text(
        &self,
        owner: &Owner,
        name: &str,
        key: &str,
    ) -> Result<Option<String>, WorkloadError> {
        self.objects.secret_text(owner, name, key).await
    }

    async fn rollout(&self, owner: &Owner, name: &str) -> Result<Option<Rollout>, WorkloadError> {
        self.objects.rollout(owner, name).await
    }

    async fn annotate_template(
        &self,
        owner: &Owner,
        name: &str,
        annotations: &BTreeMap<String, String>,
        restart: bool,
    ) -> Result<bool, WorkloadError> {
        self.objects
            .annotate_template(owner, name, annotations, restart)
            .await
    }

    async fn pods(
        &self,
        owner: &Owner,
        selector: &BTreeMap<String, String>,
    ) -> Result<Vec<PodState>, WorkloadError> {
        self.objects.pods(owner, selector).await
    }

    async fn claim_size(&self, owner: &Owner, name: &str) -> Result<Option<String>, WorkloadError> {
        self.objects.claim_size(owner, name).await
    }
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
            if !self.is_ours(&existing.metadata, owner) {
                return Err(self.conflict("Secret", name, &owner.namespace));
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
                owner_references: Some(vec![self.owner_reference(owner)]),
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
                if !self.is_ours(&existing.metadata, owner) {
                    return Err(self.conflict("Secret", name, &owner.namespace));
                }
                read(&existing)
            }
            Err(e) => Err(kube_error(&what, e)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
