//! [`Workloads`] on the Kubernetes API: the objects of a managed instance,
//! applied by server-side apply (field manager `weebo-batlehub-operator`,
//! forced: the operator owns every field it writes), each read first.
//!
//! **No implicit adoption**: an object of the same name that carries
//! neither an owner reference to the instance nor
//! `app.kubernetes.io/managed-by: weebo-batlehub` is a conflict — server-
//! side apply would take it over silently. Labelling it hands it over.

use std::collections::BTreeMap;

use api::managed::MANAGED_BY;
use application::ports::{OwnedObject, Owner, Rollout, WorkloadError, Workloads};
use k8s_openapi::ByteString;
use k8s_openapi::api::apps::v1::Deployment;
use k8s_openapi::api::core::v1::Secret;
use k8s_openapi::apimachinery::pkg::apis::meta::v1::{ObjectMeta, OwnerReference};
use kube::Client;
use kube::api::{
    Api, ApiResource, DeleteParams, DynamicObject, GroupVersionKind, Patch, PatchParams, PostParams,
};
use serde_json::json;

/// The field manager of every apply.
pub const FIELD_MANAGER: &str = "weebo-batlehub-operator";

pub struct KubeWorkloads {
    client: Client,
}

impl KubeWorkloads {
    pub fn new(client: Client) -> Self {
        Self { client }
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

/// Whether `meta` is an object the operator may write over for `owner`.
pub fn is_ours(meta: &ObjectMeta, owner: &Owner) -> bool {
    meta.owner_references
        .iter()
        .flatten()
        .any(|r| r.uid == owner.uid)
        || meta
            .labels
            .as_ref()
            .and_then(|l| l.get("app.kubernetes.io/managed-by"))
            .is_some_and(|v| v == MANAGED_BY)
}

fn conflict(kind: &str, name: &str, namespace: &str) -> WorkloadError {
    WorkloadError::Conflict(format!(
        "{kind} {namespace}/{name} exists and isn't the operator's (no owner reference to the \
         instance, no app.kubernetes.io/managed-by={MANAGED_BY} label): never taken over. \
         Delete or rename it, or label it to hand it over"
    ))
}

#[async_trait::async_trait]
impl Workloads for KubeWorkloads {
    async fn apply(&self, owner: &Owner, objects: &[OwnedObject]) -> Result<(), WorkloadError> {
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
        meta.labels = Some(BTreeMap::from([(
            "app.kubernetes.io/managed-by".into(),
            MANAGED_BY.into(),
        )]));
        assert!(is_ours(&meta, &owner()));
    }
}
