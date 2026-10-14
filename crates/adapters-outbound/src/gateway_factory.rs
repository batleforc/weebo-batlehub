//! One [`HttpAdminGateway`] per `BatleHubLocalInstance`, built on every
//! call: the instance comes from the [`LocalInstanceDirectory`] (a live
//! reflector `Store` when `operator::main` wires one in, the API
//! otherwise), its token is read fresh from `tokenSecretRef` — a rotated
//! token or an edited `url` takes effect on the next reconcile.

use std::sync::Arc;

use application::ports::{AdminGateway, BoundInstance, GatewayFactory, GatewayFactoryError};
use kube::{Client, ResourceExt};
use weebo_kit_adapters::{TokenSecretError, read_local_instance_token};
use weebo_kit_api::SecretKeyRef;

use crate::admin_gateway::HttpAdminGateway;
use crate::instances::LocalInstanceDirectory;

pub struct HttpGatewayFactory {
    client: Client,
    instances: Arc<LocalInstanceDirectory>,
}

impl HttpGatewayFactory {
    pub fn new(client: Client, instances: Arc<LocalInstanceDirectory>) -> Self {
        Self { client, instances }
    }

    /// The token is only read from a Secret labelled for it
    /// (`batlehub.weebo.io/instance-token: "true"`): the operator reads
    /// with its own rights, and the CR names the URL the token is sent to.
    async fn token(&self, secret_ref: &SecretKeyRef) -> Result<String, GatewayFactoryError> {
        let where_ = || {
            format!(
                "secret {}/{} key {:?}",
                secret_ref.namespace, secret_ref.name, secret_ref.key
            )
        };
        let bytes = read_local_instance_token(&self.client, secret_ref, &api::ANNOTATIONS)
            .await
            .map_err(|e| match e {
                TokenSecretError::NotAllowed { .. } => {
                    GatewayFactoryError::TokenNotAllowed(e.to_string())
                }
                TokenSecretError::Kubernetes(e) => GatewayFactoryError::Kubernetes(e),
            })?
            .ok_or_else(|| GatewayFactoryError::TokenSecret(format!("{} not found", where_())))?;
        let token = String::from_utf8(bytes)
            .map_err(|_| GatewayFactoryError::TokenSecret(format!("{} is not UTF-8", where_())))?;
        // A token written with `echo` carries a trailing newline.
        Ok(token.trim().to_string())
    }
}

#[async_trait::async_trait]
impl GatewayFactory for HttpGatewayFactory {
    async fn gateway_for(
        &self,
        bound: &BoundInstance,
    ) -> Result<Arc<dyn AdminGateway>, GatewayFactoryError> {
        let instance = self
            .instances
            .get(bound)
            .await
            .map_err(GatewayFactoryError::Kubernetes)?
            .ok_or_else(|| GatewayFactoryError::InstanceNotFound(bound.clone()))?;
        // The token lives in the instance's own namespace.
        let local = &instance.spec.token_secret_ref;
        let secret_ref = SecretKeyRef {
            name: local.name.clone(),
            namespace: instance.namespace().unwrap_or_default(),
            key: local.key.clone(),
        };
        let token = self.token(&secret_ref).await?;
        let client =
            HttpAdminGateway::default_client().map_err(GatewayFactoryError::InvalidSpec)?;
        let gateway = HttpAdminGateway::new(&instance.spec.url, token, client)
            .map_err(GatewayFactoryError::InvalidSpec)?;
        Ok(Arc::new(gateway))
    }
}
