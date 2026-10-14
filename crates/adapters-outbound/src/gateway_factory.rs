//! One [`HttpAdminGateway`] per `BatleHubLocalInstance`, built on every
//! call: the instance comes from the [`LocalInstanceDirectory`] (a live
//! reflector `Store` when `operator::main` wires one in, the API
//! otherwise), its token (`external.adminTokenSecretRef`) and CA
//! (`external.tls.caSecretRef`) are read fresh — a rotated token or CA, or
//! an edited `url`, takes effect on the next reconcile.

use std::sync::Arc;

use application::ports::{AdminGateway, BoundInstance, GatewayFactory, GatewayFactoryError};
use kube::{Client, ResourceExt};
use weebo_kit_adapters::{TokenSecretError, read_local_instance_token, read_secret_key};
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

    /// A CA is no secret: read without a consent label.
    async fn ca(&self, ca_ref: &SecretKeyRef) -> Result<Vec<u8>, GatewayFactoryError> {
        read_secret_key(&self.client, ca_ref)
            .await
            .map_err(GatewayFactoryError::Kubernetes)?
            .ok_or_else(|| {
                GatewayFactoryError::InvalidSpec(format!(
                    "tls.caSecretRef: secret {}/{} key {:?} not found",
                    ca_ref.namespace, ca_ref.name, ca_ref.key
                ))
            })
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
        // The token and the CA live in the instance's own namespace.
        let namespace = instance.namespace().unwrap_or_default();
        let external = &instance.spec.external;
        let token = self
            .token(&external.admin_token_secret_ref.in_namespace(&namespace))
            .await?;
        let tls = external.tls.in_namespace(&namespace);
        let ca_pem = match &tls.ca_secret_ref {
            Some(ca_ref) => Some(self.ca(ca_ref).await?),
            None => None,
        };
        let client = HttpAdminGateway::client(ca_pem.as_deref(), tls.insecure_skip_verify)
            .map_err(GatewayFactoryError::InvalidSpec)?;
        let gateway = HttpAdminGateway::new(&external.url, token, client)
            .map_err(GatewayFactoryError::InvalidSpec)?;
        Ok(Arc::new(gateway))
    }
}
