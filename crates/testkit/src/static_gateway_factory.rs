//! Test-only `GatewayFactory` and `InstanceDirectory`: the one gateway it
//! was built with, whatever the instance — no `BatleHubLocalInstance` nor
//! token `Secret` is needed. An unknown instance can still be simulated.

use std::collections::BTreeSet;
use std::sync::Arc;

use application::ports::{
    AdminGateway, BoundInstance, GatewayFactory, GatewayFactoryError, InstanceDirectory,
    InstanceError, ResolveError,
};
use weebo_kit_api::InstanceRef;

pub struct StaticGatewayFactory {
    gateway: Arc<dyn AdminGateway>,
    missing: BTreeSet<String>,
}

impl StaticGatewayFactory {
    pub fn new(gateway: Arc<dyn AdminGateway>) -> Self {
        Self {
            gateway,
            missing: BTreeSet::new(),
        }
    }

    /// The instance named `instance` doesn't exist (`InstanceNotFound`).
    pub fn without(mut self, instance: &str) -> Self {
        self.missing.insert(instance.to_string());
        self
    }
}

#[async_trait::async_trait]
impl GatewayFactory for StaticGatewayFactory {
    async fn gateway_for(
        &self,
        instance: &BoundInstance,
    ) -> Result<Arc<dyn AdminGateway>, GatewayFactoryError> {
        if self.missing.contains(&instance.name) {
            return Err(GatewayFactoryError::InstanceNotFound(instance.clone()));
        }
        Ok(self.gateway.clone())
    }
}

/// Every name is a `BatleHubLocalInstance` of the CR's namespace (or the
/// one the ref names), except the missing ones. No ref: not found.
#[async_trait::async_trait]
impl InstanceDirectory for StaticGatewayFactory {
    async fn resolve(
        &self,
        cr_namespace: Option<&str>,
        instance_ref: Option<&InstanceRef>,
        _recorded: Option<&BoundInstance>,
    ) -> Result<BoundInstance, InstanceError> {
        let Some(r) = instance_ref else {
            return Err(ResolveError::NoInstance.into());
        };
        let namespace = r.namespace.as_deref().or(cr_namespace);
        match namespace {
            Some(ns) if !self.missing.contains(&r.name) => Ok(BoundInstance::local(ns, &r.name)),
            _ => Err(ResolveError::NotFound {
                kind: "BatleHubLocalInstance".into(),
                name: r.name.clone(),
            }
            .into()),
        }
    }
}
