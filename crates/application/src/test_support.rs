//! In-memory [`AdminGateway`], [`InstanceDependents`] and
//! [`ConfigParser`] for use-case and controller tests (exposed to other
//! crates by the `test-support` feature).

use std::sync::Mutex;

use crate::ports::{
    AdminGateway, BoundInstance, ConfigError, ConfigParser, ConfigVerdict, ConfigWarning,
    GatewayError, InstanceDependents, InstanceInfo,
};

/// A BatleHub that answers, as version 1.5.0 with no configuration
/// warning, until told otherwise.
#[derive(Default)]
pub struct FakeGateway {
    failure: Mutex<Option<GatewayError>>,
    warnings_failure: Mutex<Option<GatewayError>>,
    warnings: Mutex<Vec<ConfigWarning>>,
}

impl FakeGateway {
    /// Every call fails with `failure` until it is set back to `None`.
    pub fn fail_with(&self, failure: Option<GatewayError>) {
        *self.failure.lock().unwrap() = failure;
    }

    /// Only reading the warnings fails, with `failure`.
    pub fn fail_warnings_with(&self, failure: Option<GatewayError>) {
        *self.warnings_failure.lock().unwrap() = failure;
    }

    /// The warnings BatleHub reports from now on.
    pub fn warn_with(&self, warnings: Vec<ConfigWarning>) {
        *self.warnings.lock().unwrap() = warnings;
    }

    fn check(&self) -> Result<(), GatewayError> {
        match self.failure.lock().unwrap().clone() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }
}

#[async_trait::async_trait]
impl AdminGateway for FakeGateway {
    async fn ping(&self) -> Result<InstanceInfo, GatewayError> {
        self.check()?;
        Ok(InstanceInfo {
            version: "1.5.0".into(),
        })
    }

    async fn config_warnings(&self) -> Result<Vec<ConfigWarning>, GatewayError> {
        self.check()?;
        if let Some(err) = self.warnings_failure.lock().unwrap().clone() {
            return Err(err);
        }
        Ok(self.warnings.lock().unwrap().clone())
    }
}

/// CRs bound to every instance, set by the test.
#[derive(Default)]
pub struct FakeDependents {
    dependents: Mutex<Vec<String>>,
}

impl FakeDependents {
    pub fn set(&self, dependents: Vec<String>) {
        *self.dependents.lock().unwrap() = dependents;
    }
}

#[async_trait::async_trait]
impl InstanceDependents for FakeDependents {
    async fn dependents(
        &self,
        _instance: &BoundInstance,
        _default: bool,
    ) -> Result<Vec<String>, String> {
        Ok(self.dependents.lock().unwrap().clone())
    }
}

/// A parser accepting everything but layers containing `invalid`.
#[derive(Default)]
pub struct FakeConfigParser;

impl ConfigParser for FakeConfigParser {
    fn validate(
        &self,
        layers: &[&str],
        _env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<ConfigVerdict, ConfigError> {
        match layers.iter().find(|l| l.contains("invalid")) {
            Some(_) => Err(ConfigError::Invalid("invalid layer".into())),
            None => Ok(ConfigVerdict::default()),
        }
    }
}
