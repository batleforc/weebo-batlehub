//! In-memory [`AdminGateway`] and [`ConfigParser`] for use-case and
//! controller tests (exposed to other crates by the `test-support`
//! feature).

use std::sync::Mutex;

use crate::ports::{
    AdminGateway, ConfigError, ConfigParser, ConfigVerdict, GatewayError, InstanceInfo,
};

/// A BatleHub that answers, as version 1.4.0, until told to fail.
#[derive(Default)]
pub struct FakeGateway {
    failure: Mutex<Option<GatewayError>>,
}

impl FakeGateway {
    /// Every call fails with `failure` until it is set back to `None`.
    pub fn fail_with(&self, failure: Option<GatewayError>) {
        *self.failure.lock().unwrap() = failure;
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
            version: "1.4.0".into(),
        })
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
