//! In-memory [`AdminGateway`], [`InstanceDependents`], [`ConfigParser`]
//! and [`ConfigSources`] for use-case and controller tests (exposed to
//! other crates by the `test-support` feature).

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::Value;

use crate::ports::{
    AdminGateway, BoundInstance, ConfigError, ConfigParser, ConfigSource, ConfigSources,
    ConfigVerdict, ConfigWarning, GatewayError, InstanceDependents, InstanceInfo, PendingSource,
    RegistryView, ReloadCheck, SourceError, TokenCheck,
};

/// A BatleHub that answers, as version 1.6.0 with no configuration
/// warning, until told otherwise — and whose configuration endpoints
/// behave like BatleHub's reload service: a file on disk, a pending
/// reload, and no staging of bytes identical to the last load attempt.
#[derive(Default)]
pub struct FakeGateway {
    failure: Mutex<Option<GatewayError>>,
    warnings_failure: Mutex<Option<GatewayError>>,
    warnings: Mutex<Vec<ConfigWarning>>,
    /// The first configuration file, on the instance's disk.
    file: Mutex<String>,
    /// What the instance runs (in memory).
    loaded: Mutex<Option<String>>,
    last_attempt: Mutex<Option<String>>,
    pending: Mutex<Option<(String, PendingSource)>>,
    restart_required: Mutex<Vec<String>>,
    /// Content containing this is refused (400).
    refuse: Mutex<Option<String>>,
    read_only: Mutex<bool>,
    hot_reload_disabled: Mutex<bool>,
    /// The configuration calls made, in order.
    calls: Mutex<Vec<String>>,
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

    /// The file on disk, as if written by someone else.
    pub fn write_file(&self, content: &str) {
        *self.file.lock().unwrap() = content.to_string();
    }

    pub fn file(&self) -> String {
        self.file.lock().unwrap().clone()
    }

    pub fn loaded(&self) -> Option<String> {
        self.loaded.lock().unwrap().clone()
    }

    /// The restart-only keys every dry run reports from now on.
    pub fn require_restart(&self, keys: &[&str]) {
        *self.restart_required.lock().unwrap() = keys.iter().map(|k| k.to_string()).collect();
    }

    /// Refuses (400) any content containing `marker`.
    pub fn refuse(&self, marker: Option<&str>) {
        *self.refuse.lock().unwrap() = marker.map(String::from);
    }

    /// Applies without writing the file (the persist fails).
    pub fn read_only(&self, read_only: bool) {
        *self.read_only.lock().unwrap() = read_only;
    }

    /// `BATLEHUB_DISABLE_HOT_RELOAD=1`: the content is read-only, every
    /// other configuration endpoint answers 503.
    pub fn disable_hot_reload(&self) {
        *self.hot_reload_disabled.lock().unwrap() = true;
    }

    /// A pending reload, staged by `source`, of `content`.
    pub fn stage(&self, content: &str, source: PendingSource) {
        *self.pending.lock().unwrap() = Some((content.to_string(), source));
    }

    /// The last load attempt was `content` (staging it again stages
    /// nothing), as after a refusal or an expiry.
    pub fn attempted(&self, content: &str) {
        *self.last_attempt.lock().unwrap() = Some(content.to_string());
    }

    pub fn calls(&self) -> Vec<String> {
        self.calls.lock().unwrap().clone()
    }

    fn check(&self) -> Result<(), GatewayError> {
        match self.failure.lock().unwrap().clone() {
            Some(err) => Err(err),
            None => Ok(()),
        }
    }

    fn call(&self, name: &str) -> Result<(), GatewayError> {
        self.calls.lock().unwrap().push(name.to_string());
        self.check()?;
        if *self.hot_reload_disabled.lock().unwrap() {
            return Err(GatewayError::HotReloadDisabled(format!("{name}: 503")));
        }
        Ok(())
    }

    fn judge(&self, content: &str) -> Result<(), GatewayError> {
        match self.refuse.lock().unwrap().as_deref() {
            Some(marker) if content.contains(marker) => {
                Err(GatewayError::Rejected(format!("refused: {marker}")))
            }
            _ => Ok(()),
        }
    }
}

#[async_trait::async_trait]
impl AdminGateway for FakeGateway {
    async fn ping(&self) -> Result<InstanceInfo, GatewayError> {
        self.check()?;
        Ok(InstanceInfo {
            version: "1.6.0".into(),
        })
    }

    async fn config_warnings(&self) -> Result<Vec<ConfigWarning>, GatewayError> {
        self.check()?;
        if let Some(err) = self.warnings_failure.lock().unwrap().clone() {
            return Err(err);
        }
        Ok(self.warnings.lock().unwrap().clone())
    }

    async fn config_content(&self) -> Result<String, GatewayError> {
        self.call("content")?;
        Ok(self.file())
    }

    async fn validate_config(&self, content: &str) -> Result<ReloadCheck, GatewayError> {
        self.call("validate")?;
        self.judge(content)?;
        Ok(ReloadCheck {
            restart_required: self.restart_required.lock().unwrap().clone(),
        })
    }

    async fn stage_config(&self, content: &str) -> Result<bool, GatewayError> {
        self.call("stage")?;
        let mut last = self.last_attempt.lock().unwrap();
        if last.as_deref() == Some(content) {
            return Ok(false);
        }
        *last = Some(content.to_string());
        drop(last);
        self.judge(content)?;
        self.stage(content, PendingSource::AdminRequest);
        Ok(true)
    }

    async fn apply_pending(&self) -> Result<(), GatewayError> {
        self.call("apply")?;
        let (content, source) = self
            .pending
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| GatewayError::NoPending("no pending reload".into()))?;
        *self.loaded.lock().unwrap() = Some(content.clone());
        if source == PendingSource::AdminRequest && !*self.read_only.lock().unwrap() {
            self.write_file(&content);
        }
        Ok(())
    }

    async fn pending(&self) -> Result<Option<PendingSource>, GatewayError> {
        self.call("pending")?;
        Ok(self.pending.lock().unwrap().as_ref().map(|(_, s)| *s))
    }

    async fn discard_pending(&self) -> Result<(), GatewayError> {
        self.call("discard")?;
        *self.pending.lock().unwrap() = None;
        Ok(())
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

/// A parser whose "TOML" is JSON: a layer is an object's JSON text, the
/// merge a recursive merge of objects (the later wins), and validation
/// refuses a document containing `invalid`, asking `env` for every
/// `${NAME}`. A document accepts a token it contains.
#[derive(Default)]
pub struct FakeConfigParser;

fn merge_json(base: &mut Value, over: Value) {
    match (base, over) {
        (Value::Object(b), Value::Object(o)) => {
            for (k, v) in o {
                match b.get_mut(&k) {
                    Some(existing) => merge_json(existing, v),
                    None => {
                        b.insert(k, v);
                    }
                }
            }
        }
        (base, over) => *base = over,
    }
}

impl ConfigParser for FakeConfigParser {
    fn layer(&self, object: &Value) -> Result<String, ConfigError> {
        match object {
            Value::Object(_) => Ok(object.to_string()),
            _ => Err(ConfigError::Invalid("not an object".into())),
        }
    }

    fn fragment(&self, text: &str) -> Result<Value, ConfigError> {
        match serde_json::from_str(text) {
            Ok(value @ Value::Object(_)) => Ok(value),
            _ => Err(ConfigError::Invalid(format!("not a fragment: {text}"))),
        }
    }

    fn merge(&self, layers: &[&str]) -> Result<String, ConfigError> {
        let mut merged = Value::Object(Default::default());
        if layers.is_empty() {
            return Err(ConfigError::Invalid("no config content given".into()));
        }
        for layer in layers {
            let value: Value = serde_json::from_str(layer)
                .map_err(|e| ConfigError::Invalid(format!("not JSON: {e}")))?;
            merge_json(&mut merged, value);
        }
        Ok(merged.to_string())
    }

    fn validate(
        &self,
        layers: &[&str],
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<ConfigVerdict, ConfigError> {
        for layer in layers {
            for part in layer.split("${").skip(1) {
                if let Some(name) = part.split('}').next() {
                    env(name);
                }
            }
        }
        match layers.iter().find(|l| l.contains("invalid")) {
            Some(_) => Err(ConfigError::Invalid("invalid layer".into())),
            None => Ok(ConfigVerdict::default()),
        }
    }

    fn token_check(&self, document: &str, token: &str) -> TokenCheck {
        if document.contains(token) {
            TokenCheck::Accepted
        } else {
            TokenCheck::Refused
        }
    }
}

/// `ConfigMap`s/`Secrets` by `(namespace, name)` (any key), and
/// registries, set by the test.
#[derive(Default)]
pub struct FakeSources {
    texts: Mutex<BTreeMap<(String, String), String>>,
    refused: Mutex<Vec<(String, String)>>,
    registries: Mutex<Vec<RegistryView>>,
}

impl FakeSources {
    pub fn put(&self, namespace: &str, name: &str, text: &str) {
        self.texts
            .lock()
            .unwrap()
            .insert((namespace.into(), name.into()), text.into());
    }

    /// A `Secret` without the consent label.
    pub fn refuse(&self, namespace: &str, name: &str) {
        self.refused
            .lock()
            .unwrap()
            .push((namespace.into(), name.into()));
    }

    pub fn set_registries(&self, registries: Vec<RegistryView>) {
        *self.registries.lock().unwrap() = registries;
    }
}

#[async_trait::async_trait]
impl ConfigSources for FakeSources {
    async fn read(&self, namespace: &str, source: &ConfigSource) -> Result<String, SourceError> {
        let name = source
            .config_map_ref
            .as_ref()
            .or(source.secret_ref.as_ref())
            .map(|r| r.name.clone())
            .unwrap_or_default();
        let key = (namespace.to_string(), name.clone());
        if self.refused.lock().unwrap().contains(&key) {
            return Err(SourceError::NotAllowed(format!("{namespace}/{name}")));
        }
        self.texts
            .lock()
            .unwrap()
            .get(&key)
            .cloned()
            .ok_or_else(|| SourceError::Missing(format!("{namespace}/{name} not found")))
    }

    async fn registries(&self) -> Result<Vec<RegistryView>, String> {
        Ok(self.registries.lock().unwrap().clone())
    }
}
