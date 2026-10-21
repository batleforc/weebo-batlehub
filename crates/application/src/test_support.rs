//! In-memory [`AdminGateway`], [`InstanceDependents`], [`ConfigParser`]
//! and [`ConfigSources`] for use-case and controller tests (exposed to
//! other crates by the `test-support` feature).

use std::collections::BTreeMap;
use std::sync::Mutex;

use serde_json::Value;

use crate::ports::{
    AdminGateway, AdminRequest, BoundInstance, ConfigError, ConfigParser, ConfigSource,
    ConfigSources, ConfigVerdict, ConfigWarning, Exemption, GatewayError, GrantWrite,
    InstanceDependents, InstanceInfo, KeyChanges, Ledger, PackageNode, PendingSource, RegistryView,
    ReloadCheck, Reloaded, SourceError, StoredGrant, TeamNamespace, TokenCheck,
};

/// What `releases:*` expands to, as BatleHub stores it.
pub const RELEASES: [&str; 6] = [
    "releases:read",
    "releases:list",
    "releases:publish",
    "releases:overwrite",
    "releases:yank",
    "releases:delete",
];

/// The rows of the ownership projection.
const OWNERSHIP: [&str; 3] = ["owners:read", "owners:write", "releases:publish"];

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
    /// The configuration and claim calls made, in order.
    calls: Mutex<Vec<String>>,
    /// The registries the instance serves.
    registries: Mutex<Vec<String>>,
    /// The team namespaces, by `(registry, prefix)`.
    claims: Mutex<BTreeMap<(String, String), TeamNamespace>>,
    /// The grants, by node then subject.
    grants: Mutex<BTreeMap<PackageNode, BTreeMap<String, StoredGrant>>>,
    /// The policies, by node.
    policies: Mutex<BTreeMap<PackageNode, Value>>,
    /// Whether the operator holds `gates:exempt`.
    exempt_allowed: Mutex<bool>,
    /// The admin calls made (`call`), and the answer they get.
    requests: Mutex<Vec<AdminRequest>>,
    answer: Mutex<Option<Result<Value, GatewayError>>>,
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

    /// The restart-only keys every dry run and reload reports from now on.
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

    /// The registries the instance serves from now on.
    pub fn serve(&self, registries: &[&str]) {
        *self.registries.lock().unwrap() = registries.iter().map(|r| r.to_string()).collect();
    }

    /// A claim in place, as if made by someone else.
    pub fn put_claim(&self, registry: &str, namespace: TeamNamespace) {
        self.claims
            .lock()
            .unwrap()
            .insert((registry.into(), namespace.prefix.clone()), namespace);
    }

    /// The claim of `prefix` on `registry`, if any.
    pub fn claim(&self, registry: &str, prefix: &str) -> Option<TeamNamespace> {
        self.claims
            .lock()
            .unwrap()
            .get(&(registry.into(), prefix.into()))
            .cloned()
    }

    /// A grant in place, as if written by someone else.
    pub fn put_grant_row(&self, node: &PackageNode, grant: StoredGrant) {
        self.grants
            .lock()
            .unwrap()
            .entry(node.clone())
            .or_default()
            .insert(grant.subject.clone(), grant);
    }

    /// `subject`'s grant on `node`, if any.
    pub fn grant_row(&self, node: &PackageNode, subject: &str) -> Option<StoredGrant> {
        self.grants
            .lock()
            .unwrap()
            .get(node)
            .and_then(|g| g.get(subject))
            .cloned()
    }

    /// Removes `subject`'s grant, as the console would.
    pub fn remove_grant_row(&self, node: &PackageNode, subject: &str) {
        if let Some(g) = self.grants.lock().unwrap().get_mut(node) {
            g.remove(subject);
        }
    }

    /// `subject` becomes an owner of the package `node`: the ownership
    /// projection writes its row.
    pub fn own(&self, node: &PackageNode, subject: &str) {
        self.put_grant_row(
            node,
            StoredGrant {
                subject: subject.into(),
                actions: OWNERSHIP.iter().map(|a| a.to_string()).collect(),
                from_ownership: true,
                granted_by: None,
            },
        );
    }

    /// The policy of `node` as stored (exemptions included).
    pub fn stored_policy(&self, node: &PackageNode) -> Option<Value> {
        self.policies.lock().unwrap().get(node).cloned()
    }

    /// A policy in place, as if written by someone else.
    pub fn put_policy_row(&self, node: &PackageNode, policy: Value) {
        self.policies.lock().unwrap().insert(node.clone(), policy);
    }

    /// Whether the operator's identity holds `gates:exempt`.
    pub fn allow_exemptions(&self, allowed: bool) {
        *self.exempt_allowed.lock().unwrap() = allowed;
    }

    /// The admin calls made through `call`.
    pub fn requests(&self) -> Vec<AdminRequest> {
        self.requests.lock().unwrap().clone()
    }

    /// What `call` answers from now on (`{"ok": true}` by default).
    pub fn answer(&self, answer: Option<Result<Value, GatewayError>>) {
        *self.answer.lock().unwrap() = answer;
    }

    /// A governance call: recorded, failing with `failure` when set, and
    /// 404 on a registry the instance doesn't serve.
    fn governance_call(&self, name: &str, registry: &str) -> Result<(), GatewayError> {
        self.claim_call(name)?;
        if !self
            .registries
            .lock()
            .unwrap()
            .iter()
            .any(|r| r == registry)
        {
            return Err(GatewayError::NotFound(format!(
                "registry '{registry}' is not configured"
            )));
        }
        Ok(())
    }

    /// A claim call: recorded, failing with `failure` when set.
    fn claim_call(&self, name: &str) -> Result<(), GatewayError> {
        self.calls.lock().unwrap().push(name.to_string());
        self.check()
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

    /// Reads the file: loads it when its bytes differ from the last
    /// attempt (refused like a stage), else nothing to apply.
    async fn reload(&self) -> Result<Reloaded, GatewayError> {
        self.call("reload")?;
        let file = self.file();
        let mut last = self.last_attempt.lock().unwrap();
        if last.as_deref() == Some(file.as_str()) {
            return Ok(Reloaded::AlreadyTried);
        }
        *last = Some(file.clone());
        drop(last);
        self.judge(&file)?;
        *self.loaded.lock().unwrap() = Some(file);
        Ok(Reloaded::Loaded {
            restart_required: self.restart_required.lock().unwrap().clone(),
            partially_applied: Vec::new(),
        })
    }

    async fn registry_names(&self) -> Result<Vec<String>, GatewayError> {
        self.claim_call("registries")?;
        Ok(self.registries.lock().unwrap().clone())
    }

    async fn team_namespaces(&self, registry: &str) -> Result<Vec<TeamNamespace>, GatewayError> {
        self.claim_call("namespaces")?;
        Ok(self
            .claims
            .lock()
            .unwrap()
            .iter()
            .filter(|((r, _), _)| r == registry)
            .map(|(_, n)| n.clone())
            .collect())
    }

    async fn claim_namespace(
        &self,
        registry: &str,
        namespace: &TeamNamespace,
    ) -> Result<(), GatewayError> {
        self.claim_call("claim")?;
        let mut claims = self.claims.lock().unwrap();
        let key = (registry.to_string(), namespace.prefix.clone());
        if claims.contains_key(&key) {
            return Err(GatewayError::AlreadyClaimed(format!(
                "namespace '{}' in registry '{registry}' is already claimed",
                namespace.prefix
            )));
        }
        claims.insert(key, namespace.clone());
        Ok(())
    }

    async fn release_namespace(&self, registry: &str, prefix: &str) -> Result<(), GatewayError> {
        self.claim_call("release")?;
        self.claims
            .lock()
            .unwrap()
            .remove(&(registry.to_string(), prefix.to_string()));
        Ok(())
    }

    async fn grants(&self, node: &PackageNode) -> Result<Vec<StoredGrant>, GatewayError> {
        self.claim_call("grants")?;
        Ok(self
            .grants
            .lock()
            .unwrap()
            .get(node)
            .map(|g| g.values().cloned().collect())
            .unwrap_or_default())
    }

    async fn put_grant(
        &self,
        node: &PackageNode,
        subject: &str,
        actions: &[String],
    ) -> Result<GrantWrite, GatewayError> {
        self.governance_call("put-grant", &node.registry)?;
        let mut stored: Vec<String> = Vec::new();
        for action in actions {
            let expanded: Vec<String> = match action.as_str() {
                "releases:*" => RELEASES.iter().map(|a| a.to_string()).collect(),
                a if a.starts_with("releases:")
                    || a.starts_with("owners:")
                    || a.starts_with("gates:") =>
                {
                    vec![a.to_string()]
                }
                a => return Err(GatewayError::Refused(format!("unknown action '{a}'"))),
            };
            for a in expanded {
                if !stored.contains(&a) {
                    stored.push(a);
                }
            }
        }
        let owned = self
            .grant_row(node, subject)
            .is_some_and(|g| g.from_ownership);
        if owned && !OWNERSHIP.iter().all(|a| stored.iter().any(|s| s == a)) {
            return Err(GatewayError::HeldByOwnership(format!(
                "'{subject}' holds owners:read, owners:write, releases:publish through ownership"
            )));
        }
        let warnings = if subject == "*" {
            vec!["subject already holds releases:read from a broader tier".to_string()]
        } else {
            Vec::new()
        };
        self.put_grant_row(
            node,
            StoredGrant {
                subject: subject.into(),
                actions: stored.clone(),
                from_ownership: false,
                granted_by: Some("operator".into()),
            },
        );
        Ok(GrantWrite { stored, warnings })
    }

    async fn delete_grant(&self, node: &PackageNode, subject: &str) -> Result<bool, GatewayError> {
        self.claim_call("delete-grant")?;
        if self
            .grant_row(node, subject)
            .is_some_and(|g| g.from_ownership)
        {
            return Err(GatewayError::HeldByOwnership(format!(
                "'{subject}' holds this grant through ownership"
            )));
        }
        let existed = self.grant_row(node, subject).is_some();
        self.remove_grant_row(node, subject);
        Ok(existed)
    }

    async fn policy(&self, node: &PackageNode) -> Result<Option<Value>, GatewayError> {
        self.claim_call("policy")?;
        // As BatleHub reads it back: the defaults of a section filled.
        Ok(self.stored_policy(node).map(|mut policy| {
            if let Some(Value::Object(quota)) = policy.get_mut("quota") {
                quota.entry("block").or_insert(Value::Bool(false));
            }
            policy
        }))
    }

    async fn put_policy(&self, node: &PackageNode, policy: &Value) -> Result<(), GatewayError> {
        self.governance_call("put-policy", &node.registry)?;
        if policy.get("visibility").is_some_and(|v| v == "nope") {
            return Err(GatewayError::Refused("unknown visibility 'nope'".into()));
        }
        self.put_policy_row(node, policy.clone());
        Ok(())
    }

    async fn delete_policy(&self, node: &PackageNode) -> Result<(), GatewayError> {
        self.claim_call("delete-policy")?;
        self.policies.lock().unwrap().remove(node);
        Ok(())
    }

    async fn set_exemption(
        &self,
        node: &PackageNode,
        exemption: &Exemption,
    ) -> Result<(), GatewayError> {
        self.governance_call("exempt", &node.registry)?;
        if !*self.exempt_allowed.lock().unwrap() {
            return Err(GatewayError::NotPermitted(
                "gates:exempt required on this coordinate".into(),
            ));
        }
        let mut policies = self.policies.lock().unwrap();
        let policy = policies
            .entry(node.clone())
            .or_insert_with(|| serde_json::json!({}));
        let rules = policy
            .as_object_mut()
            .expect("a policy is an object")
            .entry("rules")
            .or_insert_with(|| Value::Array(Vec::new()))
            .as_array_mut()
            .expect("rules is an array");
        rules.retain(|r| r["gate"] != exemption.gate.as_str());
        rules.push(serde_json::json!({
            "gate": exemption.gate,
            "settings": {
                "exempt": true,
                "exempt_until": exemption.exempt_until,
                "reason": exemption.reason,
                "granted_by": "operator",
                "self_approved": false,
            },
        }));
        Ok(())
    }

    async fn delete_exemption(&self, node: &PackageNode, gate: &str) -> Result<(), GatewayError> {
        self.claim_call("unexempt")?;
        if !*self.exempt_allowed.lock().unwrap() {
            return Err(GatewayError::NotPermitted(
                "gates:exempt required on this coordinate".into(),
            ));
        }
        if let Some(rules) = self
            .policies
            .lock()
            .unwrap()
            .get_mut(node)
            .and_then(|p| p.get_mut("rules"))
            .and_then(Value::as_array_mut)
        {
            rules.retain(|r| r["gate"] != gate);
        }
        Ok(())
    }

    /// Every package node holding a grant or a policy, with the versions
    /// of the version nodes.
    async fn packages(
        &self,
        registry: &str,
    ) -> Result<BTreeMap<String, std::collections::BTreeSet<String>>, GatewayError> {
        self.check()?;
        let mut out: BTreeMap<String, std::collections::BTreeSet<String>> = BTreeMap::new();
        let grants = self.grants.lock().unwrap();
        let policies = self.policies.lock().unwrap();
        for node in grants.keys().chain(policies.keys()) {
            if node.registry != registry {
                continue;
            }
            let versions = out.entry(node.package.clone()).or_default();
            if let Some(v) = &node.version {
                versions.insert(v.clone());
            }
        }
        Ok(out)
    }

    async fn package_grants(
        &self,
        registry: &str,
        package: &str,
    ) -> Result<Vec<(Option<String>, StoredGrant)>, GatewayError> {
        self.check()?;
        Ok(self
            .grants
            .lock()
            .unwrap()
            .iter()
            .filter(|(node, _)| node.registry == registry && node.package == package)
            .flat_map(|(node, rows)| {
                rows.values()
                    .map(move |g| (node.version.clone(), g.clone()))
            })
            .collect())
    }

    async fn exemption_nodes(&self, registry: &str) -> Result<Vec<(String, String)>, GatewayError> {
        self.check()?;
        Ok(self
            .policies
            .lock()
            .unwrap()
            .iter()
            .filter(|(node, policy)| {
                node.registry == registry
                    && policy["rules"]
                        .as_array()
                        .is_some_and(|r| r.iter().any(|r| r["settings"]["exempt"] == true))
            })
            .filter_map(|(node, _)| Some((node.package.clone(), node.version.clone()?)))
            .collect())
    }

    async fn whoami(&self) -> Result<Option<String>, GatewayError> {
        self.check()?;
        Ok(Some("operator".into()))
    }

    async fn call(&self, request: &AdminRequest) -> Result<Value, GatewayError> {
        self.requests.lock().unwrap().push(request.clone());
        self.check()?;
        self.answer
            .lock()
            .unwrap()
            .clone()
            .unwrap_or_else(|| Ok(serde_json::json!({"ok": true})))
    }
}

/// Records every write, failing when told to.
pub struct FakeLedger<T> {
    records: Mutex<Vec<T>>,
    fail: Mutex<bool>,
}

impl<T> Default for FakeLedger<T> {
    fn default() -> Self {
        Self {
            records: Mutex::new(Vec::new()),
            fail: Mutex::new(false),
        }
    }
}

impl<T: Clone> FakeLedger<T> {
    pub fn records(&self) -> Vec<T> {
        self.records.lock().unwrap().clone()
    }

    pub fn fail(&self, fail: bool) {
        *self.fail.lock().unwrap() = fail;
    }
}

#[async_trait::async_trait]
impl<T: Clone + Send + Sync> Ledger<T> for FakeLedger<T> {
    async fn record(&self, written: &T) -> Result<(), String> {
        if *self.fail.lock().unwrap() {
            return Err("status patch refused".into());
        }
        self.records.lock().unwrap().push(written.clone());
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

#[async_trait::async_trait]
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

    /// A changed `restart` key (`"restart": …` at the top level) is the
    /// one restart key, a changed `partial` key the one partial key.
    fn classify(&self, before: &str, after: &str) -> Result<KeyChanges, ConfigError> {
        let changed = |key: &str| {
            let read = |doc: &str| {
                serde_json::from_str::<Value>(doc)
                    .ok()
                    .and_then(|v| v.get(key).cloned())
            };
            if read(before) != read(after) {
                vec![key.to_string()]
            } else {
                Vec::new()
            }
        };
        Ok(KeyChanges {
            restart: changed("restart"),
            partial: changed("partial"),
        })
    }

    async fn hash_token(&self, token: &str) -> Result<String, ConfigError> {
        Ok(format!("hashed:{token}"))
    }

    async fn token_check(&self, document: &str, token: &str) -> TokenCheck {
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

    /// The text put for the source, read as a JSON object of strings.
    async fn read_all(
        &self,
        namespace: &str,
        source: &ConfigSource,
    ) -> Result<BTreeMap<String, Option<String>>, SourceError> {
        let text = self.read(namespace, source).await?;
        serde_json::from_str(&text).map_err(|e| SourceError::Missing(e.to_string()))
    }

    async fn registries(&self) -> Result<Vec<RegistryView>, String> {
        Ok(self.registries.lock().unwrap().clone())
    }

    async fn secret_consents(
        &self,
        namespace: &str,
        name: &str,
    ) -> Result<Option<bool>, SourceError> {
        let key = (namespace.to_string(), name.to_string());
        if self.refused.lock().unwrap().contains(&key) {
            return Ok(Some(false));
        }
        Ok(self
            .texts
            .lock()
            .unwrap()
            .contains_key(&key)
            .then_some(true))
    }
}

/// The Kubernetes objects of managed instances, in memory: the kit's
/// `FakeOwnedObjects`, plus tokens and the TokenReview binding.
#[derive(Default)]
pub struct FakeWorkloads {
    objects: weebo_kit_application::test_support::FakeOwnedObjects,
    tokens: Mutex<BTreeMap<String, String>>,
    log: Mutex<Vec<String>>,
}

impl std::ops::Deref for FakeWorkloads {
    type Target = weebo_kit_application::test_support::FakeOwnedObjects;

    fn deref(&self) -> &Self::Target {
        &self.objects
    }
}

impl FakeWorkloads {
    /// What was removed, restarted, bound and unbound.
    pub fn removed(&self) -> Vec<String> {
        let mut log = self.objects.log();
        log.extend(self.log.lock().unwrap().iter().cloned());
        log
    }

    /// The configuration file in `<name>-config`.
    pub fn config_file(&self, name: &str) -> Option<String> {
        self.objects
            .secret(&format!("{name}-config"), api::managed::CONFIG_KEY)
    }
}

#[async_trait::async_trait]
impl crate::ports::OwnedObjects for FakeWorkloads {
    async fn apply(
        &self,
        owner: &crate::ports::Owner,
        objects: &[crate::ports::OwnedObject],
    ) -> Result<(), crate::ports::WorkloadError> {
        self.objects.apply(owner, objects).await
    }

    async fn remove(
        &self,
        owner: &crate::ports::Owner,
        api_version: &str,
        kind: &str,
        name: &str,
    ) -> Result<(), crate::ports::WorkloadError> {
        self.objects.remove(owner, api_version, kind, name).await
    }

    async fn list(
        &self,
        owner: &crate::ports::Owner,
        api_version: &str,
        kind: &str,
        labels: &BTreeMap<String, String>,
    ) -> Result<Vec<weebo_kit_application::workload::Listed>, crate::ports::WorkloadError> {
        self.objects.list(owner, api_version, kind, labels).await
    }

    async fn secret_text(
        &self,
        _owner: &crate::ports::Owner,
        name: &str,
        _key: &str,
    ) -> Result<Option<String>, crate::ports::WorkloadError> {
        Ok(name
            .strip_suffix("-config")
            .and_then(|instance| self.config_file(instance)))
    }

    async fn rollout(
        &self,
        owner: &crate::ports::Owner,
        name: &str,
    ) -> Result<Option<crate::ports::Rollout>, crate::ports::WorkloadError> {
        self.objects.rollout(owner, name).await
    }

    async fn annotate_template(
        &self,
        owner: &crate::ports::Owner,
        name: &str,
        annotations: &BTreeMap<String, String>,
        restart: bool,
    ) -> Result<bool, crate::ports::WorkloadError> {
        self.objects
            .annotate_template(owner, name, annotations, restart)
            .await
    }

    async fn pods(
        &self,
        owner: &crate::ports::Owner,
        selector: &BTreeMap<String, String>,
    ) -> Result<Vec<weebo_kit_application::workload::PodState>, crate::ports::WorkloadError> {
        self.objects.pods(owner, selector).await
    }

    async fn claim_size(
        &self,
        owner: &crate::ports::Owner,
        name: &str,
    ) -> Result<Option<String>, crate::ports::WorkloadError> {
        self.objects.claim_size(owner, name).await
    }
}

#[async_trait::async_trait]
impl crate::ports::Workloads for FakeWorkloads {
    async fn operator_token(
        &self,
        _owner: &crate::ports::Owner,
        name: &str,
    ) -> Result<String, crate::ports::WorkloadError> {
        if self.objects.is_foreign("Secret", name) {
            return Err(crate::ports::WorkloadError::Conflict(format!(
                "Secret {name} exists and isn't the operator's"
            )));
        }
        Ok(self
            .tokens
            .lock()
            .unwrap()
            .entry(name.into())
            .or_insert_with(|| format!("token-of-{name}"))
            .clone())
    }

    async fn bind_token_review(
        &self,
        owner: &crate::ports::Owner,
        service_account: &str,
        cluster_role: &str,
    ) -> Result<(), crate::ports::WorkloadError> {
        self.log.lock().unwrap().push(format!(
            "bound {}/{service_account} to {cluster_role}",
            owner.namespace
        ));
        Ok(())
    }

    async fn unbind_token_review(
        &self,
        owner: &crate::ports::Owner,
        cluster_role: &str,
    ) -> Result<(), crate::ports::WorkloadError> {
        let mut log = self.log.lock().unwrap();
        log.push(format!("unbind {} from {cluster_role}", owner.name));
        if log
            .iter()
            .any(|l| l.starts_with(&format!("bound {}/", owner.namespace)))
        {
            log.push(format!("unbound {}", owner.name));
        }
        Ok(())
    }
}
