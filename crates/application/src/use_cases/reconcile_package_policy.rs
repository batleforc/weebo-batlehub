//! `BatleHubPackagePolicy`: the policy of one package or version node,
//! and a version's exemptions from its gates.
//!
//! A policy can't be compared key by key without BatleHub's schema (a read
//! fills the defaults): right after writing, the operator reads it back and
//! keeps its hash; a later read hashing otherwise was changed elsewhere,
//! and is written again. BatleHub stores exemptions as `rules` entries of
//! the version's policy (`exempt: true`): they are left out of that hash,
//! carried over when the policy is rewritten (a `PUT` replaces the node)
//! or cleared (a `DELETE` would drop them), and written one gate at a
//! time. A policy or an exemption in place that this object didn't write
//! is a conflict, never taken over.

use api::package_policy::{AppliedExemption, GateExemption, PolicyRecord};
use domain::Failure;
use domain::error::ReasonCode;
use jiff::Timestamp;
use serde_json::{Map, Value};

use super::render_config::sha256;
use super::{Outcome, Writes};
use crate::ports::{AdminGateway, Exemption, GatewayError, Ledger, PackageNode};

/// What a `BatleHubPackagePolicy` asks for.
#[derive(Debug, Clone, Copy)]
pub struct PolicySpec<'a> {
    pub node: &'a PackageNode,
    pub policy: Option<&'a Value>,
    pub exemptions: &'a [GateExemption],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyReport {
    pub outcome: Outcome,
    /// What the operator wrote, after the pass (already recorded).
    pub record: PolicyRecord,
    /// Whether the pass wrote or cleared something.
    pub changed: bool,
}

/// `value` as text, its object keys sorted at every depth: a hash that
/// doesn't depend on key order.
fn canonical(value: &Value) -> String {
    fn sorted(value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                Value::Object(
                    keys.into_iter()
                        .map(|k| (k.clone(), sorted(&map[k])))
                        .collect::<Map<_, _>>(),
                )
            }
            Value::Array(items) => Value::Array(items.iter().map(sorted).collect()),
            other => other.clone(),
        }
    }
    sorted(value).to_string()
}

pub fn policy_hash(policy: &Value) -> String {
    sha256(&canonical(policy))
}

fn is_exemption(rule: &Value) -> bool {
    rule.pointer("/settings/exempt") == Some(&Value::Bool(true))
}

/// A node's policy as read, split: the policy proper (`None` when nothing
/// is left) and its exemption rules.
fn split(read: Option<Value>) -> (Option<Value>, Vec<Value>) {
    let Some(Value::Object(mut policy)) = read else {
        return (None, Vec::new());
    };
    let rules = match policy.remove("rules") {
        Some(Value::Array(rules)) => rules,
        _ => Vec::new(),
    };
    let (exemptions, rules): (Vec<Value>, Vec<Value>) = rules.into_iter().partition(is_exemption);
    if !rules.is_empty() {
        policy.insert("rules".into(), Value::Array(rules));
    }
    let policy = (!policy.is_empty()).then_some(Value::Object(policy));
    (policy, exemptions)
}

/// `policy` with `exemptions` appended to its rules: what a `PUT` must
/// carry not to drop them.
fn with_exemptions(policy: Option<&Value>, exemptions: &[Value]) -> Value {
    let mut body = match policy {
        Some(Value::Object(p)) => p.clone(),
        _ => Map::new(),
    };
    if !exemptions.is_empty() {
        let rules = body
            .entry("rules")
            .or_insert_with(|| Value::Array(Vec::new()));
        if let Value::Array(rules) = rules {
            rules.extend(exemptions.iter().cloned());
        }
    }
    Value::Object(body)
}

/// An exemption rule's gate, end and reason.
fn exemption_of(rule: &Value) -> Option<(&str, &str, &str, Option<&str>)> {
    Some((
        rule.get("gate")?.as_str()?,
        rule.pointer("/settings/exempt_until")?.as_str()?,
        rule.pointer("/settings/reason")
            .and_then(Value::as_str)
            .unwrap_or_default(),
        rule.pointer("/settings/granted_by").and_then(Value::as_str),
    ))
}

fn same_time(a: &str, b: &str) -> bool {
    match (a.parse::<Timestamp>(), b.parse::<Timestamp>()) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Gates both set in `policy.rules` and exempted: the version node holds
/// one entry per gate.
fn overlap(policy: Option<&Value>, exemptions: &[GateExemption]) -> Option<String> {
    let rules = policy?.get("rules")?.as_array()?;
    exemptions
        .iter()
        .map(|e| e.gate.as_str())
        .find(|gate| {
            rules
                .iter()
                .any(|r| r.get("gate").and_then(Value::as_str) == Some(gate))
        })
        .map(String::from)
}

pub async fn reconcile_package_policy(
    spec: PolicySpec<'_>,
    record: PolicyRecord,
    now: Timestamp,
    gateway: &dyn AdminGateway,
    ledger: &dyn Ledger<PolicyRecord>,
) -> PolicyReport {
    let mut pass = Pass {
        spec,
        gateway,
        ledger,
        record,
        changed: false,
        registry_checked: false,
        writes: Writes::default(),
    };
    let outcome = match pass.run(now).await {
        Ok((failures, expired)) => match combine(failures) {
            Some(failure) => Outcome::failed(failure),
            None => {
                let outcome = Outcome::synced(format!("policy written on {}", spec.node));
                if expired.is_empty() {
                    outcome
                } else {
                    outcome.advise(
                        ReasonCode::ExemptionExpired,
                        format!("expired, not written: {}", expired.join(", ")),
                    )
                }
            }
        },
        Err(failure) => Outcome::failed(failure),
    };
    PolicyReport {
        outcome: outcome.wrote(pass.writes),
        record: pass.record,
        changed: pass.changed,
    }
}

fn combine(failures: Vec<Failure>) -> Option<Failure> {
    let reason = failures.first()?.reason;
    let message = failures
        .into_iter()
        .map(|f| f.message)
        .collect::<Vec<_>>()
        .join("; ");
    Some(Failure::new(reason, message))
}

struct Pass<'a> {
    spec: PolicySpec<'a>,
    gateway: &'a dyn AdminGateway,
    ledger: &'a dyn Ledger<PolicyRecord>,
    record: PolicyRecord,
    changed: bool,
    registry_checked: bool,
    writes: Writes,
}

impl Pass<'_> {
    /// `Err`: the pass stopped; `Ok`: the refusals of single exemptions,
    /// and the gates whose exemption expired.
    async fn run(&mut self, now: Timestamp) -> Result<(Vec<Failure>, Vec<String>), Failure> {
        let node = self.spec.node;
        if let Some(gate) = overlap(self.spec.policy, self.spec.exemptions) {
            return Err(Failure::new(
                ReasonCode::InvalidSpec,
                format!("gate {gate} is both set in policy.rules and exempted"),
            ));
        }
        let (current, exempt_rules) = split(self.gateway.policy(node).await?);
        self.policy(current, &exempt_rules).await?;
        self.exemptions(&exempt_rules, now).await
    }

    async fn policy(
        &mut self,
        current: Option<Value>,
        exempt_rules: &[Value],
    ) -> Result<(), Failure> {
        let node = self.spec.node;
        let observed = current.as_ref().map(policy_hash);
        match self.spec.policy {
            Some(policy) => {
                let desired = Some(policy_hash(policy));
                if self.record.applied_policy_hash.is_none() && current.is_some() {
                    return Err(Failure::new(
                        ReasonCode::PolicyConflict,
                        format!(
                            "{node} already has a policy this object didn't write: \
                             clear it, or delete this object"
                        ),
                    ));
                }
                if self.record.applied_policy_hash == desired
                    && self.record.observed_policy_hash == observed
                {
                    return Ok(());
                }
                self.check_registry().await?;
                self.gateway
                    .put_policy(node, &with_exemptions(Some(policy), exempt_rules))
                    .await
                    .map_err(|e| self.refused(e))?;
                match self.record.applied_policy_hash {
                    Some(_) => self.writes.drifted("policy"),
                    None => self.writes.created(),
                }
                let (written, _) = split(self.gateway.policy(node).await?);
                self.record.applied_policy_hash = desired;
                self.record.observed_policy_hash = written.as_ref().map(policy_hash);
                self.save().await
            }
            None if self.record.applied_policy_hash.is_some() => {
                self.clear(exempt_rules).await?;
                self.writes.drifted("policy");
                self.record.applied_policy_hash = None;
                self.record.observed_policy_hash = None;
                self.save().await
            }
            None => Ok(()),
        }
    }

    /// Clears the policy proper, keeping `exempt_rules`.
    async fn clear(&self, exempt_rules: &[Value]) -> Result<(), Failure> {
        let node = self.spec.node;
        if exempt_rules.is_empty() {
            self.gateway.delete_policy(node).await?;
        } else {
            self.gateway
                .put_policy(node, &with_exemptions(None, exempt_rules))
                .await?;
        }
        Ok(())
    }

    async fn exemptions(
        &mut self,
        exempt_rules: &[Value],
        now: Timestamp,
    ) -> Result<(Vec<Failure>, Vec<String>), Failure> {
        let node = self.spec.node;
        let mut failures = Vec::new();
        let mut expired = Vec::new();
        for exemption in self.spec.exemptions {
            let gate = exemption.gate.as_str();
            let until: Timestamp = exemption.exempt_until.parse().map_err(|e| {
                Failure::new(
                    ReasonCode::InvalidSpec,
                    format!("exemptions[{gate}].exemptUntil: {e}"),
                )
            })?;
            if until <= now {
                expired.push(format!("{gate} (until {until})"));
                continue;
            }
            let until = until.to_string();
            let row = exempt_rules
                .iter()
                .filter_map(exemption_of)
                .find(|(g, ..)| *g == gate);
            let known = self
                .record
                .applied_exemptions
                .iter()
                .any(|a| a.gate == gate);
            match row {
                Some((_, _, _, by)) if !known => {
                    failures.push(Failure::new(
                        ReasonCode::PolicyConflict,
                        format!(
                            "{node} is already exempted from {gate} by {}, not by this object",
                            by.unwrap_or("an unknown user")
                        ),
                    ));
                    continue;
                }
                Some((_, row_until, reason, _))
                    if same_time(row_until, &until) && reason == exemption.reason =>
                {
                    continue;
                }
                _ => {}
            }
            self.check_registry().await?;
            let write = Exemption {
                gate: gate.to_string(),
                exempt_until: until.clone(),
                reason: exemption.reason.clone(),
            };
            match self.gateway.set_exemption(node, &write).await {
                Ok(()) => {
                    if known {
                        self.writes.drifted("exemptions");
                    } else {
                        self.writes.created();
                    }
                    let entry = AppliedExemption {
                        gate: gate.to_string(),
                        exempt_until: until,
                        reason: exemption.reason.clone(),
                    };
                    self.record.applied_exemptions.retain(|a| a.gate != gate);
                    self.record.applied_exemptions.push(entry);
                    self.save().await?;
                }
                Err(GatewayError::NotPermitted(why)) => {
                    failures.push(self.not_permitted(gate, &why).await);
                }
                Err(err @ GatewayError::Refused(_)) => {
                    failures.push(Failure::new(err.reason(), format!("{gate}: {err}")));
                }
                Err(err) => return Err(err.into()),
            }
        }
        let gone: Vec<String> = self
            .record
            .applied_exemptions
            .iter()
            .filter(|a| {
                !self
                    .spec
                    .exemptions
                    .iter()
                    .any(|e| e.gate.as_str() == a.gate)
            })
            .map(|a| a.gate.clone())
            .collect();
        for gate in gone {
            match self.gateway.delete_exemption(node, &gate).await {
                Ok(()) => {
                    self.writes.drifted("exemptions");
                    self.record.applied_exemptions.retain(|a| a.gate != gate);
                    self.save().await?;
                }
                Err(GatewayError::NotPermitted(why)) => {
                    failures.push(self.not_permitted(&gate, &why).await);
                }
                Err(err) => return Err(err.into()),
            }
        }
        Ok((failures, expired))
    }

    /// A 403 on an exemption: the grant the operator's identity needs.
    async fn not_permitted(&self, gate: &str, why: &str) -> Failure {
        let node = self.spec.node;
        let subject = match self.gateway.whoami().await {
            Ok(Some(user)) => format!("user:{user}"),
            _ => "the operator's identity".to_string(),
        };
        Failure::new(
            ReasonCode::ExemptionNotPermitted,
            format!(
                "{gate} on {node}: {why}. No role carries gates:exempt: grant it to {subject} \
                 on {} (a BatleHubPackageGrant with actions [gates:exempt], or config.grants)",
                node.package
            ),
        )
    }

    fn refused(&self, err: GatewayError) -> Failure {
        match err {
            GatewayError::Refused(_) => Failure::new(
                ReasonCode::RemoteRejected,
                format!("policy on {}: {err}", self.spec.node),
            ),
            other => other.into(),
        }
    }

    /// BatleHub writes a policy for a registry it doesn't serve without a
    /// word: checked once per pass, before the first write.
    async fn check_registry(&mut self) -> Result<(), Failure> {
        if self.registry_checked {
            return Ok(());
        }
        let registry = &self.spec.node.registry;
        if !self
            .gateway
            .registry_names()
            .await?
            .iter()
            .any(|r| r == registry)
        {
            return Err(Failure::new(
                ReasonCode::RemoteNotFound,
                format!("the instance serves no registry named {registry:?}"),
            ));
        }
        self.registry_checked = true;
        Ok(())
    }

    async fn save(&mut self) -> Result<(), Failure> {
        self.changed = true;
        self.ledger
            .record(&self.record)
            .await
            .map_err(|e| Failure::new(ReasonCode::KubernetesApiError, e))
    }
}

/// Clears what this object wrote (`record`): its exemptions, then its
/// policy, keeping the exemptions others wrote. How many things were
/// removed.
pub async fn clear_package_policy(
    node: &PackageNode,
    record: &PolicyRecord,
    gateway: &dyn AdminGateway,
) -> Result<usize, Failure> {
    let mut removed = 0;
    for exemption in &record.applied_exemptions {
        gateway.delete_exemption(node, &exemption.gate).await?;
        removed += 1;
    }
    if record.applied_policy_hash.is_some() {
        let (current, exempt_rules) = split(gateway.policy(node).await?);
        if current.is_some() || !exempt_rules.is_empty() {
            if exempt_rules.is_empty() {
                gateway.delete_policy(node).await?;
            } else {
                gateway
                    .put_policy(node, &with_exemptions(None, &exempt_rules))
                    .await?;
            }
            removed += 1;
        }
    }
    Ok(removed)
}

#[cfg(test)]
mod tests {
    use api::package_policy::Gate;
    use domain::RemoteWrite;
    use serde_json::json;

    use super::*;
    use crate::test_support::{FakeGateway, FakeLedger};

    fn version() -> PackageNode {
        PackageNode {
            registry: "npm".into(),
            package: "@acme/billing".into(),
            version: Some("1.0.0".into()),
        }
    }

    fn now() -> Timestamp {
        "2026-10-15T00:00:00Z".parse().unwrap()
    }

    fn exemption(gate: Gate, until: &str) -> GateExemption {
        GateExemption {
            gate,
            exempt_until: until.into(),
            reason: "patched downstream".into(),
        }
    }

    async fn pass(
        gateway: &FakeGateway,
        ledger: &FakeLedger<PolicyRecord>,
        policy: Option<&Value>,
        exemptions: &[GateExemption],
        record: PolicyRecord,
    ) -> PolicyReport {
        let node = version();
        let spec = PolicySpec {
            node: &node,
            policy,
            exemptions,
        };
        reconcile_package_policy(spec, record, now(), gateway, ledger).await
    }

    fn served() -> FakeGateway {
        let gateway = FakeGateway::default();
        gateway.serve(&["npm"]);
        gateway
    }

    #[test]
    fn the_hash_ignores_key_order() {
        assert_eq!(
            policy_hash(&json!({"a": 1, "b": {"c": 2, "d": 3}})),
            policy_hash(&json!({"b": {"d": 3, "c": 2}, "a": 1}))
        );
    }

    #[tokio::test]
    async fn a_policy_is_written_read_back_then_left_alone() {
        let gateway = served();
        let ledger = FakeLedger::default();
        let policy = json!({"visibility": "team", "quota": {"max_packages_per_user": 3}});
        let report = pass(
            &gateway,
            &ledger,
            Some(&policy),
            &[],
            PolicyRecord::default(),
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        assert!(report.changed);
        assert_eq!(
            report.record.applied_policy_hash,
            Some(policy_hash(&policy))
        );
        // What the instance returned, its defaults filled: not the spec's.
        assert_ne!(
            report.record.observed_policy_hash,
            report.record.applied_policy_hash
        );
        assert_eq!(ledger.records().len(), 1);
        assert_eq!(report.outcome.writes, [RemoteWrite::Created]);

        let again = pass(&gateway, &ledger, Some(&policy), &[], report.record.clone()).await;
        assert_eq!(again.outcome.reason(), ReasonCode::Reconciled);
        assert!(!again.changed);
        // Unchanged: nothing written, nothing counted.
        assert!(again.outcome.writes.is_empty());
        assert!(again.outcome.drift.is_empty());
    }

    #[tokio::test]
    async fn a_policy_changed_elsewhere_is_written_again_one_never_written_is_a_conflict() {
        let gateway = served();
        let ledger = FakeLedger::default();
        let policy = json!({"visibility": "team"});
        gateway.put_policy_row(&version(), json!({"visibility": "public"}));
        let report = pass(
            &gateway,
            &ledger,
            Some(&policy),
            &[],
            PolicyRecord::default(),
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::PolicyConflict);
        assert_eq!(
            gateway.stored_policy(&version()),
            Some(json!({"visibility": "public"}))
        );
        assert!(report.outcome.writes.is_empty());

        let gateway = served();
        let report = pass(
            &gateway,
            &ledger,
            Some(&policy),
            &[],
            PolicyRecord::default(),
        )
        .await;
        gateway.put_policy_row(&version(), json!({"visibility": "public"}));
        let again = pass(&gateway, &ledger, Some(&policy), &[], report.record).await;
        assert_eq!(again.outcome.reason(), ReasonCode::Reconciled);
        assert!(again.changed);
        assert_eq!(gateway.stored_policy(&version()), Some(policy));
        assert_eq!(again.outcome.writes, [RemoteWrite::Drift]);
        assert_eq!(again.outcome.drift.fields(), ["policy"]);
    }

    #[tokio::test]
    async fn exemptions_survive_a_policy_rewrite_and_its_removal() {
        let gateway = served();
        gateway.allow_exemptions(true);
        let ledger = FakeLedger::default();
        let policy = json!({"visibility": "team"});
        let exemptions = [exemption(Gate::CveGate, "2099-01-01T02:00:00+02:00")];
        let report = pass(
            &gateway,
            &ledger,
            Some(&policy),
            &exemptions,
            PolicyRecord::default(),
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        // Stored in UTC; the same instant in another offset is in sync.
        assert_eq!(
            report.record.applied_exemptions[0].exempt_until,
            "2099-01-01T00:00:00Z"
        );
        // The policy and the exemption.
        assert_eq!(
            report.outcome.writes,
            [RemoteWrite::Created, RemoteWrite::Created]
        );
        let again = pass(
            &gateway,
            &ledger,
            Some(&policy),
            &exemptions,
            report.record.clone(),
        )
        .await;
        assert!(!again.changed);
        assert!(again.outcome.writes.is_empty());

        // A new policy carries the exemption over.
        let stricter = json!({"visibility": "private"});
        let rewritten = pass(
            &gateway,
            &ledger,
            Some(&stricter),
            &exemptions,
            report.record,
        )
        .await;
        assert_eq!(rewritten.outcome.reason(), ReasonCode::Reconciled);
        let stored = gateway.stored_policy(&version()).unwrap();
        assert_eq!(stored["visibility"], "private");
        assert_eq!(stored["rules"][0]["gate"], "cve_gate");
        assert_eq!(rewritten.outcome.writes, [RemoteWrite::Drift]);

        // The policy out of the spec: cleared, the exemption kept.
        let cleared = pass(&gateway, &ledger, None, &exemptions, rewritten.record).await;
        assert_eq!(cleared.outcome.reason(), ReasonCode::Reconciled);
        assert_eq!(cleared.record.applied_policy_hash, None);
        let stored = gateway.stored_policy(&version()).unwrap();
        assert!(stored.get("visibility").is_none());
        assert_eq!(stored["rules"][0]["gate"], "cve_gate");
        assert_eq!(cleared.outcome.writes, [RemoteWrite::Drift]);

        // Then the exemption out too.
        let empty = pass(&gateway, &ledger, None, &[], cleared.record).await;
        assert_eq!(empty.outcome.reason(), ReasonCode::Reconciled);
        assert!(empty.record.applied_exemptions.is_empty());
        assert_eq!(empty.outcome.writes, [RemoteWrite::Drift]);
        assert_eq!(empty.outcome.drift.fields(), ["exemptions"]);
        assert_eq!(
            gateway.stored_policy(&version()).unwrap()["rules"],
            json!([])
        );
    }

    #[tokio::test]
    async fn exemptions_need_the_verb_expired_ones_are_reported_foreign_ones_kept() {
        let gateway = served();
        let ledger = FakeLedger::default();
        let report = pass(
            &gateway,
            &ledger,
            None,
            &[exemption(Gate::CveGate, "2099-01-01T00:00:00Z")],
            PolicyRecord::default(),
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::ExemptionNotPermitted);
        let message = report.outcome.ready.unwrap_err().message;
        assert!(message.contains("user:operator"), "{message}");

        gateway.allow_exemptions(true);
        let report = pass(
            &gateway,
            &ledger,
            None,
            &[exemption(Gate::LicenseGate, "2020-01-01T00:00:00Z")],
            PolicyRecord::default(),
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        assert_eq!(
            report.outcome.advisories[0].reason,
            ReasonCode::ExemptionExpired
        );
        assert!(gateway.stored_policy(&version()).is_none());

        gateway.put_policy_row(
            &version(),
            json!({"rules": [{"gate": "flags", "settings": {
                "exempt": true, "exempt_until": "2099-01-01T00:00:00Z",
                "reason": "theirs", "granted_by": "admin",
            }}]}),
        );
        let report = pass(
            &gateway,
            &ledger,
            None,
            &[exemption(Gate::Flags, "2099-01-01T00:00:00Z")],
            PolicyRecord::default(),
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::PolicyConflict);
        assert!(
            report
                .outcome
                .ready
                .unwrap_err()
                .message
                .contains("by admin")
        );
    }

    #[tokio::test]
    async fn refusals_map_onto_their_codes() {
        let gateway = FakeGateway::default();
        let ledger = FakeLedger::default();
        let policy = json!({"visibility": "team"});
        let report = pass(
            &gateway,
            &ledger,
            Some(&policy),
            &[],
            PolicyRecord::default(),
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::RemoteNotFound);
        assert!(gateway.stored_policy(&version()).is_none());
        gateway.serve(&["npm"]);
        let bad = json!({"visibility": "nope"});
        let report = pass(&gateway, &ledger, Some(&bad), &[], PolicyRecord::default()).await;
        assert_eq!(report.outcome.reason(), ReasonCode::RemoteRejected);
        let both = json!({"rules": [{"gate": "cve_gate", "settings": {}}]});
        let report = pass(
            &gateway,
            &ledger,
            Some(&both),
            &[exemption(Gate::CveGate, "2099-01-01T00:00:00Z")],
            PolicyRecord::default(),
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::InvalidSpec);
    }

    #[tokio::test]
    async fn clearing_removes_only_what_was_written() {
        let gateway = served();
        gateway.allow_exemptions(true);
        let ledger = FakeLedger::default();
        let policy = json!({"visibility": "team"});
        let report = pass(
            &gateway,
            &ledger,
            Some(&policy),
            &[exemption(Gate::CveGate, "2099-01-01T00:00:00Z")],
            PolicyRecord::default(),
        )
        .await;
        // Someone else's exemption, added since.
        let mut stored = gateway.stored_policy(&version()).unwrap();
        stored["rules"]
            .as_array_mut()
            .unwrap()
            .push(json!({"gate": "flags", "settings": {
                "exempt": true, "exempt_until": "2099-01-01T00:00:00Z", "reason": "theirs",
            }}));
        gateway.put_policy_row(&version(), stored);
        assert_eq!(
            clear_package_policy(&version(), &report.record, &gateway)
                .await
                .unwrap(),
            2
        );
        assert_eq!(
            gateway.stored_policy(&version()),
            Some(json!({"rules": [{"gate": "flags", "settings": {
                "exempt": true, "exempt_until": "2099-01-01T00:00:00Z", "reason": "theirs",
            }}]}))
        );
    }
}
