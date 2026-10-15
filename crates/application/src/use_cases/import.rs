//! What the importer reads of an instance's governance: the grants and
//! policies written on package and version nodes (the console's, the
//! CLI's), as the `BatleHubPackageGrant` and `BatleHubPackagePolicy` that
//! would have written them — and the status those would hold, so the
//! operator adopts them instead of finding them foreign (§4.6: the
//! importer is the only adoption path).
//!
//! The nodes come from the instance's package listing (one entry per
//! version), its exemptions, and the packages named explicitly (a policy
//! on a package the instance never cached isn't listed). The ownership
//! projection's rows are left out: they are package ownership's, not
//! grants anyone wrote.

use std::collections::BTreeMap;

use api::package_grant::{AppliedGrant, SubjectGrant};
use api::package_policy::{AppliedExemption, Gate, GateExemption};
use domain::Failure;
use serde_json::{Map, Value};

use super::reconcile_package_policy::policy_hash;
use crate::ports::{AdminGateway, PackageNode, StoredGrant};

/// What to import.
#[derive(Debug, Clone, Default)]
pub struct Scope {
    /// Only these registries; all the instance serves when empty.
    pub registries: Vec<String>,
    /// Packages read besides the listed ones.
    pub packages: Vec<String>,
}

/// The grants of one node, and what the CR's status records of them.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportedGrant {
    pub node: PackageNode,
    pub grants: Vec<SubjectGrant>,
    pub applied: Vec<AppliedGrant>,
}

/// The policy of one node, and what the CR's status records of it.
#[derive(Debug, Clone, PartialEq)]
pub struct ImportedPolicy {
    pub node: PackageNode,
    pub policy: Option<Value>,
    pub exemptions: Vec<GateExemption>,
    pub applied_policy_hash: Option<String>,
    pub observed_policy_hash: Option<String>,
    pub applied_exemptions: Vec<AppliedExemption>,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Imported {
    pub grants: Vec<ImportedGrant>,
    pub policies: Vec<ImportedPolicy>,
    pub warnings: Vec<String>,
}

fn gate(name: &str) -> Option<Gate> {
    serde_json::from_value(Value::String(name.into())).ok()
}

/// A node's policy as read: the policy proper (`None` when nothing is
/// left) and its exemptions, those of a gate the CRD doesn't know set
/// aside.
fn split(node: &PackageNode, read: Value, warnings: &mut Vec<String>) -> ImportedPolicy {
    let mut policy = match read {
        Value::Object(policy) => policy,
        _ => Map::new(),
    };
    let rules = match policy.remove("rules") {
        Some(Value::Array(rules)) => rules,
        _ => Vec::new(),
    };
    let mut kept = Vec::new();
    let mut exemptions = Vec::new();
    let mut applied = Vec::new();
    for rule in rules {
        if rule.pointer("/settings/exempt") != Some(&Value::Bool(true)) {
            kept.push(rule);
            continue;
        }
        let name = rule["gate"].as_str().unwrap_or_default().to_string();
        let until = rule
            .pointer("/settings/exempt_until")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let reason = rule
            .pointer("/settings/reason")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        match gate(&name) {
            Some(gate) if !reason.is_empty() => {
                exemptions.push(GateExemption {
                    gate,
                    exempt_until: until.clone(),
                    reason: reason.clone(),
                });
                applied.push(AppliedExemption {
                    gate: name,
                    exempt_until: until,
                    reason,
                });
            }
            _ => warnings.push(format!(
                "{node}: the exemption from {name:?} isn't imported (an unknown gate, or no \
                 reason)"
            )),
        }
    }
    if !kept.is_empty() {
        policy.insert("rules".into(), Value::Array(kept));
    }
    let policy = (!policy.is_empty()).then_some(Value::Object(policy));
    let hash = policy.as_ref().map(policy_hash);
    ImportedPolicy {
        node: node.clone(),
        policy,
        exemptions,
        applied_policy_hash: hash.clone(),
        observed_policy_hash: hash,
        applied_exemptions: applied,
    }
}

fn grant_of(node: PackageNode, rows: Vec<StoredGrant>) -> ImportedGrant {
    let mut grants = Vec::new();
    let mut applied = Vec::new();
    for row in rows {
        grants.push(SubjectGrant {
            subject: row.subject.clone(),
            actions: row.actions.clone(),
        });
        let mut set = row.actions.clone();
        set.sort();
        set.dedup();
        applied.push(AppliedGrant {
            subject: row.subject,
            requested: set.clone(),
            stored: set,
            warnings: Vec::new(),
        });
    }
    ImportedGrant {
        node,
        grants,
        applied,
    }
}

pub async fn import_governance(
    gateway: &dyn AdminGateway,
    scope: &Scope,
) -> Result<Imported, Failure> {
    let mut imported = Imported::default();
    let registries = if scope.registries.is_empty() {
        gateway.registry_names().await?
    } else {
        scope.registries.clone()
    };
    for registry in registries {
        let mut catalogue: BTreeMap<String, Vec<String>> = gateway.packages(&registry).await?;
        for package in &scope.packages {
            catalogue.entry(package.clone()).or_default();
        }
        for (package, version) in gateway.exemption_nodes(&registry).await? {
            let versions = catalogue.entry(package).or_default();
            if !versions.contains(&version) {
                versions.push(version);
            }
        }
        for (package, mut versions) in catalogue {
            // Grants: one read for the package and its versions.
            let mut by_node: BTreeMap<Option<String>, Vec<StoredGrant>> = BTreeMap::new();
            for (version, grant) in gateway.package_grants(&registry, &package).await? {
                if grant.from_ownership {
                    continue;
                }
                if let Some(v) = &version
                    && !versions.contains(v)
                {
                    versions.push(v.clone());
                }
                by_node.entry(version).or_default().push(grant);
            }
            for (version, rows) in by_node {
                let node = PackageNode {
                    registry: registry.clone(),
                    package: package.clone(),
                    version,
                };
                imported.grants.push(grant_of(node, rows));
            }
            // Policies: the package node, then each version.
            versions.sort();
            for version in std::iter::once(None).chain(versions.into_iter().map(Some)) {
                let node = PackageNode {
                    registry: registry.clone(),
                    package: package.clone(),
                    version,
                };
                if let Some(read) = gateway.policy(&node).await? {
                    let policy = split(&node, read, &mut imported.warnings);
                    if policy.policy.is_some() || !policy.exemptions.is_empty() {
                        imported.policies.push(policy);
                    }
                }
            }
        }
    }
    Ok(imported)
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::test_support::FakeGateway;

    fn node(version: Option<&str>) -> PackageNode {
        PackageNode {
            registry: "npm".into(),
            package: "@acme/billing".into(),
            version: version.map(String::from),
        }
    }

    #[tokio::test]
    async fn grants_and_policies_are_read_owners_and_unknown_gates_left_out() {
        let gateway = FakeGateway::default();
        gateway.serve(&["npm"]);
        gateway.put_grant_row(
            &node(None),
            StoredGrant {
                subject: "user:alice".into(),
                actions: vec!["releases:read".into(), "releases:list".into()],
                ..Default::default()
            },
        );
        gateway.own(&node(None), "user:carol");
        gateway.put_grant_row(
            &node(Some("1.0.0")),
            StoredGrant {
                subject: "group:oidc:qa".into(),
                actions: vec!["releases:read".into()],
                ..Default::default()
            },
        );
        gateway.put_policy_row(&node(None), json!({"visibility": "team"}));
        gateway.put_policy_row(
            &node(Some("1.0.0")),
            json!({"rules": [
                {"gate": "license_gate", "settings": {"allow": ["MIT"]}},
                {"gate": "cve_gate", "settings": {"exempt": true,
                    "exempt_until": "2099-01-01T00:00:00Z", "reason": "patched"}},
                {"gate": "future_gate", "settings": {"exempt": true,
                    "exempt_until": "2099-01-01T00:00:00Z", "reason": "?"}},
            ]}),
        );

        let imported = import_governance(&gateway, &Scope::default())
            .await
            .unwrap();
        assert_eq!(imported.grants.len(), 2);
        let package = &imported.grants[0];
        assert_eq!(package.node, node(None));
        assert_eq!(package.grants.len(), 1, "the owner's row is left out");
        assert_eq!(
            package.applied[0].stored,
            ["releases:list", "releases:read"]
        );
        assert_eq!(imported.grants[1].node, node(Some("1.0.0")));

        assert_eq!(imported.policies.len(), 2);
        let version = &imported.policies[1];
        assert_eq!(
            version.policy,
            Some(json!({"rules": [{"gate": "license_gate", "settings": {"allow": ["MIT"]}}]}))
        );
        assert_eq!(version.exemptions.len(), 1);
        assert_eq!(version.applied_exemptions[0].gate, "cve_gate");
        // The status the controller computes from the same read.
        assert_eq!(version.applied_policy_hash, version.observed_policy_hash);
        assert_eq!(
            version.observed_policy_hash,
            Some(policy_hash(version.policy.as_ref().unwrap()))
        );
        assert_eq!(imported.warnings.len(), 1);
        assert!(imported.warnings[0].contains("future_gate"));
    }
}
