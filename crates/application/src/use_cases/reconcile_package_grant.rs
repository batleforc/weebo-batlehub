//! `BatleHubPackageGrant`: the grants of one package or version node,
//! one subject at a time. The object is the source of truth of the
//! subjects it lists and of nothing else: what it wrote is in
//! `status.applied` (recorded after each write), a row it didn't write is
//! a conflict, never taken over, and a subject leaving the spec is revoked
//! because the status says the operator wrote it.

use api::package_grant::{AppliedGrant, SubjectGrant};
use domain::Failure;
use domain::error::ReasonCode;

use super::{Outcome, Writes};
use crate::ports::{AdminGateway, GatewayError, Ledger, PackageNode, StoredGrant};

/// What a pass ended on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrantReport {
    pub outcome: Outcome,
    /// What the operator wrote, after the pass (already recorded).
    pub applied: Vec<AppliedGrant>,
    /// Whether the pass wrote or revoked something.
    pub changed: bool,
}

/// `actions`, sorted, without duplicates: the order of a list means
/// nothing to BatleHub.
fn set(actions: &[String]) -> Vec<String> {
    let mut set = actions.to_vec();
    set.sort();
    set.dedup();
    set
}

/// Whether `row` is still what this object wrote, as `known` recorded it,
/// for the actions now asked.
fn in_sync(known: &AppliedGrant, row: &StoredGrant, requested: &[String]) -> bool {
    set(&known.requested) == requested && set(&known.stored) == set(&row.actions)
}

/// A row in place this object didn't write.
fn foreign(node: &PackageNode, row: &StoredGrant) -> Failure {
    if row.from_ownership {
        return Failure::new(
            ReasonCode::GrantHeldByOwnership,
            format!(
                "{} owns {}: it holds {} through ownership",
                row.subject,
                node,
                row.actions.join(", ")
            ),
        );
    }
    Failure::new(
        ReasonCode::GrantConflict,
        format!(
            "{} already holds a grant on {node} this object didn't write ({}, granted by {}): \
             remove it, or this subject from spec.grants",
            row.subject,
            row.actions.join(", "),
            row.granted_by.as_deref().unwrap_or("an unknown user"),
        ),
    )
}

/// Refusals about one subject: the others are still written.
fn per_subject(err: &GatewayError) -> bool {
    matches!(
        err,
        GatewayError::HeldByOwnership(_) | GatewayError::Refused(_)
    )
}

/// Several failures as one: the first one's reason, every message.
fn combine(failures: Vec<Failure>) -> Option<Failure> {
    let reason = failures.first()?.reason;
    let message = failures
        .into_iter()
        .map(|f| f.message)
        .collect::<Vec<_>>()
        .join("; ");
    Some(Failure::new(reason, message))
}

pub async fn reconcile_package_grant(
    node: &PackageNode,
    desired: &[SubjectGrant],
    applied: Vec<AppliedGrant>,
    gateway: &dyn AdminGateway,
    ledger: &dyn Ledger<Vec<AppliedGrant>>,
) -> GrantReport {
    let mut pass = Pass {
        node,
        gateway,
        ledger,
        applied,
        changed: false,
        writes: Writes::default(),
    };
    let outcome = match pass.run(desired).await {
        Ok(failures) => match combine(failures) {
            Some(failure) => Outcome::failed(failure),
            None => synced(node, desired.len(), &pass.applied),
        },
        Err(failure) => Outcome::failed(failure),
    };
    GrantReport {
        outcome: outcome.wrote(pass.writes),
        applied: pass.applied,
        changed: pass.changed,
    }
}

fn synced(node: &PackageNode, count: usize, applied: &[AppliedGrant]) -> Outcome {
    let outcome = Outcome::synced(format!("{count} grant(s) written on {node}"));
    let warnings: Vec<String> = applied
        .iter()
        .flat_map(|a| {
            a.warnings
                .iter()
                .map(move |w| format!("{}: {w}", a.subject))
        })
        .collect();
    if warnings.is_empty() {
        outcome
    } else {
        outcome.advise(ReasonCode::SuspiciousGrant, warnings.join("; "))
    }
}

struct Pass<'a> {
    node: &'a PackageNode,
    gateway: &'a dyn AdminGateway,
    ledger: &'a dyn Ledger<Vec<AppliedGrant>>,
    applied: Vec<AppliedGrant>,
    changed: bool,
    writes: Writes,
}

impl Pass<'_> {
    /// `Err`: the pass stopped (the instance or the status out of reach);
    /// `Ok`: the refusals of single subjects, the others written.
    async fn run(&mut self, desired: &[SubjectGrant]) -> Result<Vec<Failure>, Failure> {
        let current = self.gateway.grants(self.node).await?;
        let mut failures = Vec::new();
        for grant in desired {
            let requested = set(&grant.actions);
            let row = current.iter().find(|r| r.subject == grant.subject);
            let known = self.applied.iter().find(|a| a.subject == grant.subject);
            match (row, known) {
                (Some(row), None) => {
                    failures.push(foreign(self.node, row));
                    continue;
                }
                (Some(row), Some(known)) if in_sync(known, row, &requested) => continue,
                // Absent (never written, or removed elsewhere), or drifted.
                _ => {}
            }
            match self
                .gateway
                .put_grant(self.node, &grant.subject, &grant.actions)
                .await
            {
                Ok(write) => {
                    match known {
                        Some(_) => self.writes.drifted("grants"),
                        None => self.writes.created(),
                    }
                    let entry = AppliedGrant {
                        subject: grant.subject.clone(),
                        requested,
                        stored: write.stored,
                        warnings: write.warnings,
                    };
                    match self.applied.iter_mut().find(|a| a.subject == grant.subject) {
                        Some(known) => *known = entry,
                        None => self.applied.push(entry),
                    }
                    self.record().await?;
                }
                Err(err) if per_subject(&err) => {
                    failures.push(Failure::new(
                        err.reason(),
                        format!("{} on {}: {err}", grant.subject, self.node),
                    ));
                }
                Err(err) => return Err(err.into()),
            }
        }
        let gone: Vec<String> = self
            .applied
            .iter()
            .filter(|a| !desired.iter().any(|g| g.subject == a.subject))
            .map(|a| a.subject.clone())
            .collect();
        for subject in gone {
            match self.gateway.delete_grant(self.node, &subject).await {
                // A subject left the spec: its grant is put back to none.
                Ok(true) => self.writes.drifted("grants"),
                // The row is the ownership projection's now: not ours to
                // remove any more.
                Ok(false) | Err(GatewayError::HeldByOwnership(_)) => {}
                Err(err) => return Err(err.into()),
            }
            self.applied.retain(|a| a.subject != subject);
            self.record().await?;
        }
        Ok(failures)
    }

    async fn record(&mut self) -> Result<(), Failure> {
        self.changed = true;
        self.ledger
            .record(&self.applied)
            .await
            .map_err(|e| Failure::new(ReasonCode::KubernetesApiError, e.to_string()))
    }
}

/// Revokes what this object wrote (`applied`); how many grants were
/// still there. A subject that became an owner keeps its ownership row.
pub async fn revoke_package_grant(
    node: &PackageNode,
    applied: &[AppliedGrant],
    gateway: &dyn AdminGateway,
) -> Result<usize, Failure> {
    let mut revoked: usize = 0;
    for grant in applied {
        match gateway.delete_grant(node, &grant.subject).await {
            Ok(true) => revoked = revoked.saturating_add(1),
            Ok(false) | Err(GatewayError::HeldByOwnership(_)) => {}
            Err(err) => return Err(err.into()),
        }
    }
    Ok(revoked)
}

#[cfg(test)]
mod tests {
    use domain::RemoteWrite;

    use super::*;
    use crate::test_support::{FakeGateway, FakeLedger};

    fn node() -> PackageNode {
        PackageNode {
            registry: "npm".into(),
            package: "@acme/billing".into(),
            version: None,
        }
    }

    fn grant(subject: &str, actions: &[&str]) -> SubjectGrant {
        SubjectGrant {
            subject: subject.into(),
            actions: actions.iter().map(|a| a.to_string()).collect(),
        }
    }

    async fn pass(
        gateway: &FakeGateway,
        ledger: &FakeLedger<Vec<AppliedGrant>>,
        desired: &[SubjectGrant],
        applied: Vec<AppliedGrant>,
    ) -> GrantReport {
        reconcile_package_grant(&node(), desired, applied, gateway, ledger).await
    }

    #[tokio::test]
    async fn grants_are_written_recorded_one_by_one_then_left_alone() {
        let gateway = FakeGateway::default();
        gateway.serve(&["npm"]);
        let ledger = FakeLedger::default();
        let desired = [
            grant("group:oidc:eng", &["releases:*"]),
            grant("user:alice", &["releases:read"]),
        ];
        let report = pass(&gateway, &ledger, &desired, vec![]).await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        assert!(report.changed);
        assert_eq!(report.applied.len(), 2);
        // `releases:*` is stored expanded.
        assert!(report.applied[0].stored.len() > 1);
        // Recorded after each write, not at the end.
        assert_eq!(ledger.records().len(), 2);
        assert_eq!(ledger.records()[0].len(), 1);
        assert_eq!(
            report.outcome.writes,
            [RemoteWrite::Created, RemoteWrite::Created]
        );
        assert!(report.outcome.drift.is_empty());

        let again = pass(&gateway, &ledger, &desired, report.applied.clone()).await;
        assert_eq!(again.outcome.reason(), ReasonCode::Reconciled);
        assert!(!again.changed);
        assert_eq!(again.applied, report.applied);
        // Unchanged: nothing written, nothing counted.
        assert!(again.outcome.writes.is_empty());
        assert!(again.outcome.drift.is_empty());
    }

    #[tokio::test]
    async fn a_row_written_elsewhere_is_a_conflict_the_others_are_written() {
        let gateway = FakeGateway::default();
        gateway.serve(&["npm"]);
        gateway.put_grant_row(
            &node(),
            StoredGrant {
                subject: "user:bob".into(),
                actions: vec!["releases:read".into()],
                from_ownership: false,
                granted_by: Some("admin".into()),
            },
        );
        let ledger = FakeLedger::default();
        let desired = [
            grant("user:bob", &["releases:publish"]),
            grant("user:alice", &["releases:read"]),
        ];
        let report = pass(&gateway, &ledger, &desired, vec![]).await;
        assert_eq!(report.outcome.reason(), ReasonCode::GrantConflict);
        let message = report.outcome.ready.unwrap_err().message;
        assert!(message.contains("granted by admin"), "{message}");
        assert_eq!(report.applied.len(), 1);
        assert_eq!(
            gateway.grant_row(&node(), "user:bob").unwrap().actions,
            ["releases:read"]
        );
    }

    #[tokio::test]
    async fn an_owner_row_is_held_by_ownership() {
        let gateway = FakeGateway::default();
        gateway.serve(&["npm"]);
        gateway.own(&node(), "user:carol");
        let ledger = FakeLedger::default();
        let report = pass(
            &gateway,
            &ledger,
            &[grant("user:carol", &["releases:read"])],
            vec![],
        )
        .await;
        assert_eq!(report.outcome.reason(), ReasonCode::GrantHeldByOwnership);
    }

    #[tokio::test]
    async fn drift_is_rewritten_and_a_subject_leaving_the_spec_revoked() {
        let gateway = FakeGateway::default();
        gateway.serve(&["npm"]);
        let ledger = FakeLedger::default();
        let desired = [
            grant("user:alice", &["releases:read"]),
            grant("user:bob", &["releases:read"]),
        ];
        let report = pass(&gateway, &ledger, &desired, vec![]).await;
        // Changed at the console, removed at the console.
        gateway.put_grant_row(
            &node(),
            StoredGrant {
                subject: "user:alice".into(),
                actions: vec!["releases:publish".into()],
                ..Default::default()
            },
        );
        gateway.remove_grant_row(&node(), "user:bob");
        let again = pass(&gateway, &ledger, &desired, report.applied).await;
        assert_eq!(again.outcome.reason(), ReasonCode::Reconciled);
        assert!(again.changed);
        assert_eq!(
            gateway.grant_row(&node(), "user:alice").unwrap().actions,
            ["releases:read"]
        );
        assert!(gateway.grant_row(&node(), "user:bob").is_some());
        // Both put back: drifts, the field named once.
        assert_eq!(
            again.outcome.writes,
            [RemoteWrite::Drift, RemoteWrite::Drift]
        );
        assert_eq!(again.outcome.drift.fields(), ["grants"]);

        let only_alice = [grant("user:alice", &["releases:read"])];
        let last = pass(&gateway, &ledger, &only_alice, again.applied).await;
        assert_eq!(last.outcome.reason(), ReasonCode::Reconciled);
        assert!(gateway.grant_row(&node(), "user:bob").is_none());
        assert_eq!(last.applied.len(), 1);
        assert_eq!(last.outcome.writes, [RemoteWrite::Drift]);
    }

    #[tokio::test]
    async fn refusals_and_outages_map_onto_their_codes() {
        let gateway = FakeGateway::default();
        let ledger = FakeLedger::default();
        let desired = [grant("user:alice", &["releases:read"])];
        // The fake knows no registry: BatleHub answers 404.
        let report = pass(&gateway, &ledger, &desired, vec![]).await;
        assert_eq!(report.outcome.reason(), ReasonCode::RemoteNotFound);
        gateway.serve(&["npm"]);
        let report = pass(&gateway, &ledger, &[grant("user:alice", &["nope"])], vec![]).await;
        assert_eq!(report.outcome.reason(), ReasonCode::RemoteRejected);
        gateway.fail_with(Some(GatewayError::StorageUnavailable("503".into())));
        let report = pass(&gateway, &ledger, &desired, vec![]).await;
        assert_eq!(report.outcome.reason(), ReasonCode::GrantStorageUnavailable);
        gateway.fail_with(None);
        ledger.fail(true);
        let report = pass(&gateway, &ledger, &desired, vec![]).await;
        assert_eq!(report.outcome.reason(), ReasonCode::KubernetesApiError);
    }

    #[tokio::test]
    async fn revocation_removes_only_what_was_written() {
        let gateway = FakeGateway::default();
        gateway.serve(&["npm"]);
        gateway.put_grant_row(
            &node(),
            StoredGrant {
                subject: "user:bob".into(),
                actions: vec!["releases:read".into()],
                ..Default::default()
            },
        );
        let ledger = FakeLedger::default();
        let report = pass(
            &gateway,
            &ledger,
            &[grant("user:alice", &["releases:read"])],
            vec![],
        )
        .await;
        assert_eq!(
            revoke_package_grant(&node(), &report.applied, &gateway)
                .await
                .unwrap(),
            1
        );
        assert!(gateway.grant_row(&node(), "user:alice").is_none());
        assert!(gateway.grant_row(&node(), "user:bob").is_some());
        assert_eq!(
            revoke_package_grant(&node(), &report.applied, &gateway)
                .await
                .unwrap(),
            0
        );
    }
}
