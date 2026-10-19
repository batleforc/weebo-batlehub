//! `BatleHubNamespaceClaim`: one team namespace of a registry, claimed
//! through the admin API. A claim is this CR's when it carries its marker
//! in `claimed_by`: anything else holding the prefix (the console, the
//! CLI, another CR) is a conflict, never taken over. BatleHub has no
//! update: a new group is a release then a claim.

use domain::Failure;
use domain::error::ReasonCode;

use super::{Outcome, Writes};
use crate::ports::{AdminGateway, GatewayError, TeamNamespace};

/// What a `BatleHubNamespaceClaim` asks for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim<'a> {
    pub registry: &'a str,
    pub prefix: &'a str,
    pub group: &'a str,
    /// This CR's [`marker`].
    pub marker: &'a str,
}

/// The `claimed_by` the operator writes on the claims of the CR
/// `namespace/name`: how it recognizes them, its status lost or not.
pub fn marker(namespace: &str, name: &str) -> String {
    format!("weebo-batlehub:{namespace}/{name}")
}

impl Claim<'_> {
    fn owns(&self, namespace: &TeamNamespace) -> bool {
        namespace.claimed_by.as_deref() == Some(self.marker)
    }

    fn namespace(&self) -> TeamNamespace {
        TeamNamespace {
            prefix: self.prefix.to_string(),
            group: self.group.to_string(),
            claimed_by: Some(self.marker.to_string()),
            package_count: 0,
        }
    }

    async fn current(&self, gateway: &dyn AdminGateway) -> Result<Option<TeamNamespace>, Failure> {
        Ok(gateway
            .team_namespaces(self.registry)
            .await?
            .into_iter()
            .find(|n| n.prefix == self.prefix))
    }

    fn conflict(&self, held: &TeamNamespace) -> Failure {
        let by = held.claimed_by.as_deref().unwrap_or("an unnamed claimer");
        Failure::new(
            ReasonCode::ClaimConflict,
            format!(
                "{:?} is already claimed on registry {:?} for group {:?}, by {by}: \
                 release that claim to take it",
                self.prefix, self.registry, held.group
            ),
        )
    }

    /// Claims the prefix; taken meanwhile, says by whom.
    async fn create(&self, gateway: &dyn AdminGateway) -> Result<(), Failure> {
        match gateway
            .claim_namespace(self.registry, &self.namespace())
            .await
        {
            Ok(()) => Ok(()),
            Err(err @ GatewayError::AlreadyClaimed(_)) => match self.current(gateway).await? {
                Some(held) if !self.owns(&held) => Err(self.conflict(&held)),
                _ => Err(err.into()),
            },
            // An empty prefix or group: the CRD's validation keeps them out.
            Err(GatewayError::Rejected(message)) => {
                Err(Failure::new(ReasonCode::RemoteRejected, message))
            }
            Err(err) => Err(err.into()),
        }
    }
}

/// What the instance holds for this CR after a pass.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimState {
    /// The group the prefix is claimed for by this CR; `None`: it holds
    /// no claim.
    pub group: Option<String>,
    pub package_count: Option<i64>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaimReport {
    pub outcome: Outcome,
    /// `None` when the instance couldn't tell (the status keeps what it
    /// had).
    pub state: Option<ClaimState>,
    /// Whether the pass claimed or released something.
    pub changed: bool,
}

pub async fn reconcile_namespace_claim(
    claim: &Claim<'_>,
    gateway: &dyn AdminGateway,
) -> ClaimReport {
    let mut writes = Writes::default();
    let mut report = match run(claim, gateway, &mut writes).await {
        Ok(report) => report,
        Err(failure) => ClaimReport {
            outcome: Outcome::failed(failure),
            state: None,
            changed: false,
        },
    };
    report.outcome = report.outcome.wrote(writes);
    report
}

async fn run(
    claim: &Claim<'_>,
    gateway: &dyn AdminGateway,
    writes: &mut Writes,
) -> Result<ClaimReport, Failure> {
    let held = |count: i64| ClaimState {
        group: Some(claim.group.to_string()),
        package_count: Some(count),
    };
    match claim.current(gateway).await? {
        Some(current) if !claim.owns(&current) => Ok(ClaimReport {
            outcome: Outcome::failed(claim.conflict(&current)),
            state: Some(ClaimState {
                group: None,
                package_count: None,
            }),
            changed: false,
        }),
        Some(current) if current.group == claim.group => Ok(ClaimReport {
            outcome: Outcome::synced(format!(
                "{:?} is claimed on registry {:?} for group {:?}",
                claim.prefix, claim.registry, claim.group
            )),
            state: Some(held(current.package_count)),
            changed: false,
        }),
        Some(current) => {
            // No update in BatleHub: the prefix is free between the two
            // calls, a failure in between claims it again next pass.
            gateway
                .release_namespace(claim.registry, claim.prefix)
                .await?;
            // One object rewritten, in two calls.
            writes.drifted("group");
            claim.create(gateway).await?;
            Ok(ClaimReport {
                outcome: Outcome::synced(format!(
                    "{:?} moved on registry {:?} from group {:?} to {:?}",
                    claim.prefix, claim.registry, current.group, claim.group
                )),
                state: Some(held(current.package_count)),
                changed: true,
            })
        }
        None => {
            // A claim records the separator of its registry's type: made
            // on a registry the instance doesn't serve, it would keep `/`.
            if !gateway
                .registry_names()
                .await?
                .iter()
                .any(|r| r == claim.registry)
            {
                return Err(Failure::new(
                    ReasonCode::RemoteNotFound,
                    format!("the instance serves no registry named {:?}", claim.registry),
                ));
            }
            claim.create(gateway).await?;
            writes.created();
            Ok(ClaimReport {
                outcome: Outcome::synced(format!(
                    "{:?} claimed on registry {:?} for group {:?}",
                    claim.prefix, claim.registry, claim.group
                )),
                state: Some(held(0)),
                changed: true,
            })
        }
    }
}

/// Releases the prefix when the claim in place is this CR's; `true` when
/// it released something.
pub async fn release_namespace_claim(
    claim: &Claim<'_>,
    gateway: &dyn AdminGateway,
) -> Result<bool, Failure> {
    match claim.current(gateway).await? {
        Some(current) if claim.owns(&current) => {
            gateway
                .release_namespace(claim.registry, claim.prefix)
                .await?;
            Ok(true)
        }
        _ => Ok(false),
    }
}

#[cfg(test)]
mod tests {
    use domain::RemoteWrite;

    use super::*;
    use crate::test_support::FakeGateway;

    const MARKER: &str = "weebo-batlehub:team/web";

    fn claim(group: &str) -> Claim<'_> {
        Claim {
            registry: "npm",
            prefix: "@acme/web",
            group,
            marker: MARKER,
        }
    }

    fn reason(report: &ClaimReport) -> ReasonCode {
        report.outcome.reason()
    }

    #[test]
    fn the_marker_names_the_cr() {
        assert_eq!(marker("team", "web"), MARKER);
    }

    #[tokio::test]
    async fn a_free_prefix_is_claimed_then_left_alone() {
        let gateway = FakeGateway::default();
        gateway.serve(&["npm"]);
        let report = reconcile_namespace_claim(&claim("oidc:web"), &gateway).await;
        assert_eq!(reason(&report), ReasonCode::Reconciled);
        assert!(report.changed);
        let held = gateway.claim("npm", "@acme/web").unwrap();
        assert_eq!(held.group, "oidc:web");
        assert_eq!(held.claimed_by.as_deref(), Some(MARKER));
        assert_eq!(report.outcome.writes, [RemoteWrite::Created]);

        let report = reconcile_namespace_claim(&claim("oidc:web"), &gateway).await;
        assert_eq!(reason(&report), ReasonCode::Reconciled);
        assert!(!report.changed);
        // Unchanged: nothing written, nothing counted.
        assert!(report.outcome.writes.is_empty());
        assert!(report.outcome.drift.is_empty());
        assert_eq!(
            gateway.calls(),
            ["namespaces", "registries", "claim", "namespaces"]
        );
    }

    #[tokio::test]
    async fn an_unknown_registry_is_not_claimed_on() {
        let gateway = FakeGateway::default();
        gateway.serve(&["pypi"]);
        let report = reconcile_namespace_claim(&claim("oidc:web"), &gateway).await;
        assert_eq!(reason(&report), ReasonCode::RemoteNotFound);
        assert_eq!(report.state, None);
        assert!(gateway.claim("npm", "@acme/web").is_none());
    }

    #[tokio::test]
    async fn a_prefix_held_by_anything_else_is_a_conflict() {
        let gateway = FakeGateway::default();
        gateway.serve(&["npm"]);
        let theirs = TeamNamespace {
            prefix: "@acme/web".into(),
            group: "oidc:web".into(),
            claimed_by: Some("admin".into()),
            package_count: 3,
        };
        gateway.put_claim("npm", theirs.clone());
        let report = reconcile_namespace_claim(&claim("oidc:web"), &gateway).await;
        assert_eq!(reason(&report), ReasonCode::ClaimConflict);
        let message = report.outcome.ready.unwrap_err().message;
        assert!(message.contains("by admin"), "{message}");
        assert_eq!(report.state.unwrap().group, None);
        assert!(report.outcome.writes.is_empty());
        // Never released by this CR either.
        assert!(
            !release_namespace_claim(&claim("oidc:web"), &gateway)
                .await
                .unwrap()
        );
        assert_eq!(gateway.claim("npm", "@acme/web"), Some(theirs));
    }

    #[tokio::test]
    async fn a_new_group_releases_then_claims() {
        let gateway = FakeGateway::default();
        gateway.serve(&["npm"]);
        reconcile_namespace_claim(&claim("oidc:web"), &gateway).await;
        let report = reconcile_namespace_claim(&claim("oidc:frontend"), &gateway).await;
        assert_eq!(reason(&report), ReasonCode::Reconciled);
        assert!(report.changed);
        assert_eq!(
            gateway.claim("npm", "@acme/web").unwrap().group,
            "oidc:frontend"
        );
        assert_eq!(
            report.state.unwrap().group.as_deref(),
            Some("oidc:frontend")
        );
        // Release then claim: one object rewritten.
        assert_eq!(report.outcome.writes, [RemoteWrite::Drift]);
        assert_eq!(report.outcome.drift.fields(), ["group"]);
    }

    #[tokio::test]
    async fn only_its_own_claim_is_released() {
        let gateway = FakeGateway::default();
        gateway.serve(&["npm"]);
        reconcile_namespace_claim(&claim("oidc:web"), &gateway).await;
        assert!(
            release_namespace_claim(&claim("oidc:web"), &gateway)
                .await
                .unwrap()
        );
        assert!(gateway.claim("npm", "@acme/web").is_none());
        assert!(
            !release_namespace_claim(&claim("oidc:web"), &gateway)
                .await
                .unwrap()
        );
    }

    #[tokio::test]
    async fn an_unreachable_instance_keeps_the_status() {
        let gateway = FakeGateway::default();
        gateway.fail_with(Some(GatewayError::Unreachable("down".into())));
        let report = reconcile_namespace_claim(&claim("oidc:web"), &gateway).await;
        assert_eq!(reason(&report), ReasonCode::InstanceUnreachable);
        assert_eq!(report.state, None);
        assert!(
            release_namespace_claim(&claim("oidc:web"), &gateway)
                .await
                .is_err()
        );
    }
}
