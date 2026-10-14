//! A `BatleHubLocalInstance` in external mode, without managing its
//! configuration: a connectivity and token check (`/livez`, then the
//! token's role on the admin API), and BatleHub's own warnings on its
//! configuration. Every CR bound to it depends on the result. Its
//! deletion waits while CRs are bound to it.

use domain::Failure;
use domain::error::ReasonCode;

use crate::ports::{AdminGateway, ConfigWarning};
use crate::use_cases::Outcome;

/// How many dependents or warnings a message names.
const SHOWN: usize = 5;

/// What a reconcile of the instance ends on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstanceReport {
    pub outcome: Outcome,
    /// What the instance said about itself, when it answered.
    pub observed: Option<Observed>,
}

/// The instance's status fields, read from BatleHub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub version: String,
    pub warnings: Vec<ConfigWarning>,
}

pub async fn reconcile_instance(gateway: &dyn AdminGateway) -> InstanceReport {
    let failed = |e| InstanceReport {
        outcome: Outcome::failed(e),
        observed: None,
    };
    let info = match gateway.ping().await {
        Ok(info) => info,
        Err(e) => return failed(e),
    };
    let warnings = match gateway.config_warnings().await {
        Ok(warnings) => warnings,
        Err(e) => return failed(e),
    };
    let mut outcome = Outcome::synced(format!("BatleHub {} answers", info.version));
    if !warnings.is_empty() {
        outcome = outcome.advise(ReasonCode::ConfigWarnings, warnings_message(&warnings));
    }
    InstanceReport {
        outcome,
        observed: Some(Observed {
            version: info.version,
            warnings,
        }),
    }
}

fn warnings_message(warnings: &[ConfigWarning]) -> String {
    let codes: Vec<&str> = warnings
        .iter()
        .take(SHOWN)
        .map(|w| w.code.as_str())
        .collect();
    let more = match warnings.len().saturating_sub(SHOWN) {
        0 => String::new(),
        n => format!(" and {n} more"),
    };
    format!(
        "BatleHub warns about its configuration: {}{more} (status.warnings)",
        codes.join(", ")
    )
}

/// Whether the instance may go: `Err(InstanceInUse)` while CRs are bound
/// to it (`dependents`, as `Kind/namespace/name`).
pub fn release_instance(instance: &str, dependents: &[String]) -> Result<(), Failure> {
    if dependents.is_empty() {
        return Ok(());
    }
    let shown: Vec<&str> = dependents.iter().take(SHOWN).map(String::as_str).collect();
    Err(Failure::new(
        ReasonCode::InstanceInUse,
        format!(
            "{} CR(s) still use {instance} (e.g. {}): delete them first, or annotate the \
             instance batlehub.weebo.io/force-orphan: \"true\" to leave them orphaned",
            dependents.len(),
            shown.join(", ")
        ),
    ))
}

#[cfg(test)]
mod tests {
    use domain::error::ReasonCode;

    use super::*;
    use crate::ports::GatewayError;
    use crate::test_support::FakeGateway;

    fn warning(code: &str) -> ConfigWarning {
        ConfigWarning {
            code: code.into(),
            path: "server".into(),
            message: "m".into(),
        }
    }

    #[tokio::test]
    async fn a_reachable_instance_is_ready() {
        let report = reconcile_instance(&FakeGateway::default()).await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        assert_eq!(report.outcome.ready, Ok("BatleHub 1.5.0 answers".into()));
        assert!(report.outcome.advisories.is_empty());
        let observed = report.observed.unwrap();
        assert_eq!(observed.version, "1.5.0");
        assert!(observed.warnings.is_empty());
    }

    #[tokio::test]
    async fn warnings_are_an_advisory_next_to_ready() {
        let gateway = FakeGateway::default();
        gateway.warn_with((0..7).map(|i| warning(&format!("w{i}"))).collect());
        let report = reconcile_instance(&gateway).await;
        assert_eq!(report.outcome.reason(), ReasonCode::Reconciled);
        let [advisory] = report.outcome.advisories.as_slice() else {
            panic!("{:?}", report.outcome.advisories);
        };
        assert_eq!(advisory.reason, ReasonCode::ConfigWarnings);
        assert!(
            advisory.message.contains("w0, w1, w2, w3, w4 and 2 more"),
            "{}",
            advisory.message
        );
        assert_eq!(report.observed.unwrap().warnings.len(), 7);
    }

    #[tokio::test]
    async fn an_unreachable_or_refusing_instance_is_not() {
        let gateway = FakeGateway::default();
        let reason = async |gateway: &FakeGateway| {
            let report = reconcile_instance(gateway).await;
            assert!(report.observed.is_none());
            report.outcome.reason()
        };
        gateway.fail_with(Some(GatewayError::Unreachable("dns".into())));
        assert_eq!(reason(&gateway).await, ReasonCode::InstanceUnreachable);
        gateway.fail_with(Some(GatewayError::Unauthorized("401".into())));
        assert_eq!(reason(&gateway).await, ReasonCode::OperatorUnauthorized);
        gateway.fail_with(Some(GatewayError::Remote("500".into())));
        assert_eq!(reason(&gateway).await, ReasonCode::RemoteError);
    }

    #[tokio::test]
    async fn warnings_that_cannot_be_read_fail_the_reconcile() {
        let gateway = FakeGateway::default();
        gateway.fail_warnings_with(Some(GatewayError::Unauthorized("403".into())));
        let report = reconcile_instance(&gateway).await;
        assert_eq!(report.outcome.reason(), ReasonCode::OperatorUnauthorized);
    }

    #[test]
    fn an_instance_goes_once_nothing_is_bound_to_it() {
        assert_eq!(release_instance("ns/hub", &[]), Ok(()));
        let dependents: Vec<String> = (0..6).map(|i| format!("Kind/ns/cr{i}")).collect();
        let failure = release_instance("ns/hub", &dependents).unwrap_err();
        assert_eq!(failure.reason, ReasonCode::InstanceInUse);
        assert!(failure.message.starts_with("6 CR(s) still use ns/hub"));
        assert!(
            failure.message.contains("Kind/ns/cr4)"),
            "{}",
            failure.message
        );
        assert!(!failure.message.contains("cr5"), "{}", failure.message);
    }
}
