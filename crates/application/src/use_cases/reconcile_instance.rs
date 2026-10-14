//! A `BatleHubLocalInstance` at M0: a connectivity and token check
//! (`/livez`, then the token on the admin API), whose result every CR
//! bound to it depends on. Managing its configuration comes later.

use crate::ports::AdminGateway;
use crate::use_cases::Outcome;

pub async fn reconcile_instance(gateway: &dyn AdminGateway) -> Outcome {
    match gateway.ping().await {
        Ok(info) => Outcome::synced(format!("BatleHub {} answers", info.version)),
        Err(e) => Outcome::failed(e),
    }
}

#[cfg(test)]
mod tests {
    use domain::error::ReasonCode;

    use super::*;
    use crate::ports::GatewayError;
    use crate::test_support::FakeGateway;

    #[tokio::test]
    async fn a_reachable_instance_is_ready() {
        let outcome = reconcile_instance(&FakeGateway::default()).await;
        assert_eq!(outcome.reason(), ReasonCode::Reconciled);
        assert_eq!(outcome.ready, Ok("BatleHub 1.4.0 answers".into()));
    }

    #[tokio::test]
    async fn an_unreachable_or_refusing_instance_is_not() {
        let gateway = FakeGateway::default();
        gateway.fail_with(Some(GatewayError::Unreachable("dns".into())));
        assert_eq!(
            reconcile_instance(&gateway).await.reason(),
            ReasonCode::InstanceUnreachable
        );
        gateway.fail_with(Some(GatewayError::Unauthorized("401".into())));
        assert_eq!(
            reconcile_instance(&gateway).await.reason(),
            ReasonCode::OperatorUnauthorized
        );
        gateway.fail_with(Some(GatewayError::Remote("500".into())));
        assert_eq!(
            reconcile_instance(&gateway).await.reason(),
            ReasonCode::RemoteError
        );
    }
}
