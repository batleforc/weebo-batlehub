//! `HttpAdminGateway` against a real BatleHub (`task test:live-batlehub`,
//! ignored by default): `BATLEHUB_URL`, an admin token
//! (`BATLEHUB_ADMIN_TOKEN`) and a user one (`BATLEHUB_USER_TOKEN`) —
//! `task batlehub:container:start` provides all three.

use adapters_outbound::HttpAdminGateway;
use application::ports::{AdminGateway, GatewayError};

fn env(name: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| panic!("{name} is not set"))
}

fn gateway(token: &str) -> HttpAdminGateway {
    HttpAdminGateway::new(
        &env("BATLEHUB_URL"),
        token,
        HttpAdminGateway::client(None, false).unwrap(),
    )
    .unwrap()
}

#[tokio::test]
#[ignore = "needs a real BatleHub (task test:live-batlehub)"]
async fn the_admin_token_is_accepted_and_reads_the_warnings() {
    let gateway = gateway(&env("BATLEHUB_ADMIN_TOKEN"));
    let info = gateway.ping().await.unwrap();
    assert!(!info.version.is_empty());
    // Whatever BatleHub thinks of this configuration, the answer parses
    // and every warning is complete.
    for warning in gateway.config_warnings().await.unwrap() {
        assert!(!warning.code.is_empty(), "{warning:?}");
        assert!(!warning.message.is_empty(), "{warning:?}");
    }
}

#[tokio::test]
#[ignore = "needs a real BatleHub (task test:live-batlehub)"]
async fn a_user_or_unknown_token_is_refused() {
    for (token, role) in [
        (env("BATLEHUB_USER_TOKEN"), "\"user\""),
        ("not-a-token".to_string(), "\"anonymous\""),
    ] {
        match gateway(&token).ping().await {
            Err(GatewayError::Unauthorized(why)) => assert!(why.contains(role), "{why}"),
            other => panic!("{role}: {other:?}"),
        }
    }
    // The warnings need `config:read`, which a user doesn't have.
    assert!(matches!(
        gateway(&env("BATLEHUB_USER_TOKEN")).config_warnings().await,
        Err(GatewayError::Unauthorized(_))
    ));
}
