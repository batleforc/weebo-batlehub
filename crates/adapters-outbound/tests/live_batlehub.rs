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

#[tokio::test]
#[ignore = "needs a real BatleHub (task test:live-batlehub)"]
async fn a_configuration_is_dry_run_staged_applied_and_written() {
    let admin = gateway(&env("BATLEHUB_ADMIN_TOKEN"));
    let current = admin.config_content().await.unwrap();

    // A key BatleHub only reads at startup: named by the dry run.
    let moved = current.replace("weebo-batlehub-test-db:5432", "elsewhere:5432");
    assert_ne!(moved, current, "the live config names its database host");
    let check = admin.validate_config(&moved).await.unwrap();
    assert_eq!(check.restart_required, ["database.url"]);

    // A registry is applied by a reload, and written to the file.
    let run = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let added = format!(
        "{current}\n[[registries]]\nname = \"live-{run}\"\ntype = \"npm\"\nupstreams = [\"https://registry.npmjs.org\"]\n"
    );
    assert!(
        admin
            .validate_config(&added)
            .await
            .unwrap()
            .restart_required
            .is_empty()
    );
    assert!(admin.stage_config(&added).await.unwrap());
    admin.apply_pending().await.unwrap();
    assert_eq!(admin.config_content().await.unwrap(), added);
    // The same bytes again: nothing staged, nothing to apply.
    assert!(!admin.stage_config(&added).await.unwrap());
    assert!(matches!(
        admin.apply_pending().await,
        Err(GatewayError::NoPending(_))
    ));

    // What BatleHub refuses is a refusal, not an error.
    assert!(matches!(
        admin.validate_config("not = [toml").await,
        Err(GatewayError::Rejected(_))
    ));
    // A user may not write the configuration.
    assert!(matches!(
        gateway(&env("BATLEHUB_USER_TOKEN"))
            .stage_config(&added)
            .await,
        Err(GatewayError::Unauthorized(_))
    ));
}
