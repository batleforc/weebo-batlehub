//! Contract test of `HttpAdminGateway` against a scripted BatleHub
//! (`wiremock`): the requests it sends and how each answer maps onto a
//! `GatewayError`. Response shapes follow BatleHub 1.6.0
//! (`spec/batlehub-v1.6.0.json`, `/livez` from its source).

use adapters_outbound::HttpAdminGateway;
use application::ports::{AdminGateway, GatewayError};
use serde_json::json;
use wiremock::matchers::{header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TOKEN: &str = "s3cr3t";

/// An answer of `/api/v1/me`, and the error it must map onto.
type Case = (u16, fn(&GatewayError) -> bool);

async fn setup() -> (MockServer, HttpAdminGateway) {
    let server = MockServer::start().await;
    let gateway = HttpAdminGateway::new(
        &server.uri(),
        TOKEN,
        HttpAdminGateway::client(None, false).unwrap(),
    )
    .unwrap();
    (server, gateway)
}

async fn livez(server: &MockServer) {
    Mock::given(method("GET"))
        .and(path("/livez"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"ok": true, "version": "1.6.0"})),
        )
        .mount(server)
        .await;
}

fn me(role: &str) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "role": role,
        "groups": [],
        "has_registry_access": true,
        "user_id": "weebo-batlehub-operator",
    }))
}

#[tokio::test]
async fn ping_reads_the_version_then_checks_the_token() {
    let (server, gateway) = setup().await;
    livez(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/v1/me"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(me("admin"))
        .expect(1)
        .mount(&server)
        .await;
    assert_eq!(gateway.ping().await.unwrap().version, "1.6.0");
}

#[tokio::test]
async fn a_token_without_the_admin_role_is_refused() {
    let (server, gateway) = setup().await;
    livez(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/v1/me"))
        .respond_with(me("user"))
        .mount(&server)
        .await;
    match gateway.ping().await {
        Err(GatewayError::Unauthorized(why)) => assert!(why.contains("\"user\""), "{why}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn answers_map_onto_neutral_errors() {
    let cases: [Case; 4] = [
        (401, |e| matches!(e, GatewayError::Unauthorized(_))),
        (403, |e| matches!(e, GatewayError::Unauthorized(_))),
        (502, |e| matches!(e, GatewayError::Unreachable(_))),
        (500, |e| matches!(e, GatewayError::Remote(_))),
    ];
    for (status, expected) in cases {
        let (server, gateway) = setup().await;
        livez(&server).await;
        Mock::given(method("GET"))
            .and(path("/api/v1/me"))
            .respond_with(ResponseTemplate::new(status).set_body_string("nope"))
            .mount(&server)
            .await;
        let err = gateway.ping().await.unwrap_err();
        assert!(expected(&err), "{status}: {err:?}");
    }
}

#[tokio::test]
async fn an_unknown_token_is_anonymous_hence_refused() {
    // BatleHub answers an unknown token as the anonymous role, with a 200.
    let (server, gateway) = setup().await;
    livez(&server).await;
    Mock::given(method("GET"))
        .and(path("/api/v1/me"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "role": "anonymous",
            "groups": [],
            "has_registry_access": false,
            "user_id": null,
            "auth_provider": null,
        })))
        .mount(&server)
        .await;
    match gateway.ping().await {
        Err(GatewayError::Unauthorized(why)) => assert!(why.contains("\"anonymous\""), "{why}"),
        other => panic!("{other:?}"),
    }
}

#[tokio::test]
async fn config_warnings_are_read_from_the_admin_api() {
    let (server, gateway) = setup().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/config/warnings"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"warnings": [{
                "code": "audit.no-retention",
                "message": "audit trail has no retention",
                "path": "audit",
            }]})),
        )
        .expect(1)
        .mount(&server)
        .await;
    let warnings = gateway.config_warnings().await.unwrap();
    assert_eq!(warnings.len(), 1);
    assert_eq!(warnings[0].code, "audit.no-retention");
    assert_eq!(warnings[0].path, "audit");
}

#[tokio::test]
async fn config_warnings_without_config_read_are_refused() {
    let (server, gateway) = setup().await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/config/warnings"))
        .respond_with(ResponseTemplate::new(403).set_body_json(json!({
            "error": "Forbidden",
            "message": "this endpoint requires the 'config:read' permission",
        })))
        .mount(&server)
        .await;
    assert!(matches!(
        gateway.config_warnings().await,
        Err(GatewayError::Unauthorized(_))
    ));
}

#[tokio::test]
async fn a_silent_or_strange_livez_is_reported() {
    let (server, gateway) = setup().await;
    Mock::given(method("GET"))
        .and(path("/livez"))
        .respond_with(ResponseTemplate::new(200).set_body_string("<html>"))
        .mount(&server)
        .await;
    assert!(matches!(gateway.ping().await, Err(GatewayError::Remote(_))));

    let gateway = HttpAdminGateway::new(
        "http://127.0.0.1:9",
        TOKEN,
        HttpAdminGateway::client(None, false).unwrap(),
    )
    .unwrap();
    assert!(matches!(
        gateway.ping().await,
        Err(GatewayError::Unreachable(_))
    ));
}

fn reload(pending_created: bool, restart_required: &[&str]) -> ResponseTemplate {
    ResponseTemplate::new(200).set_body_json(json!({
        "diff": {
            "added_registries": [],
            "removed_registries": [],
            "changed_registries": [],
            "access_config_changed": false,
            "limits_changed": false,
            "restart_required": restart_required,
        },
        "warnings": [],
        "pending_created": pending_created,
    }))
}

#[tokio::test]
async fn the_configuration_endpoints_send_the_content_and_read_the_answer() {
    use wiremock::matchers::body_json;
    let (server, gateway) = setup().await;
    let content = "[server]\nport = 8080\n";
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/config/content"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!({"content": content, "is_readonly": false})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/config/validate"))
        .and(header("authorization", format!("Bearer {TOKEN}").as_str()))
        .and(body_json(json!({"content": content})))
        .respond_with(reload(false, &["database.url"]))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/config/from-content"))
        .and(body_json(json!({"content": content})))
        .respond_with(reload(true, &[]))
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/api/v1/admin/config/pending/apply"))
        .respond_with(reload(false, &[]))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/config/pending"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": "6f1c1d6e-4c1b-4a43-9a51-0b1f6f2d5d10",
            "created_at": "2026-10-15T10:00:00Z",
            "expires_at": "2026-10-15T10:10:00Z",
            "source": "file_watcher",
            "diff": {
                "added_registries": [], "removed_registries": [], "changed_registries": [],
                "access_config_changed": false, "limits_changed": false,
            },
            "warnings": [],
        })))
        .mount(&server)
        .await;
    Mock::given(method("DELETE"))
        .and(path("/api/v1/admin/config/pending"))
        .respond_with(
            ResponseTemplate::new(404)
                .set_body_json(json!({"error": "Not Found", "message": "no pending reload"})),
        )
        .mount(&server)
        .await;

    assert_eq!(gateway.config_content().await.unwrap(), content);
    let check = gateway.validate_config(content).await.unwrap();
    assert_eq!(check.restart_required, ["database.url"]);
    assert!(gateway.stage_config(content).await.unwrap());
    gateway.apply_pending().await.unwrap();
    assert_eq!(
        gateway.pending().await.unwrap(),
        Some(application::ports::PendingSource::FileWatcher)
    );
    // Nothing to discard is fine.
    gateway.discard_pending().await.unwrap();
}

#[tokio::test]
async fn configuration_answers_map_per_endpoint() {
    let (server, gateway) = setup().await;
    // BatleHub's error bodies (`AppError`).
    let at = |verb: &'static str, route: &'static str, status: u16, message: &str| {
        Mock::given(method(verb)).and(path(route)).respond_with(
            ResponseTemplate::new(status).set_body_json(json!({"error": "x", "message": message})),
        )
    };
    let refusal = "parsing config TOML: TOML parse error at line 1, column 12\n  |\n\
                   1 | password = s3cr3t\n  |            ^\nexpected a value";
    at("POST", "/api/v1/admin/config/validate", 400, refusal)
        .mount(&server)
        .await;
    at(
        "POST",
        "/api/v1/admin/config/from-content",
        503,
        "hot reload is disabled on this instance (BATLEHUB_DISABLE_HOT_RELOAD=1)",
    )
    .mount(&server)
    .await;
    at(
        "POST",
        "/api/v1/admin/config/pending/apply",
        409,
        "pending reload expired",
    )
    .mount(&server)
    .await;
    at(
        "GET",
        "/api/v1/admin/config/pending",
        404,
        "no pending reload",
    )
    .mount(&server)
    .await;
    Mock::given(method("GET"))
        .and(path("/api/v1/admin/config/content"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"content": "", "is_readonly": true})),
        )
        .mount(&server)
        .await;

    match gateway.validate_config("x").await {
        Err(GatewayError::Rejected(why)) => {
            assert!(why.contains("expected a value"), "{why}");
            assert!(!why.contains("s3cr3t"), "{why}");
        }
        other => panic!("{other:?}"),
    }
    assert!(matches!(
        gateway.stage_config("x").await,
        Err(GatewayError::HotReloadDisabled(_))
    ));
    assert!(matches!(
        gateway.apply_pending().await,
        Err(GatewayError::NoPending(_))
    ));
    assert_eq!(gateway.pending().await.unwrap(), None);
    assert!(matches!(
        gateway.config_content().await,
        Err(GatewayError::HotReloadDisabled(_))
    ));
}

#[tokio::test]
async fn a_proxy_s_503_or_404_is_not_batlehub_s() {
    let (server, gateway) = setup().await;
    for (route, status) in [
        ("/api/v1/admin/config/from-content", 503),
        ("/api/v1/admin/config/pending", 404),
    ] {
        Mock::given(path(route))
            .respond_with(ResponseTemplate::new(status).set_body_string("no healthy upstream"))
            .mount(&server)
            .await;
    }
    assert!(matches!(
        gateway.stage_config("x").await,
        Err(GatewayError::Unreachable(_))
    ));
    assert!(matches!(
        gateway.pending().await,
        Err(GatewayError::Remote(_))
    ));
}
