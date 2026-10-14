//! Contract test of `HttpAdminGateway` against a scripted BatleHub
//! (`wiremock`): the requests it sends and how each answer maps onto a
//! `GatewayError`. Response shapes follow BatleHub 1.5.0
//! (`spec/batlehub-v1.5.0.json`, `/livez` from its source).

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
            ResponseTemplate::new(200).set_body_json(json!({"ok": true, "version": "1.5.0"})),
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
    assert_eq!(gateway.ping().await.unwrap().version, "1.5.0");
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
