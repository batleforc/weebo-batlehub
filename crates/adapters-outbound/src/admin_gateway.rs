//! [`AdminGateway`] on BatleHub's admin API, through the generated
//! `batlehub-client` (`spec/`, `task gen:client`) — plus `/livez`, which
//! BatleHub serves outside its OpenAPI.
//!
//! Each method translates the answers of its own endpoint into a neutral
//! [`GatewayError`]: a status code means different things on different
//! endpoints of BatleHub (the spec's §2.10).

use std::time::Duration;

use application::ports::{
    AdminGateway, ConfigWarning, GatewayError, InstanceInfo, PendingSource, ReloadCheck,
};
use batlehub_client::apis::configuration::Configuration;
use batlehub_client::apis::{Error as ClientError, back_office_api, front_office_api};
use batlehub_client::models::{ConfigFromContentRequest, ReloadSource, Role};
use reqwest::{Client, StatusCode, Url};

use crate::redact::without_source;
use serde::Deserialize;

/// Per-request timeout: a hung instance must not hold a reconcile forever.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// How much of an unexpected answer's body a message keeps.
const BODY_EXCERPT: usize = 200;

pub struct HttpAdminGateway {
    base: Url,
    config: Configuration,
}

#[derive(Deserialize)]
struct Livez {
    version: String,
}

impl HttpAdminGateway {
    /// `url`: the instance's base URL. `Err` when it can't serve as one.
    pub fn new(url: &str, token: impl Into<String>, client: Client) -> Result<Self, String> {
        let base = Url::parse(url).map_err(|e| format!("url {url:?}: {e}"))?;
        if base.cannot_be_a_base() || !matches!(base.scheme(), "http" | "https") {
            return Err(format!("url {url:?}: not an http(s) base URL"));
        }
        let config = Configuration {
            base_path: base.as_str().trim_end_matches('/').to_string(),
            user_agent: Some(format!("weebo-batlehub/{}", env!("CARGO_PKG_VERSION"))),
            client,
            bearer_access_token: Some(token.into()),
            ..Configuration::default()
        };
        Ok(Self { base, config })
    }

    /// The HTTP client: rustls, the platform trust store plus `ca_pem`
    /// (a PEM bundle) when given, certificate verification off when
    /// `insecure_skip_verify`, a timeout. A `ca_pem` holding no
    /// certificate is an error, never a silent fallback to the platform
    /// store alone.
    pub fn client(ca_pem: Option<&[u8]>, insecure_skip_verify: bool) -> Result<Client, String> {
        let mut builder = Client::builder().timeout(REQUEST_TIMEOUT);
        if let Some(pem) = ca_pem {
            let certs = reqwest::Certificate::from_pem_bundle(pem)
                .map_err(|e| format!("tls.caSecretRef: {e}"))?;
            if certs.is_empty() {
                return Err("tls.caSecretRef holds no PEM certificate".into());
            }
            for cert in certs {
                builder = builder.add_root_certificate(cert);
            }
        }
        if insecure_skip_verify {
            builder = builder.danger_accept_invalid_certs(true);
        }
        builder
            .build()
            .map_err(|e| format!("building the HTTP client: {e}"))
    }

    /// `{url}/<segments…>`, each segment percent-encoded.
    fn url(&self, segments: &[&str]) -> Url {
        let mut url = self.base.clone();
        url.path_segments_mut()
            // Checked in `new`.
            .expect("an http(s) URL is a base")
            .pop_if_empty()
            .extend(segments);
        url
    }

    /// `GET /livez`: unauthenticated, answers `{"ok": true, "version"}`.
    async fn livez(&self) -> Result<String, GatewayError> {
        let response = self
            .config
            .client
            .get(self.url(&["livez"]))
            .send()
            .await
            .map_err(|e| GatewayError::Unreachable(e.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(unexpected_status(status, &body));
        }
        response
            .json::<Livez>()
            .await
            .map(|l| l.version)
            .map_err(|e| GatewayError::Remote(format!("/livez: unexpected answer: {e}")))
    }

    /// `GET /api/v1/me`: the token must be known and carry the admin role.
    /// BatleHub answers an unknown token as `anonymous` (200), not 401.
    async fn check_token(&self) -> Result<(), GatewayError> {
        let me = front_office_api::me(&self.config)
            .await
            .map_err(|e| client_error("/api/v1/me", e))?;
        if me.role != Role::Admin {
            return Err(GatewayError::Unauthorized(format!(
                "the token's role is {:?}, the operator needs \"admin\"",
                me.role.to_string()
            )));
        }
        Ok(())
    }
}

/// 401/403 refuse the token, 502/503/504 mean no answer, anything else is
/// unexpected — for the endpoints that document nothing more.
fn unexpected_status(status: StatusCode, body: &str) -> GatewayError {
    let why = format!(
        "{status}: {}",
        body.chars().take(BODY_EXCERPT).collect::<String>()
    );
    match status {
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => GatewayError::Unauthorized(why),
        StatusCode::BAD_GATEWAY | StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT => {
            GatewayError::Unreachable(why)
        }
        _ => GatewayError::Remote(why),
    }
}

/// A configuration endpoint's answer, by what BatleHub says rather than
/// the status alone — a proxy in front of it answers 503 or 404 too: 400
/// is the instance refusing the configuration, a 503 saying hot reload is
/// disabled is that, a 404/409 about the pending reload is nothing (or
/// nothing live) staged; anything else as [`client_error`]. A refusal may
/// quote a configuration line (from a Secret layer): that line goes.
fn config_error<T>(endpoint: &str, err: ClientError<T>) -> GatewayError {
    match err {
        ClientError::ResponseError(response) => {
            let body = response.content.to_lowercase();
            // BatleHub's `{"error", "message"}`: the message decoded (a
            // quoted line hides behind `\n` escapes otherwise).
            let message = serde_json::from_str::<serde_json::Value>(&response.content)
                .ok()
                .and_then(|v| v.get("message")?.as_str().map(String::from))
                .unwrap_or_else(|| response.content.clone());
            let why = || {
                format!(
                    "{endpoint}: {}",
                    without_source(&message)
                        .chars()
                        .take(BODY_EXCERPT * 4)
                        .collect::<String>()
                )
            };
            match response.status {
                StatusCode::BAD_REQUEST => GatewayError::Rejected(why()),
                StatusCode::SERVICE_UNAVAILABLE if body.contains("hot reload is disabled") => {
                    GatewayError::HotReloadDisabled(why())
                }
                StatusCode::NOT_FOUND | StatusCode::CONFLICT if body.contains("pending reload") => {
                    GatewayError::NoPending(why())
                }
                status => unexpected_status(status, &response.content),
            }
        }
        other => client_error(endpoint, other),
    }
}

fn client_error<T>(endpoint: &str, err: ClientError<T>) -> GatewayError {
    match err {
        ClientError::ResponseError(response) => {
            unexpected_status(response.status, &response.content)
        }
        ClientError::Reqwest(e) if e.is_decode() => {
            GatewayError::Remote(format!("{endpoint}: unexpected answer: {e}"))
        }
        ClientError::Reqwest(e) => GatewayError::Unreachable(e.to_string()),
        ClientError::Serde(e) => {
            GatewayError::Remote(format!("{endpoint}: unexpected answer: {e}"))
        }
        ClientError::Io(e) => GatewayError::Unreachable(e.to_string()),
    }
}

#[async_trait::async_trait]
impl AdminGateway for HttpAdminGateway {
    async fn ping(&self) -> Result<InstanceInfo, GatewayError> {
        let version = self.livez().await?;
        self.check_token().await?;
        Ok(InstanceInfo { version })
    }

    /// `GET /api/v1/admin/config/warnings` (`config:read`, which the admin
    /// role has).
    async fn config_warnings(&self) -> Result<Vec<ConfigWarning>, GatewayError> {
        let response = back_office_api::get_config_warnings(&self.config)
            .await
            .map_err(|e| client_error("/api/v1/admin/config/warnings", e))?;
        Ok(response
            .warnings
            .into_iter()
            .map(|w| ConfigWarning {
                code: w.code,
                path: w.path,
                message: w.message,
            })
            .collect())
    }

    /// `GET /api/v1/admin/config/content` (`config:read`). A read-only
    /// file (hot reload disabled) can't take a push.
    async fn config_content(&self) -> Result<String, GatewayError> {
        const ENDPOINT: &str = "/api/v1/admin/config/content";
        let response = back_office_api::get_config_content(&self.config)
            .await
            .map_err(|e| client_error(ENDPOINT, e))?;
        if response.is_readonly {
            return Err(GatewayError::HotReloadDisabled(format!(
                "{ENDPOINT}: the configuration is read-only (BATLEHUB_DISABLE_HOT_RELOAD)"
            )));
        }
        Ok(response.content)
    }

    /// `POST /api/v1/admin/config/validate` (`config:read`): a dry run.
    async fn validate_config(&self, content: &str) -> Result<ReloadCheck, GatewayError> {
        const ENDPOINT: &str = "/api/v1/admin/config/validate";
        let params = back_office_api::ValidateConfigContentParams {
            config_from_content_request: ConfigFromContentRequest::new(content.to_string()),
        };
        let response = back_office_api::validate_config_content(&self.config, params)
            .await
            .map_err(|e| config_error(ENDPOINT, e))?;
        Ok(ReloadCheck {
            restart_required: response.diff.restart_required.unwrap_or_default(),
        })
    }

    /// `POST /api/v1/admin/config/from-content` (`config:write`).
    async fn stage_config(&self, content: &str) -> Result<bool, GatewayError> {
        const ENDPOINT: &str = "/api/v1/admin/config/from-content";
        let params = back_office_api::LoadConfigFromContentParams {
            config_from_content_request: ConfigFromContentRequest::new(content.to_string()),
        };
        let response = back_office_api::load_config_from_content(&self.config, params)
            .await
            .map_err(|e| config_error(ENDPOINT, e))?;
        Ok(response.pending_created)
    }

    /// `POST /api/v1/admin/config/pending/apply` (`config:write`).
    async fn apply_pending(&self) -> Result<(), GatewayError> {
        back_office_api::apply_pending_reload(&self.config)
            .await
            .map(|_| ())
            .map_err(|e| config_error("/api/v1/admin/config/pending/apply", e))
    }

    /// `GET /api/v1/admin/config/pending` (`config:read`): 404 is none.
    async fn pending(&self) -> Result<Option<PendingSource>, GatewayError> {
        match back_office_api::get_pending_reload(&self.config).await {
            Ok(snapshot) => Ok(Some(match snapshot.source {
                ReloadSource::FileWatcher => PendingSource::FileWatcher,
                ReloadSource::AdminRequest => PendingSource::AdminRequest,
            })),
            Err(e) => match config_error("/api/v1/admin/config/pending", e) {
                GatewayError::NoPending(_) => Ok(None),
                other => Err(other),
            },
        }
    }

    /// `DELETE /api/v1/admin/config/pending` (`config:write`): none is
    /// fine.
    async fn discard_pending(&self) -> Result<(), GatewayError> {
        match back_office_api::discard_pending_reload(&self.config).await {
            Ok(()) => Ok(()),
            Err(e) => match config_error("/api/v1/admin/config/pending", e) {
                GatewayError::NoPending(_) => Ok(()),
                other => Err(other),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gateway(url: &str) -> Result<HttpAdminGateway, String> {
        HttpAdminGateway::new(url, "t", Client::new())
    }

    #[test]
    fn paths_hang_off_the_base_url() {
        let gw = gateway("https://example.com/sub/").unwrap();
        assert_eq!(gw.url(&["livez"]).as_str(), "https://example.com/sub/livez");
        assert_eq!(gw.config.base_path, "https://example.com/sub");
        let gw = gateway("https://example.com").unwrap();
        assert_eq!(gw.url(&["livez"]).as_str(), "https://example.com/livez");
        assert_eq!(gw.config.base_path, "https://example.com");
    }

    #[test]
    fn a_ca_must_hold_a_certificate() {
        assert!(HttpAdminGateway::client(None, false).is_ok());
        assert!(HttpAdminGateway::client(None, true).is_ok());
        assert!(HttpAdminGateway::client(Some(b"not a pem"), false).is_err());
        assert!(HttpAdminGateway::client(Some(b""), false).is_err());
    }

    #[test]
    fn only_http_base_urls_are_accepted() {
        assert!(gateway("not a url").is_err());
        assert!(gateway("mailto:someone@example.com").is_err());
        assert!(gateway("ftp://example.com").is_err());
    }

    #[test]
    fn statuses_map_onto_neutral_errors() {
        assert!(matches!(
            unexpected_status(StatusCode::UNAUTHORIZED, ""),
            GatewayError::Unauthorized(_)
        ));
        assert!(matches!(
            unexpected_status(StatusCode::GATEWAY_TIMEOUT, ""),
            GatewayError::Unreachable(_)
        ));
        let long = "x".repeat(1000);
        match unexpected_status(StatusCode::INTERNAL_SERVER_ERROR, &long) {
            GatewayError::Remote(why) => assert!(why.len() < 300),
            other => panic!("{other:?}"),
        }
    }
}
