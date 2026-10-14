//! [`AdminGateway`] on BatleHub's admin API, through the generated
//! `batlehub-client` (`spec/`, `task gen:client`) — plus `/livez`, which
//! BatleHub serves outside its OpenAPI.
//!
//! Each method translates the answers of its own endpoint into a neutral
//! [`GatewayError`]: a status code means different things on different
//! endpoints of BatleHub (the spec's §2.10).

use std::time::Duration;

use application::ports::{AdminGateway, ConfigWarning, GatewayError, InstanceInfo};
use batlehub_client::apis::configuration::Configuration;
use batlehub_client::apis::{Error as ClientError, back_office_api, front_office_api};
use batlehub_client::models::Role;
use reqwest::{Client, StatusCode, Url};
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
