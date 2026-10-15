//! [`AdminGateway`] on BatleHub's admin API, through the generated
//! `batlehub-client` (`spec/`, `task gen:client`) — plus `/livez`, which
//! BatleHub serves outside its OpenAPI.
//!
//! Each method translates the answers of its own endpoint into a neutral
//! [`GatewayError`]: a status code means different things on different
//! endpoints of BatleHub (the spec's §2.10).

use std::time::Duration;

use application::ports::{
    AdminGateway, AdminRequest, ConfigWarning, Exemption, GatewayError, GrantWrite, InstanceInfo,
    Method, PackageNode, PendingSource, ReloadCheck, StoredGrant, TeamNamespace,
};
use batlehub_client::apis::configuration::Configuration;
use batlehub_client::apis::{Error as ClientError, back_office_api, front_office_api};
use batlehub_client::models::{
    ClaimNamespaceRequest, ConfigFromContentRequest, ReloadSource, Role,
};
use reqwest::{Client, StatusCode, Url};

use crate::redact::without_source;
use serde::Deserialize;
use serde_json::{Value, json};

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

    /// `request` with the token and user agent the generated client sends.
    fn authorized(&self, mut request: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(token) = &self.config.bearer_access_token {
            request = request.bearer_auth(token);
        }
        if let Some(agent) = &self.config.user_agent {
            request = request.header(reqwest::header::USER_AGENT, agent);
        }
        request
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

impl HttpAdminGateway {
    /// One call by path, its status and body; no answer is
    /// [`GatewayError::Unreachable`].
    async fn raw(
        &self,
        method: reqwest::Method,
        segments: &[&str],
        query: &[(&str, &str)],
        body: Option<&Value>,
    ) -> Result<(StatusCode, String), GatewayError> {
        self.raw_within(method, segments, query, body, None).await
    }

    /// [`Self::raw`], `timeout` replacing the client's.
    async fn raw_within(
        &self,
        method: reqwest::Method,
        segments: &[&str],
        query: &[(&str, &str)],
        body: Option<&Value>,
        timeout: Option<Duration>,
    ) -> Result<(StatusCode, String), GatewayError> {
        let mut request = self
            .authorized(self.config.client.request(method, self.url(segments)))
            .query(query);
        if let Some(timeout) = timeout {
            request = request.timeout(timeout);
        }
        if let Some(body) = body {
            request = request.json(body);
        }
        let response = request
            .send()
            .await
            .map_err(|e| GatewayError::Unreachable(e.to_string()))?;
        let status = response.status();
        let body = response
            .text()
            .await
            .map_err(|e| GatewayError::Unreachable(e.to_string()))?;
        Ok((status, body))
    }

    /// `/api/v1/admin/registries/{registry}/<rest…>`.
    fn registry_path<'a>(registry: &'a str, rest: &[&'a str]) -> Vec<&'a str> {
        let mut path = vec!["api", "v1", "admin", "registries", registry];
        path.extend_from_slice(rest);
        path
    }

    /// The policy route of `node`: the package's slashes stay separators
    /// on the package route (it takes the rest of the path), the package
    /// is one (encoded) segment on the version route.
    fn policy_path(node: &PackageNode) -> Vec<&str> {
        match &node.version {
            None => {
                let mut rest = vec!["policy", "package"];
                rest.extend(node.package.split('/'));
                Self::registry_path(&node.registry, &rest)
            }
            Some(version) => Self::registry_path(
                &node.registry,
                &["policy", "version", &node.package, version],
            ),
        }
    }
}

/// `endpoint: <BatleHub's message>` — its `{"error", "message"}` decoded,
/// cut.
fn refusal(endpoint: &str, body: &str) -> String {
    let message = serde_json::from_str::<Value>(body)
        .ok()
        .and_then(|v| v.get("message")?.as_str().map(String::from))
        .unwrap_or_else(|| body.to_string());
    format!(
        "{endpoint}: {}",
        message.chars().take(BODY_EXCERPT * 2).collect::<String>()
    )
}

/// A governance endpoint's answer: 400 a refusal, 404 an unknown
/// registry, 409 an ownership row, 503 no grant storage; anything else as
/// [`unexpected_status`].
fn governance_error(endpoint: &str, status: StatusCode, body: &str) -> GatewayError {
    match status {
        StatusCode::BAD_REQUEST => GatewayError::Refused(refusal(endpoint, body)),
        StatusCode::NOT_FOUND => GatewayError::NotFound(refusal(endpoint, body)),
        StatusCode::CONFLICT => GatewayError::HeldByOwnership(refusal(endpoint, body)),
        StatusCode::SERVICE_UNAVAILABLE => {
            GatewayError::StorageUnavailable(refusal(endpoint, body))
        }
        status => unexpected_status(status, body),
    }
}

/// An exemption endpoint's answer: 403 is the missing `gates:exempt`.
fn exemption_error(endpoint: &str, status: StatusCode, body: &str) -> GatewayError {
    match status {
        StatusCode::FORBIDDEN => GatewayError::NotPermitted(refusal(endpoint, body)),
        status => governance_error(endpoint, status, body),
    }
}

fn decode<T: serde::de::DeserializeOwned>(endpoint: &str, body: &str) -> Result<T, GatewayError> {
    serde_json::from_str(body)
        .map_err(|e| GatewayError::Remote(format!("{endpoint}: unexpected answer: {e}")))
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

    /// `GET /api/v1/admin/health` (`system:read`): one entry per registry.
    /// Only `registry` is read: the generated model decodes every
    /// statistic, which this has no use for.
    async fn registry_names(&self) -> Result<Vec<String>, GatewayError> {
        const ENDPOINT: &str = "/api/v1/admin/health";
        #[derive(Deserialize)]
        struct Entry {
            registry: String,
        }
        let response = self
            .authorized(
                self.config
                    .client
                    .get(self.url(&["api", "v1", "admin", "health"])),
            )
            .send()
            .await
            .map_err(|e| GatewayError::Unreachable(e.to_string()))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            return Err(unexpected_status(status, &body));
        }
        let entries = response
            .json::<Vec<Entry>>()
            .await
            .map_err(|e| GatewayError::Remote(format!("{ENDPOINT}: unexpected answer: {e}")))?;
        Ok(entries.into_iter().map(|e| e.registry).collect())
    }

    /// `GET /api/v1/admin/registries/{registry}/namespaces` (`owners:read`).
    async fn team_namespaces(&self, registry: &str) -> Result<Vec<TeamNamespace>, GatewayError> {
        let params = back_office_api::ListNamespacesParams {
            registry: registry.to_string(),
        };
        let namespaces = back_office_api::list_namespaces(&self.config, params)
            .await
            .map_err(|e| client_error("/api/v1/admin/registries/{registry}/namespaces", e))?;
        Ok(namespaces
            .into_iter()
            .map(|n| TeamNamespace {
                prefix: n.prefix,
                group: n.group_id,
                claimed_by: n.claimed_by.flatten(),
                package_count: n.package_count,
            })
            .collect())
    }

    /// `POST /api/v1/admin/registries/{registry}/namespaces`
    /// (`owners:write`): 409 when the prefix is claimed.
    async fn claim_namespace(
        &self,
        registry: &str,
        namespace: &TeamNamespace,
    ) -> Result<(), GatewayError> {
        const ENDPOINT: &str = "/api/v1/admin/registries/{registry}/namespaces";
        let mut request =
            ClaimNamespaceRequest::new(namespace.group.clone(), namespace.prefix.clone());
        request.claimed_by = Some(namespace.claimed_by.clone());
        let params = back_office_api::ClaimNamespaceParams {
            registry: registry.to_string(),
            claim_namespace_request: request,
        };
        match back_office_api::claim_namespace(&self.config, params).await {
            Ok(()) => Ok(()),
            Err(ClientError::ResponseError(response))
                if response.status == StatusCode::CONFLICT =>
            {
                Err(GatewayError::AlreadyClaimed(format!(
                    "{ENDPOINT}: {}",
                    response
                        .content
                        .chars()
                        .take(BODY_EXCERPT)
                        .collect::<String>()
                )))
            }
            Err(ClientError::ResponseError(response))
                if response.status == StatusCode::BAD_REQUEST =>
            {
                Err(GatewayError::Rejected(format!(
                    "{ENDPOINT}: {}",
                    response
                        .content
                        .chars()
                        .take(BODY_EXCERPT)
                        .collect::<String>()
                )))
            }
            Err(e) => Err(client_error(ENDPOINT, e)),
        }
    }

    /// `DELETE /api/v1/admin/registries/{registry}/namespaces/{prefix}`
    /// (`owners:write`), none claimed is fine. The prefix's slashes stay
    /// path separators (the route takes the rest of the path): the
    /// generated client would encode them.
    async fn release_namespace(&self, registry: &str, prefix: &str) -> Result<(), GatewayError> {
        let mut segments = vec!["api", "v1", "admin", "registries", registry, "namespaces"];
        segments.extend(prefix.split('/'));
        let response = self
            .authorized(self.config.client.delete(self.url(&segments)))
            .send()
            .await
            .map_err(|e| GatewayError::Unreachable(e.to_string()))?;
        let status = response.status();
        if status.is_success() {
            return Ok(());
        }
        let body = response.text().await.unwrap_or_default();
        Err(unexpected_status(status, &body))
    }

    /// `GET /api/v1/admin/registries/{registry}/grants` (`grants:read`):
    /// a package node's listing also has its versions' rows, left out.
    async fn grants(&self, node: &PackageNode) -> Result<Vec<StoredGrant>, GatewayError> {
        const ENDPOINT: &str = "/api/v1/admin/registries/{registry}/grants";
        #[derive(Deserialize)]
        struct Row {
            node_kind: String,
            node_key: String,
            subject: String,
            actions: Vec<String>,
            #[serde(default)]
            from_ownership: bool,
            #[serde(default)]
            granted_by: Option<String>,
        }
        #[derive(Deserialize)]
        struct Listing {
            grants: Vec<Row>,
        }
        let mut query = vec![("package", node.package.as_str())];
        if let Some(version) = &node.version {
            query.push(("version", version));
        }
        let (status, body) = self
            .raw(
                reqwest::Method::GET,
                &Self::registry_path(&node.registry, &["grants"]),
                &query,
                None,
            )
            .await?;
        if !status.is_success() {
            return Err(governance_error(ENDPOINT, status, &body));
        }
        let (kind, key) = match &node.version {
            Some(v) => ("version", format!("{}@{v}", node.package)),
            None => ("package", node.package.clone()),
        };
        Ok(decode::<Listing>(ENDPOINT, &body)?
            .grants
            .into_iter()
            .filter(|r| r.node_kind == kind && r.node_key == key)
            .map(|r| StoredGrant {
                subject: r.subject,
                actions: r.actions,
                from_ownership: r.from_ownership,
                granted_by: r.granted_by,
            })
            .collect())
    }

    /// `PUT /api/v1/admin/registries/{registry}/grants` (`grants:write`).
    async fn put_grant(
        &self,
        node: &PackageNode,
        subject: &str,
        actions: &[String],
    ) -> Result<GrantWrite, GatewayError> {
        const ENDPOINT: &str = "PUT /api/v1/admin/registries/{registry}/grants";
        #[derive(Deserialize)]
        struct Written {
            actions: Vec<String>,
            #[serde(default)]
            warnings: Vec<String>,
        }
        let body = json!({
            "package": node.package,
            "version": node.version,
            "subject": subject,
            "actions": actions,
        });
        let (status, body) = self
            .raw(
                reqwest::Method::PUT,
                &Self::registry_path(&node.registry, &["grants"]),
                &[],
                Some(&body),
            )
            .await?;
        if !status.is_success() {
            return Err(governance_error(ENDPOINT, status, &body));
        }
        let written: Written = decode(ENDPOINT, &body)?;
        Ok(GrantWrite {
            stored: written.actions,
            warnings: written.warnings,
        })
    }

    /// `DELETE /api/v1/admin/registries/{registry}/grants`
    /// (`grants:write`): absent is a success.
    async fn delete_grant(&self, node: &PackageNode, subject: &str) -> Result<bool, GatewayError> {
        const ENDPOINT: &str = "DELETE /api/v1/admin/registries/{registry}/grants";
        #[derive(Deserialize)]
        struct Removed {
            removed: bool,
        }
        let body = json!({
            "package": node.package,
            "version": node.version,
            "subject": subject,
        });
        let (status, body) = self
            .raw(
                reqwest::Method::DELETE,
                &Self::registry_path(&node.registry, &["grants"]),
                &[],
                Some(&body),
            )
            .await?;
        if !status.is_success() {
            return Err(governance_error(ENDPOINT, status, &body));
        }
        Ok(decode::<Removed>(ENDPOINT, &body)?.removed)
    }

    /// `GET …/policy/package/{package}` or `…/policy/version/{package}/{version}`
    /// (`owners:read`): 404 is no policy on the node.
    async fn policy(&self, node: &PackageNode) -> Result<Option<Value>, GatewayError> {
        const ENDPOINT: &str = "GET /api/v1/admin/registries/{registry}/policy";
        let (status, body) = self
            .raw(reqwest::Method::GET, &Self::policy_path(node), &[], None)
            .await?;
        match status {
            StatusCode::NOT_FOUND => Ok(None),
            status if status.is_success() => decode(ENDPOINT, &body).map(Some),
            status => Err(governance_error(ENDPOINT, status, &body)),
        }
    }

    /// `PUT …/policy/…` (`owners:write`): replaces the node's policy.
    async fn put_policy(&self, node: &PackageNode, policy: &Value) -> Result<(), GatewayError> {
        const ENDPOINT: &str = "PUT /api/v1/admin/registries/{registry}/policy";
        let (status, body) = self
            .raw(
                reqwest::Method::PUT,
                &Self::policy_path(node),
                &[],
                Some(policy),
            )
            .await?;
        if !status.is_success() {
            return Err(governance_error(ENDPOINT, status, &body));
        }
        Ok(())
    }

    /// `DELETE …/policy/…` (`owners:write`): absent is a success.
    async fn delete_policy(&self, node: &PackageNode) -> Result<(), GatewayError> {
        const ENDPOINT: &str = "DELETE /api/v1/admin/registries/{registry}/policy";
        let (status, body) = self
            .raw(reqwest::Method::DELETE, &Self::policy_path(node), &[], None)
            .await?;
        if !status.is_success() {
            return Err(governance_error(ENDPOINT, status, &body));
        }
        Ok(())
    }

    /// `PUT …/policy/version/{package}/{version}/rules/{gate}`
    /// (`gates:exempt` on the version, which no role carries).
    async fn set_exemption(
        &self,
        node: &PackageNode,
        exemption: &Exemption,
    ) -> Result<(), GatewayError> {
        const ENDPOINT: &str =
            "PUT /api/v1/admin/registries/{registry}/policy/version/…/rules/{gate}";
        let mut path = Self::policy_path(node);
        path.extend(["rules", exemption.gate.as_str()]);
        let body = json!({
            "exempt_until": exemption.exempt_until,
            "reason": exemption.reason,
        });
        let (status, body) = self
            .raw(reqwest::Method::PUT, &path, &[], Some(&body))
            .await?;
        if !status.is_success() {
            return Err(exemption_error(ENDPOINT, status, &body));
        }
        Ok(())
    }

    /// `DELETE …/rules/{gate}` (`gates:exempt`): absent is a success.
    async fn delete_exemption(&self, node: &PackageNode, gate: &str) -> Result<(), GatewayError> {
        const ENDPOINT: &str =
            "DELETE /api/v1/admin/registries/{registry}/policy/version/…/rules/{gate}";
        let mut path = Self::policy_path(node);
        path.extend(["rules", gate]);
        let (status, body) = self.raw(reqwest::Method::DELETE, &path, &[], None).await?;
        if !status.is_success() {
            return Err(exemption_error(ENDPOINT, status, &body));
        }
        Ok(())
    }

    /// `GET /api/v1/me`.
    async fn whoami(&self) -> Result<Option<String>, GatewayError> {
        let me = front_office_api::me(&self.config)
            .await
            .map_err(|e| client_error("/api/v1/me", e))?;
        Ok(me.user_id.flatten())
    }

    /// Any admin call: a 2xx answer as JSON (`null` when empty, the text
    /// as a string when not JSON); 400 a refusal, 404 not found.
    async fn call(&self, request: &AdminRequest) -> Result<Value, GatewayError> {
        let method = match request.method {
            Method::Get => reqwest::Method::GET,
            Method::Post => reqwest::Method::POST,
            Method::Put => reqwest::Method::PUT,
            Method::Delete => reqwest::Method::DELETE,
        };
        let segments: Vec<&str> = request.path.iter().map(String::as_str).collect();
        let query: Vec<(&str, &str)> = request
            .query
            .iter()
            .map(|(k, v)| (k.as_str(), v.as_str()))
            .collect();
        let endpoint = format!("{} /{}", method, request.path.join("/"));
        let (status, body) = self
            .raw_within(
                method,
                &segments,
                &query,
                request.body.as_ref(),
                request.timeout,
            )
            .await?;
        match status {
            status if status.is_success() => Ok(if body.trim().is_empty() {
                Value::Null
            } else {
                serde_json::from_str(&body).unwrap_or(Value::String(body))
            }),
            StatusCode::BAD_REQUEST => Err(GatewayError::Refused(refusal(&endpoint, &body))),
            StatusCode::NOT_FOUND => Err(GatewayError::NotFound(refusal(&endpoint, &body))),
            status => Err(unexpected_status(status, &body)),
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
