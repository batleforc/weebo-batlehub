//! The configuration an instance runs with `external.manageConfig`:
//! `spec.config`, then `spec.configLayers` ([`base_layers`]), then the
//! `BatleHubRegistry`s it accepts as `[[registries]]` entries
//! ([`render_registries`]) — merged by BatleHub's own `merge_layers` into
//! one canonical document whose `${VAR}` stay for the instance to resolve,
//! validated by BatleHub's parser, hashed ([`render_config`]); then the
//! operator's token checked against it ([`check_token`]). Separate steps,
//! so the reconcile reports the causes in the order of the spec's §5.
//!
//! No message quotes a source's text: a layer may come from a Secret.

use std::collections::BTreeMap;

use api::LocalInstance;
use api::local_instance::{RegistrySelector, Validation};
use api::registry::RegistrySpec;
use domain::error::ReasonCode;
use domain::{Advisory, Failure};
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};
use weebo_kit_application::instances::SharedWith;
use weebo_kit_application::sharing::shares_with;

use crate::ports::{
    BoundInstance, ConfigError, ConfigParser, ConfigSources, RegistryView, SourceError, TokenCheck,
};

/// What a `${VAR}` the operator can't read stands for while validating:
/// shaped like the URLs most placeholders hold (a database, an issuer, an
/// endpoint), which BatleHub checks for `https`. Never sent anywhere.
pub const STAND_IN: &str = "https://weebo-batlehub.invalid";

/// The configuration rendered for an instance.
#[derive(Debug, Clone, PartialEq)]
pub struct Rendered {
    /// One TOML document, as `merge_layers` writes it.
    pub document: String,
    /// SHA-256 of [`Self::document`], hex.
    pub hash: String,
    /// `UnresolvedPlaceholders`, `ConfigInvalidLenient`.
    pub advisories: Vec<Advisory>,
}

/// What became of a registry bound to the instance.
#[derive(Debug, Clone, PartialEq)]
pub struct RegistryDecision {
    pub namespace: String,
    pub name: String,
    /// The name BatleHub serves it under.
    pub registry_name: String,
    pub bound: BoundInstance,
    /// `Ok(true)`: rendered; `Ok(false)`: suspended; `Err`: left out.
    pub rendered: Result<bool, Failure>,
}

/// SHA-256 of `text`, hex.
pub fn sha256(text: &str) -> String {
    Sha256::digest(text.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// The registries bound to `instance` and what becomes of each, and the
/// `[[registries]]` entries of those rendered (sorted by namespace, then
/// name).
/// `statics`: the registry names the instance's own layers declare
/// ([`static_registry_names`]).
pub async fn render_registries(
    instance: &LocalInstance,
    bound: &BoundInstance,
    registries: Vec<RegistryView>,
    statics: &[String],
    sources: &dyn ConfigSources,
    parser: &dyn ConfigParser,
) -> (Vec<RegistryDecision>, Vec<Value>) {
    let namespace = bound.namespace.as_deref().unwrap_or_default();
    let mut mine: Vec<RegistryView> = registries
        .into_iter()
        .filter(|r| r.bound.as_ref().is_ok_and(|b| b == bound))
        .collect();
    // The oldest wins a duplicate name.
    mine.sort_by(|a, b| {
        (&a.created, &a.namespace, &a.name).cmp(&(&b.created, &b.namespace, &b.name))
    });
    let mut taken: BTreeMap<String, String> = BTreeMap::new();
    let mut decisions = Vec::new();
    let mut entries: Vec<(String, String, Value)> = Vec::new();
    for registry in mine {
        let registry_name = registry.spec.registry_name(&registry.name).to_string();
        let foreign = registry.namespace != namespace;
        let rendered = async {
            if registry.spec.suspend {
                return Ok(None);
            }
            if !selects(&instance.spec.registry_selector, &registry.labels) {
                return Err(Failure::new(
                    ReasonCode::InstanceNotAllowed,
                    format!("{bound} doesn't select this registry (its registrySelector.selector)"),
                ));
            }
            if let Some(winner) = taken.get(&registry_name) {
                return Err(Failure::new(
                    ReasonCode::DuplicateRegistryName,
                    format!(
                        "{winner} already renders a registry named {registry_name:?} on {bound}"
                    ),
                ));
            }
            // Attached: the oldest holds the name, rendered or not (its
            // fault fixed, it would take the name back from a younger one).
            taken.insert(
                registry_name.clone(),
                format!("BatleHubRegistry {}/{}", registry.namespace, registry.name),
            );
            if foreign && statics.contains(&registry_name) {
                return Err(Failure::new(
                    ReasonCode::DuplicateRegistryName,
                    format!(
                        "{bound}'s own configuration declares a registry named \
                         {registry_name:?}: only a registry of its namespace may complete it"
                    ),
                ));
            }
            let entry = registry_entry(&registry, &registry_name, sources, parser).await?;
            if foreign && contains_placeholder(&entry) {
                return Err(Failure::new(
                    ReasonCode::NamespaceNotAllowed,
                    format!(
                        "a registry of another namespace than {bound}'s may not contain `${{`: \
                         placeholders resolve from the instance's environment"
                    ),
                ));
            }
            Ok(Some(entry))
        }
        .await;
        let rendered = match rendered {
            Ok(Some(entry)) => {
                entries.push((registry.namespace.clone(), registry.name.clone(), entry));
                Ok(true)
            }
            Ok(None) => Ok(false),
            Err(failure) => Err(failure),
        };
        decisions.push(RegistryDecision {
            namespace: registry.namespace,
            name: registry.name,
            registry_name,
            bound: bound.clone(),
            rendered,
        });
    }
    entries.sort_by(|a, b| (&a.0, &a.1).cmp(&(&b.0, &b.1)));
    (decisions, entries.into_iter().map(|(_, _, e)| e).collect())
}

/// The registry's table: `config`, its `configFrom` fragments over it,
/// then `type` and `name`.
async fn registry_entry(
    registry: &RegistryView,
    registry_name: &str,
    sources: &dyn ConfigSources,
    parser: &dyn ConfigParser,
) -> Result<Value, Failure> {
    let spec: &RegistrySpec = &registry.spec;
    let mut entry = match &spec.config {
        Value::Null => Map::new(),
        Value::Object(map) => map.clone(),
        _ => {
            return Err(Failure::new(
                ReasonCode::ConfigInvalid,
                "spec.config must be an object",
            ));
        }
    };
    for (i, source) in spec.config_from.iter().enumerate() {
        let text = sources
            .read(&registry.namespace, source)
            .await
            .map_err(source_failure)?;
        let fragment = parser.fragment(&text).map_err(|e| {
            Failure::new(
                ReasonCode::ConfigInvalid,
                format!("spec.configFrom[{i}] is not TOML: {e}"),
            )
        })?;
        let Value::Object(fragment) = fragment else {
            unreachable!("a TOML document is a table");
        };
        if let Some(key) = ["type", "name"].iter().find(|k| fragment.contains_key(**k)) {
            return Err(Failure::new(
                ReasonCode::ConfigInvalid,
                format!("spec.configFrom[{i}] may not set {key:?}"),
            ));
        }
        deep_merge(&mut entry, fragment);
    }
    entry.insert("type".into(), json!(spec.r#type));
    entry.insert("name".into(), json!(registry_name));
    Ok(Value::Object(entry))
}

/// Tables merge recursively; anything else is replaced.
fn deep_merge(base: &mut Map<String, Value>, over: Map<String, Value>) {
    for (key, value) in over {
        match (base.get_mut(&key), value) {
            (Some(Value::Object(b)), Value::Object(o)) => deep_merge(b, o),
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

fn contains_placeholder(value: &Value) -> bool {
    match value {
        Value::String(s) => s.contains("${"),
        Value::Array(items) => items.iter().any(contains_placeholder),
        Value::Object(map) => map
            .iter()
            .any(|(k, v)| k.contains("${") || contains_placeholder(v)),
        _ => false,
    }
}

/// The `name`s of the `registries` the instance's own layers declare
/// (`spec.config` and `spec.configLayers`): only a registry of its
/// namespace may complete one. Layers that don't merge declare none here
/// ([`render_config`] reports them).
pub fn static_registry_names(base: &[String], parser: &dyn ConfigParser) -> Vec<String> {
    let layers: Vec<&str> = base.iter().map(String::as_str).collect();
    let Ok(document) = parser
        .merge(&layers)
        .and_then(|merged| parser.fragment(&merged))
    else {
        return Vec::new();
    };
    document
        .get("registries")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|r| r.get("name").and_then(Value::as_str).map(String::from))
        .collect()
}

/// The `${NAME}` placeholders of a document as `merge_layers` writes it
/// (where every literal `$` is `\u0024`).
fn placeholders(document: &str) -> std::collections::BTreeSet<String> {
    document
        .split("${")
        .skip(1)
        .filter_map(|rest| rest.split_once('}').map(|(name, _)| name.to_string()))
        .collect()
}

/// Whether `registrySelector.selector` (unset: all) matches `labels`.
fn selects(selector: &RegistrySelector, labels: &BTreeMap<String, String>) -> bool {
    let Some(selector) = &selector.selector else {
        return true;
    };
    // The kit's pure label-selector match, through the one function that
    // exposes it.
    let shared = SharedWith {
        namespace_selector: Some(selector.clone()),
        ..Default::default()
    };
    shares_with(Some(&shared), Some(""), Some(labels))
}

fn source_failure(err: SourceError) -> Failure {
    Failure::new(err.reason(), err.to_string())
}

/// The instance's own layers: `spec.config` as TOML, then each of
/// `spec.configLayers`.
pub async fn base_layers(
    instance: &LocalInstance,
    namespace: &str,
    sources: &dyn ConfigSources,
    parser: &dyn ConfigParser,
) -> Result<Vec<String>, Failure> {
    let spec = &instance.spec;
    let mut layers = Vec::new();
    match &spec.config {
        Value::Null => {}
        object @ Value::Object(_) => {
            layers.push(parser.layer(object).map_err(|e| {
                Failure::new(ReasonCode::ConfigInvalid, format!("spec.config: {e}"))
            })?);
        }
        _ => {
            return Err(Failure::new(
                ReasonCode::InvalidSpec,
                "spec.config must be an object",
            ));
        }
    }
    for source in &spec.config_layers {
        layers.push(
            sources
                .read(namespace, source)
                .await
                .map_err(source_failure)?,
        );
    }
    if layers.is_empty() {
        return Err(Failure::new(
            ReasonCode::InvalidSpec,
            "external.manageConfig needs spec.config or spec.configLayers: the operator \
             would replace the instance's configuration with nothing",
        ));
    }
    Ok(layers)
}

/// The configuration of `instance`: its `base` layers ([`base_layers`]),
/// then `registries` (the entries [`render_registries`] returns), merged
/// and validated.
pub fn render_config(
    instance: &LocalInstance,
    base: &[String],
    registries: Vec<Value>,
    parser: &dyn ConfigParser,
) -> Result<Rendered, Failure> {
    let invalid = |what: &str| {
        let what = what.to_string();
        move |e: ConfigError| Failure::new(ReasonCode::ConfigInvalid, format!("{what}: {e}"))
    };
    let mut layers = base.to_vec();
    if !registries.is_empty() {
        let layer = parser
            .layer(&json!({ "registries": registries }))
            .map_err(invalid("the registries"))?;
        layers.push(layer);
    }
    let layers: Vec<&str> = layers.iter().map(String::as_str).collect();
    let document = parser
        .merge(&layers)
        .map_err(invalid("merging the configuration"))?;

    let mut advisories = Vec::new();
    // `env` answers the placeholders, with a stand-in; the overrides
    // BatleHub also reads from it (`PROXY_CACHE__*`…) are unknown here, so
    // not set — a stand-in would override the file.
    let unresolved = placeholders(&document);
    let env = |name: &str| unresolved.contains(name).then(|| STAND_IN.to_string());
    if let Err(e) = parser.validate(&[&document], &env) {
        let message = format!("BatleHub's parser refuses the configuration: {e}");
        match instance.spec.reload.validation {
            Validation::Strict => return Err(Failure::new(ReasonCode::ConfigInvalid, message)),
            Validation::Lenient => advisories.push(Advisory {
                reason: ReasonCode::ConfigInvalidLenient,
                message: format!("{message} (pushed anyway: reload.validation is Lenient)"),
            }),
        }
    }
    if !unresolved.is_empty() {
        let names: Vec<&str> = unresolved.iter().map(String::as_str).collect();
        advisories.push(Advisory {
            reason: ReasonCode::UnresolvedPlaceholders,
            message: format!(
                "validated with a stand-in for {}: the instance resolves them from its own \
                 environment",
                names.join(", ")
            ),
        });
    }
    let hash = sha256(&document);
    Ok(Rendered {
        document,
        hash,
        advisories,
    })
}

/// Whether the rendered configuration still lets the operator in with
/// `token`: `OperatorTokenShadowed` otherwise.
pub fn check_token(
    rendered: &Rendered,
    token: &str,
    parser: &dyn ConfigParser,
) -> Result<(), Failure> {
    match parser.token_check(&rendered.document, token) {
        TokenCheck::Accepted | TokenCheck::Unverifiable => Ok(()),
        TokenCheck::Refused => Err(Failure::new(
            ReasonCode::OperatorTokenShadowed,
            "the configuration no longer accepts the operator's token with the admin role \
             (no [[auth]] type = \"token\" entry answers it as admin): pushing it would lock \
             the operator out at the instance's next restart. Declare the token of \
             external.adminTokenSecretRef (plain, or hashed with `batlehub hash-token`) with \
             role = \"admin\"",
        )),
    }
}

#[cfg(test)]
mod tests {
    use api::config::ConfigSource;
    use api::local_instance::LocalSecretKeyRef;
    use api::local_instance::{
        ExternalInstance, LocalInstanceSpec, NamespacesFrom, RegistryNamespaces,
    };

    use super::*;
    use crate::test_support::{FakeConfigParser, FakeSources};

    fn instance(config: Value) -> LocalInstance {
        let mut instance = LocalInstance::new(
            "hub",
            LocalInstanceSpec {
                external: ExternalInstance {
                    url: "http://hub".into(),
                    admin_token_secret_ref: LocalSecretKeyRef {
                        name: "t".into(),
                        key: "token".into(),
                    },
                    tls: Default::default(),
                    manage_config: true,
                    pod_selector: None,
                },
                config,
                config_layers: vec![],
                reload: Default::default(),
                registry_selector: Default::default(),
            },
        );
        instance.metadata.namespace = Some("ns".into());
        instance
    }

    fn registry(namespace: &str, name: &str, created: &str, config: Value) -> RegistryView {
        RegistryView {
            namespace: namespace.into(),
            name: name.into(),
            created: created.into(),
            labels: Default::default(),
            spec: RegistrySpec {
                instance_ref: None,
                r#type: "npm".into(),
                name: None,
                config,
                config_from: vec![],
                suspend: false,
            },
            bound: Ok(BoundInstance::local("ns", "hub")),
        }
    }

    async fn render(
        hub: &LocalInstance,
        sources: &FakeSources,
        parser: &FakeConfigParser,
        token: Option<&str>,
    ) -> Result<Rendered, Failure> {
        let base = base_layers(hub, "ns", sources, parser).await?;
        let rendered = render_config(hub, &base, vec![], parser)?;
        if let Some(token) = token {
            check_token(&rendered, token, parser)?;
        }
        Ok(rendered)
    }

    #[tokio::test]
    async fn every_placeholder_gets_a_stand_in_whatever_its_name() {
        let sources = FakeSources::default();
        let parser = FakeConfigParser;
        let hub = instance(json!({"front": "${BATLEHUB_FRONT_URL}", "db": "${PROXY_CACHE_DB}"}));
        let rendered = render(&hub, &sources, &parser, None).await.unwrap();
        let [advisory] = rendered.advisories.as_slice() else {
            panic!("{:?}", rendered.advisories)
        };
        assert!(
            advisory
                .message
                .contains("BATLEHUB_FRONT_URL, PROXY_CACHE_DB")
        );
        assert_eq!(
            placeholders("a ${A} \\u0024{B} ${C}"),
            ["A".to_string(), "C".to_string()].into()
        );
    }

    #[tokio::test]
    async fn the_names_of_the_instance_s_own_registries_come_from_every_layer() {
        let sources = FakeSources::default();
        let parser = FakeConfigParser;
        sources.put("ns", "layer", r#"{"registries": [{"name": "from-layer"}]}"#);
        let mut hub = instance(json!({"registries": [{"name": "from-spec"}]}));
        hub.spec.config_layers = vec![ConfigSource::config_map("layer", "config.toml")];
        let base = base_layers(&hub, "ns", &sources, &parser).await.unwrap();
        // The fake merges arrays by replacing them: the layer's wins.
        assert_eq!(static_registry_names(&base, &parser), ["from-layer"]);
        assert!(static_registry_names(&["not json".into()], &parser).is_empty());
    }

    #[tokio::test]
    async fn the_oldest_registry_keeps_its_name_while_it_fails() {
        let sources = FakeSources::default();
        let parser = FakeConfigParser;
        let hub = instance(json!({}));
        let bound = BoundInstance::local("ns", "hub");
        let mut broken = registry("ns", "old", "1", Value::Null);
        broken.spec.name = Some("npm".into());
        broken.spec.config_from = vec![ConfigSource::config_map("absent", "config.toml")];
        let mut young = registry("ns", "young", "2", Value::Null);
        young.spec.name = Some("npm".into());
        let (decisions, entries) =
            render_registries(&hub, &bound, vec![young, broken], &[], &sources, &parser).await;
        assert!(entries.is_empty());
        let reasons: Vec<_> = decisions
            .iter()
            .map(|d| d.rendered.as_ref().unwrap_err().reason)
            .collect();
        assert_eq!(
            reasons,
            [
                ReasonCode::ConfigLayerMissing,
                ReasonCode::DuplicateRegistryName
            ]
        );
    }

    #[test]
    fn hashes_are_sha256_hex() {
        assert_eq!(
            sha256("abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[tokio::test]
    async fn layers_merge_in_order_and_hash() {
        let sources = FakeSources::default();
        sources.put("ns", "layer", r#"{"server": {"port": 9090}}"#);
        let mut hub = instance(json!({"server": {"port": 8080}}));
        hub.spec.config_layers = vec![ConfigSource::config_map("layer", "config.toml")];
        let parser = FakeConfigParser;
        let rendered = render(&hub, &sources, &parser, None).await.unwrap();
        assert!(rendered.document.contains("9090"), "{}", rendered.document);
        assert_eq!(rendered.hash, sha256(&rendered.document));
    }

    #[tokio::test]
    async fn sources_that_cannot_be_read_block() {
        let sources = FakeSources::default();
        let parser = FakeConfigParser;
        let mut hub = instance(Value::Null);
        hub.spec.config_layers = vec![ConfigSource::secret("absent", "config.toml")];
        let failure = render(&hub, &sources, &parser, None).await.unwrap_err();
        assert_eq!(failure.reason, ReasonCode::ConfigLayerMissing);
        sources.refuse("ns", "locked");
        hub.spec.config_layers = vec![ConfigSource::secret("locked", "config.toml")];
        let failure = render(&hub, &sources, &parser, None).await.unwrap_err();
        assert_eq!(failure.reason, ReasonCode::SecretNotAllowed);
        hub.spec.config_layers = vec![];
        let failure = render(&hub, &sources, &parser, None).await.unwrap_err();
        assert_eq!(failure.reason, ReasonCode::InvalidSpec);
    }

    #[tokio::test]
    async fn the_parser_decides_strictly_or_leniently() {
        let sources = FakeSources::default();
        let parser = FakeConfigParser;
        let mut hub = instance(json!({"invalid": true, "url": "${DB}"}));
        let failure = render(&hub, &sources, &parser, None).await.unwrap_err();
        assert_eq!(failure.reason, ReasonCode::ConfigInvalid);
        hub.spec.reload.validation = Validation::Lenient;
        let rendered = render(&hub, &sources, &parser, None).await.unwrap();
        let reasons: Vec<_> = rendered.advisories.iter().map(|a| a.reason).collect();
        assert_eq!(
            reasons,
            [
                ReasonCode::ConfigInvalidLenient,
                ReasonCode::UnresolvedPlaceholders
            ]
        );
        assert!(rendered.advisories[1].message.contains("DB"));
    }

    #[tokio::test]
    async fn the_operator_token_must_stay_declared() {
        let sources = FakeSources::default();
        let parser = FakeConfigParser;
        let hub = instance(json!({"auth": "admin-token"}));
        assert!(
            render(&hub, &sources, &parser, Some("admin-token"))
                .await
                .is_ok()
        );
        let failure = render(&hub, &sources, &parser, Some("other"))
            .await
            .unwrap_err();
        assert_eq!(failure.reason, ReasonCode::OperatorTokenShadowed);
    }

    #[tokio::test]
    async fn registries_render_sorted_and_the_oldest_wins_a_name() {
        let sources = FakeSources::default();
        let parser = FakeConfigParser;
        let hub = instance(json!({"registries": [{"name": "static", "type": "npm"}]}));
        let bound = BoundInstance::local("ns", "hub");
        let mut late = registry("ns", "a-late", "2026-02-01T00:00:00Z", Value::Null);
        late.spec.name = Some("npm".into());
        let mut suspended = registry("ns", "c", "2026-01-01T00:00:00Z", Value::Null);
        suspended.spec.suspend = true;
        let mut other_instance = registry("ns", "d", "2026-01-01T00:00:00Z", Value::Null);
        other_instance.bound = Ok(BoundInstance::local("ns", "other"));
        let mut foreign = registry("team", "static", "2026-01-01T00:00:00Z", Value::Null);
        foreign.bound = Ok(bound.clone());
        let mut placeholder = registry(
            "team",
            "p",
            "2026-01-01T00:00:00Z",
            json!({"token": "${T}"}),
        );
        placeholder.bound = Ok(bound.clone());
        let registries = vec![
            late,
            registry(
                "ns",
                "npm",
                "2026-01-01T00:00:00Z",
                json!({"mode": "proxy"}),
            ),
            suspended,
            other_instance,
            foreign,
            placeholder,
        ];
        let (decisions, entries) = render_registries(
            &hub,
            &bound,
            registries,
            &["static".into()],
            &sources,
            &parser,
        )
        .await;
        let outcome: Vec<(String, Result<bool, ReasonCode>)> = decisions
            .iter()
            .map(|d| (d.name.clone(), d.rendered.clone().map_err(|f| f.reason)))
            .collect();
        assert_eq!(
            outcome,
            [
                ("c".to_string(), Ok(false)),
                ("npm".into(), Ok(true)),
                ("p".into(), Err(ReasonCode::NamespaceNotAllowed)),
                ("static".into(), Err(ReasonCode::DuplicateRegistryName)),
                ("a-late".into(), Err(ReasonCode::DuplicateRegistryName)),
            ]
        );
        assert_eq!(
            entries,
            [json!({"mode": "proxy", "type": "npm", "name": "npm"})]
        );
    }

    #[tokio::test]
    async fn fragments_complete_a_registry_but_never_rename_it() {
        let sources = FakeSources::default();
        let parser = FakeConfigParser;
        sources.put("ns", "auth", r#"{"upstream_auth": {"token": "t"}}"#);
        sources.put("ns", "rename", r#"{"name": "x"}"#);
        let hub = instance(json!({}));
        let bound = BoundInstance::local("ns", "hub");
        let mut good = registry("ns", "npm", "1", json!({"cache": {"ttl": 1}}));
        good.spec.config_from = vec![ConfigSource::config_map("auth", "config.toml")];
        let (_, entries) =
            render_registries(&hub, &bound, vec![good], &[], &sources, &parser).await;
        assert_eq!(
            entries,
            [
                json!({"cache": {"ttl": 1}, "upstream_auth": {"token": "t"}, "type": "npm", "name": "npm"})
            ]
        );
        let mut bad = registry("ns", "npm", "1", Value::Null);
        bad.spec.config_from = vec![ConfigSource::config_map("rename", "config.toml")];
        let (decisions, _) =
            render_registries(&hub, &bound, vec![bad], &[], &sources, &parser).await;
        assert_eq!(
            decisions[0].rendered.as_ref().unwrap_err().reason,
            ReasonCode::ConfigInvalid
        );
    }

    #[tokio::test]
    async fn a_fragment_s_namespaces_replace_the_config_s() {
        let sources = FakeSources::default();
        let parser = FakeConfigParser;
        sources.put("ns", "ci", r#"{"namespaces": [{"match": "@acme/ci"}]}"#);
        let hub = instance(json!({}));
        let bound = BoundInstance::local("ns", "hub");
        let mut npm = registry(
            "ns",
            "npm",
            "1",
            json!({"namespaces": [{"match": "@acme/billing", "visibility": "team"}]}),
        );
        npm.spec.config_from = vec![ConfigSource::config_map("ci", "config.toml")];
        let (_, entries) = render_registries(&hub, &bound, vec![npm], &[], &sources, &parser).await;
        // As BatleHub merges its layers: a list of tables keyed by `match`
        // has no identity to merge on.
        assert_eq!(
            entries,
            [json!({"namespaces": [{"match": "@acme/ci"}], "type": "npm", "name": "npm"})]
        );
    }

    #[tokio::test]
    async fn the_registry_selector_filters_by_label() {
        let sources = FakeSources::default();
        let parser = FakeConfigParser;
        let mut hub = instance(json!({}));
        hub.spec.registry_selector = RegistrySelector {
            selector: Some(api::config::LabelSelector {
                match_labels: Some(BTreeMap::from([("hub".into(), "main".into())])),
                ..Default::default()
            }),
            namespaces: RegistryNamespaces {
                from: NamespacesFrom::Same,
                selector: None,
            },
        };
        let bound = BoundInstance::local("ns", "hub");
        let mut chosen = registry("ns", "a", "1", Value::Null);
        chosen.labels = BTreeMap::from([("hub".into(), "main".into())]);
        let (decisions, entries) = render_registries(
            &hub,
            &bound,
            vec![chosen, registry("ns", "b", "1", Value::Null)],
            &[],
            &sources,
            &parser,
        )
        .await;
        assert_eq!(entries.len(), 1);
        assert_eq!(
            decisions[1].rendered.as_ref().unwrap_err().reason,
            ReasonCode::InstanceNotAllowed
        );
    }
}
