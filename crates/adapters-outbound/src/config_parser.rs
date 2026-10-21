//! [`ConfigParser`] on BatleHub's own `batlehub-config` (its RFC 0037):
//! `merge_layers` merges with the server's rules and keeps every `${VAR}`,
//! `validate_layers` validates against an environment the caller supplies
//! — never the operator's own. Plus the two conversions between the CRDs'
//! YAML and TOML, and the check that a configuration still accepts the
//! operator's token.
//!
//! A layer may come from a Secret: no message quotes its text (a TOML
//! parse error prints the offending line, [`crate::redact`] drops it).

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Mutex, PoisonError};

use application::ports::{ConfigError, ConfigParser, ConfigVerdict, KeyChanges, TokenCheck};
use argon2::password_hash::phc::PasswordHash;
use argon2::{Argon2, PasswordVerifier};
use serde_json::Value as Json;
use toml::Value as Toml;

use crate::redact::without_source;

/// How many `(hash, token)` verdicts are kept (and as many hashes): a
/// token rotation or a new hash adds one, never removes the old.
const VERIFIED_CAPACITY: usize = 64;

#[derive(Default)]
pub struct BatleHubConfigParser {
    /// `(PHC hash, token) → verified`: Argon2id at BatleHub's parameters
    /// (19 MiB, 2 passes) is deliberately slow, and the same pair comes
    /// back on every reconcile — verified once. Keyed by the token's own
    /// text: the map never leaves the process. Full, one entry makes room.
    verified: Mutex<HashMap<(String, String), bool>>,
    /// `token → its hash`, computed once per token for the same reason.
    hashed: Mutex<HashMap<String, String>>,
}

/// `key → value` into `cache`, which holds at most [`VERIFIED_CAPACITY`]
/// entries: when full, one goes (any: a verdict lost is only computed
/// again, where emptying the map would recompute every one).
fn remember<K: Eq + Hash + Clone, V>(cache: &Mutex<HashMap<K, V>>, key: K, value: V) {
    let mut map = cache.lock().unwrap_or_else(PoisonError::into_inner);
    if map.len() >= VERIFIED_CAPACITY
        && !map.contains_key(&key)
        && let Some(old) = map.keys().next().cloned()
    {
        map.remove(&old);
    }
    map.insert(key, value);
}

/// `work` (Argon2: tens of milliseconds of CPU, 19 MiB) on the blocking
/// pool rather than an async worker, which other reconciles share.
async fn off_runtime<T: Send + 'static>(
    work: impl FnOnce() -> T + Send + 'static,
) -> Result<T, tokio::task::JoinError> {
    tokio::task::spawn_blocking(work).await
}

/// `token` hashed as BatleHub's `hash-token` does, salted from the token.
fn hash_with_own_salt(token: &str) -> Result<String, ConfigError> {
    use argon2::PasswordHasher;
    use sha2::{Digest, Sha256};
    // 16 bytes of a digest of the token, under a label of ours: a salt
    // nobody else derives the same way.
    let salt = Sha256::digest(format!("weebo-batlehub operator token:{token}"));
    Argon2::default()
        .hash_password_with_salt(token.as_bytes(), &salt[..16])
        .map(|hash| hash.to_string())
        .map_err(|e| ConfigError::Invalid(format!("hashing the operator's token: {e}")))
}

impl BatleHubConfigParser {
    /// Whether `token` matches the PHC `hash`; `None` when the check
    /// couldn't run.
    async fn verify_hash(&self, hash: &str, token: &str) -> Option<bool> {
        let key = (hash.to_string(), token.to_string());
        let known = self
            .verified
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(&key)
            .copied();
        if known.is_some() {
            return known;
        }
        let (phc, text) = key.clone();
        let verified = off_runtime(move || {
            PasswordHash::new(&phc)
                .map(|parsed| {
                    Argon2::default()
                        .verify_password(text.as_bytes(), &parsed)
                        .is_ok()
                })
                .unwrap_or(false)
        })
        .await;
        match verified {
            Ok(ok) => {
                remember(&self.verified, key, ok);
                Some(ok)
            }
            Err(e) => {
                tracing::warn!(error = %e, "verifying a token hash didn't finish");
                None
            }
        }
    }

    /// How one `[[auth]] type = "token"` provider answers `token`, as
    /// BatleHub's `StaticTokenAuthProvider` does: a plain value first (the
    /// last entry of a value wins, a map insert), then the first hash that
    /// verifies. `Err(())`: a `${VAR}` value, or a hash not checked,
    /// unknowable here.
    async fn provider_role(&self, tokens: &[Toml], token: &str) -> Result<Option<String>, ()> {
        let entries: Vec<(&str, &str)> = tokens
            .iter()
            .filter_map(|t| {
                Some((
                    t.get("value")?.as_str()?,
                    t.get("role").and_then(Toml::as_str).unwrap_or_default(),
                ))
            })
            .collect();
        if entries.iter().any(|(value, _)| value.contains("${")) {
            return Err(());
        }
        let plain = entries
            .iter()
            .rev()
            .find(|(value, _)| !is_argon2(value) && *value == token);
        if let Some((_, role)) = plain {
            return Ok(Some(role.to_string()));
        }
        for (value, role) in entries.iter().filter(|(value, _)| is_argon2(value)) {
            match self.verify_hash(value, token).await {
                Some(true) => return Ok(Some(role.to_string())),
                Some(false) => {}
                None => return Err(()),
            }
        }
        Ok(None)
    }
}

#[async_trait::async_trait]
impl ConfigParser for BatleHubConfigParser {
    fn classify(&self, before: &str, after: &str) -> Result<KeyChanges, ConfigError> {
        batlehub_config::reload_keys::classify(before, after)
            .map(|verdict| KeyChanges {
                restart: verdict.restart,
                partial: verdict.partial,
            })
            .map_err(|e| ConfigError::Invalid(without_source(&format!("{e:#}"))))
    }

    async fn hash_token(&self, token: &str) -> Result<String, ConfigError> {
        let known = self
            .hashed
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .get(token)
            .cloned();
        if let Some(hash) = known {
            return Ok(hash);
        }
        let text = token.to_string();
        let hash = off_runtime(move || hash_with_own_salt(&text))
            .await
            .map_err(|e| ConfigError::Invalid(format!("hashing the operator's token: {e}")))??;
        // Verified once already: it is the operator's own.
        remember(&self.verified, (hash.clone(), token.to_string()), true);
        remember(&self.hashed, token.to_string(), hash.clone());
        Ok(hash)
    }

    fn layer(&self, object: &Json) -> Result<String, ConfigError> {
        let Json::Object(map) = object else {
            return Err(ConfigError::Invalid(
                "the configuration must be an object".into(),
            ));
        };
        let mut out = String::new();
        for (key, value) in map {
            out.push_str(&format!("{} = {}\n", basic(key), inline(value, key)?));
        }
        Ok(out)
    }

    fn fragment(&self, text: &str) -> Result<Json, ConfigError> {
        let table: toml::Table = toml::from_str(text)
            .map_err(|e| ConfigError::Invalid(without_source(&e.to_string())))?;
        Ok(to_json(&Toml::Table(table)))
    }

    fn merge(&self, layers: &[&str]) -> Result<String, ConfigError> {
        batlehub_config::merge_layers(layers)
            .map_err(|e| ConfigError::Invalid(without_source(&format!("{e:#}"))))
    }

    fn validate(
        &self,
        layers: &[&str],
        env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<ConfigVerdict, ConfigError> {
        let config = batlehub_config::validate_layers(layers, env)
            .map_err(|e| ConfigError::Invalid(without_source(&format!("{e:#}"))))?;
        Ok(ConfigVerdict {
            warnings: config
                .warnings()
                .into_iter()
                .map(|w| format!("{}: {}", w.code, w.message))
                .collect(),
        })
    }

    /// The first `[[auth]] type = "token"` provider that knows the token
    /// decides, as BatleHub asks its providers in order; it must answer
    /// `admin`. A provider whose answer depends on a `${VAR}` makes the
    /// verdict unknowable, which is not a refusal. The other provider
    /// types don't take a static token.
    async fn token_check(&self, document: &str, token: &str) -> TokenCheck {
        let Ok(doc) = toml::from_str::<toml::Table>(document) else {
            return TokenCheck::Unverifiable;
        };
        let providers = doc
            .get("auth")
            .and_then(Toml::as_array)
            .into_iter()
            .flatten()
            .filter(|p| p.get("type").and_then(Toml::as_str) == Some("token"));
        for provider in providers {
            let tokens = provider
                .get("tokens")
                .and_then(Toml::as_array)
                .map(Vec::as_slice)
                .unwrap_or_default();
            match self.provider_role(tokens, token).await {
                Err(()) => return TokenCheck::Unverifiable,
                Ok(Some(role)) if role.eq_ignore_ascii_case("admin") => {
                    return TokenCheck::Accepted;
                }
                Ok(Some(_)) => return TokenCheck::Refused,
                Ok(None) => {}
            }
        }
        TokenCheck::Refused
    }
}

fn is_argon2(value: &str) -> bool {
    ["$argon2id$", "$argon2i$", "$argon2d$"]
        .iter()
        .any(|p| value.starts_with(p))
}

/// A TOML basic string on one line: `merge_layers` refuses a `${VAR}` in a
/// multi-line one, and a YAML block scalar is one line with `\n` here.
fn basic(text: &str) -> String {
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => out.push_str(&format!("\\u{:04X}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

/// YAML (as JSON) as an inline TOML value: `null` has no TOML spelling.
fn inline(value: &Json, path: &str) -> Result<String, ConfigError> {
    Ok(match value {
        Json::Null => {
            return Err(ConfigError::Invalid(format!(
                "{path}: null has no TOML equivalent (remove the key)"
            )));
        }
        Json::Bool(b) => b.to_string(),
        Json::Number(n) => match n.as_i64() {
            Some(i) => i.to_string(),
            None => Toml::Float(n.as_f64().unwrap_or_default()).to_string(),
        },
        Json::String(s) => basic(s),
        Json::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .enumerate()
                .map(|(i, v)| inline(v, &format!("{path}[{i}]")))
                .collect::<Result<Vec<_>, _>>()?
                .join(", ")
        ),
        Json::Object(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(k, v)| Ok(format!(
                    "{} = {}",
                    basic(k),
                    inline(v, &format!("{path}.{k}"))?
                )))
                .collect::<Result<Vec<_>, ConfigError>>()?
                .join(", ")
        ),
    })
}

/// TOML to JSON; a datetime becomes its text.
fn to_json(value: &Toml) -> Json {
    match value {
        Toml::String(s) => Json::String(s.clone()),
        Toml::Integer(i) => Json::from(*i),
        Toml::Float(f) => serde_json::Number::from_f64(*f).map_or(Json::Null, Json::Number),
        Toml::Boolean(b) => Json::Bool(*b),
        Toml::Datetime(d) => Json::String(d.to_string()),
        Toml::Array(items) => Json::Array(items.iter().map(to_json).collect()),
        Toml::Table(table) => {
            Json::Object(table.iter().map(|(k, v)| (k.clone(), to_json(v))).collect())
        }
    }
}

#[cfg(test)]
mod tests {
    use argon2::PasswordHasher;
    use serde_json::json;

    use super::*;

    const BASE: &str = r#"
[server]
host = "0.0.0.0"
port = 8080
[database]
type = "postgresql"
url = "${DATABASE_URL}"
[storage]
type = "filesystem"
path = "/var/cache/batlehub"
"#;

    fn parser() -> BatleHubConfigParser {
        BatleHubConfigParser::default()
    }

    #[tokio::test]
    async fn the_operator_token_hashes_the_same_and_verifies() {
        let parser = parser();
        let hash = parser.hash_token("s3cr3t").await.unwrap();
        assert!(
            hash.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"),
            "{hash}"
        );
        assert_eq!(
            BatleHubConfigParser::default()
                .hash_token("s3cr3t")
                .await
                .unwrap(),
            hash
        );
        assert_ne!(parser.hash_token("other").await.unwrap(), hash);
        let parsed = PasswordHash::new(&hash).unwrap();
        assert!(
            Argon2::default()
                .verify_password(b"s3cr3t", &parsed)
                .is_ok()
        );
    }

    #[test]
    fn a_full_cache_makes_room_for_one_entry_not_all() {
        let cache = Mutex::new(HashMap::new());
        for i in 0..VERIFIED_CAPACITY + 10 {
            remember(&cache, i, ());
        }
        let cache = cache.into_inner().unwrap();
        assert_eq!(cache.len(), VERIFIED_CAPACITY);
        assert!(cache.contains_key(&(VERIFIED_CAPACITY + 9)));
    }

    #[test]
    fn key_tiers_are_batlehub_s() {
        let parser = parser();
        let before = parser.merge(&[BASE]).unwrap();
        let after = parser
            .merge(&[
                BASE,
                "[server]\nport = 9090\n[[registries]]\nname = \"npm\"\ntype = \"npm\"\n",
            ])
            .unwrap();
        let changes = parser.classify(&before, &after).unwrap();
        let keys = &changes.restart;
        assert!(keys.contains(&"server.port".to_string()), "{keys:?}");
        assert!(
            keys.iter()
                .all(|k| !k.starts_with("registries[npm]") || k.contains('.')),
            "{keys:?}"
        );
        // A registry added is applied to requests, not to what was built
        // at startup (warming, imports): BatleHub's Partial tier.
        assert!(
            changes.partial.iter().any(|k| k.starts_with("registries")),
            "{changes:?}"
        );
    }

    #[test]
    fn yaml_becomes_toml_batlehub_reads() {
        let layer = parser()
            .layer(&json!({
                "server": {"port": 8080, "host": "0.0.0.0"},
                "registries": [{"name": "npm", "type": "npm", "upstreams": ["https://r"]}],
                "limits": {"ratio": 0.5},
            }))
            .unwrap();
        let merged = parser().merge(&[&layer]).unwrap();
        assert!(merged.contains("[[registries]]"), "{merged}");
        assert!(merged.contains("ratio = 0.5"), "{merged}");
        assert!(merged.contains("port = 8080"), "{merged}");
    }

    #[test]
    fn null_and_non_objects_are_refused() {
        let err = parser()
            .layer(&json!({"server": {"host": null}}))
            .unwrap_err();
        assert!(err.to_string().contains("server.host"), "{err}");
        assert!(parser().layer(&json!(["x"])).is_err());
    }

    #[test]
    fn a_multi_line_string_with_a_placeholder_stays_one_line() {
        let layer = parser()
            .layer(&json!({"banner": {"message": "line one\nhello ${WHO} \"quoted\" \\"}}))
            .unwrap();
        let merged = parser().merge(&[&layer]).unwrap();
        assert!(merged.contains("${WHO}"), "{merged}");
        let back = parser().fragment(&merged).unwrap();
        assert_eq!(
            back["banner"]["message"],
            json!("line one\nhello ${WHO} \"quoted\" \\")
        );
    }

    #[test]
    fn a_secret_s_text_is_never_quoted() {
        let err = parser().fragment("password = s3cr3t-P4ss\n").unwrap_err();
        assert!(!err.to_string().contains("s3cr3t"), "{err}");
        let err = parser().merge(&["password = s3cr3t-P4ss\n"]).unwrap_err();
        assert!(!err.to_string().contains("s3cr3t"), "{err}");
    }

    #[test]
    fn fragments_are_read_as_tables() {
        let value = parser()
            .fragment("token = \"t\"\n[tls]\nca = \"x\"\nwhen = 1979-05-27\n")
            .unwrap();
        assert_eq!(
            value,
            json!({"token": "t", "tls": {"ca": "x", "when": "1979-05-27"}})
        );
        assert!(parser().fragment("not toml =").is_err());
    }

    #[test]
    fn merging_keeps_placeholders_and_is_canonical() {
        let a = parser().merge(&[BASE, "[server]\nport = 9090\n"]).unwrap();
        let b = parser()
            .merge(&[BASE, "[server]\nport = 9090 # a comment\n"])
            .unwrap();
        assert_eq!(a, b);
        assert!(a.contains("url = \"${DATABASE_URL}\""), "{a}");
        assert!(a.contains("port = 9090"), "{a}");
        assert!(parser().merge(&["[server]\nport = ${PORT}\n"]).is_err());
        assert!(parser().merge(&[]).is_err());
    }

    #[test]
    fn validation_reads_the_environment_given_never_the_process() {
        let env = |name: &str| (name == "DATABASE_URL").then(|| "postgresql://x/y".to_string());
        assert!(parser().validate(&[BASE], &env).is_ok());
        let err = parser().validate(&[BASE], &|_| None).unwrap_err();
        assert!(err.to_string().contains("DATABASE_URL"), "{err}");
        let err = parser()
            .validate(&["[server]\nport = 8080\n"], &env)
            .unwrap_err();
        assert!(err.to_string().contains("missing field"), "{err}");
    }

    #[test]
    fn registry_namespaces_validate_and_a_later_list_replaces_the_earlier() {
        let namespaces = |prefix: &str| {
            json!({"registries": [{
                "name": "npm",
                "type": "npm",
                "mode": "local",
                "namespaces": [{
                    "match": prefix,
                    "visibility": "team",
                    "grants": {"group:oidc1:platform": ["releases:publish"]},
                }],
            }]})
        };
        let instance = parser().layer(&namespaces("@acme/billing")).unwrap();
        let registry = parser().layer(&namespaces("@acme/ci")).unwrap();
        let env = |name: &str| (name == "DATABASE_URL").then(|| "postgresql://x/y".to_string());
        let merged = parser().merge(&[BASE, &instance]).unwrap();
        assert!(merged.contains("[[registries.namespaces]]"), "{merged}");
        assert!(parser().validate(&[&merged], &env).is_ok());
        // `[[registries.namespaces]]` has no `name` nor `type` to merge on:
        // BatleHub replaces the whole list, it doesn't add to it.
        let merged = parser().merge(&[BASE, &instance, &registry]).unwrap();
        let back = parser().fragment(&merged).unwrap();
        let matches: Vec<&Json> = back["registries"][0]["namespaces"]
            .as_array()
            .unwrap()
            .iter()
            .map(|n| &n["match"])
            .collect();
        assert_eq!(matches, [&json!("@acme/ci")]);
    }

    fn with_admin(value: &str) -> String {
        format!(
            "{BASE}\n[[auth]]\ntype = \"token\"\n[[auth.tokens]]\nvalue = \"other\"\nrole = \"user\"\n\
             [[auth.tokens]]\nvalue = '{value}'\nrole = \"admin\"\n"
        )
    }

    #[tokio::test]
    async fn the_first_provider_knowing_the_token_decides_as_in_batlehub() {
        let p = parser();
        let doc = |providers: &str| format!("{BASE}\n{providers}");
        let provider = |tokens: &[(&str, &str)]| {
            let mut out = String::from("[[auth]]\ntype = \"token\"\n");
            for (value, role) in tokens {
                out.push_str(&format!(
                    "[[auth.tokens]]\nvalue = \"{value}\"\nrole = \"{role}\"\n"
                ));
            }
            out
        };
        // A later plain entry of the same value wins (a map insert).
        let shadowed = doc(&provider(&[("t", "admin"), ("t", "user")]));
        assert_eq!(p.token_check(&shadowed, "t").await, TokenCheck::Refused);
        // An earlier provider answering `user` hides a later admin one.
        let earlier = doc(&(provider(&[("t", "user")]) + &provider(&[("t", "admin")])));
        assert_eq!(p.token_check(&earlier, "t").await, TokenCheck::Refused);
        // A provider that doesn't know it lets the next one answer.
        let next = doc(&(provider(&[("other", "user")]) + &provider(&[("t", "Admin")])));
        assert_eq!(p.token_check(&next, "t").await, TokenCheck::Accepted);
    }

    #[tokio::test]
    async fn the_operator_token_must_stay_declared() {
        let p = parser();
        assert_eq!(
            p.token_check(&with_admin("secret"), "secret").await,
            TokenCheck::Accepted
        );
        assert_eq!(
            p.token_check(&with_admin("secret"), "other").await,
            TokenCheck::Refused
        );
        assert_eq!(p.token_check(BASE, "secret").await, TokenCheck::Refused);
        assert_eq!(
            p.token_check(&with_admin("${ADMIN_TOKEN}"), "secret").await,
            TokenCheck::Unverifiable
        );
        let hash = Argon2::default()
            .hash_password(b"secret")
            .unwrap()
            .to_string();
        assert_eq!(
            p.token_check(&with_admin(&hash), "secret").await,
            TokenCheck::Accepted
        );
        assert_eq!(
            p.token_check(&with_admin(&hash), "nope").await,
            TokenCheck::Refused
        );
        // Cached both ways.
        assert_eq!(p.verified.lock().unwrap().len(), 2);
        // The user-role entry knows "other": refused, not admin.
        assert_eq!(
            p.token_check(&with_admin("x"), "other").await,
            TokenCheck::Refused
        );
    }
}
