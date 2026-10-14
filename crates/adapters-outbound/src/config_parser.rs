//! [`ConfigParser`] until `batlehub-config` has what validating needs:
//! `merge_layers` and `validate_layers(layers, env)` (the spec's D4, D8),
//! which it doesn't have up to v1.5.0 — its loaders
//! (`load_layered_from_str`) read the operator's own environment. Nothing validates before
//! M2 (external instances without `manageConfig` render no
//! configuration), so this adapter only says so.

use application::ports::{ConfigError, ConfigParser, ConfigVerdict};

#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableConfigParser;

impl ConfigParser for UnavailableConfigParser {
    fn validate(
        &self,
        _layers: &[&str],
        _env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<ConfigVerdict, ConfigError> {
        Err(ConfigError::Unavailable(
            "validating a BatleHub configuration needs a batlehub-config with \
             merge_layers and validate_layers (not in v1.5.0)"
                .into(),
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_never_validates() {
        let verdict = UnavailableConfigParser.validate(&["[server]"], &|_| None);
        assert!(matches!(verdict, Err(ConfigError::Unavailable(_))));
    }
}
