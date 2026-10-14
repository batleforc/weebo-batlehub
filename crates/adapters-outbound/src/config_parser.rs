//! [`ConfigParser`] until BatleHub v1.5.0: validating a configuration
//! needs `batlehub_config::merge_layers` and `validate_layers(layers, env)`
//! (the spec's D4), which `batlehub-config` 1.4.0 doesn't have — its
//! loaders read the operator's own environment. Nothing validates before
//! M2 (external instances without `manageConfig` render no
//! configuration), so this adapter only says so.

use application::ports::{ConfigError, ConfigParser, ConfigVerdict};

/// The BatleHub version whose `batlehub-config` the real adapter needs.
pub const PARSER_VERSION: &str = "1.5.0";

#[derive(Debug, Default, Clone, Copy)]
pub struct UnavailableConfigParser;

impl ConfigParser for UnavailableConfigParser {
    fn validate(
        &self,
        _layers: &[&str],
        _env: &dyn Fn(&str) -> Option<String>,
    ) -> Result<ConfigVerdict, ConfigError> {
        Err(ConfigError::Unavailable(format!(
            "validating a BatleHub configuration needs batlehub-config v{PARSER_VERSION} \
             (merge_layers, validate_layers)"
        )))
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
