//! Messages that may carry what a Secret holds. A TOML parse error (the
//! `toml` crate's, or BatleHub's that wraps it) prints the offending line
//! of the source under a `|` gutter:
//!
//! ```text
//! TOML parse error at line 1, column 10
//!   |
//! 1 | password = s3cr3t
//!   |          ^
//! expected a value
//! ```
//!
//! The source may be a Secret layer: the gutter lines go, the position and
//! the explanation stay.

/// `message` without the source lines a parse error quotes.
pub fn without_source(message: &str) -> String {
    message
        .lines()
        .filter(|line| {
            let line = line.trim_start();
            let after_number = line.trim_start_matches(|c: char| c.is_ascii_digit());
            !after_number.trim_start().starts_with('|')
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_quoted_source_goes_the_position_stays() {
        let error = toml::from_str::<toml::Table>("password = s3cr3t-P4ss\n").unwrap_err();
        let shown = without_source(&error.to_string());
        assert!(!shown.contains("s3cr3t"), "{shown}");
        assert!(shown.contains("line 1"), "{shown}");
        assert_eq!(without_source("a | b\nplain"), "a | b\nplain");
    }
}
