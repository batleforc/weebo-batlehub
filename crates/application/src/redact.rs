//! Messages about a configuration a Secret contributed to. BatleHub's
//! parser and its admin API quote values: `invalid type: string "…"`,
//! `invalid 'base_domain' '…'`, a URL with its credentials. When a Secret's
//! text (a layer, a registry's `configFrom`, the credentials layer, an
//! environment value from a Secret) is part of what was judged, a message
//! keeps the key path and the position, never a quoted value.

/// `message` with every quoted span (`"…"`, `'…'`, `` `…` ``) emptied, the
/// credentials of a URL dropped, and the source lines a TOML parse error
/// quotes (under its `|` gutter) removed.
pub fn values(message: &str) -> String {
    message
        .lines()
        .filter(|line| {
            let line = line.trim_start();
            let after_number = line.trim_start_matches(|c: char| c.is_ascii_digit());
            !after_number.trim_start().starts_with('|')
        })
        .map(line)
        .collect::<Vec<_>>()
        .join("\n")
}

fn line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '"' | '`' | '\'' if quotes(c, &out, chars.clone()) => {
                // Skip to the closing quote (escapes inside "…").
                let mut escaped = false;
                for inner in chars.by_ref() {
                    if escaped {
                        escaped = false;
                    } else if inner == '\\' && c == '"' {
                        escaped = true;
                    } else if inner == c {
                        break;
                    }
                }
                out.push(c);
                out.push('…');
                out.push(c);
            }
            _ => out.push(c),
        }
    }
    userinfo(&out)
}

/// Whether `c` opens a quoted span: it closes later on the line, and an
/// apostrophe isn't one inside a word (`doesn't`).
fn quotes(c: char, before: &str, rest: std::iter::Peekable<std::str::Chars<'_>>) -> bool {
    if c == '\'' && before.chars().last().is_some_and(char::is_alphanumeric) {
        return false;
    }
    rest.clone().any(|r| r == c)
}

/// `scheme://user:password@host` → `scheme://…@host`.
fn userinfo(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find("://") {
        let (head, tail) = rest.split_at(at.saturating_add(3));
        out.push_str(head);
        let end = tail
            .find(|c: char| c.is_whitespace() || c == '/')
            .unwrap_or(tail.len());
        match tail[..end].rfind('@') {
            Some(i) => {
                out.push('…');
                rest = &tail[i..];
            }
            None => rest = tail,
        }
    }
    out.push_str(rest);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quoted_values_and_url_credentials_go_the_path_and_position_stay() {
        let serde = "parsing config TOML: TOML parse error at line 3, column 7\n  |\n\
                     3 | url = \"postgres://u:s3cr3t@db/x\"\n  |       ^\n\
                     invalid type: string \"s3cr3t\", expected u32";
        let shown = values(serde);
        assert!(!shown.contains("s3cr3t"), "{shown}");
        assert!(shown.contains("line 3, column 7"), "{shown}");
        assert!(
            shown.contains("invalid type: string \"…\", expected u32"),
            "{shown}"
        );
        assert_eq!(
            values("[subdomain_routing]: invalid 'base_domain' 'p4ss': bad"),
            "[subdomain_routing]: invalid '…' '…': bad"
        );
        assert_eq!(
            values("database.url postgres://admin:p4ss@db:5432/hub doesn't answer"),
            "database.url postgres://…@db:5432/hub doesn't answer"
        );
        assert_eq!(
            values("unknown variant `x`, expected `a`"),
            "unknown variant `…`, expected `…`"
        );
        assert_eq!(values("plain text, it's fine"), "plain text, it's fine");
    }
}
