// SPDX-License-Identifier: Apache-2.0

use std::{env, fmt::Write, io, ops::Range, sync::LazyLock};

use regex::Regex;
use zeroize::Zeroizing;

static ASSIGNMENT: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(?m)^[ \t]*(?:export[ \t]+)?(?:'([^'\r\n]+)'|([^#=\s]+))[ \t]*=[ \t]*")
        .expect("valid environment assignment pattern")
});
static REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\$\{([^}:]*)(?::-([^}]*))?\}").expect("valid environment reference pattern")
});
static COMMENT: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"[ \t]+#").expect("valid environment comment pattern"));

pub(super) struct EnvFile<'a> {
    source: &'a str,
    assignments: Vec<Assignment<'a>>,
}

struct Assignment<'a> {
    name: &'a str,
    value: Zeroizing<String>,
    prefix: &'a str,
    range: Range<usize>,
}

impl<'a> EnvFile<'a> {
    pub(super) fn parse(source: &'a str) -> io::Result<Self> {
        let mut assignments: Vec<Assignment<'a>> = Vec::new();
        let mut parsed = 0;
        for captures in ASSIGNMENT.captures_iter(source) {
            let Some((header, name)) = captures
                .get(0)
                .zip(captures.get(1).or_else(|| captures.get(2)))
            else {
                continue;
            };
            if header.start() < parsed {
                continue;
            }
            let (len, value) = value_at(&source[header.end()..])?;
            parsed = header.end() + len;
            let mut expanded = Zeroizing::new(String::new());
            let mut consumed = 0;
            for reference in REFERENCE.captures_iter(value.as_str()) {
                let Some((expression, name)) = reference.get(0).zip(reference.get(1)) else {
                    continue;
                };
                expanded.push_str(&value[consumed..expression.start()]);
                if let Some(previous) = assignments
                    .iter()
                    .rev()
                    .find(|entry| entry.name == name.as_str())
                {
                    expanded.push_str(previous.value.as_str());
                } else if let Ok(environment) = env::var(name.as_str()) {
                    expanded.push_str(&Zeroizing::new(environment));
                } else if let Some(default) = reference.get(2) {
                    expanded.push_str(default.as_str());
                }
                consumed = expression.end();
            }
            expanded.push_str(&value[consumed..]);
            assignments.push(Assignment {
                name: name.as_str(),
                value: expanded,
                prefix: source[header.start()..name.start()].trim_end_matches('\''),
                range: header.start()..parsed,
            });
        }
        Ok(Self {
            source,
            assignments,
        })
    }

    pub(super) fn get(&self, name: &str) -> Option<&str> {
        self.assignments
            .iter()
            .rev()
            .find(|entry| entry.name.eq_ignore_ascii_case(name))
            .map(|entry| entry.value.as_str())
    }

    pub(super) fn update(&self, updates: &[(&str, Zeroizing<String>)]) -> Zeroizing<String> {
        let mut updated = vec![false; updates.len()];
        let mut out = Zeroizing::new(String::new());
        let mut copied = 0;
        for entry in &self.assignments {
            let Some((index, (name, replacement))) = updates
                .iter()
                .enumerate()
                .find(|(_, (name, _))| entry.name.eq_ignore_ascii_case(name))
            else {
                continue;
            };
            let line = &self.source[entry.range.clone()];
            let newline = if line.ends_with("\r\n") { "\r\n" } else { "\n" };
            out.push_str(&self.source[copied..entry.range.start]);
            let _ = write!(
                out,
                "{}{name}={replacement}{newline}",
                entry.prefix,
                replacement = replacement.as_str()
            );
            copied = entry.range.end;
            updated[index] = true;
        }
        out.push_str(&self.source[copied..]);
        for ((name, value), present) in updates.iter().zip(updated) {
            if !present {
                if !out.is_empty() && !out.ends_with('\n') {
                    out.push('\n');
                }
                let _ = writeln!(out, "{name}={}", value.as_str());
            }
        }
        out
    }
}

fn value_at(text: &str) -> io::Result<(usize, Zeroizing<String>)> {
    let Some(quote @ ('"' | '\'')) = text.chars().next() else {
        let end = next_line(text);
        let line = &text[..end];
        let value = COMMENT
            .find(line)
            .map_or(line, |comment| &line[..comment.start()]);
        return Ok((end, Zeroizing::new(value.trim_end().to_owned())));
    };
    let mut value = Zeroizing::new(String::new());
    let mut chars = text[1..].char_indices();
    while let Some((position, ch)) = chars.next() {
        match ch {
            ch if ch == quote => {
                let end = position + 2;
                return Ok((end + next_line(&text[end..]), value));
            }
            '\\' => {
                if let Some((_, escaped)) = chars.next() {
                    match (quote, escaped) {
                        (_, '\\') => value.push('\\'),
                        ('\'', '\'') => value.push('\''),
                        ('"', '"') => value.push('"'),
                        ('"', '\'') => value.push('\''),
                        ('"', 'n') => value.push('\n'),
                        ('"', 'r') => value.push('\r'),
                        ('"', 't') => value.push('\t'),
                        ('"', 'v') => value.push('\x0B'),
                        ('"', 'b') => value.push('\x08'),
                        ('"', 'a') => value.push('\x07'),
                        ('"', 'f') => value.push('\x0C'),
                        _ => {
                            value.push('\\');
                            value.push(escaped);
                        }
                    }
                }
            }
            _ => value.push(ch),
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "unterminated quoted environment value",
    ))
}

fn next_line(text: &str) -> usize {
    text.find('\n').map_or(text.len(), |position| position + 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patch_replaces_assignments_and_preserves_multiline_values() {
        let document = concat!(
            "# retained\r\n",
            "CERT=\"first\nJWT_SECRET_KEY=inside-certificate\nlast\"\r\n",
            "export jwt_secret_key='short' # weak\r\n",
            "'jwt_secret_key'=repeat\r\n",
            "TAIL=retained"
        );
        let file = EnvFile::parse(document).unwrap();
        assert_eq!(file.get("JWT_SECRET_KEY"), Some("repeat"));
        let output = file.update(&[
            ("JWT_SECRET_KEY", Zeroizing::new("replacement".to_owned())),
            ("AUTH_ENCRYPTION_SECRET", Zeroizing::new("added".to_owned())),
        ]);
        assert_eq!(
            output.as_str(),
            concat!(
                "# retained\r\n",
                "CERT=\"first\nJWT_SECRET_KEY=inside-certificate\nlast\"\r\n",
                "export JWT_SECRET_KEY=replacement\r\n",
                "JWT_SECRET_KEY=replacement\r\n",
                "TAIL=retained\n",
                "AUTH_ENCRYPTION_SECRET=added\n",
            )
        );
    }
}
