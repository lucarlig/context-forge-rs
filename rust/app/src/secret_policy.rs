// SPDX-License-Identifier: Apache-2.0

use std::{collections::HashMap, fmt};

use zeroize::Zeroizing;

pub(crate) const MIN_SECRET_LENGTH: usize = 32;
const MIN_ENTROPY: f64 = 3.5;

pub(crate) enum SecretProblem {
    Empty,
    Short { length: usize, minimum: usize },
    Placeholder,
    KnownWeak,
    LowEntropy(f64),
}

impl fmt::Display for SecretProblem {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(output, "secret is empty"),
            Self::Short { length, minimum } => {
                write!(output, "too short ({length} chars, minimum {minimum})")
            }
            Self::Placeholder => write!(output, "unset placeholder (__REPLACE_ME__) rejected"),
            Self::KnownWeak => write!(output, "known-weak/default value rejected"),
            Self::LowEntropy(score) => {
                write!(output, "low entropy (score {score:.2} < {MIN_ENTROPY})")
            }
        }
    }
}

pub(crate) fn problem(value: &str, minimum: usize, check_entropy: bool) -> Option<SecretProblem> {
    if value.trim().is_empty() {
        return Some(SecretProblem::Empty);
    }
    let length = value.chars().count();
    if length < minimum {
        return Some(SecretProblem::Short { length, minimum });
    }
    let lower = Zeroizing::new(value.to_ascii_lowercase());
    if lower.starts_with("__replace_me__") || lower.starts_with("replaceme") {
        return Some(SecretProblem::Placeholder);
    }
    if matches!(
        lower.as_str(),
        "my-test-key"
            | "my-test-key-but-now-longer-than-32-bytes"
            | "my-test-salt"
            | "changeme"
            | "secret"
            | "password"
            | "test-secret"
            | "my-secret"
            | "12345678"
    ) {
        return Some(SecretProblem::KnownWeak);
    }
    if check_entropy {
        let score = entropy(value);
        if score < MIN_ENTROPY {
            return Some(SecretProblem::LowEntropy(score));
        }
    }
    None
}

fn entropy(value: &str) -> f64 {
    let mut counts = HashMap::new();
    let mut length = 0;
    for ch in value.chars() {
        *counts.entry(ch).or_insert(0) += 1;
        length += 1;
    }
    -counts
        .into_values()
        .map(|count| {
            let proportion = f64::from(count) / f64::from(length);
            proportion * proportion.log2()
        })
        .sum::<f64>()
}
