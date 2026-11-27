// SPDX-License-Identifier: Apache-2.0

use argon2::{
    Algorithm, Argon2, PasswordHash, PasswordHasher, PasswordVerifier, Version,
    password_hash::SaltString,
};
use ring::rand::{SecureRandom, SystemRandom};
use tokio::sync::Semaphore;
use zeroize::Zeroizing;

use crate::config::SecretKdf;

use super::{AccountError, AccountSettings};

static PASSWORD_WORKERS: Semaphore = Semaphore::const_new(4);

pub(super) async fn hash(
    password: Zeroizing<String>,
    kdf: SecretKdf,
) -> Result<String, AccountError> {
    let permit = PASSWORD_WORKERS
        .acquire()
        .await
        .map_err(|_| AccountError::unavailable())?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        let mut random = [0_u8; 16];
        SystemRandom::new()
            .fill(&mut random)
            .map_err(|_| AccountError::unavailable())?;
        let salt = SaltString::encode_b64(&random).map_err(|_| AccountError::unavailable())?;
        Argon2::new(
            Algorithm::Argon2id,
            Version::V0x13,
            kdf.params().map_err(|_| AccountError::unavailable())?,
        )
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|_| AccountError::unavailable())
    })
    .await
    .map_err(|_| AccountError::unavailable())?
}

pub(super) async fn verify(
    password: Zeroizing<String>,
    stored_hash: String,
) -> Result<bool, AccountError> {
    let permit = PASSWORD_WORKERS
        .acquire()
        .await
        .map_err(|_| AccountError::unavailable())?;
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        PasswordHash::new(&stored_hash).is_ok_and(|parsed| {
            parsed.algorithm.as_str() == "argon2id"
                && Argon2::default()
                    .verify_password(password.as_bytes(), &parsed)
                    .is_ok()
        })
    })
    .await
    .map_err(|_| AccountError::unavailable())
}

pub(super) fn validate(
    settings: &AccountSettings,
    password: &str,
    account: &str,
    admin: bool,
) -> Result<(), AccountError> {
    let minimum = if admin {
        settings.password_min_admin
    } else {
        settings.password_min_user
    };
    if password.len() > 1024 {
        return Err(AccountError::bad_request("Password is too long"));
    }
    if !settings.password_policy {
        return Ok(());
    }
    let account_type = if admin {
        "privileged account"
    } else {
        "user account"
    };
    if password.chars().count() < minimum {
        return Err(AccountError::bad_request(format!(
            "Password must be at least {minimum} characters long ({account_type})"
        )));
    }
    let classes = [
        password.bytes().any(|byte| byte.is_ascii_uppercase()),
        password.bytes().any(|byte| byte.is_ascii_lowercase()),
        password.bytes().any(|byte| byte.is_ascii_digit()),
        password
            .chars()
            .any(|character| r#"!@#$%^&*(),.?":{}|<>-_=+[]\;'`~"#.contains(character)),
    ];
    if classes.into_iter().filter(|matched| *matched).count() < 3 {
        return Err(AccountError::bad_request(
            "Password must contain at least 3 of the following: lowercase letters, uppercase letters, numbers, special characters",
        ));
    }
    let lowered = Zeroizing::new(password.to_lowercase());
    let username = account.split('@').next().unwrap_or_default();
    if include_str!("common_passwords.txt")
        .lines()
        .any(|word| word == *lowered)
    {
        return Err(AccountError::bad_request(
            "Password is too common or easily guessable",
        ));
    }
    if username.len() >= 3 && lowered.contains(username) {
        return Err(AccountError::bad_request(
            "Password must not be based on your username",
        ));
    }
    if lowered.as_bytes().windows(3).any(|window| {
        let same_class =
            window.iter().all(u8::is_ascii_digit) || window.iter().all(u8::is_ascii_lowercase);
        let first = i16::from(window[1]) - i16::from(window[0]);
        let second = i16::from(window[2]) - i16::from(window[1]);
        same_class && first.abs() == 1 && first == second
    }) {
        return Err(AccountError::bad_request(
            "Password contains too many sequential characters",
        ));
    }
    Ok(())
}
