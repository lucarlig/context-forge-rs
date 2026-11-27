// SPDX-License-Identifier: Apache-2.0
//! Verification of first-party gateway JWTs.

use hmac::{Hmac, KeyInit, Mac};
use jiff::{
    Timestamp,
    civil::{Time, Weekday},
};
use jsonwebtoken::{
    Algorithm, AlgorithmFamily, DecodingKey, EncodingKey, Header, Validation, decode, encode,
    errors::ErrorKind,
};
use serde::Deserialize;
use serde_json::Value;
use sha2::Sha256;
use thiserror::Error;

pub struct JwtConfig<'a> {
    pub algorithm: &'a str,
    /// HMAC secret or asymmetric public key in PEM format.
    pub key: &'a [u8],
    pub issuer: Option<&'a str>,
    pub audience: Option<&'a str>,
    pub require_expiration: bool,
    pub require_jti: bool,
    pub environment: &'a str,
    pub validate_environment: bool,
    pub derive_key_per_environment: bool,
}

impl Default for JwtConfig<'_> {
    fn default() -> Self {
        Self {
            algorithm: "HS256",
            key: &[],
            issuer: Some("mcpgateway"),
            audience: Some("mcpgateway-api"),
            require_expiration: true,
            require_jti: true,
            environment: "development",
            validate_environment: true,
            derive_key_per_environment: false,
        }
    }
}

#[derive(Debug, Error)]
pub enum JwtConfigError {
    #[error("Unsupported JWT algorithm")]
    Algorithm,
    #[error("Invalid JWT verification key")]
    Key,
    #[error("JWT HMAC secret must contain at least 32 bytes")]
    WeakKey,
    #[error("JWT issuer, audience, and environment must be nonempty when configured")]
    EmptySetting,
}

#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum JwtError {
    #[error("Invalid token")]
    Invalid,
    #[error("Token has expired")]
    Expired,
    #[error(
        "Token is missing required expiration claim. Set REQUIRE_TOKEN_EXPIRATION=false to allow."
    )]
    MissingExpiration,
    #[error("Token is missing required JTI claim. Set REQUIRE_JTI=false to allow.")]
    MissingJti,
    #[error("Token environment mismatch")]
    EnvironmentMismatch,
    #[error("Token has invalid time restrictions")]
    InvalidTimeRestrictions,
    #[error("Token access is outside its allowed time restrictions")]
    TimeRestricted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TokenUse {
    Api,
    Session,
}

/// Authenticated claims. Resolve the identity and permissions against the database.
pub struct VerifiedJwt {
    payload: Value,
    token_use: TokenUse,
}

impl VerifiedJwt {
    pub fn payload(&self) -> &Value {
        &self.payload
    }

    pub fn token_use(&self) -> TokenUse {
        self.token_use
    }

    pub fn subject(&self) -> Option<&str> {
        self.payload.get("sub").and_then(Value::as_str)
    }

    pub fn jti(&self) -> Option<&str> {
        self.payload.get("jti").and_then(Value::as_str)
    }
}

pub struct JwtVerifier {
    key: DecodingKey,
    validation: Validation,
    require_jti: bool,
    environment: Option<String>,
}

#[derive(Clone)]
pub struct JwtIssuer {
    key: EncodingKey,
    header: Header,
    issuer: String,
    audience: String,
    environment: String,
}

impl JwtIssuer {
    pub fn new(
        algorithm: &str,
        key: &[u8],
        issuer: String,
        audience: String,
        environment: String,
        derive_key: bool,
    ) -> Result<Self, JwtConfigError> {
        if issuer.is_empty() || audience.is_empty() || environment.is_empty() {
            return Err(JwtConfigError::EmptySetting);
        }
        let algorithm: Algorithm = algorithm.parse().map_err(|_| JwtConfigError::Algorithm)?;
        let key = match algorithm.family() {
            AlgorithmFamily::Hmac if key.len() < 32 => return Err(JwtConfigError::WeakKey),
            AlgorithmFamily::Hmac if derive_key => {
                EncodingKey::from_secret(&environment_key(key, &environment)?)
            }
            AlgorithmFamily::Hmac => EncodingKey::from_secret(key),
            AlgorithmFamily::Rsa => EncodingKey::from_rsa_pem(key),
            AlgorithmFamily::Ec => EncodingKey::from_ec_pem(key),
            AlgorithmFamily::Ed => EncodingKey::from_ed_pem(key),
        }
        .map_err(|_| JwtConfigError::Key)?;
        Ok(Self {
            key,
            header: Header::new(algorithm),
            issuer,
            audience,
            environment,
        })
    }

    pub(crate) fn sign(&self, mut claims: Value) -> Result<String, jsonwebtoken::errors::Error> {
        claims["iss"] = self.issuer.as_str().into();
        claims["aud"] = self.audience.as_str().into();
        claims["env"] = self.environment.as_str().into();
        encode(&self.header, &claims, &self.key)
    }
}

impl JwtVerifier {
    pub fn new(config: JwtConfig<'_>) -> Result<Self, JwtConfigError> {
        if config.issuer.is_some_and(str::is_empty)
            || config.audience.is_some_and(str::is_empty)
            || ((config.validate_environment || config.derive_key_per_environment)
                && config.environment.is_empty())
        {
            return Err(JwtConfigError::EmptySetting);
        }
        let algorithm: Algorithm = config
            .algorithm
            .parse()
            .map_err(|_| JwtConfigError::Algorithm)?;
        let key = match algorithm.family() {
            AlgorithmFamily::Hmac if config.key.len() < 32 => return Err(JwtConfigError::WeakKey),
            AlgorithmFamily::Hmac if config.derive_key_per_environment => {
                DecodingKey::from_secret(&environment_key(config.key, config.environment)?)
            }
            AlgorithmFamily::Hmac => DecodingKey::from_secret(config.key),
            AlgorithmFamily::Rsa => DecodingKey::from_rsa_pem(config.key),
            AlgorithmFamily::Ec => DecodingKey::from_ec_pem(config.key),
            AlgorithmFamily::Ed => DecodingKey::from_ed_pem(config.key),
        }
        .map_err(|_| JwtConfigError::Key)?;

        let mut validation = Validation::new(algorithm);
        validation.leeway = 0;
        validation.validate_nbf = true;
        validation.validate_aud = config.audience.is_some();
        validation.required_spec_claims.clear();
        if config.require_expiration {
            validation.required_spec_claims.insert("exp".into());
        }
        if let Some(issuer) = config.issuer {
            validation.set_issuer(&[issuer]);
            validation.required_spec_claims.insert("iss".into());
        }
        if let Some(audience) = config.audience {
            validation.set_audience(&[audience]);
            validation.required_spec_claims.insert("aud".into());
        }

        Ok(Self {
            key,
            validation,
            require_jti: config.require_jti,
            environment: config
                .validate_environment
                .then(|| config.environment.to_owned()),
        })
    }

    pub fn verify(&self, token: &str) -> Result<VerifiedJwt, JwtError> {
        let payload = decode::<Value>(token, &self.key, &self.validation)
            .map_err(|error| match error.kind() {
                ErrorKind::ExpiredSignature => JwtError::Expired,
                ErrorKind::MissingRequiredClaim(claim) if claim == "exp" => {
                    JwtError::MissingExpiration
                }
                _ => JwtError::Invalid,
            })?
            .claims;
        let claims = payload.as_object().ok_or(JwtError::Invalid)?;
        let now = Timestamp::now();

        if let Some(expiration) = claims.get("exp") {
            let expiration = expiration.as_i64().ok_or(JwtError::Invalid)?;
            if expiration <= now.as_second() {
                return Err(JwtError::Expired);
            }
        }
        for name in ["iat", "nbf"] {
            if let Some(time) = claims.get(name)
                && time.as_i64().is_none_or(|time| time > now.as_second())
            {
                return Err(JwtError::Invalid);
            }
        }
        if claims
            .get("sub")
            .is_some_and(|value| !nonempty_string(value))
            || (self.validation.iss.is_some()
                && claims
                    .get("iss")
                    .is_some_and(|value| !nonempty_string(value)))
        {
            return Err(JwtError::Invalid);
        }
        match claims.get("jti") {
            None if self.require_jti => return Err(JwtError::MissingJti),
            Some(value) if !nonempty_string(value) => return Err(JwtError::Invalid),
            _ => {}
        }
        if let (Some(expected), Some(actual)) = (&self.environment, claims.get("env"))
            && !actual.is_null()
            && actual.as_str() != Some(expected)
        {
            return Err(JwtError::EnvironmentMismatch);
        }
        let token_use = match claims.get("token_use") {
            None => TokenUse::Api,
            Some(value) => match value.as_str() {
                Some("api") => TokenUse::Api,
                Some("session") => TokenUse::Session,
                _ => return Err(JwtError::Invalid),
            },
        };
        match claims.get("scopes") {
            None | Some(Value::Null) => {}
            Some(Value::Object(scopes)) => {
                if let Some(restrictions) = scopes.get("time_restrictions")
                    && !restrictions.is_null()
                {
                    validate_time_restrictions(restrictions, now)?;
                }
            }
            Some(_) => return Err(JwtError::Invalid),
        }
        Ok(VerifiedJwt { payload, token_use })
    }
}

fn nonempty_string(value: &Value) -> bool {
    value.as_str().is_some_and(|value| !value.trim().is_empty())
}

fn environment_key(secret: &[u8], environment: &str) -> Result<[u8; 64], JwtConfigError> {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret).map_err(|_| JwtConfigError::Key)?;
    mac.update(b"mcpgw-env:");
    mac.update(environment.as_bytes());
    let digest = mac.finalize().into_bytes();
    let hex = b"0123456789abcdef";
    Ok(std::array::from_fn(|index| {
        let byte = digest[index / 2];
        let digit = if index % 2 == 0 {
            byte >> 4
        } else {
            byte & 0x0f
        };
        hex[usize::from(digit)]
    }))
}

#[derive(Deserialize)]
struct TimeRestrictions<'a> {
    start_time: Option<&'a str>,
    end_time: Option<&'a str>,
    #[serde(default = "utc")]
    timezone: &'a str,
    #[serde(default)]
    days: Vec<&'a str>,
}

fn utc() -> &'static str {
    "UTC"
}

pub(crate) fn validate_time_restrictions(
    restrictions: &Value,
    now: Timestamp,
) -> Result<(), JwtError> {
    let restrictions = TimeRestrictions::deserialize(restrictions)
        .map_err(|_| JwtError::InvalidTimeRestrictions)?;
    let start = restrictions.start_time.filter(|time| !time.is_empty());
    let end = restrictions.end_time.filter(|time| !time.is_empty());
    let window = match (start, end) {
        (None, None) => None,
        (Some(start), Some(end)) => Some((parse_time(start)?, parse_time(end)?)),
        _ => return Err(JwtError::InvalidTimeRestrictions),
    };
    if window.is_none() && restrictions.days.is_empty() {
        return Ok(());
    }
    let local = now
        .in_tz(restrictions.timezone)
        .map_err(|_| JwtError::InvalidTimeRestrictions)?;
    let weekday = match local.weekday() {
        Weekday::Monday => "Monday",
        Weekday::Tuesday => "Tuesday",
        Weekday::Wednesday => "Wednesday",
        Weekday::Thursday => "Thursday",
        Weekday::Friday => "Friday",
        Weekday::Saturday => "Saturday",
        Weekday::Sunday => "Sunday",
    };
    if restrictions.days.iter().any(|day| {
        !matches!(
            *day,
            "Monday" | "Tuesday" | "Wednesday" | "Thursday" | "Friday" | "Saturday" | "Sunday"
        )
    }) {
        return Err(JwtError::InvalidTimeRestrictions);
    }
    if !restrictions.days.is_empty() && !restrictions.days.contains(&weekday) {
        return Err(JwtError::TimeRestricted);
    }
    if let Some((start, end)) = window {
        let time = local.time();
        let allowed = if start <= end {
            (start..=end).contains(&time)
        } else {
            time >= start || time <= end
        };
        if !allowed {
            return Err(JwtError::TimeRestricted);
        }
    }
    Ok(())
}

fn parse_time(time: &str) -> Result<Time, JwtError> {
    Time::strptime("%H:%M:%S", time)
        .or_else(|_| Time::strptime("%H:%M", time))
        .map_err(|_| JwtError::InvalidTimeRestrictions)
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use serde_json::json;

    const KEY: &[u8] = &[0xab; 64];

    fn verifier() -> JwtVerifier {
        JwtVerifier::new(JwtConfig {
            key: KEY,
            ..JwtConfig::default()
        })
        .expect("JWT verifier")
    }

    fn claims() -> Value {
        let now = Timestamp::now().as_second();
        json!({
            "sub": "member@example.com",
            "jti": "token-001",
            "iss": "mcpgateway",
            "aud": "mcpgateway-api",
            "exp": now + 600,
            "nbf": now - 60,
            "iat": now - 60
        })
    }

    fn signed(claims: &Value, secret: &[u8], algorithm: Algorithm) -> String {
        encode(
            &Header::new(algorithm),
            claims,
            &EncodingKey::from_secret(secret).expect("test HMAC key"),
        )
        .expect("sign token")
    }

    fn token(claims: &Value) -> String {
        signed(claims, KEY, Algorithm::HS256)
    }

    #[test]
    fn verifies_legacy_api_and_session_tokens() {
        let verifier = verifier();
        for (claim, expected) in [
            (None, TokenUse::Api),
            (Some("api"), TokenUse::Api),
            (Some("session"), TokenUse::Session),
        ] {
            let mut payload = claims();
            if let Some(claim) = claim {
                payload["token_use"] = json!(claim);
            }
            let verified = verifier.verify(&token(&payload)).expect("verified token");
            assert_eq!(verified.payload(), &payload);
            assert_eq!(verified.subject(), Some("member@example.com"));
            assert_eq!(verified.jti(), Some("token-001"));
            assert_eq!(verified.token_use(), expected);
        }
    }

    #[test]
    fn rejects_bad_signature_algorithms_and_malformed_tokens() {
        let verifier = verifier();
        for token in [
            signed(&claims(), &[0xba; 64], Algorithm::HS256),
            signed(&claims(), KEY, Algorithm::HS512),
            "eyJhbGciOiJub25lIn0.e30.".into(),
            "not.a.token".into(),
            token(&json!(["not-an-object"])),
        ] {
            assert_eq!(verifier.verify(&token).err(), Some(JwtError::Invalid));
        }

        for key in [b"".as_slice(), b"short-secret".as_slice()] {
            assert!(matches!(
                JwtVerifier::new(JwtConfig {
                    key,
                    ..JwtConfig::default()
                }),
                Err(JwtConfigError::WeakKey)
            ));
        }
        assert!(matches!(
            JwtVerifier::new(JwtConfig {
                algorithm: "none",
                key: KEY,
                ..JwtConfig::default()
            }),
            Err(JwtConfigError::Algorithm)
        ));
    }

    #[test]
    fn requires_and_validates_token_lifetime_and_id() {
        let verifier = verifier();
        let future = Timestamp::now().as_second() + 600;
        for (claim, value, expected) in [
            ("exp", json!(1), JwtError::Expired),
            ("nbf", json!(future), JwtError::Invalid),
            ("iat", json!(future), JwtError::Invalid),
            ("nbf", json!("0"), JwtError::Invalid),
            ("iat", json!(null), JwtError::Invalid),
            ("jti", json!(1), JwtError::Invalid),
            ("jti", json!(""), JwtError::Invalid),
        ] {
            let mut payload = claims();
            payload[claim] = value;
            assert_eq!(
                verifier.verify(&token(&payload)).err(),
                Some(expected),
                "{claim}"
            );
        }

        let mut payload = claims();
        payload.as_object_mut().unwrap().remove("jti");
        assert_eq!(
            verifier.verify(&token(&payload)).err(),
            Some(JwtError::MissingJti)
        );
        payload.as_object_mut().unwrap().remove("exp");
        assert_eq!(
            verifier.verify(&token(&payload)).err(),
            Some(JwtError::MissingExpiration)
        );

        let relaxed = JwtVerifier::new(JwtConfig {
            key: KEY,
            require_jti: false,
            require_expiration: false,
            ..JwtConfig::default()
        })
        .unwrap();
        assert!(relaxed.verify(&token(&payload)).is_ok());
        payload["exp"] = json!(1);
        assert_eq!(
            relaxed.verify(&token(&payload)).err(),
            Some(JwtError::Expired)
        );
    }

    #[test]
    fn honors_configured_issuer_and_audience_and_rejects_wrong_claim_types() {
        let verifier = verifier();
        for (claim, value) in [
            ("iss", json!("other-issuer")),
            ("aud", json!("other-audience")),
            ("iss", json!(["mcpgateway"])),
            ("aud", json!(42)),
            ("sub", json!(42)),
            ("scopes", json!([])),
            ("token_use", json!("unknown")),
        ] {
            let mut payload = claims();
            payload[claim] = value;
            assert_eq!(
                verifier.verify(&token(&payload)).err(),
                Some(JwtError::Invalid),
                "{claim}"
            );
        }
        let custom = JwtVerifier::new(JwtConfig {
            key: KEY,
            issuer: Some("my-gateway"),
            audience: Some("my-client"),
            ..JwtConfig::default()
        })
        .unwrap();
        let mut payload = claims();
        assert!(custom.verify(&token(&payload)).is_err());
        payload["iss"] = json!("my-gateway");
        payload["aud"] = json!(["my-client", "other"]);
        assert!(custom.verify(&token(&payload)).is_ok());
        let unrestricted = JwtVerifier::new(JwtConfig {
            key: KEY,
            issuer: None,
            audience: None,
            ..JwtConfig::default()
        })
        .unwrap();
        payload.as_object_mut().unwrap().remove("aud");
        payload.as_object_mut().unwrap().remove("iss");
        assert!(unrestricted.verify(&token(&payload)).is_ok());
    }

    #[test]
    fn isolates_environments_with_claims_and_derived_keys() {
        let mut payload = claims();
        payload["env"] = json!("production");
        assert_eq!(
            verifier().verify(&token(&payload)).err(),
            Some(JwtError::EnvironmentMismatch)
        );
        let test_derivation = environment_key(&[0x11], "production").unwrap();
        assert_eq!(
            &test_derivation,
            b"98f7f28b647ebdae377fd8a3fded022193ba79d9ad241d665d1da1e8256c56d3"
        );
        let production = JwtVerifier::new(JwtConfig {
            key: KEY,
            environment: "production",
            derive_key_per_environment: true,
            ..JwtConfig::default()
        })
        .unwrap();
        let key = environment_key(KEY, "production").unwrap();
        let signed_for_production = signed(&payload, &key, Algorithm::HS256);
        assert!(production.verify(&signed_for_production).is_ok());
        assert!(verifier().verify(&signed_for_production).is_err());
        assert!(production.verify(&token(&payload)).is_err());
    }

    #[test]
    fn verifies_ed25519_public_keys() {
        // RFC 8032 test key.
        let private = [
            0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
            0x04, 0x20, 0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4,
            0x92, 0xec, 0x2c, 0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b,
            0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
        ];
        let public = b"-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo=\n-----END PUBLIC KEY-----\n";
        let verifier = JwtVerifier::new(JwtConfig {
            algorithm: "EdDSA",
            key: public,
            ..JwtConfig::default()
        })
        .unwrap();
        let payload = claims();
        let signed = encode(
            &Header::new(Algorithm::EdDSA),
            &payload,
            &EncodingKey::from_ed_der(&private),
        )
        .unwrap();
        assert_eq!(verifier.verify(&signed).unwrap().payload(), &payload);
        assert!(verifier.verify(&token(&payload)).is_err());
    }

    #[test]
    fn enforces_local_time_windows_and_days() {
        let restrictions = json!({
            "start_time": "22:00",
            "end_time": "06:00:00",
            "timezone": "America/New_York",
            "days": ["Monday"],
        });
        let monday_night = "2026-11-03T03:00:00Z".parse().unwrap();
        let monday_midday = "2026-11-02T17:00:00Z".parse().unwrap();
        let tuesday_morning = "2026-11-03T10:00:00Z".parse().unwrap();
        assert_eq!(
            validate_time_restrictions(&restrictions, monday_night),
            Ok(())
        );
        assert_eq!(
            validate_time_restrictions(&restrictions, monday_midday),
            Err(JwtError::TimeRestricted)
        );
        assert_eq!(
            validate_time_restrictions(&restrictions, tuesday_morning),
            Err(JwtError::TimeRestricted)
        );

        let verifier = verifier();
        let mut payload = claims();
        for invalid in [
            json!({"start_time": "09:00"}),
            json!({"start_time": "09:00", "end_time": "24:00"}),
            json!({"days": ["Mon"]}),
            json!({"days": "Monday"}),
            json!({"days": ["Monday"], "timezone": "Not/A_Zone"}),
        ] {
            payload["scopes"] = json!({"time_restrictions": invalid});
            assert_eq!(
                verifier.verify(&token(&payload)).err(),
                Some(JwtError::InvalidTimeRestrictions)
            );
        }
    }
}
