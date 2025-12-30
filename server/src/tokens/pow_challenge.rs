use std::time::Duration;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};

use crate::{analysis::proof_of_work::PowChallenge, encodings::Base64};

use super::TimeClaims;

/// Algorithm used for proof of work tokens.
pub static JWT_POW_ALGORITHM: Algorithm = Algorithm::HS256;

/// Encodes a proof of work challenge into a JWT.
pub fn encode(
    pow_challenge: PowChallenge,
    enc_key: &Base64,
) -> Result<String, jsonwebtoken::errors::Error> {
    jsonwebtoken::encode(
        &Header::new(JWT_POW_ALGORITHM),
        &TimeClaims::with_timeout(Duration::from_secs(300), pow_challenge),
        &EncodingKey::from_base64_secret(enc_key.as_str())?,
    )
}

/// Encodes a proof of work challenge into a JWT with a custom timeout.
pub fn encode_with_timeout(
    pow_challenge: PowChallenge,
    enc_key_b64: &str,
    timeout: Duration,
) -> Result<String, jsonwebtoken::errors::Error> {
    jsonwebtoken::encode(
        &Header::new(JWT_POW_ALGORITHM),
        &TimeClaims::with_timeout(timeout, pow_challenge),
        &EncodingKey::from_base64_secret(enc_key_b64)?,
    )
}

/// Decodes a proof of work challenge from a JWT.
pub fn decode(jwt: &str, dec_key_b64: &str) -> Result<PowChallenge, jsonwebtoken::errors::Error> {
    let mut validation = Validation::new(JWT_POW_ALGORITHM);
    TimeClaims::<PowChallenge>::build_validation(&mut validation);

    jsonwebtoken::decode::<_>(
        jwt,
        &DecodingKey::from_base64_secret(dec_key_b64)?,
        &validation,
    )
    .map(|tok| tok.claims)
}
