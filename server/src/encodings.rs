use std::{
    fmt::{Debug, Display},
    marker::PhantomData,
};

use base64::{DecodeSliceError, prelude::*};
use rand::{Rng, RngCore};
use secrecy::Zeroize;
use serde::{Deserialize, Serialize};

/// Default key size in bytes.
pub const KEY_SIZE: usize = 48;

/// Standard base64 alphabet marker.
#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Standard;
/// URL-safe base64 alphabet marker.
#[derive(Debug, Serialize, Deserialize, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UrlSafe;

/// Base64 encoded string wrapper.
#[derive(Serialize, Deserialize, Default, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(transparent)]
pub struct Base64<A = Standard>(Box<str>, PhantomData<A>);

impl<A> Base64<A> {
    fn new(value: String) -> Self {
        Base64(value.into_boxed_str(), PhantomData)
    }

    /// Returns the underlying string slice.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl Base64<Standard> {
    /// Generates a random base64 string.
    pub fn random<const N: usize>() -> Self {
        let mut rng = rand::rng();
        Self::new(BASE64_STANDARD.encode(rng.random::<[u8; N]>()))
    }

    /// Generates a random base64 string using provided RNG.
    pub fn random_with<const N: usize>(mut rng: impl RngCore) -> Self {
        Self::new(BASE64_STANDARD.encode(rng.random::<[u8; N]>()))
    }
}

impl Base64<UrlSafe> {
    /// Generates a random URL-safe base64 string.
    pub fn random<const N: usize>() -> Self {
        let mut rng = rand::rng();
        Self::new(BASE64_URL_SAFE.encode(rng.random::<[u8; N]>()))
    }

    /// Generates a random URL-safe base64 string using provided RNG.
    pub fn random_with<const N: usize>(mut rng: impl RngCore) -> Self {
        Self::new(BASE64_URL_SAFE.encode(rng.random::<[u8; N]>()))
    }
}

impl TryFrom<String> for Base64<Standard> {
    type Error = DecodeSliceError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        // PERF: find method to just check string validity
        let mut out_buf = [0; KEY_SIZE];
        BASE64_STANDARD.decode_slice(&value, &mut out_buf)?;
        Ok(Self::new(value))
    }
}

impl TryFrom<String> for Base64<UrlSafe> {
    type Error = DecodeSliceError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        // PERF: find method to just check string validity
        let mut out_buf = [0; KEY_SIZE];
        BASE64_URL_SAFE.decode_slice(&value, &mut out_buf)?;
        Ok(Self::new(value))
    }
}

impl Debug for Base64<Standard> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Base64<Standard>").field(&self.0).finish()
    }
}

impl Debug for Base64<UrlSafe> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Base64<UrlSafe>").field(&self.0).finish()
    }
}

impl Display for Base64<UrlSafe> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl<A> secrecy::DebugSecret for Base64<A> {}

impl<A> Zeroize for Base64<A> {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
