use std::fmt::{self, Display, Formatter};

use axum::http::{HeaderName, HeaderValue};
use axum_extra::headers::Header;

use crate::encodings::{Base64, UrlSafe};

/// Custom header for passing the site key.
#[derive(Debug, Clone)]
pub struct XSiteKey(pub Base64<UrlSafe>);

impl Header for XSiteKey {
    fn name() -> &'static HeaderName {
        static NAME: HeaderName = HeaderName::from_static("x-site-key");
        &NAME
    }

    fn decode<'i, I>(values: &mut I) -> Result<Self, axum_extra::headers::Error>
    where
        I: Iterator<Item = &'i HeaderValue>,
    {
        if let Some(value) = values.next() {
            let s = value
                .to_str()
                .map_err(|_| axum_extra::headers::Error::invalid())?;
            Ok(XSiteKey(
                Base64::try_from(s.to_owned())
                    .map_err(|_| axum_extra::headers::Error::invalid())?,
            ))
        } else {
            Err(axum_extra::headers::Error::invalid())
        }
    }

    fn encode<E>(&self, values: &mut E)
    where
        E: Extend<HeaderValue>,
    {
        if let Ok(val) = HeaderValue::from_str(self.0.as_str()) {
            values.extend(std::iter::once(val));
        }
    }
}

impl Display for XSiteKey {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}
