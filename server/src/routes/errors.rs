use axum::{
    Json,
    extract::rejection::FormRejection,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use axum_extra::typed_header::TypedHeaderRejection;
use thiserror::Error;

use crate::db::{self, ConstraintKind};

use super::verification::{ErrorCodes, VerificationResponse};

/// Errors regarding challenge operations.
#[derive(Debug, Error)]
pub enum ChallengeError {
    /// Invalid key.
    #[error("Invalid key")]
    InvalidKey,
    /// Invalid origin header.
    #[error("Invalid origin header")]
    InvalidOrigin,
    /// Invalid proof of work challenge.
    #[error("Invalid proof of work challenge")]
    InvalidProofOfWork(#[from] jsonwebtoken::errors::Error),
    /// Failed proof of work challenge.
    #[error("Failed proof of work challenge")]
    FailedProofOfWork,
    /// No matching challenge.
    #[error("No matching challenge")]
    NoMatchingChallenge,
    /// Domain not allowed.
    #[error("Domain not allowed, add this domain to the list of allowed domains")]
    DomainNotAllowed,
    /// Unexpected error.
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

impl IntoResponse for ChallengeError {
    fn into_response(self) -> Response {
        tracing::error!(error = ?self, "ChallengeError");
        match self {
            ChallengeError::Unexpected(e) => try_unwrap_db_error(e, |err| match err {
                ChallengeError::Unexpected(_) => None,
                other => Some(other.into_response()),
            }),
            ChallengeError::InvalidKey => (StatusCode::FORBIDDEN, self.to_string()).into_response(),
            ChallengeError::InvalidOrigin => {
                (StatusCode::UNPROCESSABLE_ENTITY, self.to_string()).into_response()
            }
            ChallengeError::InvalidProofOfWork(_) => {
                (StatusCode::BAD_REQUEST, self.to_string()).into_response()
            }
            ChallengeError::FailedProofOfWork => {
                (StatusCode::BAD_REQUEST, self.to_string()).into_response()
            }
            ChallengeError::NoMatchingChallenge => {
                (StatusCode::NOT_FOUND, self.to_string()).into_response()
            }
            ChallengeError::DomainNotAllowed => {
                (StatusCode::FORBIDDEN, self.to_string()).into_response()
            }
        }
    }
}

impl From<db::Error> for ChallengeError {
    fn from(db_err: db::Error) -> Self {
        Self::Unexpected(anyhow::Error::new(db_err).context("database error"))
    }
}

/// Errors regarding console operations.
#[derive(Debug, Error)]
pub enum ConsoleError {
    /// Not found.
    #[error("Not found: {what}")]
    NotFound { what: String },
    /// Forbidden.
    #[error("Access forbidden")]
    Forbidden,
    /// Duplicate resource.
    #[error("Duplicate")]
    Duplicate,
    /// Invalid input.
    #[error("Invalid input: {what}")]
    InvalidInput { what: String },
    /// Unexpected error.
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

impl IntoResponse for ConsoleError {
    fn into_response(self) -> Response {
        tracing::error!(error = ?self, "ConsoleError");
        match self {
            ConsoleError::Unexpected(e) => try_unwrap_db_error(e, |err| match err {
                ConsoleError::Unexpected(_) => None,
                other => Some(other.into_response()),
            }),
            ConsoleError::Duplicate => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
            ConsoleError::NotFound { .. } => {
                (StatusCode::NOT_FOUND, self.to_string()).into_response()
            }
            ConsoleError::Forbidden => StatusCode::FORBIDDEN.into_response(),
            ConsoleError::InvalidInput { .. } => {
                (StatusCode::UNPROCESSABLE_ENTITY, self.to_string()).into_response()
            }
        }
    }
}

impl From<db::Error> for ConsoleError {
    fn from(db_err: db::Error) -> Self {
        match db_err {
            db::Error::Constraint { source, kind: ConstraintKind::ForeignKey }
                if source.constraint().unwrap() == "api_key_console_id_fkey" =>
            {
                ConsoleError::Forbidden
            }
            db::Error::Constraint {
                source,
                kind: ConstraintKind::PrimaryKey | ConstraintKind::UniqueKey,
            } if source
                .constraint()
                .is_some_and(|c| c == "api_key_secret_unique" || c == "api_key_pkey") =>
            {
                ConsoleError::Duplicate
            }
            err => Self::Unexpected(anyhow::Error::new(err).context("database error")),
        }
    }
}

/// Errors regarding admin operations.
#[derive(Debug, Error)]
pub enum AdminError {
    /// Resource not unique.
    #[error("{what} resource already exists")]
    NotUnique { what: String },
    /// Invalid dimensions.
    #[error("Dimensions out of range: width and height must be greater than 0")]
    InvalidDimensions,
    /// Invalid URL.
    #[error("Could not parse URL")]
    InvalidUrl,
    /// Not found.
    #[error("Challenge not found: url('{0}')")]
    NotFound(String),
    /// Unauthorized.
    #[error(transparent)]
    Unauthorized(#[from] TypedHeaderRejection),
    /// Unexpected error.
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

impl IntoResponse for AdminError {
    fn into_response(self) -> Response {
        tracing::error!(error = ?self, "AdminError");
        match self {
            // if a db::Error was wrapped in an anyhow error we try to unwrap it
            AdminError::Unexpected(e) => try_unwrap_db_error(e, |err| match err {
                AdminError::Unexpected(_) => None,
                other => Some(other.into_response()),
            }),
            AdminError::NotUnique { what: _ } => {
                (StatusCode::CONFLICT, self.to_string()).into_response()
            }
            AdminError::InvalidDimensions => {
                (StatusCode::UNPROCESSABLE_ENTITY, self.to_string()).into_response()
            }
            AdminError::InvalidUrl => (StatusCode::BAD_REQUEST, self.to_string()).into_response(),
            AdminError::NotFound(_) => (StatusCode::NOT_FOUND, self.to_string()).into_response(),
            AdminError::Unauthorized(err) => {
                (StatusCode::UNAUTHORIZED, err.to_string()).into_response()
            }
        }
    }
}

impl From<db::Error> for AdminError {
    fn from(db_err: db::Error) -> Self {
        match db_err {
            db::Error::Constraint { kind: ConstraintKind::ValueRange, .. } => {
                AdminError::InvalidDimensions
            }
            db::Error::Constraint { source, kind: ConstraintKind::PrimaryKey }
                if source.constraint() == Some("challenge_pkey") =>
            {
                AdminError::NotUnique { what: "Challenge url".into() }
            }
            err => Self::Unexpected(anyhow::Error::new(err).context("database error")),
        }
    }
}

/// Errors regarding verification operations.
#[derive(Debug, Error)]
pub enum VerificationError {
    /// Verification error.
    #[error(transparent)]
    UserError(#[from] VerificationResponse),
    /// Bad request.
    #[error(transparent)]
    BadRequest(#[from] FormRejection),
    /// Unexpected error.
    #[error(transparent)]
    Unexpected(#[from] anyhow::Error),
}

impl IntoResponse for VerificationError {
    fn into_response(self) -> Response {
        tracing::error!(error = ?self, "VerificationError");
        match self {
            // if a db::Error was wrapped in an anyhow error we try to unwrap it
            VerificationError::Unexpected(e) => try_unwrap_db_error(e, |err| match err {
                VerificationError::Unexpected(_) => None,
                other => Some(other.into_response()),
            }),
            VerificationError::UserError(verification) => Json(verification).into_response(),
            VerificationError::BadRequest(_) => {
                Json(VerificationResponse::failure(vec![ErrorCodes::BadRequest])).into_response()
            }
        }
    }
}

impl From<db::Error> for VerificationError {
    fn from(db_err: db::Error) -> Self {
        Self::Unexpected(anyhow::Error::new(db_err).context("database error"))
    }
}

fn try_unwrap_db_error<E: From<db::Error>>(
    e: anyhow::Error,
    and_then: impl FnOnce(E) -> Option<Response>,
) -> Response {
    e.downcast::<db::Error>()
        .ok()
        .map(E::from)
        .and_then(and_then)
        .unwrap_or_else(|| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}
