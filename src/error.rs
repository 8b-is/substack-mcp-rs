use rmcp::ErrorData as McpError;
use thiserror::Error;

/// Unified application error type designed never to expose raw credentials or stack secrets.
#[derive(Debug, Error)]
pub enum AppError {
    #[error("invalid Substack publication subdomain: {0}")]
    InvalidSubdomain(String),

    #[error("invalid identifier: {0}")]
    InvalidIdentifier(String),

    #[error("blocked potentially unsafe URL or SSRF target: {0}")]
    SsrfBlocked(String),

    #[error("invalid URL: {0}")]
    InvalidUrl(String),

    #[error("authentication required: {0}")]
    AuthRequired(String),

    #[error("publishing is locked: {0}")]
    PublishLocked(String),

    #[error("payload exceeds maximum allowed size of {max_bytes} bytes")]
    PayloadTooLarge { max_bytes: usize },

    #[error("upstream HTTP error ({status}): {message}")]
    UpstreamHttp { status: u16, message: String },

    #[error("invalid ProseMirror document: {0}")]
    ProseMirrorInvalid(String),

    #[error("TurboFieldfare model integrity check failed: {0}")]
    ModelIntegrity(String),

    #[error("path traversal or symlink violation blocked: {0}")]
    PathTraversal(String),

    #[error("rate limit configuration error: {0}")]
    InvalidConfig(String),

    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON serialization failure: {0}")]
    Json(#[from] serde_json::Error),

    #[error("HTTP client failure: {0}")]
    Http(String),
}

impl From<AppError> for McpError {
    fn from(err: AppError) -> Self {
        match &err {
            AppError::InvalidSubdomain(_)
            | AppError::InvalidIdentifier(_)
            | AppError::SsrfBlocked(_)
            | AppError::InvalidUrl(_)
            | AppError::AuthRequired(_)
            | AppError::PublishLocked(_)
            | AppError::PayloadTooLarge { .. }
            | AppError::ProseMirrorInvalid(_)
            | AppError::PathTraversal(_)
            | AppError::InvalidConfig(_) => McpError::invalid_params(err.to_string(), None),
            AppError::UpstreamHttp { .. }
            | AppError::ModelIntegrity(_)
            | AppError::Io(_)
            | AppError::Json(_)
            | AppError::Http(_) => McpError::internal_error(err.to_string(), None),
        }
    }
}
