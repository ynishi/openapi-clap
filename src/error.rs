//! Error types for the openapi-clap crate.

use thiserror::Error;

/// Errors that can occur during API dispatch.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum DispatchError {
    #[error("invalid JSON in --json argument")]
    InvalidJsonBody(#[source] serde_json::Error),

    #[error("invalid --field format: {field} (expected key=value)")]
    InvalidFieldFormat { field: String },

    #[error("request body is required (use --json or --field)")]
    BodyRequired,

    #[error("unsupported HTTP method: {method}")]
    UnsupportedMethod { method: String },

    #[error("HTTP request failed")]
    RequestFailed(#[source] reqwest::Error),

    #[error("failed to read response body")]
    ResponseRead(#[source] reqwest::Error),

    #[error("HTTP {status}: {body}")]
    HttpError {
        status: reqwest::StatusCode,
        body: String,
    },

    #[error("failed to read JSON from file: {path}")]
    JsonFileRead {
        path: String,
        #[source]
        source: std::io::Error,
    },

    #[error("failed to read JSON from stdin")]
    JsonStdinRead(#[source] std::io::Error),
}
