//! Auto-generate clap CLI commands from OpenAPI specs.
//!
//! Parses a dereferenced OpenAPI JSON, extracts operations into an IR,
//! builds a clap `Command` tree, and dispatches HTTP requests.
//!
//! # Usage
//!
//! ```no_run
//! use openapi_clap::{CliConfig, build_commands, extract_operations, find_operation, dispatch};
//! use openapi_deref::resolve;
//! use reqwest::blocking::Client;
//!
//! let spec_json = r#"{"openapi":"3.0.0","paths":{}}"#;
//! let raw: serde_json::Value = serde_json::from_str(spec_json).unwrap();
//! let resolved = resolve(&raw).unwrap();
//! let ops = extract_operations(&resolved.value);
//!
//! let config = CliConfig::new("myapi", "My API CLI", "https://api.example.com");
//!
//! let cmd = build_commands(&config, &ops);
//! ```

pub mod builder;
pub mod dispatch;
pub mod error;
pub mod spec;

pub use builder::{
    build_commands, find_operation, normalize_group, normalize_operation_id, CliConfig,
    CommandNaming,
};
pub use dispatch::dispatch;
pub use error::DispatchError;
pub use spec::{extract_operations, is_bool_schema, ApiOperation, Param};

// Re-export dependencies for downstream crates
pub use clap;
pub use reqwest;
