//! Auto-generate clap CLI commands from OpenAPI specs.
//!
//! Parses a dereferenced OpenAPI JSON, extracts operations into an IR,
//! builds a clap `Command` tree, and dispatches HTTP requests.
//!
//! # Usage
//!
//! ```no_run
//! use openapi_clap::{Auth, CliConfig, build_commands, extract_operations, find_operation, dispatch};
//! use openapi_deref::resolve;
//! use reqwest::blocking::Client;
//!
//! let spec_json = r#"{"openapi":"3.0.0","paths":{}}"#;
//! let raw: serde_json::Value = serde_json::from_str(spec_json).unwrap();
//! let resolved = resolve(&raw).unwrap();
//! let ops = extract_operations(&resolved.value);
//!
//! let config = CliConfig::new("myapi", "My API CLI", "https://api.example.com");
//! let cmd = build_commands(&config, &ops);
//! let matches = cmd.get_matches();
//!
//! let (group, group_matches) = matches.subcommand().expect("subcommand required");
//! let (op_name, op_matches) = group_matches.subcommand().expect("operation required");
//!
//! if let Some(op) = find_operation(&ops, group, op_name, &config) {
//!     let base_url = op_matches.get_one::<String>("base-url").unwrap();
//!     let api_key = std::env::var("API_KEY").unwrap_or_default();
//!     let auth = Auth::Bearer(&api_key);
//!     let client = Client::new();
//!     match dispatch(&client, base_url, &auth, op, op_matches) {
//!         Ok(value) => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
//!         Err(e) => eprintln!("error: {e}"),
//!     }
//! }
//! ```

pub mod builder;
pub mod dispatch;
pub mod error;
pub mod spec;

pub use builder::{
    build_commands, find_operation, normalize_group, normalize_operation_id, CliConfig,
    CommandNaming,
};
pub use dispatch::{
    build_body, dispatch, resolve_json, Auth, PreparedRequest, ResolvedAuth, SendResponse,
};
pub use error::DispatchError;
pub use spec::{extract_operations, is_bool_schema, ApiOperation, Param};

// Re-export dependencies for downstream crates
pub use clap;
pub use reqwest;
