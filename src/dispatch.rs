//! ArgMatches → HTTP request dispatch
//!
//! Takes parsed clap matches and the matching ApiOperation, constructs an HTTP
//! request, and returns the response.
//!
//! # Three-phase dispatch
//!
//! 1. **Prepare** – [`PreparedRequest::from_operation`] resolves URL, parameters,
//!    headers, and authentication from an [`ApiOperation`] and clap matches.
//!    [`build_body`] resolves the request body from `--json` / `--field` arguments.
//! 2. **Send** – [`PreparedRequest::send`] transmits the request and returns a
//!    [`SendResponse`] containing full response metadata (status, headers, body,
//!    elapsed time).
//! 3. **Consume** – [`SendResponse::into_json`] checks the status code and parses
//!    the body as JSON.
//!
//! The convenience function [`dispatch`] chains all three steps for callers that
//! don't need the intermediate representations.

use std::io::Read as _;
use std::time::Instant;

use reqwest::blocking::Client;
use reqwest::Method;
use serde_json::Value;
use tracing::{debug, trace};

use crate::error::DispatchError;
use crate::spec::{is_bool_schema, ApiOperation};

/// Authentication method for API requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Auth<'a> {
    /// No authentication.
    None,
    /// Bearer token (`Authorization: Bearer <token>`).
    Bearer(&'a str),
    /// Custom header (e.g. `X-API-Key: <value>`).
    Header { name: &'a str, value: &'a str },
    /// HTTP Basic authentication.
    Basic {
        username: &'a str,
        password: Option<&'a str>,
    },
    /// API key sent as a query parameter (e.g. `?api_key=<value>`).
    Query { name: &'a str, value: &'a str },
}

/// Owned authentication resolved from [`Auth`].
///
/// Held by [`PreparedRequest`] so the prepared request is `'static` and can be
/// stored, logged, or sent across threads without lifetime constraints.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ResolvedAuth {
    /// No authentication.
    None,
    /// Bearer token.
    Bearer(String),
    /// Custom header.
    Header { name: String, value: String },
    /// HTTP Basic authentication.
    Basic {
        username: String,
        password: Option<String>,
    },
    /// API key as query parameter.
    Query { name: String, value: String },
}

/// Debug output masks secret values to prevent credential leakage in logs.
impl std::fmt::Debug for ResolvedAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Bearer(_) => write!(f, "Bearer(***)"),
            Self::Header { name, .. } => f
                .debug_struct("Header")
                .field("name", name)
                .field("value", &"***")
                .finish(),
            Self::Basic { username, .. } => f
                .debug_struct("Basic")
                .field("username", username)
                .field("password", &"***")
                .finish(),
            Self::Query { name, .. } => f
                .debug_struct("Query")
                .field("name", name)
                .field("value", &"***")
                .finish(),
        }
    }
}

impl From<&Auth<'_>> for ResolvedAuth {
    fn from(auth: &Auth<'_>) -> Self {
        match auth {
            Auth::None => Self::None,
            Auth::Bearer(token) => Self::Bearer(token.to_string()),
            Auth::Header { name, value } => Self::Header {
                name: name.to_string(),
                value: value.to_string(),
            },
            Auth::Basic { username, password } => Self::Basic {
                username: username.to_string(),
                password: password.map(|p| p.to_string()),
            },
            Auth::Query { name, value } => Self::Query {
                name: name.to_string(),
                value: value.to_string(),
            },
        }
    }
}

/// HTTP response from [`PreparedRequest::send`].
///
/// Contains the full response metadata (status, headers, body text, elapsed
/// time).  Use [`into_json`](Self::into_json) for the common path that checks
/// the status code and parses JSON, or access individual fields for verbose
/// logging and dry-run display.
#[derive(Debug)]
#[non_exhaustive]
pub struct SendResponse {
    /// HTTP status code.
    pub status: reqwest::StatusCode,
    /// Response headers.
    pub headers: reqwest::header::HeaderMap,
    /// Raw response body text.
    pub body: String,
    /// Time elapsed from request start to response body fully read.
    pub elapsed: std::time::Duration,
}

impl SendResponse {
    /// Check for a success status and parse the body as JSON.
    ///
    /// Returns [`DispatchError::HttpError`] for non-2xx status codes.
    /// Falls back to [`Value::String`] if the body is not valid JSON.
    pub fn into_json(self) -> Result<Value, DispatchError> {
        if !self.status.is_success() {
            return Err(DispatchError::HttpError {
                status: self.status,
                body: self.body,
            });
        }
        Ok(serde_json::from_str(&self.body).unwrap_or(Value::String(self.body)))
    }

    /// Parse the body as JSON without checking the status code.
    ///
    /// Falls back to [`Value::String`] if the body is not valid JSON.
    pub fn json(&self) -> Value {
        serde_json::from_str(&self.body).unwrap_or_else(|_| Value::String(self.body.clone()))
    }
}

/// A fully resolved HTTP request ready to be sent or inspected.
///
/// Created by [`PreparedRequest::from_operation`], this struct holds all the
/// data needed to execute an HTTP request.  Consumers can inspect the fields
/// for dry-run display, verbose logging, or request modification before
/// calling [`send`](PreparedRequest::send).
///
/// # Example
///
/// ```no_run
/// # use openapi_clap::dispatch::{PreparedRequest, Auth};
/// # use openapi_clap::spec::ApiOperation;
/// # use reqwest::blocking::Client;
/// # fn example(op: &ApiOperation, matches: &clap::ArgMatches) -> Result<(), Box<dyn std::error::Error>> {
/// let prepared = PreparedRequest::from_operation(
///     "https://api.example.com",
///     &Auth::Bearer("token"),
///     op,
///     matches,
/// )?;
///
/// // Inspect before sending (dry-run / verbose)
/// eprintln!("{} {}", prepared.method, prepared.url);
///
/// let resp = prepared.send(&Client::new())?;
/// let value = resp.into_json()?;
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct PreparedRequest {
    /// HTTP method (GET, POST, etc.).
    pub method: Method,
    /// Fully resolved URL with path parameters substituted.
    pub url: String,
    /// Query parameters from the API operation.
    ///
    /// Auth query parameters (see [`ResolvedAuth::Query`]) are kept in the
    /// [`auth`](Self::auth) field and applied separately during
    /// [`send`](Self::send).
    pub query_pairs: Vec<(String, String)>,
    /// Headers from the API operation.
    ///
    /// Auth headers are kept in the [`auth`](Self::auth) field.
    pub headers: Vec<(String, String)>,
    /// JSON request body, if any.
    pub body: Option<Value>,
    /// Resolved authentication.
    pub auth: ResolvedAuth,
}

impl PreparedRequest {
    /// Create a new prepared request with the given HTTP method and URL.
    ///
    /// Use the builder methods ([`query`](Self::query), [`header`](Self::header),
    /// [`body`](Self::body), [`auth`](Self::auth)) to set additional fields,
    /// then call [`send`](Self::send) to execute.
    ///
    /// # Example
    ///
    /// ```no_run
    /// # use openapi_clap::dispatch::{PreparedRequest, ResolvedAuth};
    /// # use reqwest::Method;
    /// # use serde_json::json;
    /// let req = PreparedRequest::new(Method::POST, "https://api.example.com/v2/abc/run")
    ///     .auth(ResolvedAuth::Bearer("my-token".into()))
    ///     .body(json!({"input": {"prompt": "hello"}}));
    /// ```
    pub fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            query_pairs: Vec::new(),
            headers: Vec::new(),
            body: None,
            auth: ResolvedAuth::None,
        }
    }

    /// Add a query parameter.
    pub fn query(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.query_pairs.push((name.into(), value.into()));
        self
    }

    /// Add a header.
    pub fn header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }

    /// Set the JSON request body.
    pub fn body(mut self, body: Value) -> Self {
        self.body = Some(body);
        self
    }

    /// Set the authentication method.
    pub fn auth(mut self, auth: ResolvedAuth) -> Self {
        self.auth = auth;
        self
    }

    /// Remove all query parameters.
    pub fn clear_query(mut self) -> Self {
        self.query_pairs.clear();
        self
    }

    /// Remove all headers.
    pub fn clear_headers(mut self) -> Self {
        self.headers.clear();
        self
    }

    /// Resolve URL, parameters, headers, and authentication from an API
    /// operation and clap matches.
    ///
    /// The request body is **not** included — use [`build_body`] to resolve
    /// it separately, then chain with [`.body()`](Self::body).  The
    /// convenience function [`dispatch`] handles this automatically.
    pub fn from_operation(
        base_url: &str,
        auth: &Auth<'_>,
        op: &ApiOperation,
        matches: &clap::ArgMatches,
    ) -> Result<Self, DispatchError> {
        let url = build_url(base_url, op, matches);
        let query_pairs = build_query_pairs(op, matches);
        let headers = collect_headers(op, matches);
        let method: Method = op
            .method
            .parse()
            .map_err(|_| DispatchError::UnsupportedMethod {
                method: op.method.clone(),
            })?;

        Ok(Self {
            method,
            url,
            query_pairs,
            headers,
            body: None,
            auth: ResolvedAuth::from(auth),
        })
    }

    /// Send the prepared request and return full response metadata.
    ///
    /// Use [`SendResponse::into_json`] to check the status and parse the body,
    /// or access [`SendResponse`] fields directly for verbose logging.
    pub fn send(&self, client: &Client) -> Result<SendResponse, DispatchError> {
        debug!(method = %self.method, url = %self.url, "sending request");
        trace!(?self.headers, ?self.auth, body_present = self.body.is_some());

        let mut req = client.request(self.method.clone(), &self.url);

        match &self.auth {
            ResolvedAuth::None => {}
            ResolvedAuth::Bearer(token) => {
                req = req.bearer_auth(token);
            }
            ResolvedAuth::Header { name, value } => {
                req = req.header(name, value);
            }
            ResolvedAuth::Basic { username, password } => {
                req = req.basic_auth(username, password.as_deref());
            }
            ResolvedAuth::Query { .. } => {} // applied after operation query params
        }
        if !self.query_pairs.is_empty() {
            req = req.query(&self.query_pairs);
        }
        if let ResolvedAuth::Query { name, value } = &self.auth {
            req = req.query(&[(name, value)]);
        }
        for (name, val) in &self.headers {
            req = req.header(name, val);
        }
        if let Some(body) = &self.body {
            req = req.json(body);
        }

        let start = Instant::now();
        let resp = req.send().map_err(DispatchError::RequestFailed)?;
        let status = resp.status();
        let headers = resp.headers().clone();
        let text = resp.text().map_err(DispatchError::ResponseRead)?;
        let elapsed = start.elapsed();

        debug!(%status, elapsed_ms = elapsed.as_millis(), "response received");
        // NOTE: response headers may contain Set-Cookie or auth tokens.
        // TRACE level is opt-in; callers should avoid persisting trace logs
        // in shared/public storage.
        trace!(?headers);

        Ok(SendResponse {
            status,
            headers,
            body: text,
            elapsed,
        })
    }
}

/// Execute an API operation based on clap matches.
///
/// Convenience wrapper that chains [`PreparedRequest::from_operation`] +
/// [`build_body`] + [`PreparedRequest::send`] + [`SendResponse::into_json`].
pub fn dispatch(
    client: &Client,
    base_url: &str,
    auth: &Auth<'_>,
    op: &ApiOperation,
    matches: &clap::ArgMatches,
) -> Result<Value, DispatchError> {
    let mut req = PreparedRequest::from_operation(base_url, auth, op, matches)?;
    if let Some(body) = build_body(op, matches)? {
        req = req.body(body);
    }
    req.send(client)?.into_json()
}

fn build_url(base_url: &str, op: &ApiOperation, matches: &clap::ArgMatches) -> String {
    let base = base_url.trim_end_matches('/');
    let mut url = format!("{}{}", base, op.path);
    for param in &op.path_params {
        if let Some(val) = matches.get_one::<String>(&param.name) {
            url = url.replace(&format!("{{{}}}", param.name), &urlencoding::encode(val));
        }
    }
    url
}

fn build_query_pairs(op: &ApiOperation, matches: &clap::ArgMatches) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    for param in &op.query_params {
        if is_bool_schema(&param.schema) {
            if matches.get_flag(&param.name) {
                pairs.push((param.name.clone(), "true".to_string()));
            }
        } else if let Some(val) = matches.get_one::<String>(&param.name) {
            pairs.push((param.name.clone(), val.clone()));
        }
    }
    pairs
}

fn collect_headers(op: &ApiOperation, matches: &clap::ArgMatches) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    for param in &op.header_params {
        if let Some(val) = matches.get_one::<String>(&param.name) {
            headers.push((param.name.clone(), val.clone()));
        }
    }
    headers
}

/// Resolve the request body from `--json` / `--field` clap arguments.
///
/// Returns `Ok(None)` when the operation has no body schema or no body
/// arguments were provided (and the body is not required).
///
/// This is separated from [`PreparedRequest::from_operation`] so that
/// downstream crates can substitute their own body resolution (e.g.
/// `@file` / stdin support) while reusing URL and parameter resolution.
pub fn build_body(
    op: &ApiOperation,
    matches: &clap::ArgMatches,
) -> Result<Option<Value>, DispatchError> {
    if op.body_schema.is_none() {
        return Ok(None);
    }

    // --json takes precedence
    if let Some(json_str) = matches.get_one::<String>("json-body") {
        return Ok(Some(resolve_json(json_str)?));
    }

    // --field key=value pairs
    if let Some(fields) = matches.get_many::<String>("field") {
        let mut obj = serde_json::Map::new();
        for field in fields {
            let (key, val) =
                field
                    .split_once('=')
                    .ok_or_else(|| DispatchError::InvalidFieldFormat {
                        field: field.to_string(),
                    })?;
            // Try to parse as JSON value, fall back to string
            let json_val = serde_json::from_str(val).unwrap_or(Value::String(val.to_string()));
            obj.insert(key.to_string(), json_val);
        }
        return Ok(Some(Value::Object(obj)));
    }

    if op.body_required {
        return Err(DispatchError::BodyRequired);
    }

    Ok(None)
}

/// Resolve a JSON value from a raw string, file path, or stdin.
///
/// | Input     | Behaviour                                 |
/// |-----------|-------------------------------------------|
/// | `"-"`     | Read all of stdin, then parse as JSON     |
/// | `"@path"` | Read the file at `path`, then parse       |
/// | otherwise | Parse the string directly as JSON         |
///
/// This is the convention used by curl, httpie, and gh CLI.
///
/// # Security
///
/// File-path inputs (`@...`) are **not** sandboxed. The caller is responsible
/// for validating or restricting the `input` value when it originates from
/// untrusted sources.
pub fn resolve_json(input: &str) -> Result<Value, DispatchError> {
    let text = match input {
        "-" => {
            let mut buf = String::new();
            std::io::stdin()
                .read_to_string(&mut buf)
                .map_err(DispatchError::JsonStdinRead)?;
            buf
        }
        s if s.starts_with('@') => {
            let path = &s[1..];
            std::fs::read_to_string(path).map_err(|e| DispatchError::JsonFileRead {
                path: path.to_string(),
                source: e,
            })?
        }
        s => s.to_string(),
    };
    serde_json::from_str(&text).map_err(DispatchError::InvalidJsonBody)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{ApiOperation, Param};
    use clap::{Arg, ArgAction, Command};
    use reqwest::blocking::Client;
    use serde_json::json;

    fn make_op_with_body(body_schema: Option<Value>) -> ApiOperation {
        ApiOperation {
            operation_id: "TestOp".to_string(),
            method: "POST".to_string(),
            path: "/test".to_string(),
            group: "Test".to_string(),
            summary: String::new(),
            path_params: Vec::new(),
            query_params: Vec::new(),
            header_params: Vec::new(),
            body_schema,
            body_required: false,
        }
    }

    fn build_matches_with_args(args: &[&str], has_body: bool) -> clap::ArgMatches {
        let mut cmd = Command::new("test");
        if has_body {
            cmd = cmd
                .arg(
                    Arg::new("json-body")
                        .long("json")
                        .short('j')
                        .action(ArgAction::Set),
                )
                .arg(
                    Arg::new("field")
                        .long("field")
                        .short('f')
                        .action(ArgAction::Append),
                );
        }
        cmd.try_get_matches_from(args).unwrap()
    }

    #[test]
    fn build_body_returns_none_when_no_body_schema() {
        let op = make_op_with_body(None);
        let matches = build_matches_with_args(&["test"], false);

        let result = build_body(&op, &matches).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn build_body_parses_json_flag() {
        let op = make_op_with_body(Some(json!({"type": "object"})));
        let matches =
            build_matches_with_args(&["test", "--json", r#"{"name":"pod1","gpu":2}"#], true);

        let result = build_body(&op, &matches).unwrap();
        assert!(result.is_some());
        let body = result.unwrap();
        assert_eq!(body["name"], "pod1");
        assert_eq!(body["gpu"], 2);
    }

    #[test]
    fn build_body_parses_field_key_value() {
        let op = make_op_with_body(Some(json!({"type": "object"})));
        let matches =
            build_matches_with_args(&["test", "--field", "name=pod1", "--field", "gpu=2"], true);

        let result = build_body(&op, &matches).unwrap();
        assert!(result.is_some());
        let body = result.unwrap();
        assert_eq!(body["name"], "pod1");
        // "2" should be parsed as JSON number
        assert_eq!(body["gpu"], 2);
    }

    #[test]
    fn build_body_field_string_fallback() {
        let op = make_op_with_body(Some(json!({"type": "object"})));
        let matches = build_matches_with_args(&["test", "--field", "name=hello world"], true);

        let result = build_body(&op, &matches).unwrap();
        let body = result.unwrap();
        assert_eq!(body["name"], "hello world");
    }

    #[test]
    fn build_body_returns_error_for_invalid_field_format() {
        let op = make_op_with_body(Some(json!({"type": "object"})));
        let matches = build_matches_with_args(&["test", "--field", "no-equals-sign"], true);

        let result = build_body(&op, &matches);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid --field format"),
            "error should mention invalid format, got: {err_msg}"
        );
    }

    #[test]
    fn build_body_returns_error_for_invalid_json() {
        let op = make_op_with_body(Some(json!({"type": "object"})));
        let matches = build_matches_with_args(&["test", "--json", "{invalid json}"], true);

        let result = build_body(&op, &matches);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("invalid JSON"),
            "error should mention invalid JSON, got: {err_msg}"
        );
    }

    #[test]
    fn build_body_returns_none_when_schema_present_but_no_flags() {
        let op = make_op_with_body(Some(json!({"type": "object"})));
        let matches = build_matches_with_args(&["test"], true);

        let result = build_body(&op, &matches).unwrap();
        assert!(result.is_none());
    }

    #[test]
    fn build_body_json_takes_precedence_over_field() {
        let op = make_op_with_body(Some(json!({"type": "object"})));
        let matches = build_matches_with_args(
            &[
                "test",
                "--json",
                r#"{"from":"json"}"#,
                "--field",
                "from=field",
            ],
            true,
        );

        let result = build_body(&op, &matches).unwrap();
        let body = result.unwrap();
        // --json should win over --field
        assert_eq!(body["from"], "json");
    }

    #[test]
    fn build_body_returns_error_when_body_required_but_not_provided() {
        let mut op = make_op_with_body(Some(json!({"type": "object"})));
        op.body_required = true;
        let matches = build_matches_with_args(&["test"], true);

        let result = build_body(&op, &matches);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("request body is required"));
    }

    // -- dispatch integration tests --

    fn make_full_op(
        method: &str,
        path: &str,
        path_params: Vec<Param>,
        query_params: Vec<Param>,
        header_params: Vec<Param>,
        body_schema: Option<serde_json::Value>,
    ) -> ApiOperation {
        ApiOperation {
            operation_id: "TestOp".to_string(),
            method: method.to_string(),
            path: path.to_string(),
            group: "Test".to_string(),
            summary: String::new(),
            path_params,
            query_params,
            header_params,
            body_schema,
            body_required: false,
        }
    }

    #[test]
    fn dispatch_sends_get_with_path_and_query_params() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/pods/123")
            .match_query(mockito::Matcher::UrlEncoded(
                "verbose".into(),
                "true".into(),
            ))
            .match_header("authorization", "Bearer test-key")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"123"}"#)
            .create();

        let op = make_full_op(
            "GET",
            "/pods/{podId}",
            vec![Param {
                name: "podId".into(),
                description: String::new(),
                required: true,
                schema: json!({"type": "string"}),
            }],
            vec![Param {
                name: "verbose".into(),
                description: String::new(),
                required: false,
                schema: json!({"type": "boolean"}),
            }],
            Vec::new(),
            None,
        );

        let cmd = Command::new("test")
            .arg(Arg::new("podId").required(true))
            .arg(
                Arg::new("verbose")
                    .long("verbose")
                    .action(ArgAction::SetTrue),
            );
        let matches = cmd
            .try_get_matches_from(["test", "123", "--verbose"])
            .unwrap();

        let client = Client::new();
        let result = dispatch(
            &client,
            &server.url(),
            &Auth::Bearer("test-key"),
            &op,
            &matches,
        );
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["id"], "123");
        mock.assert();
    }

    #[test]
    fn dispatch_sends_post_with_json_body() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/pods")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({"name": "pod1"})))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"new"}"#)
            .create();

        let op = make_full_op(
            "POST",
            "/pods",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(json!({"type": "object"})),
        );

        let cmd = Command::new("test").arg(
            Arg::new("json-body")
                .long("json")
                .short('j')
                .action(ArgAction::Set),
        );
        let matches = cmd
            .try_get_matches_from(["test", "--json", r#"{"name":"pod1"}"#])
            .unwrap();

        let client = Client::new();
        let result = dispatch(&client, &server.url(), &Auth::Bearer("key"), &op, &matches);
        assert!(result.is_ok());
        assert_eq!(result.unwrap()["id"], "new");
        mock.assert();
    }

    #[test]
    fn dispatch_sends_header_params() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/test")
            .match_header("X-Request-Id", "abc123")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"ok":true}"#)
            .create();

        let op = make_full_op(
            "GET",
            "/test",
            Vec::new(),
            Vec::new(),
            vec![Param {
                name: "X-Request-Id".into(),
                description: String::new(),
                required: false,
                schema: json!({"type": "string"}),
            }],
            None,
        );

        let cmd = Command::new("test").arg(
            Arg::new("X-Request-Id")
                .long("X-Request-Id")
                .action(ArgAction::Set),
        );
        let matches = cmd
            .try_get_matches_from(["test", "--X-Request-Id", "abc123"])
            .unwrap();

        let client = Client::new();
        let result = dispatch(&client, &server.url(), &Auth::Bearer("key"), &op, &matches);
        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn dispatch_url_encodes_path_params() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/items/hello%20world")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"ok":true}"#)
            .create();

        let op = make_full_op(
            "GET",
            "/items/{itemId}",
            vec![Param {
                name: "itemId".into(),
                description: String::new(),
                required: true,
                schema: json!({"type": "string"}),
            }],
            Vec::new(),
            Vec::new(),
            None,
        );

        let cmd = Command::new("test").arg(Arg::new("itemId").required(true));
        let matches = cmd.try_get_matches_from(["test", "hello world"]).unwrap();

        let client = Client::new();
        let result = dispatch(&client, &server.url(), &Auth::Bearer("key"), &op, &matches);
        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn dispatch_returns_error_on_non_success_status() {
        let mut server = mockito::Server::new();
        let _mock = server
            .mock("GET", "/fail")
            .with_status(404)
            .with_body("not found")
            .create();

        let op = make_full_op("GET", "/fail", Vec::new(), Vec::new(), Vec::new(), None);

        let cmd = Command::new("test");
        let matches = cmd.try_get_matches_from(["test"]).unwrap();

        let client = Client::new();
        let result = dispatch(&client, &server.url(), &Auth::Bearer("key"), &op, &matches);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("404"),
            "error should contain status code, got: {err_msg}"
        );
    }

    #[test]
    fn dispatch_omits_auth_header_when_auth_none() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/test")
            .match_header("authorization", mockito::Matcher::Missing)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"ok":true}"#)
            .create();

        let op = make_full_op("GET", "/test", Vec::new(), Vec::new(), Vec::new(), None);

        let cmd = Command::new("test");
        let matches = cmd.try_get_matches_from(["test"]).unwrap();

        let client = Client::new();
        let result = dispatch(&client, &server.url(), &Auth::None, &op, &matches);
        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn dispatch_sends_custom_header_auth() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/test")
            .match_header("X-API-Key", "my-secret")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"ok":true}"#)
            .create();

        let op = make_full_op("GET", "/test", Vec::new(), Vec::new(), Vec::new(), None);

        let cmd = Command::new("test");
        let matches = cmd.try_get_matches_from(["test"]).unwrap();

        let client = Client::new();
        let auth = Auth::Header {
            name: "X-API-Key",
            value: "my-secret",
        };
        let result = dispatch(&client, &server.url(), &auth, &op, &matches);
        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn dispatch_sends_basic_auth() {
        let mut server = mockito::Server::new();
        // Basic auth header: base64("user:pass") = "dXNlcjpwYXNz"
        let mock = server
            .mock("GET", "/test")
            .match_header("authorization", "Basic dXNlcjpwYXNz")
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"ok":true}"#)
            .create();

        let op = make_full_op("GET", "/test", Vec::new(), Vec::new(), Vec::new(), None);

        let cmd = Command::new("test");
        let matches = cmd.try_get_matches_from(["test"]).unwrap();

        let client = Client::new();
        let auth = Auth::Basic {
            username: "user",
            password: Some("pass"),
        };
        let result = dispatch(&client, &server.url(), &auth, &op, &matches);
        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn dispatch_sends_query_auth() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/test")
            .match_query(mockito::Matcher::UrlEncoded(
                "api_key".into(),
                "my-secret".into(),
            ))
            .match_header("authorization", mockito::Matcher::Missing)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"ok":true}"#)
            .create();

        let op = make_full_op("GET", "/test", Vec::new(), Vec::new(), Vec::new(), None);

        let cmd = Command::new("test");
        let matches = cmd.try_get_matches_from(["test"]).unwrap();

        let client = Client::new();
        let auth = Auth::Query {
            name: "api_key",
            value: "my-secret",
        };
        let result = dispatch(&client, &server.url(), &auth, &op, &matches);
        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn dispatch_query_auth_coexists_with_operation_query_params() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/test")
            .match_query(mockito::Matcher::AllOf(vec![
                mockito::Matcher::UrlEncoded("verbose".into(), "true".into()),
                mockito::Matcher::UrlEncoded("api_key".into(), "secret".into()),
            ]))
            .match_header("authorization", mockito::Matcher::Missing)
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"ok":true}"#)
            .create();

        let op = make_full_op(
            "GET",
            "/test",
            Vec::new(),
            vec![Param {
                name: "verbose".into(),
                description: String::new(),
                required: false,
                schema: json!({"type": "boolean"}),
            }],
            Vec::new(),
            None,
        );

        let cmd = Command::new("test").arg(
            Arg::new("verbose")
                .long("verbose")
                .action(ArgAction::SetTrue),
        );
        let matches = cmd.try_get_matches_from(["test", "--verbose"]).unwrap();

        let client = Client::new();
        let auth = Auth::Query {
            name: "api_key",
            value: "secret",
        };
        let result = dispatch(&client, &server.url(), &auth, &op, &matches);
        assert!(result.is_ok());
        mock.assert();
    }

    #[test]
    fn dispatch_returns_string_value_for_non_json_response() {
        let mut server = mockito::Server::new();
        let _mock = server
            .mock("GET", "/plain")
            .with_status(200)
            .with_header("content-type", "text/plain")
            .with_body("plain text response")
            .create();

        let op = make_full_op("GET", "/plain", Vec::new(), Vec::new(), Vec::new(), None);

        let cmd = Command::new("test");
        let matches = cmd.try_get_matches_from(["test"]).unwrap();

        let client = Client::new();
        let result = dispatch(&client, &server.url(), &Auth::Bearer("key"), &op, &matches);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Value::String("plain text response".into()));
    }

    // -- PreparedRequest unit tests --

    #[test]
    fn prepared_request_resolves_url_and_method() {
        let op = make_full_op(
            "GET",
            "/pods/{podId}",
            vec![Param {
                name: "podId".into(),
                description: String::new(),
                required: true,
                schema: json!({"type": "string"}),
            }],
            Vec::new(),
            Vec::new(),
            None,
        );
        let cmd = Command::new("test").arg(Arg::new("podId").required(true));
        let matches = cmd.try_get_matches_from(["test", "abc"]).unwrap();

        let prepared =
            PreparedRequest::from_operation("https://api.example.com", &Auth::None, &op, &matches)
                .unwrap();

        assert_eq!(prepared.method, Method::GET);
        assert_eq!(prepared.url, "https://api.example.com/pods/abc");
        assert!(prepared.query_pairs.is_empty());
        assert!(prepared.headers.is_empty());
        assert!(prepared.body.is_none());
        assert_eq!(prepared.auth, ResolvedAuth::None);
    }

    #[test]
    fn prepared_request_collects_query_pairs() {
        let op = make_full_op(
            "GET",
            "/test",
            Vec::new(),
            vec![
                Param {
                    name: "limit".into(),
                    description: String::new(),
                    required: false,
                    schema: json!({"type": "integer"}),
                },
                Param {
                    name: "verbose".into(),
                    description: String::new(),
                    required: false,
                    schema: json!({"type": "boolean"}),
                },
            ],
            Vec::new(),
            None,
        );
        let cmd = Command::new("test")
            .arg(Arg::new("limit").long("limit").action(ArgAction::Set))
            .arg(
                Arg::new("verbose")
                    .long("verbose")
                    .action(ArgAction::SetTrue),
            );
        let matches = cmd
            .try_get_matches_from(["test", "--limit", "10", "--verbose"])
            .unwrap();

        let prepared =
            PreparedRequest::from_operation("https://api.example.com", &Auth::None, &op, &matches)
                .unwrap();

        assert_eq!(
            prepared.query_pairs,
            vec![
                ("limit".to_string(), "10".to_string()),
                ("verbose".to_string(), "true".to_string()),
            ]
        );
    }

    #[test]
    fn prepared_request_collects_headers() {
        let op = make_full_op(
            "GET",
            "/test",
            Vec::new(),
            Vec::new(),
            vec![Param {
                name: "X-Request-Id".into(),
                description: String::new(),
                required: false,
                schema: json!({"type": "string"}),
            }],
            None,
        );
        let cmd = Command::new("test").arg(
            Arg::new("X-Request-Id")
                .long("X-Request-Id")
                .action(ArgAction::Set),
        );
        let matches = cmd
            .try_get_matches_from(["test", "--X-Request-Id", "req-42"])
            .unwrap();

        let prepared =
            PreparedRequest::from_operation("https://api.example.com", &Auth::None, &op, &matches)
                .unwrap();

        assert_eq!(
            prepared.headers,
            vec![("X-Request-Id".to_string(), "req-42".to_string())]
        );
    }

    #[test]
    fn from_operation_does_not_set_body() {
        let op = make_full_op(
            "POST",
            "/test",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Some(json!({"type": "object"})),
        );
        let cmd = Command::new("test").arg(
            Arg::new("json-body")
                .long("json")
                .short('j')
                .action(ArgAction::Set),
        );
        let matches = cmd
            .try_get_matches_from(["test", "--json", r#"{"key":"val"}"#])
            .unwrap();

        let prepared =
            PreparedRequest::from_operation("https://api.example.com", &Auth::None, &op, &matches)
                .unwrap();

        // from_operation no longer resolves body
        assert_eq!(prepared.body, None);

        // build_body resolves it separately
        let body = build_body(&op, &matches).unwrap();
        assert_eq!(body, Some(json!({"key": "val"})));
    }

    #[test]
    fn prepared_request_resolves_bearer_auth() {
        let op = make_full_op("GET", "/test", Vec::new(), Vec::new(), Vec::new(), None);
        let cmd = Command::new("test");
        let matches = cmd.try_get_matches_from(["test"]).unwrap();

        let prepared = PreparedRequest::from_operation(
            "https://api.example.com",
            &Auth::Bearer("my-token"),
            &op,
            &matches,
        )
        .unwrap();

        assert_eq!(prepared.auth, ResolvedAuth::Bearer("my-token".to_string()));
    }

    #[test]
    fn prepared_request_resolves_basic_auth() {
        let op = make_full_op("GET", "/test", Vec::new(), Vec::new(), Vec::new(), None);
        let cmd = Command::new("test");
        let matches = cmd.try_get_matches_from(["test"]).unwrap();

        let prepared = PreparedRequest::from_operation(
            "https://api.example.com",
            &Auth::Basic {
                username: "user",
                password: Some("pass"),
            },
            &op,
            &matches,
        )
        .unwrap();

        assert_eq!(
            prepared.auth,
            ResolvedAuth::Basic {
                username: "user".to_string(),
                password: Some("pass".to_string()),
            }
        );
    }

    #[test]
    fn prepared_request_resolves_header_auth() {
        let op = make_full_op("GET", "/test", Vec::new(), Vec::new(), Vec::new(), None);
        let cmd = Command::new("test");
        let matches = cmd.try_get_matches_from(["test"]).unwrap();

        let prepared = PreparedRequest::from_operation(
            "https://api.example.com",
            &Auth::Header {
                name: "X-API-Key",
                value: "secret",
            },
            &op,
            &matches,
        )
        .unwrap();

        assert_eq!(
            prepared.auth,
            ResolvedAuth::Header {
                name: "X-API-Key".to_string(),
                value: "secret".to_string(),
            }
        );
    }

    #[test]
    fn prepared_request_resolves_query_auth_separate_from_query_pairs() {
        let op = make_full_op(
            "GET",
            "/test",
            Vec::new(),
            vec![Param {
                name: "verbose".into(),
                description: String::new(),
                required: false,
                schema: json!({"type": "boolean"}),
            }],
            Vec::new(),
            None,
        );
        let cmd = Command::new("test").arg(
            Arg::new("verbose")
                .long("verbose")
                .action(ArgAction::SetTrue),
        );
        let matches = cmd.try_get_matches_from(["test", "--verbose"]).unwrap();

        let prepared = PreparedRequest::from_operation(
            "https://api.example.com",
            &Auth::Query {
                name: "api_key",
                value: "secret",
            },
            &op,
            &matches,
        )
        .unwrap();

        // Auth query param is NOT in query_pairs — it's in auth
        assert_eq!(
            prepared.query_pairs,
            vec![("verbose".to_string(), "true".to_string())]
        );
        assert_eq!(
            prepared.auth,
            ResolvedAuth::Query {
                name: "api_key".to_string(),
                value: "secret".to_string(),
            }
        );
    }

    #[test]
    fn prepared_request_url_encodes_path_params() {
        let op = make_full_op(
            "GET",
            "/items/{name}",
            vec![Param {
                name: "name".into(),
                description: String::new(),
                required: true,
                schema: json!({"type": "string"}),
            }],
            Vec::new(),
            Vec::new(),
            None,
        );
        let cmd = Command::new("test").arg(Arg::new("name").required(true));
        let matches = cmd.try_get_matches_from(["test", "hello world"]).unwrap();

        let prepared =
            PreparedRequest::from_operation("https://api.example.com", &Auth::None, &op, &matches)
                .unwrap();

        assert_eq!(prepared.url, "https://api.example.com/items/hello%20world");
    }

    #[test]
    fn prepared_request_returns_error_for_unsupported_method() {
        // Method must contain invalid HTTP token characters to fail parsing
        let op = make_full_op(
            "NOT VALID",
            "/test",
            Vec::new(),
            Vec::new(),
            Vec::new(),
            None,
        );
        let cmd = Command::new("test");
        let matches = cmd.try_get_matches_from(["test"]).unwrap();

        let result =
            PreparedRequest::from_operation("https://api.example.com", &Auth::None, &op, &matches);
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("unsupported HTTP method"));
    }

    // -- PreparedRequest builder tests --

    #[test]
    fn builder_new_sets_method_and_url() {
        let req = PreparedRequest::new(Method::GET, "https://api.example.com/test");

        assert_eq!(req.method, Method::GET);
        assert_eq!(req.url, "https://api.example.com/test");
        assert!(req.query_pairs.is_empty());
        assert!(req.headers.is_empty());
        assert!(req.body.is_none());
        assert_eq!(req.auth, ResolvedAuth::None);
    }

    #[test]
    fn builder_query_appends_pairs() {
        let req = PreparedRequest::new(Method::GET, "https://example.com")
            .query("limit", "10")
            .query("offset", "0");

        assert_eq!(
            req.query_pairs,
            vec![
                ("limit".to_string(), "10".to_string()),
                ("offset".to_string(), "0".to_string()),
            ]
        );
    }

    #[test]
    fn builder_header_appends_headers() {
        let req = PreparedRequest::new(Method::GET, "https://example.com")
            .header("X-Request-Id", "abc123")
            .header("Accept", "application/json");

        assert_eq!(
            req.headers,
            vec![
                ("X-Request-Id".to_string(), "abc123".to_string()),
                ("Accept".to_string(), "application/json".to_string()),
            ]
        );
    }

    #[test]
    fn builder_clear_query_removes_all_pairs() {
        let req = PreparedRequest::new(Method::GET, "https://example.com")
            .query("a", "1")
            .query("b", "2")
            .clear_query();

        assert!(req.query_pairs.is_empty());
    }

    #[test]
    fn builder_clear_headers_removes_all_headers() {
        let req = PreparedRequest::new(Method::GET, "https://example.com")
            .header("X-Foo", "bar")
            .header("X-Baz", "qux")
            .clear_headers();

        assert!(req.headers.is_empty());
    }

    #[test]
    fn builder_body_sets_json() {
        let req = PreparedRequest::new(Method::POST, "https://example.com")
            .body(json!({"input": {"prompt": "hello"}}));

        assert_eq!(req.body, Some(json!({"input": {"prompt": "hello"}})));
    }

    #[test]
    fn builder_auth_sets_resolved_auth() {
        let req = PreparedRequest::new(Method::POST, "https://example.com")
            .auth(ResolvedAuth::Bearer("my-token".into()));

        assert_eq!(req.auth, ResolvedAuth::Bearer("my-token".to_string()));
    }

    #[test]
    fn builder_chaining_all_fields() {
        let req = PreparedRequest::new(Method::POST, "https://api.runpod.ai/v2/abc/run")
            .auth(ResolvedAuth::Bearer("key".into()))
            .body(json!({"input": {}}))
            .query("wait", "90000")
            .header("X-Custom", "value");

        assert_eq!(req.method, Method::POST);
        assert_eq!(req.url, "https://api.runpod.ai/v2/abc/run");
        assert_eq!(req.auth, ResolvedAuth::Bearer("key".to_string()));
        assert_eq!(req.body, Some(json!({"input": {}})));
        assert_eq!(
            req.query_pairs,
            vec![("wait".to_string(), "90000".to_string())]
        );
        assert_eq!(
            req.headers,
            vec![("X-Custom".to_string(), "value".to_string())]
        );
    }

    #[test]
    fn builder_send_executes_request() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("POST", "/v2/abc/run")
            .match_header("authorization", "Bearer test-key")
            .match_header("content-type", "application/json")
            .match_body(mockito::Matcher::Json(json!({"input": {"prompt": "hi"}})))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"id":"job-123","status":"IN_QUEUE"}"#)
            .create();

        let req = PreparedRequest::new(Method::POST, format!("{}/v2/abc/run", server.url()))
            .auth(ResolvedAuth::Bearer("test-key".into()))
            .body(json!({"input": {"prompt": "hi"}}));

        let client = Client::new();
        let resp = req.send(&client).expect("send should succeed");
        assert!(resp.status.is_success());
        let val = resp.into_json().expect("should parse JSON");
        assert_eq!(val["id"], "job-123");
        assert_eq!(val["status"], "IN_QUEUE");
        mock.assert();
    }

    #[test]
    fn builder_send_with_query_auth() {
        let mut server = mockito::Server::new();
        let mock = server
            .mock("GET", "/health")
            .match_query(mockito::Matcher::UrlEncoded(
                "api_key".into(),
                "secret".into(),
            ))
            .with_status(200)
            .with_header("content-type", "application/json")
            .with_body(r#"{"ok":true}"#)
            .create();

        let req = PreparedRequest::new(Method::GET, format!("{}/health", server.url())).auth(
            ResolvedAuth::Query {
                name: "api_key".into(),
                value: "secret".into(),
            },
        );

        let client = Client::new();
        let resp = req.send(&client).expect("send should succeed");
        let val = resp.into_json().expect("should parse JSON");
        assert_eq!(val["ok"], true);
        mock.assert();
    }

    // -- resolve_json tests --

    #[test]
    fn resolve_json_parses_raw_string() {
        let val = resolve_json(r#"{"key":"value"}"#).unwrap();
        assert_eq!(val, json!({"key": "value"}));
    }

    #[test]
    fn resolve_json_reads_file() {
        let dir = std::env::temp_dir().join("openapi_clap_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test_input.json");
        std::fs::write(&path, r#"{"from":"file"}"#).unwrap();

        let val = resolve_json(&format!("@{}", path.display())).unwrap();
        assert_eq!(val, json!({"from": "file"}));

        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn resolve_json_returns_error_for_missing_file() {
        let result = resolve_json("@/nonexistent/path/file.json");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("failed to read JSON from file"));
    }

    #[test]
    fn resolve_json_returns_error_for_invalid_json() {
        let result = resolve_json("{not valid json}");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("invalid JSON"));
    }

    #[test]
    fn build_body_json_flag_resolves_file() {
        let dir = std::env::temp_dir().join("openapi_clap_test");
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("body_test.json");
        std::fs::write(&path, r#"{"name":"from-file"}"#).unwrap();

        let op = make_op_with_body(Some(json!({"type": "object"})));
        let matches =
            build_matches_with_args(&["test", "--json", &format!("@{}", path.display())], true);

        let result = build_body(&op, &matches).unwrap();
        assert_eq!(result, Some(json!({"name": "from-file"})));

        std::fs::remove_file(&path).unwrap();
    }
}
