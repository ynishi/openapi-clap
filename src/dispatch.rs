//! ArgMatches → HTTP request dispatch
//!
//! Takes parsed clap matches and the matching ApiOperation, constructs an HTTP
//! request, and returns the response.

use reqwest::blocking::Client;
use reqwest::Method;
use serde_json::Value;

use crate::error::DispatchError;
use crate::spec::{is_bool_schema, ApiOperation};

/// Execute an API operation based on clap matches.
pub fn dispatch(
    client: &Client,
    base_url: &str,
    api_key: &str,
    op: &ApiOperation,
    matches: &clap::ArgMatches,
) -> Result<Value, DispatchError> {
    let url = build_url(base_url, op, matches);
    let query_pairs = build_query_pairs(op, matches);
    let body = build_body(op, matches)?;
    let headers = collect_headers(op, matches);

    let method: Method = op
        .method
        .parse()
        .map_err(|_| DispatchError::UnsupportedMethod {
            method: op.method.clone(),
        })?;

    let mut req = client.request(method, &url);

    if !api_key.is_empty() {
        req = req.bearer_auth(api_key);
    }
    if !query_pairs.is_empty() {
        req = req.query(&query_pairs);
    }
    for (name, val) in &headers {
        req = req.header(name, val);
    }
    if let Some(body) = body {
        req = req.json(&body);
    }

    send_request(req)
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

fn send_request(req: reqwest::blocking::RequestBuilder) -> Result<Value, DispatchError> {
    let resp = req.send().map_err(DispatchError::RequestFailed)?;
    let status = resp.status();
    let text = resp.text().map_err(DispatchError::ResponseRead)?;

    if !status.is_success() {
        return Err(DispatchError::HttpError { status, body: text });
    }

    let value: Value = serde_json::from_str(&text).unwrap_or(Value::String(text));
    Ok(value)
}

fn build_body(
    op: &ApiOperation,
    matches: &clap::ArgMatches,
) -> Result<Option<Value>, DispatchError> {
    if op.body_schema.is_none() {
        return Ok(None);
    }

    // --json takes precedence
    if let Some(json_str) = matches.get_one::<String>("json-body") {
        let val: Value = serde_json::from_str(json_str).map_err(DispatchError::InvalidJsonBody)?;
        return Ok(Some(val));
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
        let result = dispatch(&client, &server.url(), "test-key", &op, &matches);
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
        let result = dispatch(&client, &server.url(), "key", &op, &matches);
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
        let result = dispatch(&client, &server.url(), "key", &op, &matches);
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
        let result = dispatch(&client, &server.url(), "key", &op, &matches);
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
        let result = dispatch(&client, &server.url(), "key", &op, &matches);
        assert!(result.is_err());
        let err_msg = result.unwrap_err().to_string();
        assert!(
            err_msg.contains("404"),
            "error should contain status code, got: {err_msg}"
        );
    }

    #[test]
    fn dispatch_omits_auth_header_when_api_key_empty() {
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
        let result = dispatch(&client, &server.url(), "", &op, &matches);
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
        let result = dispatch(&client, &server.url(), "key", &op, &matches);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), Value::String("plain text response".into()));
    }
}
