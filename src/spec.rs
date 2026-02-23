//! OpenAPI spec → internal IR (intermediate representation)
//!
//! Parses a dereferenced OpenAPI JSON into a flat list of `ApiOperation`s
//! that the CLI builder can consume.

use std::collections::HashMap;

use serde_json::Value;

/// A parsed API operation ready for CLI command generation.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct ApiOperation {
    /// operationId from the spec (e.g. "CreatePod")
    pub operation_id: String,
    /// HTTP method (GET, POST, etc.)
    pub method: String,
    /// URL path template (e.g. "/pods/{podId}")
    pub path: String,
    /// First tag (used as command group)
    pub group: String,
    /// Summary text for help
    pub summary: String,
    /// Path parameters
    pub path_params: Vec<Param>,
    /// Query parameters
    pub query_params: Vec<Param>,
    /// Header parameters
    pub header_params: Vec<Param>,
    /// Request body JSON schema (if any)
    pub body_schema: Option<Value>,
    /// Whether request body is required
    pub body_required: bool,
}

/// A single API parameter.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Param {
    pub name: String,
    pub description: String,
    pub required: bool,
    pub schema: Value,
}

/// Extract all operations from a dereferenced OpenAPI spec.
pub fn extract_operations(spec: &Value) -> Vec<ApiOperation> {
    let mut ops = Vec::new();

    let paths = match spec.get("paths").and_then(|p| p.as_object()) {
        Some(p) => p,
        None => return ops,
    };

    for (path, path_item) in paths {
        let path_level_params = path_item.get("parameters");

        for method in &[
            "get", "post", "put", "patch", "delete", "head", "options", "trace",
        ] {
            let operation = match path_item.get(*method) {
                Some(op) => op,
                None => continue,
            };

            if let Some(op) = extract_single_operation(path, method, operation, path_level_params) {
                ops.push(op);
            }
        }
    }

    ops
}

fn extract_single_operation(
    path: &str,
    method: &str,
    operation: &Value,
    path_level_params: Option<&Value>,
) -> Option<ApiOperation> {
    let operation_id = operation
        .get("operationId")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if operation_id.is_empty() {
        return None;
    }

    let summary = operation
        .get("summary")
        .or_else(|| operation.get("description"))
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let group = operation
        .get("tags")
        .and_then(|v| v.as_array())
        .and_then(|arr| arr.first())
        .and_then(|v| v.as_str())
        .unwrap_or("other")
        .to_string();

    let (mut path_params, query_params, header_params) =
        collect_params(path_level_params, operation.get("parameters"));

    // Sort path params by position in path template, others by name
    path_params.sort_by_cached_key(|p| path.find(&format!("{{{}}}", p.name)).unwrap_or(usize::MAX));

    let (body_schema, body_required) = extract_body(operation);

    Some(ApiOperation {
        operation_id: operation_id.to_string(),
        method: method.to_uppercase(),
        path: path.to_string(),
        summary,
        group,
        path_params,
        query_params,
        header_params,
        body_schema,
        body_required,
    })
}

/// Merge path-level + operation-level parameters, split by location.
/// Operation-level overrides path-level per OpenAPI spec.
fn collect_params(
    path_level: Option<&Value>,
    operation_level: Option<&Value>,
) -> (Vec<Param>, Vec<Param>, Vec<Param>) {
    let mut param_map: HashMap<(String, String), Param> = HashMap::new();

    for source in [path_level, operation_level].iter().flatten() {
        if let Some(params) = source.as_array() {
            for param in params {
                if let Some((p, location)) = parse_param(param) {
                    param_map.insert((p.name.clone(), location), p);
                }
            }
        }
    }

    let mut path_params = Vec::new();
    let mut query_params = Vec::new();
    let mut header_params = Vec::new();

    for ((_, location), p) in param_map {
        match location.as_str() {
            "path" => path_params.push(p),
            "query" => query_params.push(p),
            "header" => header_params.push(p),
            _ => {}
        }
    }

    query_params.sort_by(|a, b| a.name.cmp(&b.name));
    header_params.sort_by(|a, b| a.name.cmp(&b.name));

    (path_params, query_params, header_params)
}

fn extract_body(operation: &Value) -> (Option<Value>, bool) {
    let request_body = operation.get("requestBody");
    let body_required = request_body
        .and_then(|rb| rb.get("required"))
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let body_schema = request_body
        .and_then(|rb| rb.get("content"))
        .and_then(|c| c.get("application/json"))
        .and_then(|ct| ct.get("schema"))
        .cloned();

    (body_schema, body_required)
}

/// Check if a JSON schema describes a boolean type.
pub fn is_bool_schema(schema: &Value) -> bool {
    schema.get("type").and_then(|v| v.as_str()) == Some("boolean")
}

/// Parse a single parameter from its JSON representation.
fn parse_param(param: &Value) -> Option<(Param, String)> {
    let name = param.get("name")?.as_str()?.to_string();
    let location = param.get("in")?.as_str()?.to_string();
    let description = param
        .get("description")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();
    let required = param
        .get("required")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let schema = param
        .get("schema")
        .cloned()
        .unwrap_or(serde_json::json!({"type": "string"}));

    Some((
        Param {
            name,
            description,
            required,
            schema,
        },
        location,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extract_operations_valid_spec_with_get_and_post() {
        let spec = json!({
            "openapi": "3.0.0",
            "paths": {
                "/pods/{podId}": {
                    "get": {
                        "operationId": "GetPod",
                        "summary": "Get a pod",
                        "tags": ["Pods"],
                        "parameters": [
                            {
                                "name": "podId",
                                "in": "path",
                                "required": true,
                                "description": "Pod identifier",
                                "schema": { "type": "string" }
                            },
                            {
                                "name": "verbose",
                                "in": "query",
                                "required": false,
                                "description": "Verbose output",
                                "schema": { "type": "boolean" }
                            },
                            {
                                "name": "X-Request-Id",
                                "in": "header",
                                "required": false,
                                "description": "Request tracking ID",
                                "schema": { "type": "string" }
                            }
                        ]
                    },
                    "post": {
                        "operationId": "CreatePod",
                        "summary": "Create a pod",
                        "tags": ["Pods"],
                        "requestBody": {
                            "required": true,
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": { "type": "string" }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        });

        let ops = extract_operations(&spec);
        assert_eq!(ops.len(), 2);

        let get_op = ops.iter().find(|o| o.operation_id == "GetPod").unwrap();
        assert_eq!(get_op.method, "GET");
        assert_eq!(get_op.path, "/pods/{podId}");
        assert_eq!(get_op.group, "Pods");
        assert_eq!(get_op.summary, "Get a pod");
        assert_eq!(get_op.path_params.len(), 1);
        assert_eq!(get_op.path_params[0].name, "podId");
        assert!(get_op.path_params[0].required);
        assert_eq!(get_op.path_params[0].description, "Pod identifier");
        assert_eq!(get_op.query_params.len(), 1);
        assert_eq!(get_op.query_params[0].name, "verbose");
        assert!(!get_op.query_params[0].required);
        assert_eq!(get_op.header_params.len(), 1);
        assert_eq!(get_op.header_params[0].name, "X-Request-Id");
        assert!(get_op.body_schema.is_none());
        assert!(!get_op.body_required);

        let post_op = ops.iter().find(|o| o.operation_id == "CreatePod").unwrap();
        assert_eq!(post_op.method, "POST");
        assert_eq!(post_op.path, "/pods/{podId}");
        assert_eq!(post_op.group, "Pods");
        assert!(post_op.body_schema.is_some());
        assert!(post_op.body_required);
        assert!(post_op.path_params.is_empty());
        assert!(post_op.query_params.is_empty());
    }

    #[test]
    fn extract_operations_skips_operations_without_operation_id() {
        let spec = json!({
            "openapi": "3.0.0",
            "paths": {
                "/health": {
                    "get": {
                        "summary": "Health check"
                    }
                },
                "/pods": {
                    "get": {
                        "operationId": "ListPods",
                        "summary": "List pods",
                        "tags": ["Pods"]
                    }
                }
            }
        });

        let ops = extract_operations(&spec);
        assert_eq!(ops.len(), 1);
        assert_eq!(ops[0].operation_id, "ListPods");
    }

    #[test]
    fn extract_operations_returns_empty_for_empty_paths() {
        let spec = json!({
            "openapi": "3.0.0",
            "paths": {}
        });

        let ops = extract_operations(&spec);
        assert!(ops.is_empty());
    }

    #[test]
    fn extract_operations_returns_empty_when_no_paths_key() {
        let spec = json!({
            "openapi": "3.0.0"
        });

        let ops = extract_operations(&spec);
        assert!(ops.is_empty());
    }

    #[test]
    fn extract_operations_merges_path_and_operation_params_with_override() {
        let spec = json!({
            "openapi": "3.0.0",
            "paths": {
                "/items/{itemId}": {
                    "parameters": [
                        {
                            "name": "itemId",
                            "in": "path",
                            "required": true,
                            "description": "Path-level description",
                            "schema": { "type": "string" }
                        },
                        {
                            "name": "shared",
                            "in": "query",
                            "required": false,
                            "description": "Path-level shared param",
                            "schema": { "type": "string" }
                        }
                    ],
                    "get": {
                        "operationId": "GetItem",
                        "tags": ["Items"],
                        "parameters": [
                            {
                                "name": "shared",
                                "in": "query",
                                "required": true,
                                "description": "Operation-level override",
                                "schema": { "type": "integer" }
                            }
                        ]
                    }
                }
            }
        });

        let ops = extract_operations(&spec);
        assert_eq!(ops.len(), 1);

        let op = &ops[0];
        // Path param from path-level should be present
        assert_eq!(op.path_params.len(), 1);
        assert_eq!(op.path_params[0].name, "itemId");
        assert_eq!(op.path_params[0].description, "Path-level description");

        // Query param "shared" should be overridden by operation-level
        assert_eq!(op.query_params.len(), 1);
        assert_eq!(op.query_params[0].name, "shared");
        assert_eq!(op.query_params[0].description, "Operation-level override");
        assert!(op.query_params[0].required);
        assert_eq!(op.query_params[0].schema, json!({ "type": "integer" }));
    }

    #[test]
    fn extract_operations_uses_description_when_no_summary() {
        let spec = json!({
            "openapi": "3.0.0",
            "paths": {
                "/pods": {
                    "get": {
                        "operationId": "ListPods",
                        "description": "Fallback description",
                        "tags": ["Pods"]
                    }
                }
            }
        });

        let ops = extract_operations(&spec);
        assert_eq!(ops[0].summary, "Fallback description");
    }

    #[test]
    fn extract_operations_defaults_group_to_other() {
        let spec = json!({
            "openapi": "3.0.0",
            "paths": {
                "/untagged": {
                    "get": {
                        "operationId": "UntaggedOp",
                        "summary": "No tags"
                    }
                }
            }
        });

        let ops = extract_operations(&spec);
        assert_eq!(ops[0].group, "other");
    }

    #[test]
    fn is_bool_schema_returns_true_for_boolean() {
        let schema = json!({ "type": "boolean" });
        assert!(is_bool_schema(&schema));
    }

    #[test]
    fn is_bool_schema_returns_false_for_string() {
        let schema = json!({ "type": "string" });
        assert!(!is_bool_schema(&schema));
    }

    #[test]
    fn is_bool_schema_returns_false_for_no_type() {
        let schema = json!({});
        assert!(!is_bool_schema(&schema));
    }
}
