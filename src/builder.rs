//! IR → clap Command tree builder
//!
//! Converts `ApiOperation`s into a clap `Command` tree grouped by tags.

use std::collections::{BTreeMap, HashMap};

use clap::{Arg, ArgAction, Command};

use crate::spec::{is_bool_schema, ApiOperation};

/// Strategy for generating CLI command names from operation IDs.
#[derive(Debug, Clone, Copy)]
pub enum CommandNaming {
    /// Use normalized operation_id as-is (default, backward compatible).
    ///
    /// `"listPods"` under group `"Pods"` → command `"list-pods"`
    Default,
    /// Strip group name from command name for shorter commands.
    ///
    /// `"listPods"` under group `"Pods"` → command `"list"`
    StripGroup,
    /// Custom naming logic.
    ///
    /// Arguments: `(normalized_op_id, normalized_group) -> command_name`
    Custom(fn(&str, &str) -> String),
}

impl CommandNaming {
    fn apply(&self, normalized_op_id: &str, normalized_group: &str) -> String {
        let result = match self {
            Self::Default => return normalized_op_id.to_string(),
            Self::StripGroup => strip_group(normalized_op_id, normalized_group),
            Self::Custom(f) => f(normalized_op_id, normalized_group),
        };
        // Guard: empty command name would panic in clap
        if result.is_empty() {
            normalized_op_id.to_string()
        } else {
            result
        }
    }
}

/// Strip group name (or its singular form) from an operation name.
///
/// Tries suffix removal first, then prefix removal.
/// Falls back to the original name if stripping is not possible.
fn strip_group(op: &str, group: &str) -> String {
    // suffix: "list-pods" - "-pods" → "list"
    if let Some(stripped) = op.strip_suffix(&format!("-{group}")) {
        if !stripped.is_empty() {
            return stripped.to_string();
        }
    }

    // suffix with singular (trailing 's' removed): "create-pod" when group is "pods"
    if let Some(singular) = group.strip_suffix('s') {
        if !singular.is_empty() {
            if let Some(stripped) = op.strip_suffix(&format!("-{singular}")) {
                if !stripped.is_empty() {
                    return stripped.to_string();
                }
            }
        }
    }

    // prefix: "pods-list" - "pods-" → "list"
    if let Some(stripped) = op.strip_prefix(&format!("{group}-")) {
        if !stripped.is_empty() {
            return stripped.to_string();
        }
    }

    if let Some(singular) = group.strip_suffix('s') {
        if !singular.is_empty() {
            if let Some(stripped) = op.strip_prefix(&format!("{singular}-")) {
                if !stripped.is_empty() {
                    return stripped.to_string();
                }
            }
        }
    }

    // Can't strip: return as-is
    op.to_string()
}

/// Configuration for building a CLI from an OpenAPI spec.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CliConfig {
    /// Root command name (e.g. "runpod", "myapi")
    pub name: String,
    /// Root command about/description
    pub about: String,
    /// Default base URL for the API
    pub default_base_url: String,
    /// Strategy for generating command names from operation IDs
    pub command_naming: CommandNaming,
}

impl CliConfig {
    pub fn new(
        name: impl Into<String>,
        about: impl Into<String>,
        default_base_url: impl Into<String>,
    ) -> Self {
        Self {
            name: name.into(),
            about: about.into(),
            default_base_url: default_base_url.into(),
            command_naming: CommandNaming::Default,
        }
    }

    /// Set the command naming strategy.
    pub fn command_naming(mut self, naming: CommandNaming) -> Self {
        self.command_naming = naming;
        self
    }
}

/// Build a clap `Command` tree from a list of API operations.
///
/// Structure: `<name> <group> <operation> [args] [--options]`
/// Groups are derived from OpenAPI tags (e.g. "pods", "endpoints").
pub fn build_commands(config: &CliConfig, ops: &[ApiOperation]) -> Command {
    let root = Command::new(config.name.clone())
        .about(config.about.clone())
        .subcommand_required(true)
        .arg_required_else_help(true)
        .arg(
            Arg::new("base-url")
                .long("base-url")
                .global(true)
                .default_value(config.default_base_url.clone())
                .help("API base URL"),
        );

    // Group operations by tag
    let mut groups: BTreeMap<String, Vec<&ApiOperation>> = BTreeMap::new();
    for op in ops {
        groups.entry(op.group.clone()).or_default().push(op);
    }

    let mut root = root;
    for (group_name, group_ops) in &groups {
        let norm_group = normalize_group(group_name);
        let mut group_cmd = Command::new(norm_group.clone())
            .about(format!("Manage {group_name}"))
            .subcommand_required(true)
            .arg_required_else_help(true);

        // Detect duplicate names (after command_naming applied) within this group
        let mut name_count: HashMap<String, usize> = HashMap::new();
        for op in group_ops {
            let name = config
                .command_naming
                .apply(&normalize_operation_id(&op.operation_id), &norm_group);
            *name_count.entry(name).or_default() += 1;
        }

        for op in group_ops {
            let base_name = config
                .command_naming
                .apply(&normalize_operation_id(&op.operation_id), &norm_group);
            let cmd_name = if name_count.get(&base_name).copied().unwrap_or(0) > 1 {
                format!("{}-{}", base_name, op.method.to_lowercase())
            } else {
                base_name
            };
            group_cmd = group_cmd.subcommand(build_operation_command(op, &cmd_name));
        }

        root = root.subcommand(group_cmd);
    }

    root
}

/// Find the matching `ApiOperation` for a resolved group + operation name.
pub fn find_operation<'a>(
    ops: &'a [ApiOperation],
    group_name: &str,
    op_name: &str,
    config: &CliConfig,
) -> Option<&'a ApiOperation> {
    ops.iter().find(|o| {
        let norm_group = normalize_group(&o.group);
        let base = config
            .command_naming
            .apply(&normalize_operation_id(&o.operation_id), &norm_group);
        let with_method = format!("{}-{}", base, o.method.to_lowercase());
        (base == op_name || with_method == op_name) && norm_group == group_name
    })
}

fn build_operation_command(op: &ApiOperation, cmd_name: &str) -> Command {
    let mut cmd = Command::new(cmd_name.to_owned()).about(op.summary.clone());

    // Path parameters → positional args
    for param in &op.path_params {
        cmd = cmd.arg(
            Arg::new(param.name.clone())
                .help(param.description.clone())
                .required(true),
        );
    }

    // Query parameters → --flag options
    for param in &op.query_params {
        let arg = Arg::new(param.name.clone())
            .long(param.name.clone())
            .help(param.description.clone())
            .required(param.required);

        let arg = if is_bool_schema(&param.schema) {
            arg.action(ArgAction::SetTrue)
        } else {
            arg.action(ArgAction::Set)
        };

        cmd = cmd.arg(arg);
    }

    // Header parameters → --header-name options
    for param in &op.header_params {
        cmd = cmd.arg(
            Arg::new(param.name.clone())
                .long(param.name.clone())
                .help(param.description.clone())
                .required(param.required)
                .action(ArgAction::Set),
        );
    }

    // Request body → --json or --field options
    if op.body_schema.is_some() {
        cmd = cmd
            .arg(
                Arg::new("json-body")
                    .long("json")
                    .short('j')
                    .help("Request body as JSON string")
                    .action(ArgAction::Set),
            )
            .arg(
                Arg::new("field")
                    .long("field")
                    .short('f')
                    .help("Set body field: key=value (repeatable)")
                    .action(ArgAction::Append),
            );
    }

    cmd
}

pub fn normalize_group(name: &str) -> String {
    let mut result = String::with_capacity(name.len());
    for c in name.chars() {
        if c.is_alphanumeric() {
            result.push(c.to_ascii_lowercase());
        } else if !result.is_empty() && !result.ends_with('-') {
            result.push('-');
        }
    }
    while result.ends_with('-') {
        result.pop();
    }
    result
}

pub fn normalize_operation_id(s: &str) -> String {
    let chars: Vec<char> = s.chars().collect();
    let mut result = String::with_capacity(s.len() + 4);
    for i in 0..chars.len() {
        let c = chars[i];
        if c.is_uppercase() {
            if i > 0 {
                let prev = chars[i - 1];
                let next_is_lower = chars.get(i + 1).is_some_and(|n| n.is_lowercase());
                if prev.is_lowercase() || (prev.is_uppercase() && next_is_lower) {
                    result.push('-');
                }
            }
            result.push(c.to_ascii_lowercase());
        } else {
            result.push(c);
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::spec::{ApiOperation, Param};
    use serde_json::json;

    fn make_operation(operation_id: &str, method: &str, path: &str, group: &str) -> ApiOperation {
        ApiOperation {
            operation_id: operation_id.to_string(),
            method: method.to_string(),
            path: path.to_string(),
            group: group.to_string(),
            summary: String::new(),
            path_params: Vec::new(),
            query_params: Vec::new(),
            header_params: Vec::new(),
            body_schema: None,
            body_required: false,
        }
    }

    fn default_config() -> CliConfig {
        CliConfig {
            name: "testcli".into(),
            about: "Test".into(),
            default_base_url: "https://example.com".into(),
            command_naming: CommandNaming::Default,
        }
    }

    // -- normalize_operation_id --

    #[test]
    fn normalize_operation_id_pascal_case() {
        assert_eq!(normalize_operation_id("CreatePod"), "create-pod");
    }

    #[test]
    fn normalize_operation_id_camel_case() {
        assert_eq!(normalize_operation_id("getPods"), "get-pods");
    }

    #[test]
    fn normalize_operation_id_already_lowercase() {
        assert_eq!(normalize_operation_id("list"), "list");
    }

    #[test]
    fn normalize_operation_id_consecutive_uppercase() {
        assert_eq!(normalize_operation_id("getHTTPStatus"), "get-http-status");
    }

    #[test]
    fn normalize_operation_id_acronym_at_start() {
        assert_eq!(normalize_operation_id("HTMLParser"), "html-parser");
    }

    #[test]
    fn normalize_operation_id_acronym_at_end() {
        assert_eq!(normalize_operation_id("getAPI"), "get-api");
    }

    #[test]
    fn normalize_operation_id_empty() {
        assert_eq!(normalize_operation_id(""), "");
    }

    // -- normalize_group --

    #[test]
    fn normalize_group_with_spaces() {
        assert_eq!(normalize_group("My Group"), "my-group");
    }

    #[test]
    fn normalize_group_already_lowercase() {
        assert_eq!(normalize_group("pods"), "pods");
    }

    #[test]
    fn normalize_group_uppercase() {
        assert_eq!(normalize_group("PODS"), "pods");
    }

    #[test]
    fn normalize_group_multiple_spaces() {
        assert_eq!(normalize_group("My Cool Group"), "my-cool-group");
    }

    #[test]
    fn normalize_group_special_characters() {
        assert_eq!(normalize_group("My/Group"), "my-group");
        assert_eq!(normalize_group("My_Group"), "my-group");
        assert_eq!(normalize_group("My..Group"), "my-group");
    }

    // -- strip_group --

    #[test]
    fn strip_group_suffix_plural() {
        assert_eq!(strip_group("list-pods", "pods"), "list");
    }

    #[test]
    fn strip_group_suffix_singular() {
        assert_eq!(strip_group("create-pod", "pods"), "create");
    }

    #[test]
    fn strip_group_prefix() {
        assert_eq!(strip_group("pods-list", "pods"), "list");
    }

    #[test]
    fn strip_group_no_match_returns_original() {
        assert_eq!(strip_group("get-status", "pods"), "get-status");
    }

    #[test]
    fn strip_group_exact_match_returns_original() {
        // "pods" stripped from "pods" would be empty → fallback to original
        assert_eq!(strip_group("pods", "pods"), "pods");
    }

    #[test]
    fn strip_group_multi_word_group() {
        assert_eq!(strip_group("list-user-roles", "user-roles"), "list");
    }

    // -- CommandNaming --

    #[test]
    fn command_naming_default_returns_normalized_op_id() {
        let naming = CommandNaming::Default;
        assert_eq!(naming.apply("list-pods", "pods"), "list-pods");
    }

    #[test]
    fn command_naming_strip_group_removes_suffix() {
        let naming = CommandNaming::StripGroup;
        assert_eq!(naming.apply("list-pods", "pods"), "list");
        assert_eq!(naming.apply("create-pod", "pods"), "create");
    }

    #[test]
    fn command_naming_custom() {
        let naming = CommandNaming::Custom(|op, _group| op.replace("my-", ""));
        assert_eq!(naming.apply("my-list", "group"), "list");
    }

    #[test]
    fn command_naming_custom_empty_result_falls_back() {
        let naming = CommandNaming::Custom(|_op, _group| String::new());
        assert_eq!(naming.apply("list-pods", "pods"), "list-pods");
    }

    // -- build_commands --

    #[test]
    fn build_commands_creates_correct_tree_structure() {
        let ops = vec![
            make_operation("ListPods", "GET", "/pods", "Pods"),
            make_operation("CreatePod", "POST", "/pods", "Pods"),
            make_operation("ListEndpoints", "GET", "/endpoints", "Endpoints"),
        ];

        let config = CliConfig {
            name: "testcli".into(),
            about: "Test CLI".into(),
            default_base_url: "https://api.example.com".into(),
            command_naming: CommandNaming::Default,
        };

        let cmd = build_commands(&config, &ops);

        assert_eq!(cmd.get_name(), "testcli");

        let subcommands: Vec<&str> = cmd.get_subcommands().map(|c| c.get_name()).collect();
        assert!(subcommands.contains(&"pods"), "should have 'pods' group");
        assert!(
            subcommands.contains(&"endpoints"),
            "should have 'endpoints' group"
        );

        let pods_cmd = cmd
            .get_subcommands()
            .find(|c| c.get_name() == "pods")
            .unwrap();
        let pod_subs: Vec<&str> = pods_cmd.get_subcommands().map(|c| c.get_name()).collect();
        assert!(pod_subs.contains(&"list-pods"), "should have 'list-pods'");
        assert!(pod_subs.contains(&"create-pod"), "should have 'create-pod'");

        let endpoints_cmd = cmd
            .get_subcommands()
            .find(|c| c.get_name() == "endpoints")
            .unwrap();
        let ep_subs: Vec<&str> = endpoints_cmd
            .get_subcommands()
            .map(|c| c.get_name())
            .collect();
        assert!(
            ep_subs.contains(&"list-endpoints"),
            "should have 'list-endpoints'"
        );
    }

    #[test]
    fn build_commands_with_strip_group() {
        let ops = vec![
            make_operation("ListPods", "GET", "/pods", "Pods"),
            make_operation("CreatePod", "POST", "/pods", "Pods"),
            make_operation("GetPod", "GET", "/pods/{id}", "Pods"),
        ];

        let config = CliConfig::new("testcli", "Test", "https://example.com")
            .command_naming(CommandNaming::StripGroup);

        let cmd = build_commands(&config, &ops);
        let pods_cmd = cmd
            .get_subcommands()
            .find(|c| c.get_name() == "pods")
            .unwrap();
        let pod_subs: Vec<&str> = pods_cmd.get_subcommands().map(|c| c.get_name()).collect();
        assert!(pod_subs.contains(&"list"), "should have 'list'");
        assert!(pod_subs.contains(&"create"), "should have 'create'");
        assert!(pod_subs.contains(&"get"), "should have 'get'");
    }

    #[test]
    fn build_commands_includes_path_params_as_positional_args() {
        let ops = vec![ApiOperation {
            operation_id: "GetPod".to_string(),
            method: "GET".to_string(),
            path: "/pods/{podId}".to_string(),
            group: "Pods".to_string(),
            summary: "Get a pod".to_string(),
            path_params: vec![Param {
                name: "podId".to_string(),
                description: "Pod ID".to_string(),
                required: true,
                schema: json!({"type": "string"}),
            }],
            query_params: Vec::new(),
            header_params: Vec::new(),
            body_schema: None,
            body_required: false,
        }];

        let config = default_config();

        let cmd = build_commands(&config, &ops);
        let pods = cmd
            .get_subcommands()
            .find(|c| c.get_name() == "pods")
            .unwrap();
        let get_pod = pods
            .get_subcommands()
            .find(|c| c.get_name() == "get-pod")
            .unwrap();

        let arg = get_pod.get_arguments().find(|a| a.get_id() == "podId");
        assert!(arg.is_some(), "should have podId positional arg");
        assert!(arg.unwrap().is_required_set());
    }

    #[test]
    fn build_commands_includes_body_args_when_body_schema_present() {
        let ops = vec![ApiOperation {
            operation_id: "CreatePod".to_string(),
            method: "POST".to_string(),
            path: "/pods".to_string(),
            group: "Pods".to_string(),
            summary: "Create a pod".to_string(),
            path_params: Vec::new(),
            query_params: Vec::new(),
            header_params: Vec::new(),
            body_schema: Some(json!({"type": "object"})),
            body_required: true,
        }];

        let config = default_config();

        let cmd = build_commands(&config, &ops);
        let pods = cmd
            .get_subcommands()
            .find(|c| c.get_name() == "pods")
            .unwrap();
        let create_pod = pods
            .get_subcommands()
            .find(|c| c.get_name() == "create-pod")
            .unwrap();

        assert!(
            create_pod
                .get_arguments()
                .any(|a| a.get_id() == "json-body"),
            "should have --json arg"
        );
        assert!(
            create_pod.get_arguments().any(|a| a.get_id() == "field"),
            "should have --field arg"
        );
    }

    #[test]
    fn build_commands_global_base_url_arg() {
        let config = default_config();

        let cmd = build_commands(&config, &[]);
        let base_url_arg = cmd.get_arguments().find(|a| a.get_id() == "base-url");
        assert!(base_url_arg.is_some(), "should have global base-url arg");
    }

    // -- find_operation --

    #[test]
    fn find_operation_returns_matching_operation() {
        let config = default_config();
        let ops = vec![
            make_operation("ListPods", "GET", "/pods", "Pods"),
            make_operation("CreatePod", "POST", "/pods", "Pods"),
        ];

        let found = find_operation(&ops, "pods", "create-pod", &config);
        assert!(found.is_some());
        assert_eq!(found.unwrap().operation_id, "CreatePod");
    }

    #[test]
    fn find_operation_returns_none_for_nonexistent() {
        let config = default_config();
        let ops = vec![make_operation("ListPods", "GET", "/pods", "Pods")];

        let found = find_operation(&ops, "pods", "delete-pod", &config);
        assert!(found.is_none());
    }

    #[test]
    fn find_operation_returns_none_for_wrong_group() {
        let config = default_config();
        let ops = vec![make_operation("ListPods", "GET", "/pods", "Pods")];

        let found = find_operation(&ops, "endpoints", "list-pods", &config);
        assert!(found.is_none());
    }

    #[test]
    fn find_operation_matches_with_method_suffix() {
        let config = default_config();
        let ops = vec![
            make_operation("UpdatePod", "PUT", "/pods/{id}", "Pods"),
            make_operation("UpdatePod", "PATCH", "/pods/{id}", "Pods"),
        ];

        let found = find_operation(&ops, "pods", "update-pod-patch", &config);
        assert!(found.is_some());
        assert_eq!(found.unwrap().method, "PATCH");
    }

    #[test]
    fn find_operation_with_strip_group() {
        let config = CliConfig::new("testcli", "Test", "https://example.com")
            .command_naming(CommandNaming::StripGroup);
        let ops = vec![
            make_operation("ListPods", "GET", "/pods", "Pods"),
            make_operation("CreatePod", "POST", "/pods", "Pods"),
        ];

        let found = find_operation(&ops, "pods", "list", &config);
        assert!(found.is_some());
        assert_eq!(found.unwrap().operation_id, "ListPods");

        let found = find_operation(&ops, "pods", "create", &config);
        assert!(found.is_some());
        assert_eq!(found.unwrap().operation_id, "CreatePod");
    }

    #[test]
    fn find_operation_with_strip_group_method_suffix() {
        let config = CliConfig::new("testcli", "Test", "https://example.com")
            .command_naming(CommandNaming::StripGroup);
        let ops = vec![
            make_operation("UpdatePod", "PUT", "/pods/{id}", "Pods"),
            make_operation("UpdatePod", "PATCH", "/pods/{id}", "Pods"),
        ];

        let found = find_operation(&ops, "pods", "update-patch", &config);
        assert!(found.is_some());
        assert_eq!(found.unwrap().method, "PATCH");
    }
}
