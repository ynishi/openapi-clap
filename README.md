# openapi-clap

Auto-generate [clap](https://crates.io/crates/clap) CLI commands from [OpenAPI](https://www.openapis.org/) specs.

Given a dereferenced OpenAPI 3.x JSON document, `openapi-clap` extracts operations into an intermediate representation, builds a clap `Command` tree, and dispatches HTTP requests -- turning any REST API into a CLI with zero hand-written argument definitions.

## Features

- **Spec-driven**: paths, parameters (path / query / header), and request bodies are mapped to clap subcommands and arguments automatically.
- **Grouped by tag**: operations are organized under tag-based subcommands (e.g. `mycli pods list-pods`).
- **Body input**: supports `--json '{...}'` for raw JSON and `--field key=value` for individual fields.
- **Customizable**: `CliConfig` lets you set the root command name, description, and default base URL.
- **Re-exports**: `clap` and `reqwest` are re-exported so downstream crates can avoid version conflicts.

## Quick start

Add to your `Cargo.toml`:

```toml
[dependencies]
openapi-clap = "0.1"
openapi-deref = "0.1"
serde_json = "1"
```

Build and dispatch:

```rust,no_run
use openapi_clap::{Auth, CliConfig, build_commands, extract_operations, find_operation, dispatch};
use openapi_deref::resolve;
use reqwest::blocking::Client;

fn main() {
    // Load and dereference your OpenAPI spec
    let raw: serde_json::Value =
        serde_json::from_str(include_str!("spec.json")).expect("invalid JSON");
    let resolved = resolve(&raw).expect("failed to resolve $ref");

    let ops = extract_operations(&resolved.value);
    let config = CliConfig::new("myapi", "My API CLI", "https://api.example.com");
    let cmd = build_commands(&config, &ops);

    let matches = cmd.get_matches();

    // Resolve the two-level subcommand: <group> <operation>
    let (group_name, group_matches) = matches.subcommand().expect("subcommand required");
    let (op_name, op_matches) = group_matches.subcommand().expect("operation required");

    if let Some(op) = find_operation(&ops, group_name, op_name, &config) {
        let base_url = op_matches.get_one::<String>("base-url").unwrap();
        let api_key = std::env::var("API_KEY").unwrap_or_default();
        let auth = Auth::Bearer(&api_key);
        let client = Client::new();
        match dispatch(&client, base_url, &auth, op, op_matches) {
            Ok(value) => println!("{}", serde_json::to_string_pretty(&value).unwrap()),
            Err(e) => eprintln!("error: {e}"),
        }
    }
}
```

## How it works

1. **Parse** -- `extract_operations()` walks the OpenAPI `paths` object and produces a `Vec<ApiOperation>`.
2. **Build** -- `build_commands()` converts operations into a clap `Command` tree grouped by tag.
3. **Match** -- `find_operation()` resolves the user's subcommand back to the original `ApiOperation`.
4. **Dispatch** -- `dispatch()` constructs and sends the HTTP request, returning the response as `serde_json::Value`.

## License

Licensed under either of

- [Apache License, Version 2.0](LICENSE-APACHE)
- [MIT License](LICENSE-MIT)

at your option.
