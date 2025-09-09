use anyhow::Result;
use schemars::schema::RootSchema;
use schemars::schema_for;
use serde_json::json;

fn main() -> Result<()> {
    // Collect schemas for the main user-facing config types.
    let schemas: Vec<(&str, RootSchema)> = vec![
        ("ConfigToml", schema_for!(codex_core::config::ConfigToml)),
        (
            "ConfigProfile",
            schema_for!(codex_core::config_profile::ConfigProfile),
        ),
        (
            "ProjectConfig",
            schema_for!(codex_core::config::ProjectConfig),
        ),
        ("ToolsToml", schema_for!(codex_core::config::ToolsToml)),
        (
            "McpServerConfig",
            schema_for!(codex_core::config_types::McpServerConfig),
        ),
        (
            "UriBasedFileOpener",
            schema_for!(codex_core::config_types::UriBasedFileOpener),
        ),
        ("History", schema_for!(codex_core::config_types::History)),
        (
            "HistoryPersistence",
            schema_for!(codex_core::config_types::HistoryPersistence),
        ),
        ("Tui", schema_for!(codex_core::config_types::Tui)),
        (
            "SandboxWorkspaceWrite",
            schema_for!(codex_core::config_types::SandboxWorkspaceWrite),
        ),
        (
            "ShellEnvironmentPolicyToml",
            schema_for!(codex_core::config_types::ShellEnvironmentPolicyToml),
        ),
        (
            "ReasoningSummaryFormat",
            schema_for!(codex_core::config_types::ReasoningSummaryFormat),
        ),
        (
            "ReasoningEffort",
            schema_for!(codex_core::protocol_config_types::ReasoningEffort),
        ),
        (
            "ReasoningSummary",
            schema_for!(codex_core::protocol_config_types::ReasoningSummary),
        ),
        (
            "Verbosity",
            schema_for!(codex_core::protocol_config_types::Verbosity),
        ),
        (
            "SandboxMode",
            schema_for!(codex_core::protocol_config_types::SandboxMode),
        ),
    ];

    let mut map = serde_json::Map::new();
    for (name, schema) in schemas {
        map.insert(name.to_string(), json!(schema));
    }

    let combined = serde_json::Value::Object(map);
    println!("{}", serde_json::to_string_pretty(&combined)?);
    Ok(())
}
