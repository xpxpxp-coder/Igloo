//! Governed, relay-independent one-shot ACP execution.
//!
//! This is the narrow library surface used by the remote Snowman executor. It
//! deliberately does not expose the long-lived relay harness, Nostr identity,
//! desktop observer, ambient runtime environment, or permissive local tool
//! behavior.

use std::{path::Path, time::Duration};

use serde::{Deserialize, Serialize};

use crate::acp::{
    resolve_model_switch_method, AcpClient, EnvVar, McpServer, ModelSwitchMethod, PermissionPolicy,
    StopReason,
};

const RUNTIME_ROOT: &str = "/opt/snowman/runtime/bin";
const MCP_ROOT: &str = "/usr/local/bin";
const WORKSPACE_ROOT: &str = "/workspace";
const MAX_SYSTEM_PROMPT_BYTES: usize = 64 * 1024;
const MAX_PROMPT_BYTES: usize = 512 * 1024;
const MAX_ADAPTER_ARGS: usize = 32;
const MAX_MCP_SERVERS: usize = 8;

const ALLOWED_MCP_ENV_KEYS: &[&str] = &[
    "SNOWMAN_AGENT_JOB_ID",
    "SNOWMAN_AGENT_JOB_TOKEN",
    "SNOWMAN_AGENT_BROKER_URL",
];

/// Exact governed MCP process provided to an adapter session.
#[derive(Debug, Clone)]
pub struct GovernedMcpServer {
    /// Stable server identifier.
    pub name: String,
    /// Absolute executable path under `/usr/local/bin` whose basename starts
    /// with `snowman-agent-`.
    pub command: String,
    /// Bounded arguments baked into the reviewed runtime image contract.
    pub args: Vec<String>,
    /// Purpose-bound job values; no relay, cloud, human, or provider secret is
    /// accepted.
    pub env: Vec<(String, String)>,
}

/// Immutable input for one adapter process and one prompt turn.
#[derive(Debug, Clone)]
pub struct OneShotConfig {
    /// Digest-reviewed adapter executable inside the runtime image.
    pub adapter_command: String,
    /// Adapter arguments from the immutable runtime profile.
    pub adapter_args: Vec<String>,
    /// Exact evaluated model catalog ID selected by Snowman policy.
    pub model_id: String,
    /// Trusted Snowman system policy. User/connector content belongs only in
    /// `prompt`.
    pub system_prompt: String,
    /// Bounded, already-classified job prompt.
    pub prompt: String,
    /// Governed tool servers. Empty is valid for reasoning-only work.
    pub mcp_servers: Vec<GovernedMcpServer>,
    /// Silent-process ceiling.
    pub idle_timeout: Duration,
    /// Absolute wall-clock ceiling.
    pub max_duration: Duration,
}

/// User-facing outcome of one governed adapter turn.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct OneShotResult {
    /// Terminal ACP stop reason.
    pub stop_reason: String,
    /// Bounded `agent_message_chunk` text only.
    pub output: String,
    /// True when the output exceeded the capture ceiling.
    pub output_truncated: bool,
    /// Best-effort input-token count when the adapter reported it.
    pub input_tokens: Option<u64>,
    /// Best-effort output-token count when the adapter reported it.
    pub output_tokens: Option<u64>,
}

/// Non-sensitive one-shot execution failure.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum OneShotError {
    /// The immutable runtime or job contract is invalid.
    #[error("one-shot ACP configuration is invalid: {0}")]
    Configuration(&'static str),
    /// Adapter startup or protocol initialization failed.
    #[error("one-shot ACP adapter failed during {0}")]
    Adapter(&'static str),
    /// The evaluated model was not advertised by the adapter.
    #[error("one-shot ACP adapter does not advertise the governed model")]
    UnsupportedModel,
}

/// Run exactly one prompt in a fresh ACP adapter process.
pub async fn run(config: OneShotConfig) -> Result<OneShotResult, OneShotError> {
    validate(&config)?;

    let codex_overlay = is_codex_command(&config.adapter_command).then(|| {
        vec![(
            "CODEX_CONFIG".to_owned(),
            r#"{"sandbox_workspace_write":{"network_access":false}}"#.to_owned(),
        )]
    });
    let extra_env = codex_overlay.as_deref().unwrap_or_default();
    let mut client = AcpClient::spawn_governed(
        &config.adapter_command,
        &config.adapter_args,
        extra_env,
        codex_overlay.is_some(),
    )
    .await
    .map_err(|_| OneShotError::Adapter("spawn"))?;
    client.set_permission_policy(PermissionPolicy::RejectOnce);

    let result = run_with_client(&mut client, &config).await;
    client.shutdown().await;
    result
}

async fn run_with_client(
    client: &mut AcpClient,
    config: &OneShotConfig,
) -> Result<OneShotResult, OneShotError> {
    client
        .initialize()
        .await
        .map_err(|_| OneShotError::Adapter("initialize"))?;

    let mcp_servers = config
        .mcp_servers
        .iter()
        .map(|server| McpServer {
            name: server.name.clone(),
            command: server.command.clone(),
            args: server.args.clone(),
            env: server
                .env
                .iter()
                .map(|(name, value)| EnvVar {
                    name: name.clone(),
                    value: value.clone(),
                })
                .collect(),
        })
        .collect();
    let session = client
        .session_new_full(
            WORKSPACE_ROOT,
            mcp_servers,
            Some(config.system_prompt.as_str()),
        )
        .await
        .map_err(|_| OneShotError::Adapter("session"))?;

    let model_switch = resolve_model_switch_method(&session.raw, &config.model_id)
        .ok_or(OneShotError::UnsupportedModel)?;
    apply_model(client, &session.session_id, &model_switch).await?;

    // If the adapter exposes a permission mode, use its fail-closed mode in
    // addition to rejecting every runtime-originated permission request.
    if advertises_config_value(&session.raw, "mode", "dontAsk") {
        client
            .session_set_config_option(&session.session_id, "mode", "dontAsk")
            .await
            .map_err(|_| OneShotError::Adapter("permission policy"))?;
    }

    let stop_reason = client
        .session_prompt_with_idle_timeout(
            &session.session_id,
            &config.prompt,
            config.idle_timeout,
            config.max_duration,
        )
        .await
        .map_err(|_| OneShotError::Adapter("prompt"))?;
    let output = client.take_captured_turn_output();
    let usage = client.take_turn_usage();

    Ok(OneShotResult {
        stop_reason: stop_reason_label(&stop_reason).to_owned(),
        output: output.text,
        output_truncated: output.truncated,
        input_tokens: usage.as_ref().and_then(|value| value.turn_input_tokens),
        output_tokens: usage.as_ref().and_then(|value| value.turn_output_tokens),
    })
}

async fn apply_model(
    client: &mut AcpClient,
    session_id: &str,
    method: &ModelSwitchMethod,
) -> Result<(), OneShotError> {
    match method {
        ModelSwitchMethod::ConfigOption {
            config_id,
            option_value,
        } => {
            client
                .session_set_config_option(session_id, config_id, option_value)
                .await
        }
        ModelSwitchMethod::SetModel { model_id } => {
            client.session_set_model(session_id, model_id).await
        }
    }
    .map(|_| ())
    .map_err(|_| OneShotError::Adapter("model selection"))
}

fn validate(config: &OneShotConfig) -> Result<(), OneShotError> {
    validate_command(&config.adapter_command, RUNTIME_ROOT, None)?;
    validate_args(&config.adapter_args)?;
    if config.model_id.is_empty()
        || config.model_id.len() > 256
        || config.model_id.contains("://")
        || config.model_id.chars().any(char::is_control)
    {
        return Err(OneShotError::Configuration("model ID is invalid"));
    }
    if config.system_prompt.is_empty() || config.system_prompt.len() > MAX_SYSTEM_PROMPT_BYTES {
        return Err(OneShotError::Configuration(
            "system prompt is empty or too large",
        ));
    }
    if config.prompt.is_empty() || config.prompt.len() > MAX_PROMPT_BYTES {
        return Err(OneShotError::Configuration(
            "job prompt is empty or too large",
        ));
    }
    if config.idle_timeout < Duration::from_secs(5)
        || config.idle_timeout > Duration::from_secs(900)
        || config.max_duration < Duration::from_secs(60)
        || config.max_duration > Duration::from_secs(14_400)
        || config.idle_timeout >= config.max_duration
    {
        return Err(OneShotError::Configuration("task timeouts are invalid"));
    }
    if config.mcp_servers.len() > MAX_MCP_SERVERS {
        return Err(OneShotError::Configuration("too many MCP servers"));
    }
    for server in &config.mcp_servers {
        if server.name.is_empty()
            || server.name.len() > 64
            || !server
                .name
                .chars()
                .all(|value| value.is_ascii_alphanumeric() || matches!(value, '-' | '_'))
        {
            return Err(OneShotError::Configuration("MCP name is invalid"));
        }
        validate_command(&server.command, MCP_ROOT, Some("snowman-agent-"))?;
        validate_args(&server.args)?;
        if server.env.len() > ALLOWED_MCP_ENV_KEYS.len()
            || server.env.iter().any(|(name, value)| {
                !ALLOWED_MCP_ENV_KEYS.contains(&name.as_str())
                    || value.is_empty()
                    || value.len() > 4096
                    || value.chars().any(|character| character == '\0')
            })
        {
            return Err(OneShotError::Configuration("MCP environment is invalid"));
        }
    }
    Ok(())
}

fn validate_command(
    command: &str,
    root: &str,
    required_basename_prefix: Option<&str>,
) -> Result<(), OneShotError> {
    let path = Path::new(command);
    let parent_matches = path
        .parent()
        .is_some_and(|parent| parent == Path::new(root));
    let basename = path.file_name().and_then(|value| value.to_str());
    if !path.is_absolute()
        || !parent_matches
        || basename.is_none()
        || command.len() > 512
        || command.chars().any(char::is_control)
        || required_basename_prefix
            .is_some_and(|prefix| !basename.expect("checked above").starts_with(prefix))
    {
        return Err(OneShotError::Configuration(
            "executable is outside its governed image path",
        ));
    }
    Ok(())
}

fn validate_args(args: &[String]) -> Result<(), OneShotError> {
    if args.len() > MAX_ADAPTER_ARGS
        || args.iter().any(|argument| {
            argument.len() > 1024 || argument.chars().any(|character| character == '\0')
        })
    {
        return Err(OneShotError::Configuration(
            "executable arguments are invalid",
        ));
    }
    Ok(())
}

fn is_codex_command(command: &str) -> bool {
    Path::new(command)
        .file_name()
        .and_then(|value| value.to_str())
        .is_some_and(|name| name.to_ascii_lowercase().contains("codex"))
}

fn advertises_config_value(result: &serde_json::Value, config_id: &str, value: &str) -> bool {
    result["configOptions"].as_array().is_some_and(|options| {
        options.iter().any(|option| {
            option.get("configId").and_then(|item| item.as_str()) == Some(config_id)
                && option["options"].as_array().is_some_and(|values| {
                    values.iter().any(|item| {
                        item.get("value").and_then(|entry| entry.as_str()) == Some(value)
                    })
                })
        })
    })
}

fn stop_reason_label(reason: &StopReason) -> &'static str {
    match reason {
        StopReason::EndTurn => "end_turn",
        StopReason::Cancelled => "cancelled",
        StopReason::MaxTokens => "max_tokens",
        StopReason::MaxTurnRequests => "max_turn_requests",
        StopReason::Refusal => "refusal",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_config() -> OneShotConfig {
        OneShotConfig {
            adapter_command: "/opt/snowman/runtime/bin/snowman-acp".into(),
            adapter_args: vec!["serve".into()],
            model_id: "snowman-research-v1".into(),
            system_prompt: "Follow the governed task contract.".into(),
            prompt: "Prepare the bounded work product.".into(),
            mcp_servers: vec![GovernedMcpServer {
                name: "snowman-tools".into(),
                command: "/usr/local/bin/snowman-agent-tools".into(),
                args: vec![],
                env: vec![
                    ("SNOWMAN_AGENT_JOB_ID".into(), "job-id".into()),
                    ("SNOWMAN_AGENT_JOB_TOKEN".into(), "opaque-token".into()),
                    (
                        "SNOWMAN_AGENT_BROKER_URL".into(),
                        "https://agents.internal.snowmanai.org".into(),
                    ),
                ],
            }],
            idle_timeout: Duration::from_secs(60),
            max_duration: Duration::from_secs(3600),
        }
    }

    #[test]
    fn valid_contract_is_accepted() {
        assert_eq!(validate(&valid_config()), Ok(()));
    }

    #[test]
    fn adapter_command_cannot_escape_immutable_runtime_path() {
        for command in [
            "/bin/sh",
            "/opt/snowman/runtime/bin/../bin/snowman-acp",
            "snowman-acp",
        ] {
            let mut config = valid_config();
            config.adapter_command = command.into();
            assert!(matches!(
                validate(&config),
                Err(OneShotError::Configuration(_))
            ));
        }
    }

    #[test]
    fn mcp_environment_rejects_relay_cloud_and_provider_authority() {
        for forbidden in [
            "BUZZ_PRIVATE_KEY",
            "AWS_SESSION_TOKEN",
            "OPENAI_API_KEY",
            "GOOGLE_APPLICATION_CREDENTIALS",
        ] {
            let mut config = valid_config();
            config.mcp_servers[0].env = vec![(forbidden.into(), "secret".into())];
            assert!(matches!(
                validate(&config),
                Err(OneShotError::Configuration("MCP environment is invalid"))
            ));
        }
    }

    #[test]
    fn adapter_model_and_time_limits_fail_closed() {
        let mut config = valid_config();
        config.model_id = "https://provider.example/model".into();
        assert!(matches!(
            validate(&config),
            Err(OneShotError::Configuration("model ID is invalid"))
        ));

        let mut config = valid_config();
        config.idle_timeout = config.max_duration;
        assert!(matches!(
            validate(&config),
            Err(OneShotError::Configuration("task timeouts are invalid"))
        ));
    }

    #[test]
    fn permission_mode_detection_is_exact() {
        let value = serde_json::json!({
            "configOptions": [{
                "configId": "mode",
                "options": [{"value": "dontAsk"}, {"value": "plan"}]
            }]
        });
        assert!(advertises_config_value(&value, "mode", "dontAsk"));
        assert!(!advertises_config_value(
            &value,
            "mode",
            "bypassPermissions"
        ));
    }
}
