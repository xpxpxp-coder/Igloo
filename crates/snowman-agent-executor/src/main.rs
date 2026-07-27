#![forbid(unsafe_code)]
#![warn(missing_docs)]
//! Credentialless, relay-independent Snowman one-shot agent executor.

use std::{env, path::Path, time::Duration};

use buzz_acp::oneshot::{OneShotConfig, OneShotError, OneShotResult};
use chrono::Utc;
use reqwest::{header, redirect::Policy, Client, Response};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest, Sha256};
#[cfg(test)]
use snowman_agent_contract::{AgentDataPolicy, Classification};
use snowman_agent_contract::{
    BrokerAck, JobSnapshot, ResultReceipt, RuntimeOutcome, StartedReceipt, BROKER_ACK_SCHEMA,
    JOB_RESULT_SCHEMA, JOB_SNAPSHOT_SCHEMA, JOB_STARTED_SCHEMA,
};
use url::Url;
use uuid::Uuid;
use zeroize::Zeroizing;

const MANIFEST_PATH: &str = "/opt/snowman/runtime/manifest.json";
const MAX_MANIFEST_BYTES: u64 = 64 * 1024;
const MAX_SNAPSHOT_BYTES: usize = 768 * 1024;
const MAX_BROKER_RESPONSE_BYTES: usize = 64 * 1024;

#[derive(Debug, thiserror::Error)]
enum Error {
    #[error("agent executor configuration is invalid: {0}")]
    Configuration(&'static str),
    #[error("agent executor runtime manifest is invalid")]
    Manifest,
    #[error("agent broker transport failed")]
    Transport,
    #[error("agent broker rejected the operation with HTTP {0}")]
    BrokerRejected(u16),
    #[error("agent broker response is invalid: {0}")]
    BrokerContract(&'static str),
    #[error("agent runtime failed")]
    Runtime,
}

struct Config {
    broker_url: Url,
    tenant_id: Uuid,
    job_id: Uuid,
    job_token: Zeroizing<String>,
    runtime_id: String,
    model_gateway_url: Url,
    max_task_duration: Duration,
}

impl Config {
    fn from_env() -> Result<Self, Error> {
        let broker_url = parse_snowman_origin(&required("SNOWMAN_AGENT_BROKER_URL")?)?;
        let model_gateway_url = parse_snowman_origin(&required("SNOWMAN_MODEL_GATEWAY_URL")?)?;
        let tenant_id = required("SNOWMAN_AGENT_TENANT_ID")?
            .parse::<Uuid>()
            .map_err(|_| Error::Configuration("tenant ID is invalid"))?;
        let job_id = required("SNOWMAN_AGENT_JOB_ID")?
            .parse::<Uuid>()
            .map_err(|_| Error::Configuration("job ID is invalid"))?;
        let job_token = Zeroizing::new(required("SNOWMAN_AGENT_JOB_TOKEN")?);
        if job_token.len() < 32
            || job_token.len() > 2048
            || !job_token.chars().all(|value| value.is_ascii_graphic())
        {
            return Err(Error::Configuration("job token is invalid"));
        }
        let runtime_id = required("SNOWMAN_AGENT_RUNTIME_ID")?;
        if !valid_identifier(&runtime_id, 64) {
            return Err(Error::Configuration("runtime ID is invalid"));
        }
        let max_task_seconds = required("SNOWMAN_AGENT_MAX_TASK_SECONDS")?
            .parse::<u64>()
            .map_err(|_| Error::Configuration("task duration is invalid"))?;
        if !(60..=14_400).contains(&max_task_seconds) {
            return Err(Error::Configuration("task duration is invalid"));
        }
        if env::var("SNOWMAN_AGENT_NETWORK_POLICY").as_deref() != Ok("private-snowman-only")
            || env::var("SNOWMAN_AGENT_REQUIRE_BROKERED_JOB_TOKEN").as_deref() != Ok("true")
            || env::var("SNOWMAN_AGENT_DISABLE_SELF_UPDATE").as_deref() != Ok("true")
        {
            return Err(Error::Configuration(
                "sandbox enforcement flags are missing",
            ));
        }
        Ok(Self {
            broker_url,
            tenant_id,
            job_id,
            job_token,
            runtime_id,
            model_gateway_url,
            max_task_duration: Duration::from_secs(max_task_seconds),
        })
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuntimeManifest {
    schema_version: String,
    runtime_id: String,
    adapter_command: String,
    #[serde(default)]
    adapter_args: Vec<String>,
    sbom_sha256: String,
    provenance_sha256: String,
    evaluation_evidence_sha256: String,
}

struct BrokerClient {
    origin: Url,
    token: Zeroizing<String>,
    http: Client,
}

impl BrokerClient {
    fn new(origin: Url, token: Zeroizing<String>, timeout: Duration) -> Result<Self, Error> {
        let http = Client::builder()
            .no_proxy()
            .redirect(Policy::none())
            .connect_timeout(Duration::from_secs(5))
            .timeout(timeout)
            .user_agent("snowman-agent-executor/1")
            .build()
            .map_err(|_| Error::Transport)?;
        Ok(Self {
            origin,
            token,
            http,
        })
    }

    async fn snapshot(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
    ) -> Result<(JobSnapshot, String), Error> {
        let url = self.endpoint(&format!("v1/tenants/{tenant_id}/jobs/{job_id}/snapshot"))?;
        let response = self
            .http
            .get(url)
            .bearer_auth(self.token.as_str())
            .header(header::ACCEPT, "application/json")
            .send()
            .await
            .map_err(|_| Error::Transport)?;
        ensure_success(&response)?;
        let expected_digest = response
            .headers()
            .get("x-snowman-content-sha256")
            .and_then(|value| value.to_str().ok())
            .filter(|value| valid_sha256(value))
            .ok_or(Error::BrokerContract("snapshot digest is missing"))?
            .to_owned();
        let bytes = read_bounded(response, MAX_SNAPSHOT_BYTES).await?;
        let actual_digest = hex::encode(Sha256::digest(&bytes));
        if actual_digest != expected_digest {
            return Err(Error::BrokerContract("snapshot digest does not match"));
        }
        let snapshot = serde_json::from_slice(&bytes)
            .map_err(|_| Error::BrokerContract("snapshot schema is invalid"))?;
        Ok((snapshot, expected_digest))
    }

    async fn post<T: Serialize>(
        &self,
        tenant_id: Uuid,
        job_id: Uuid,
        generation: u32,
        operation: &str,
        body: &T,
    ) -> Result<(), Error> {
        let url = self.endpoint(&format!("v1/tenants/{tenant_id}/jobs/{job_id}/{operation}"))?;
        let response = self
            .http
            .post(url)
            .bearer_auth(self.token.as_str())
            .header(header::CONTENT_TYPE, "application/json")
            .header(
                "idempotency-key",
                format!("{job_id}:{generation}:{operation}"),
            )
            .json(body)
            .send()
            .await
            .map_err(|_| Error::Transport)?;
        ensure_success(&response)?;
        let ack: BrokerAck = decode_bounded(response, MAX_BROKER_RESPONSE_BYTES).await?;
        if ack.schema_version != BROKER_ACK_SCHEMA || !ack.accepted {
            return Err(Error::BrokerContract("broker acknowledgement is invalid"));
        }
        Ok(())
    }

    fn endpoint(&self, path: &str) -> Result<Url, Error> {
        self.origin
            .join(path)
            .map_err(|_| Error::Configuration("broker endpoint could not be constructed"))
    }
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        // This production-only binary intentionally ignores ambient RUST_LOG.
        // ACP wire/debug records can contain prompt, response, and tool data.
        .with_env_filter("snowman_agent_executor=info,buzz_acp=info,acp::wire=off")
        .json()
        .init();

    if let Err(error) = execute().await {
        tracing::error!(%error, "one-shot agent job failed");
        std::process::exit(1);
    }
}

async fn execute() -> Result<(), Error> {
    let config = Config::from_env()?;
    let manifest = load_manifest(MANIFEST_PATH)?;
    validate_manifest(&manifest, &config.runtime_id)?;
    let broker = BrokerClient::new(
        config.broker_url.clone(),
        config.job_token.clone(),
        config.max_task_duration,
    )?;
    let (snapshot, snapshot_sha256) = broker.snapshot(config.tenant_id, config.job_id).await?;
    validate_snapshot(&snapshot, &config)?;

    broker
        .post(
            config.tenant_id,
            config.job_id,
            snapshot.generation,
            "started",
            &StartedReceipt {
                schema_version: JOB_STARTED_SCHEMA.into(),
                job_id: config.job_id,
                generation: snapshot.generation,
                snapshot_sha256: snapshot_sha256.clone(),
                runtime_id: snapshot.runtime_id.clone(),
                model_id: snapshot.model_id.clone(),
                started_at: Utc::now(),
            },
        )
        .await?;

    let remaining = (snapshot.deadline_at - Utc::now())
        .to_std()
        .map_err(|_| Error::BrokerContract("job deadline has expired"))?;
    let max_duration = remaining.min(config.max_task_duration);
    let idle_timeout = Duration::from_secs(60).min(max_duration / 2);
    let runtime_result = buzz_acp::oneshot::run(OneShotConfig {
        adapter_command: manifest.adapter_command,
        adapter_args: manifest.adapter_args,
        model_id: snapshot.model_id.clone(),
        system_prompt: snapshot.system_prompt,
        prompt: snapshot.prompt,
        mcp_servers: vec![],
        idle_timeout,
        max_duration,
    })
    .await;

    let outcome = match runtime_result.as_ref() {
        Ok(result) => successful_outcome(result),
        Err(error) => RuntimeOutcome::Failed {
            failure_code: runtime_failure_code(error).into(),
        },
    };
    let outcome_failed = matches!(&outcome, RuntimeOutcome::Failed { .. });

    broker
        .post(
            config.tenant_id,
            config.job_id,
            snapshot.generation,
            "result",
            &ResultReceipt {
                schema_version: JOB_RESULT_SCHEMA.into(),
                job_id: config.job_id,
                generation: snapshot.generation,
                snapshot_sha256: snapshot_sha256.clone(),
                runtime_id: snapshot.runtime_id.clone(),
                model_id: snapshot.model_id.clone(),
                completed_at: Utc::now(),
                outcome,
            },
        )
        .await?;
    if runtime_result.is_err() || outcome_failed {
        return Err(Error::Runtime);
    }
    tracing::info!(job_id=%config.job_id, generation=snapshot.generation, "one-shot agent job completed");
    Ok(())
}

fn successful_outcome(result: &OneShotResult) -> RuntimeOutcome {
    if result.stop_reason == "cancelled" {
        return RuntimeOutcome::Failed {
            failure_code: "runtime_cancelled".into(),
        };
    }
    if result.stop_reason == "refusal" {
        return RuntimeOutcome::Failed {
            failure_code: "runtime_refusal".into(),
        };
    }
    if result.output.trim().is_empty() {
        return RuntimeOutcome::Failed {
            failure_code: "runtime_empty_output".into(),
        };
    }
    RuntimeOutcome::Succeeded {
        stop_reason: result.stop_reason.clone(),
        output: result.output.clone(),
        output_truncated: result.output_truncated,
        input_tokens: result.input_tokens,
        output_tokens: result.output_tokens,
    }
}

fn runtime_failure_code(error: &OneShotError) -> &'static str {
    match error {
        OneShotError::Configuration(_) => "runtime_configuration",
        OneShotError::Adapter(stage) => match *stage {
            "spawn" => "adapter_spawn",
            "initialize" => "adapter_initialize",
            "session" => "adapter_session",
            "model selection" => "adapter_model_selection",
            "permission policy" => "adapter_permission_policy",
            "prompt" => "adapter_prompt",
            _ => "adapter_failure",
        },
        OneShotError::UnsupportedModel => "unsupported_model",
    }
}

fn load_manifest(path: &str) -> Result<RuntimeManifest, Error> {
    let metadata = std::fs::metadata(path).map_err(|_| Error::Manifest)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_MANIFEST_BYTES {
        return Err(Error::Manifest);
    }
    let bytes = std::fs::read(path).map_err(|_| Error::Manifest)?;
    serde_json::from_slice(&bytes).map_err(|_| Error::Manifest)
}

fn validate_manifest(manifest: &RuntimeManifest, runtime_id: &str) -> Result<(), Error> {
    if manifest.schema_version != "snowman.agent.runtime.v1"
        || manifest.runtime_id != runtime_id
        || !valid_sha256(&manifest.sbom_sha256)
        || !valid_sha256(&manifest.provenance_sha256)
        || !valid_sha256(&manifest.evaluation_evidence_sha256)
        || Path::new(&manifest.adapter_command).parent()
            != Some(Path::new("/opt/snowman/runtime/bin"))
        || manifest.adapter_args.len() > 32
        || manifest
            .adapter_args
            .iter()
            .any(|argument| argument.len() > 1024 || argument.contains('\0'))
    {
        return Err(Error::Manifest);
    }
    Ok(())
}

fn validate_snapshot(snapshot: &JobSnapshot, config: &Config) -> Result<(), Error> {
    let now = Utc::now();
    if snapshot.schema_version != JOB_SNAPSHOT_SCHEMA
        || snapshot.job_id != config.job_id
        || snapshot.tenant_id != config.tenant_id.to_string()
        || snapshot.generation == 0
        || snapshot.runtime_id != config.runtime_id
        || !valid_scope(&snapshot.tenant_id)
        || !valid_identifier(&snapshot.model_id, 256)
        || snapshot.model_id.contains("://")
        || !valid_identifier(&snapshot.specialist_role, 64)
        || !snapshot.data_policy.pii_prohibited
        || !valid_sha256(&snapshot.data_policy.minimization_evidence_sha256)
        || snapshot.system_prompt.is_empty()
        || snapshot.system_prompt.len() > 64 * 1024
        || snapshot.prompt.is_empty()
        || snapshot.prompt.len() > 512 * 1024
        || snapshot.capability_grants.len() > 64
        || snapshot
            .capability_grants
            .iter()
            .any(|capability| !valid_capability(capability))
        || snapshot.max_input_tokens == 0
        || snapshot.max_input_tokens > 10_000_000
        || snapshot.max_output_tokens == 0
        || snapshot.max_output_tokens > 1_000_000
        || snapshot.max_cost_microusd > 1_000_000_000
        || snapshot.deadline_at <= now + chrono::Duration::seconds(30)
        || snapshot.deadline_at
            > now
                + chrono::Duration::from_std(config.max_task_duration)
                    .map_err(|_| Error::BrokerContract("task duration is invalid"))?
    {
        return Err(Error::BrokerContract("job snapshot is outside policy"));
    }
    let _ = (
        snapshot.workspace_id,
        snapshot.request_id,
        snapshot.task_id,
        &snapshot.classification,
        &config.model_gateway_url,
    );
    Ok(())
}

fn parse_snowman_origin(raw: &str) -> Result<Url, Error> {
    let url = Url::parse(raw).map_err(|_| Error::Configuration("Snowman URL is invalid"))?;
    let host = url
        .host_str()
        .ok_or(Error::Configuration("Snowman URL host is missing"))?;
    if url.scheme() != "https"
        || !(host == "snowmanai.org" || host.ends_with(".snowmanai.org"))
        || url.port().is_some_and(|port| port != 443)
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.path() != "/"
    {
        return Err(Error::Configuration(
            "URL is outside the Snowman private HTTPS boundary",
        ));
    }
    Ok(url)
}

fn required(name: &'static str) -> Result<String, Error> {
    env::var(name)
        .ok()
        .filter(|value| !value.is_empty())
        .ok_or(Error::Configuration(name))
}

fn valid_identifier(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.' | ':' | '/')
        })
}

fn valid_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 120
        && value.chars().all(|character| {
            character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.')
        })
}

fn valid_capability(value: &str) -> bool {
    value.len() >= 3
        && value.len() <= 120
        && value.split('.').count() >= 2
        && value
            .split('.')
            .all(|segment| valid_identifier(segment, 40) && !segment.contains('/'))
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn ensure_success(response: &Response) -> Result<(), Error> {
    if response.status().is_success() {
        Ok(())
    } else {
        Err(Error::BrokerRejected(response.status().as_u16()))
    }
}

async fn decode_bounded<T: DeserializeOwned>(response: Response, limit: usize) -> Result<T, Error> {
    let bytes = read_bounded(response, limit).await?;
    let value: T = serde_json::from_slice(&bytes)
        .map_err(|_| Error::BrokerContract("response schema is invalid"))?;
    Ok(value)
}

async fn read_bounded(mut response: Response, limit: usize) -> Result<Vec<u8>, Error> {
    if response
        .content_length()
        .is_some_and(|length| length > limit as u64)
    {
        return Err(Error::BrokerContract("response is too large"));
    }
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await.map_err(|_| Error::Transport)? {
        if bytes.len().saturating_add(chunk.len()) > limit {
            return Err(Error::BrokerContract("response is too large"));
        }
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config() -> Config {
        Config {
            broker_url: Url::parse("https://agents.internal.snowmanai.org/").unwrap(),
            tenant_id: Uuid::parse_str("20000000-0000-4000-8000-000000000001").unwrap(),
            job_id: Uuid::parse_str("10000000-0000-4000-8000-000000000001").unwrap(),
            job_token: Zeroizing::new("a".repeat(64)),
            runtime_id: "snowman-acp".into(),
            model_gateway_url: Url::parse("https://models.internal.snowmanai.org/").unwrap(),
            max_task_duration: Duration::from_secs(3600),
        }
    }

    fn snapshot() -> JobSnapshot {
        let config = config();
        JobSnapshot {
            schema_version: JOB_SNAPSHOT_SCHEMA.into(),
            job_id: config.job_id,
            tenant_id: config.tenant_id.to_string(),
            workspace_id: config.tenant_id,
            request_id: Uuid::new_v4(),
            task_id: Uuid::new_v4(),
            generation: 1,
            runtime_id: config.runtime_id,
            model_id: "snowman-research-v1".into(),
            specialist_role: "research_evidence".into(),
            classification: Classification::Confidential,
            data_policy: AgentDataPolicy {
                pii_prohibited: true,
                minimization_evidence_sha256: "ab".repeat(32),
            },
            system_prompt: "Follow the governed Snowman policy.".into(),
            prompt: "Prepare the bounded work product.".into(),
            capability_grants: vec!["artifact.draft".into()],
            max_input_tokens: 100_000,
            max_output_tokens: 20_000,
            max_cost_microusd: 50_000,
            deadline_at: Utc::now() + chrono::Duration::minutes(30),
        }
    }

    #[test]
    fn snowman_origins_are_exact_and_pathless() {
        for allowed in [
            "https://snowmanai.org/",
            "https://agents.internal.snowmanai.org/",
            "https://models.snowmanai.org:443/",
        ] {
            assert!(parse_snowman_origin(allowed).is_ok(), "{allowed}");
        }
        for denied in [
            "https://snowmanai.org.attacker.test/",
            "https://api.openai.com/",
            "http://agents.internal.snowmanai.org/",
            "https://agents.internal.snowmanai.org/path",
            "https://user@agents.internal.snowmanai.org/",
        ] {
            assert!(parse_snowman_origin(denied).is_err(), "{denied}");
        }
    }

    #[test]
    fn snapshot_rejects_cross_job_runtime_provider_and_ambient_capability() {
        let config = config();

        let mut value = snapshot();
        value.job_id = Uuid::new_v4();
        assert!(validate_snapshot(&value, &config).is_err());

        let mut value = snapshot();
        value.runtime_id = "hermes-acp".into();
        assert!(validate_snapshot(&value, &config).is_err());

        let mut value = snapshot();
        value.model_id = "https://api.openai.com/model".into();
        assert!(validate_snapshot(&value, &config).is_err());

        let mut value = snapshot();
        value.data_policy.pii_prohibited = false;
        assert!(validate_snapshot(&value, &config).is_err());

        let mut value = snapshot();
        value.capability_grants = vec!["admin".into()];
        assert!(validate_snapshot(&value, &config).is_err());
    }

    #[test]
    fn snapshot_requires_a_bounded_future_deadline() {
        let config = config();
        let mut value = snapshot();
        value.deadline_at = Utc::now() + chrono::Duration::hours(2);
        assert!(validate_snapshot(&value, &config).is_err());

        let mut value = snapshot();
        value.deadline_at = Utc::now() + chrono::Duration::seconds(5);
        assert!(validate_snapshot(&value, &config).is_err());
    }

    #[test]
    fn manifest_requires_exact_runtime_and_evidence_digests() {
        let mut manifest = RuntimeManifest {
            schema_version: "snowman.agent.runtime.v1".into(),
            runtime_id: "snowman-acp".into(),
            adapter_command: "/opt/snowman/runtime/bin/snowman-acp".into(),
            adapter_args: vec![],
            sbom_sha256: "a".repeat(64),
            provenance_sha256: "b".repeat(64),
            evaluation_evidence_sha256: "c".repeat(64),
        };
        assert!(validate_manifest(&manifest, "snowman-acp").is_ok());
        manifest.adapter_command = "/opt/snowman/runtime/bin/../escaped".into();
        assert!(validate_manifest(&manifest, "snowman-acp").is_err());
        manifest.adapter_command = "/opt/snowman/runtime/bin/snowman-acp".into();
        manifest.runtime_id = "other".into();
        assert!(validate_manifest(&manifest, "snowman-acp").is_err());
    }

    #[test]
    fn runtime_failures_have_bounded_receipt_codes() {
        assert_eq!(
            runtime_failure_code(&OneShotError::UnsupportedModel),
            "unsupported_model"
        );
        assert_eq!(
            runtime_failure_code(&OneShotError::Adapter("prompt")),
            "adapter_prompt"
        );
        assert_eq!(
            runtime_failure_code(&OneShotError::Configuration("secret detail")),
            "runtime_configuration"
        );
        let refused = successful_outcome(&OneShotResult {
            stop_reason: "refusal".into(),
            output: "cannot comply".into(),
            output_truncated: false,
            input_tokens: None,
            output_tokens: None,
        });
        assert!(matches!(
            refused,
            RuntimeOutcome::Failed { failure_code } if failure_code == "runtime_refusal"
        ));
        let empty = successful_outcome(&OneShotResult {
            stop_reason: "end_turn".into(),
            output: "   ".into(),
            output_truncated: false,
            input_tokens: None,
            output_tokens: None,
        });
        assert!(matches!(
            empty,
            RuntimeOutcome::Failed { failure_code } if failure_code == "runtime_empty_output"
        ));
    }
}
