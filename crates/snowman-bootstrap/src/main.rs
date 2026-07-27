#![deny(unsafe_code)]

use std::collections::{BTreeMap, BTreeSet};

use anyhow::{bail, Context};
use aws_sdk_secretsmanager::Client;
use chrono::{DateTime, Utc};
use nostr::Keys;
use percent_encoding::percent_decode_str;
use rand::random;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

const WORKFORCE_MANIFEST_SCHEMA: &str = "snowman.workforce.bootstrap.v1";
const MAX_WORKFORCE_IDENTITIES: usize = 64;
const MAX_MODEL_ROUTES: usize = 64;

#[derive(Deserialize)]
struct RdsMasterSecret {
    username: String,
    password: String,
    host: String,
    port: u16,
    #[serde(default)]
    dbname: Option<String>,
}

impl Drop for RdsMasterSecret {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RelayRuntimeSecret {
    #[serde(rename = "DATABASE_URL")]
    database_url: String,
    #[serde(rename = "BUZZ_RELAY_PRIVATE_KEY")]
    relay_private_key: String,
    #[serde(rename = "BUZZ_GIT_HOOK_HMAC_SECRET")]
    git_hook_hmac_secret: String,
    #[serde(rename = "RELAY_OWNER_PUBKEY")]
    relay_owner_pubkey: String,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct DatabaseRuntimeSecret {
    #[serde(rename = "DATABASE_URL")]
    database_url: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct WorkforceBootstrapManifest {
    schema_version: String,
    community_id: Uuid,
    community_host: String,
    identities: Vec<ServiceIdentityManifest>,
    model_routes: Vec<ModelRouteManifest>,
    team: TeamManifest,
    identity_authority: IdentityAuthorityManifest,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct IdentityAuthorityManifest {
    broker_id: String,
    provider: String,
    hosted_domain: String,
    tenant_id: String,
    client_id: String,
    project_id: String,
    signing_kms_key_arn: String,
    max_session_seconds: i32,
    assurance_level: String,
    assurance_evidence_sha256: String,
    assurance_evaluated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ServiceIdentityManifest {
    identity_id: Uuid,
    display_name: String,
    specialist_role: String,
    capabilities: BTreeSet<String>,
    secret_arn: String,
    secret_kind: ServiceSecretKind,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum ServiceSecretKind {
    Worker,
    Scheduler,
    Trigger,
    Reminder,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ModelRouteManifest {
    model_id: String,
    gateway_url: String,
    suited_roles: BTreeSet<String>,
    allowed_classifications: BTreeSet<String>,
    quality_score: i32,
    latency_score: i32,
    max_cost_microusd_per_million_tokens: i64,
    max_context_tokens: i64,
    evaluation_evidence_sha256: String,
    evaluated_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TeamManifest {
    lead: Uuid,
    governed_analyst: Uuid,
    client_delivery: Uuid,
    quality_risk_reviewer: Uuid,
    #[serde(default)]
    model_overrides: TeamModelOverrides,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct TeamModelOverrides {
    governed_analyst: Option<String>,
    client_delivery: Option<String>,
    quality_risk_reviewer: Option<String>,
}

struct PreparedServiceIdentity {
    manifest: ServiceIdentityManifest,
    public_key: [u8; 32],
}

impl Drop for RelayRuntimeSecret {
    fn drop(&mut self) {
        self.database_url.zeroize();
        self.relay_private_key.zeroize();
        self.git_hook_hmac_secret.zeroize();
    }
}

impl Drop for DatabaseRuntimeSecret {
    fn drop(&mut self) {
        self.database_url.zeroize();
    }
}

fn required_env(name: &str) -> anyhow::Result<String> {
    let value = std::env::var(name).with_context(|| format!("{name} is required"))?;
    if value.trim().is_empty() {
        bail!("{name} must not be empty");
    }
    Ok(value)
}

fn validate_owner_pubkey(value: &str) -> anyhow::Result<()> {
    nostr::PublicKey::from_hex(value)
        .context("SNOWMAN_RELAY_OWNER_PUBKEY must be a valid 32-byte Nostr public key")?;
    Ok(())
}

fn validate_runtime_key_material(secret: &RelayRuntimeSecret) -> anyhow::Result<()> {
    Keys::parse(&secret.relay_private_key).context("existing BUZZ_RELAY_PRIVATE_KEY is invalid")?;
    let hmac = hex::decode(&secret.git_hook_hmac_secret)
        .context("existing BUZZ_GIT_HOOK_HMAC_SECRET is not hexadecimal")?;
    if hmac.len() != 32 {
        bail!("existing BUZZ_GIT_HOOK_HMAC_SECRET must be exactly 32 bytes");
    }
    validate_owner_pubkey(&secret.relay_owner_pubkey)?;
    Ok(())
}

fn exact_capabilities(role: &str) -> Option<BTreeSet<String>> {
    let values: &[&str] = match role {
        "lead" => &["workforce.plan", "workforce.tasks.execute"],
        "governed_analyst" => &[
            "analytics.query",
            "workforce.context.write",
            "workforce.tasks.execute",
        ],
        "client_delivery" => &[
            "artifact.build",
            "workforce.context.read",
            "workforce.context.write",
            "workforce.tasks.execute",
        ],
        "quality_risk_reviewer" => &[
            "artifact.build",
            "artifact.review",
            "workforce.context.read",
            "workforce.context.write",
            "workforce.tasks.execute",
        ],
        "research_evidence" => &[
            "evidence.manifest.read",
            "workforce.context.write",
            "workforce.tasks.execute",
        ],
        "scheduler" => &["workforce.maintenance"],
        "trigger" => &["workforce.proactive.propose", "workforce.schedules.trigger"],
        "deadline_operations" => &["deadline.remind", "workforce.tasks.execute"],
        _ => return None,
    };
    Some(values.iter().map(|value| (*value).to_string()).collect())
}

fn expected_secret_kind(role: &str) -> ServiceSecretKind {
    match role {
        "scheduler" => ServiceSecretKind::Scheduler,
        "trigger" => ServiceSecretKind::Trigger,
        "deadline_operations" => ServiceSecretKind::Reminder,
        _ => ServiceSecretKind::Worker,
    }
}

fn validate_snowman_gateway(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
        return false;
    };
    let host = url.host_str().unwrap_or("");
    value == value.to_ascii_lowercase()
        && url.scheme() == "https"
        && (host == "snowmanai.org" || host.ends_with(".snowmanai.org"))
        && url.port_or_known_default() == Some(443)
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
}

fn valid_model_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && !value.contains("://")
        && !value.chars().any(char::is_control)
}

fn decode_sha256(value: &str, field: &str) -> anyhow::Result<[u8; 32]> {
    let decoded = hex::decode(value).with_context(|| format!("{field} must be hexadecimal"))?;
    decoded
        .try_into()
        .map_err(|_| anyhow::anyhow!("{field} must be exactly 32 bytes"))
}

fn parse_workforce_manifest(raw: &str) -> anyhow::Result<WorkforceBootstrapManifest> {
    let mut manifest: WorkforceBootstrapManifest =
        serde_json::from_str(raw).context("invalid workforce bootstrap manifest schema")?;
    manifest
        .identities
        .sort_by_key(|identity| identity.identity_id);
    manifest
        .model_routes
        .sort_by(|left, right| left.model_id.cmp(&right.model_id));
    validate_workforce_manifest(&manifest)?;
    Ok(manifest)
}

fn validate_workforce_manifest(manifest: &WorkforceBootstrapManifest) -> anyhow::Result<()> {
    if manifest.schema_version != WORKFORCE_MANIFEST_SCHEMA
        || manifest.community_id.is_nil()
        || !valid_snowman_host(&manifest.community_host)
    {
        bail!("workforce manifest schema or community identity is invalid");
    }
    let authority = &manifest.identity_authority;
    if !valid_identifier(&authority.broker_id)
        || authority.provider != "google_workspace"
        || !valid_snowman_host(&authority.hosted_domain)
        || !valid_scope(&authority.tenant_id)
        || !valid_scope(&authority.client_id)
        || !valid_scope(&authority.project_id)
        || authority.tenant_id != authority.client_id
        || !valid_kms_key_arn(&authority.signing_kms_key_arn)
        || !(60..=3600).contains(&authority.max_session_seconds)
        || !matches!(
            authority.assurance_level.as_str(),
            "mfa" | "phishing_resistant"
        )
        || decode_sha256(
            &authority.assurance_evidence_sha256,
            "assurance_evidence_sha256",
        )
        .is_err()
        || authority.assurance_evaluated_at > Utc::now() + chrono::Duration::minutes(5)
        || Utc::now() - authority.assurance_evaluated_at > chrono::Duration::days(120)
    {
        bail!("workforce identity authority violates the governed Google/KMS boundary");
    }
    if manifest.identities.is_empty() || manifest.identities.len() > MAX_WORKFORCE_IDENTITIES {
        bail!("workforce manifest must contain between 1 and 64 service identities");
    }
    if manifest.model_routes.is_empty() || manifest.model_routes.len() > MAX_MODEL_ROUTES {
        bail!("workforce manifest must contain between 1 and 64 evaluated model routes");
    }

    let mut ids = BTreeSet::new();
    let mut secret_arns = BTreeSet::new();
    let mut roles = BTreeMap::new();
    for identity in &manifest.identities {
        let Some(required) = exact_capabilities(&identity.specialist_role) else {
            bail!("workforce identity has an unsupported specialist role");
        };
        if identity.identity_id.is_nil()
            || identity.display_name.trim().is_empty()
            || identity.display_name.len() > 256
            || identity.display_name.chars().any(char::is_control)
            || identity.capabilities != required
            || identity.secret_kind != expected_secret_kind(&identity.specialist_role)
            || !identity.secret_arn.starts_with("arn:")
            || !identity.secret_arn.contains(":secretsmanager:")
            || identity.secret_arn.len() > 2048
            || !ids.insert(identity.identity_id)
            || !secret_arns.insert(identity.secret_arn.as_str())
        {
            bail!("workforce identity violates its exact role, capability, or secret boundary");
        }
        roles
            .entry(identity.specialist_role.as_str())
            .or_insert_with(Vec::new)
            .push(identity.identity_id);
    }

    let expected_team = [
        ("lead", manifest.team.lead),
        ("governed_analyst", manifest.team.governed_analyst),
        ("client_delivery", manifest.team.client_delivery),
        ("quality_risk_reviewer", manifest.team.quality_risk_reviewer),
    ];
    let mut team_ids = BTreeSet::new();
    for (role, identity_id) in expected_team {
        if identity_id.is_nil()
            || !team_ids.insert(identity_id)
            || roles
                .get(role)
                .is_none_or(|values| values.as_slice() != [identity_id])
        {
            bail!("workforce team must bind one distinct identity to every required role");
        }
    }

    let allowed_roles: BTreeSet<&str> = [
        "lead",
        "client_delivery",
        "research_evidence",
        "governed_analyst",
        "quality_risk_reviewer",
        "deadline_operations",
    ]
    .into_iter()
    .collect();
    let allowed_classifications: BTreeSet<&str> = ["internal", "confidential", "restricted"]
        .into_iter()
        .collect();
    let mut model_ids = BTreeSet::new();
    for route in &manifest.model_routes {
        if !valid_model_id(&route.model_id)
            || !model_ids.insert(route.model_id.as_str())
            || !validate_snowman_gateway(&route.gateway_url)
            || route.suited_roles.is_empty()
            || route.suited_roles.len() > 16
            || !route
                .suited_roles
                .iter()
                .all(|role| allowed_roles.contains(role.as_str()))
            || route.allowed_classifications.is_empty()
            || route.allowed_classifications.len() > 3
            || !route
                .allowed_classifications
                .iter()
                .all(|value| allowed_classifications.contains(value.as_str()))
            || !(0..=1000).contains(&route.quality_score)
            || !(0..=1000).contains(&route.latency_score)
            || route.max_cost_microusd_per_million_tokens < 0
            || !(1..=10_000_000).contains(&route.max_context_tokens)
            || decode_sha256(
                &route.evaluation_evidence_sha256,
                "evaluation_evidence_sha256",
            )
            .is_err()
            || route.evaluated_at > Utc::now() + chrono::Duration::minutes(5)
        {
            bail!("workforce model route violates the governed catalog boundary");
        }
    }
    for (role, override_id) in [
        (
            "governed_analyst",
            manifest.team.model_overrides.governed_analyst.as_deref(),
        ),
        (
            "client_delivery",
            manifest.team.model_overrides.client_delivery.as_deref(),
        ),
        (
            "quality_risk_reviewer",
            manifest
                .team
                .model_overrides
                .quality_risk_reviewer
                .as_deref(),
        ),
    ] {
        if let Some(model_id) = override_id {
            let matched = manifest
                .model_routes
                .iter()
                .any(|route| route.model_id == model_id && route.suited_roles.contains(role));
            if !matched {
                bail!("team model override is not an evaluated route for its specialist role");
            }
        }
    }
    Ok(())
}

fn valid_snowman_host(value: &str) -> bool {
    value == value.to_ascii_lowercase()
        && value.len() <= 253
        && !value
            .chars()
            .any(|character| matches!(character, '/' | ':' | '@'))
        && (value == "snowmanai.org" || value.ends_with(".snowmanai.org"))
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label.chars().all(|character| {
                    character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-'
                })
        })
}

fn valid_identifier(value: &str) -> bool {
    (3..=200).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'/' | b'-'))
        })
}

fn valid_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 120
        && value.is_ascii()
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b':' | b'-'))
}

fn valid_kms_key_arn(value: &str) -> bool {
    let parts: Vec<&str> = value.split(':').collect();
    parts.len() == 6
        && parts[0] == "arn"
        && parts[1].starts_with("aws")
        && parts[2] == "kms"
        && !parts[3].is_empty()
        && parts[4].len() == 12
        && parts[4].bytes().all(|byte| byte.is_ascii_digit())
        && parts[5].starts_with("key/")
        && parts[5].len() == 40
}

fn random_hex() -> String {
    hex::encode(random::<[u8; 32]>())
}

fn database_url(
    master: &RdsMasterSecret,
    database: &str,
    username: &str,
    password: &str,
) -> anyhow::Result<Zeroizing<String>> {
    let mut url = url::Url::parse("postgresql://localhost")?;
    url.set_host(Some(&master.host))?;
    url.set_port(Some(master.port))
        .map_err(|_| anyhow::anyhow!("invalid PostgreSQL port"))?;
    url.set_username(username)
        .map_err(|_| anyhow::anyhow!("invalid PostgreSQL username"))?;
    url.set_password(Some(password))
        .map_err(|_| anyhow::anyhow!("invalid PostgreSQL password"))?;
    url.set_path(database);
    url.query_pairs_mut().append_pair("sslmode", "require");
    Ok(Zeroizing::new(url.into()))
}

fn decoded_url_password(url: &url::Url) -> anyhow::Result<String> {
    let encoded = url
        .password()
        .context("runtime DATABASE_URL has no password")?;
    Ok(percent_decode_str(encoded)
        .decode_utf8()
        .context("runtime DATABASE_URL password is not UTF-8")?
        .into_owned())
}

async fn get_secret(client: &Client, arn: &str) -> anyhow::Result<Zeroizing<String>> {
    let output = client
        .get_secret_value()
        .secret_id(arn)
        .send()
        .await
        .with_context(|| format!("could not retrieve governed secret {arn}"))?;
    let value = output
        .secret_string()
        .context("governed secret must contain a UTF-8 secret string")?;
    Ok(Zeroizing::new(value.to_owned()))
}

async fn existing_runtime_secret(
    client: &Client,
    arn: &str,
) -> anyhow::Result<Option<RelayRuntimeSecret>> {
    match client.get_secret_value().secret_id(arn).send().await {
        Ok(output) => {
            let Some(value) = output.secret_string() else {
                bail!("relay runtime secret must contain a UTF-8 secret string");
            };
            let secret: RelayRuntimeSecret = serde_json::from_str(value)
                .context("relay runtime secret exists but does not match the governed schema")?;
            validate_runtime_key_material(&secret)?;
            Ok(Some(secret))
        }
        Err(error)
            if error
                .as_service_error()
                .is_some_and(|error| error.is_resource_not_found_exception()) =>
        {
            Ok(None)
        }
        Err(error) => Err(error).context("could not inspect relay runtime secret"),
    }
}

async fn existing_database_runtime_secret(
    client: &Client,
    arn: &str,
) -> anyhow::Result<Option<DatabaseRuntimeSecret>> {
    match client.get_secret_value().secret_id(arn).send().await {
        Ok(output) => {
            let value = output
                .secret_string()
                .context("database runtime secret must contain UTF-8 JSON")?;
            let secret = serde_json::from_str(value)
                .context("database runtime secret does not match the governed schema")?;
            Ok(Some(secret))
        }
        Err(error)
            if error
                .as_service_error()
                .is_some_and(|error| error.is_resource_not_found_exception()) =>
        {
            Ok(None)
        }
        Err(error) => Err(error).context("could not inspect database runtime secret"),
    }
}

fn service_secret_field(kind: ServiceSecretKind) -> &'static str {
    match kind {
        ServiceSecretKind::Worker => "SNOWMAN_WORKFORCE_NOSTR_PRIVATE_KEY",
        ServiceSecretKind::Scheduler => "SNOWMAN_WORKFORCE_SCHEDULER_NOSTR_PRIVATE_KEY",
        ServiceSecretKind::Trigger => "SNOWMAN_WORKFORCE_TRIGGER_NOSTR_PRIVATE_KEY",
        ServiceSecretKind::Reminder => "SNOWMAN_WORKFORCE_REMINDER_NOSTR_PRIVATE_KEY",
    }
}

fn team_runtime_json(team: &TeamManifest) -> anyhow::Result<String> {
    serde_json::to_string(&json!({
        "governed_analyst": team.governed_analyst,
        "client_delivery": team.client_delivery,
        "quality_risk_reviewer": team.quality_risk_reviewer,
        "model_overrides": team.model_overrides,
    }))
    .context("could not encode workforce team runtime contract")
}

async fn existing_service_secret(
    client: &Client,
    arn: &str,
) -> anyhow::Result<Option<Zeroizing<String>>> {
    match client.get_secret_value().secret_id(arn).send().await {
        Ok(output) => Ok(Some(Zeroizing::new(
            output
                .secret_string()
                .context("workforce identity secret must contain UTF-8 JSON")?
                .to_owned(),
        ))),
        Err(error)
            if error
                .as_service_error()
                .is_some_and(|error| error.is_resource_not_found_exception()) =>
        {
            Ok(None)
        }
        Err(error) => Err(error).context("could not inspect workforce identity secret"),
    }
}

async fn prepare_service_identities(
    client: &Client,
    manifest: &WorkforceBootstrapManifest,
) -> anyhow::Result<Vec<PreparedServiceIdentity>> {
    let team_json = team_runtime_json(&manifest.team)?;
    let mut prepared = Vec::with_capacity(manifest.identities.len());
    for identity in &manifest.identities {
        let field = service_secret_field(identity.secret_kind);
        let existing = existing_service_secret(client, &identity.secret_arn).await?;
        let mut existing_value = existing
            .as_ref()
            .map(|value| serde_json::from_str::<BTreeMap<String, String>>(value.as_str()))
            .transpose()
            .context("workforce identity secret contains invalid JSON")?;
        let private_key = if let Some(document) = &mut existing_value {
            let allowed: BTreeSet<&str> = if identity.secret_kind == ServiceSecretKind::Worker {
                [field, "SNOWMAN_WORKFORCE_TEAM_IDENTITIES_JSON"]
                    .into_iter()
                    .collect()
            } else {
                [field].into_iter().collect()
            };
            if document.keys().any(|key| !allowed.contains(key.as_str())) {
                bail!("workforce identity secret has an unrecognized field");
            }
            let key = document
                .remove(field)
                .context("workforce identity secret has no private key")?;
            for value in document.values_mut() {
                value.zeroize();
            }
            Zeroizing::new(key)
        } else {
            Zeroizing::new(Keys::generate().secret_key().display_secret().to_string())
        };
        let keys =
            Keys::parse(&private_key).context("workforce identity private key is invalid")?;
        let mut document = BTreeMap::new();
        document.insert(field, private_key.as_str());
        if identity.secret_kind == ServiceSecretKind::Worker {
            document.insert("SNOWMAN_WORKFORCE_TEAM_IDENTITIES_JSON", team_json.as_str());
        }
        let mut encoded = Zeroizing::new(serde_json::to_string(&document)?);
        if existing.as_ref().map(|value| value.as_str()) != Some(encoded.as_str()) {
            client
                .put_secret_value()
                .secret_id(&identity.secret_arn)
                .secret_string(encoded.as_str())
                .send()
                .await
                .context("could not reconcile workforce identity secret")?;
        }
        encoded.zeroize();
        prepared.push(PreparedServiceIdentity {
            manifest: identity.clone(),
            public_key: keys.public_key().to_bytes(),
        });
    }
    Ok(prepared)
}

fn digest_bytes(domain: &[u8], parts: &[&[u8]]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    for part in parts {
        digest.update((part.len() as u64).to_be_bytes());
        digest.update(part);
    }
    digest.finalize().into()
}

fn deterministic_uuid(domain: &[u8], parts: &[&[u8]]) -> Uuid {
    let digest = digest_bytes(domain, parts);
    let mut bytes: [u8; 16] = digest[..16].try_into().expect("digest prefix");
    bytes[6] = (bytes[6] & 0x0f) | 0x50;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    Uuid::from_bytes(bytes)
}

async fn reconcile_workforce_manifest(
    pool: &PgPool,
    manifest: &WorkforceBootstrapManifest,
    identities: &[PreparedServiceIdentity],
) -> anyhow::Result<[u8; 32]> {
    let canonical = serde_json::to_vec(manifest)?;
    let manifest_sha256: [u8; 32] = Sha256::digest(&canonical).into();
    let community_id = manifest.community_id;
    let mut tx = pool.begin().await?;
    let community = sqlx::query(
        r#"
        INSERT INTO communities (id, host)
        VALUES ($1,$2)
        ON CONFLICT (id) DO UPDATE SET host=EXCLUDED.host
        WHERE lower(communities.host)=lower(EXCLUDED.host)
          AND communities.archived_at IS NULL
        RETURNING id
        "#,
    )
    .bind(community_id)
    .bind(&manifest.community_host)
    .fetch_optional(&mut *tx)
    .await?;
    if community.is_none() {
        bail!("workforce bootstrap community conflicts with an existing or archived tenant");
    }
    let foreign_service_authority: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
          SELECT 1 FROM snowman_workforce_identities
          WHERE community_id=$1 AND identity_type='service' AND status='active'
            AND provisioning_authority IS DISTINCT FROM 'workforce_bootstrap'
        )
        "#,
    )
    .bind(community_id)
    .fetch_one(&mut *tx)
    .await?;
    let foreign_model_authority: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
          SELECT 1 FROM snowman_model_routes
          WHERE community_id=$1 AND status='active'
            AND provisioning_authority IS DISTINCT FROM 'workforce_bootstrap'
        )
        "#,
    )
    .bind(community_id)
    .fetch_one(&mut *tx)
    .await?;
    if foreign_service_authority || foreign_model_authority {
        bail!("workforce bootstrap found an active identity or model outside its authority");
    }

    let authority = &manifest.identity_authority;
    let assurance_evidence = decode_sha256(
        &authority.assurance_evidence_sha256,
        "assurance_evidence_sha256",
    )?;
    let broker = sqlx::query(
        r#"
        INSERT INTO snowman_workforce_identity_brokers
          (community_id, broker_id, provider, hosted_domain, tenant_id,
           client_id, project_id, assurance_level,
           assurance_evidence_sha256, assurance_evaluated_at,
           signing_kms_key_arn, max_session_seconds, status,
           provisioning_authority)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'active','workforce_bootstrap')
        ON CONFLICT (community_id, broker_id) DO UPDATE SET
          provider=EXCLUDED.provider,
          hosted_domain=EXCLUDED.hosted_domain,
          tenant_id=EXCLUDED.tenant_id,
          client_id=EXCLUDED.client_id,
          project_id=EXCLUDED.project_id,
          assurance_level=EXCLUDED.assurance_level,
          assurance_evidence_sha256=EXCLUDED.assurance_evidence_sha256,
          assurance_evaluated_at=EXCLUDED.assurance_evaluated_at,
          signing_kms_key_arn=EXCLUDED.signing_kms_key_arn,
          max_session_seconds=EXCLUDED.max_session_seconds,
          status='active', updated_at=NOW(), revoked_at=NULL
        WHERE snowman_workforce_identity_brokers.provisioning_authority='workforce_bootstrap'
        RETURNING broker_id
        "#,
    )
    .bind(community_id)
    .bind(&authority.broker_id)
    .bind(&authority.provider)
    .bind(&authority.hosted_domain)
    .bind(&authority.tenant_id)
    .bind(&authority.client_id)
    .bind(&authority.project_id)
    .bind(&authority.assurance_level)
    .bind(assurance_evidence.as_slice())
    .bind(authority.assurance_evaluated_at)
    .bind(&authority.signing_kms_key_arn)
    .bind(authority.max_session_seconds)
    .fetch_optional(&mut *tx)
    .await?;
    if broker.is_none() {
        bail!("workforce identity authority conflicts with another provisioning authority");
    }
    sqlx::query(
        r#"
        UPDATE snowman_workforce_identity_brokers
        SET status='revoked', revoked_at=COALESCE(revoked_at,NOW()), updated_at=NOW()
        WHERE community_id=$1 AND broker_id<>$2
          AND provisioning_authority='workforce_bootstrap' AND status<>'revoked'
        "#,
    )
    .bind(community_id)
    .bind(&authority.broker_id)
    .execute(&mut *tx)
    .await?;

    for prepared in identities {
        let identity = &prepared.manifest;
        let subject_sha256 = digest_bytes(
            b"snowman.service-identity.v1\0",
            &[community_id.as_bytes(), identity.identity_id.as_bytes()],
        );
        let upserted = sqlx::query(
            r#"
            INSERT INTO snowman_workforce_identities
              (community_id, identity_id, identity_type, provider,
               provider_subject_sha256, display_name, role, status,
               provisioning_authority)
            VALUES ($1,$2,'service','snowman_service',$3,$4,'agent','active',
                    'workforce_bootstrap')
            ON CONFLICT (community_id, identity_id) DO UPDATE SET
              display_name=EXCLUDED.display_name, status='active',
              updated_at=NOW(), expires_at=NULL, revoked_at=NULL
            WHERE snowman_workforce_identities.identity_type='service'
              AND snowman_workforce_identities.provider='snowman_service'
              AND snowman_workforce_identities.provisioning_authority='workforce_bootstrap'
              AND snowman_workforce_identities.provider_subject_sha256=EXCLUDED.provider_subject_sha256
            RETURNING identity_id
            "#,
        )
        .bind(community_id)
        .bind(identity.identity_id)
        .bind(subject_sha256.as_slice())
        .bind(&identity.display_name)
        .fetch_optional(&mut *tx)
        .await?;
        if upserted.is_none() {
            bail!("workforce identity conflicts with an existing authority");
        }
        sqlx::query(
            r#"
            UPDATE snowman_workforce_key_bindings
            SET revoked_at=COALESCE(revoked_at, NOW())
            WHERE community_id=$1 AND identity_id=$2 AND pubkey<>$3 AND revoked_at IS NULL
            "#,
        )
        .bind(community_id)
        .bind(identity.identity_id)
        .bind(prepared.public_key.as_slice())
        .execute(&mut *tx)
        .await?;
        let bound = sqlx::query(
            r#"
            INSERT INTO snowman_workforce_key_bindings
              (community_id, pubkey, identity_id, binding_type, session_id, bound_at)
            VALUES ($1,$2,$3,'service_runtime',NULL,NOW())
            ON CONFLICT (community_id, pubkey) DO UPDATE SET
              binding_type='service_runtime', session_id=NULL,
              expires_at=NULL, revoked_at=NULL
            WHERE snowman_workforce_key_bindings.identity_id=EXCLUDED.identity_id
            RETURNING identity_id
            "#,
        )
        .bind(community_id)
        .bind(prepared.public_key.as_slice())
        .bind(identity.identity_id)
        .fetch_optional(&mut *tx)
        .await?;
        if bound.is_none() {
            bail!("workforce service key is already bound to another identity");
        }

        let desired: Vec<String> = identity.capabilities.iter().cloned().collect();
        sqlx::query(
            r#"
            UPDATE snowman_workforce_capability_grants
            SET revoked_at=COALESCE(revoked_at, NOW())
            WHERE community_id=$1 AND identity_id=$2 AND revoked_at IS NULL
              AND NOT (capability=ANY($3::TEXT[]))
            "#,
        )
        .bind(community_id)
        .bind(identity.identity_id)
        .bind(&desired)
        .execute(&mut *tx)
        .await?;
        for capability in &identity.capabilities {
            let grant_id = deterministic_uuid(
                b"snowman.service-capability-grant.v1\0",
                &[
                    community_id.as_bytes(),
                    identity.identity_id.as_bytes(),
                    capability.as_bytes(),
                ],
            );
            let granted = sqlx::query(
                r#"
                INSERT INTO snowman_workforce_capability_grants
                  (community_id, grant_id, identity_id, capability,
                   grant_source, granted_at)
                VALUES ($1,$2,$3,$4,'role_policy',NOW())
                ON CONFLICT (community_id, grant_id) DO UPDATE SET
                  capability=EXCLUDED.capability, grant_source='role_policy',
                  expires_at=NULL, revoked_at=NULL
                WHERE snowman_workforce_capability_grants.identity_id=EXCLUDED.identity_id
                RETURNING grant_id
                "#,
            )
            .bind(community_id)
            .bind(grant_id)
            .bind(identity.identity_id)
            .bind(capability)
            .fetch_optional(&mut *tx)
            .await?;
            if granted.is_none() {
                bail!("workforce capability grant conflicts with another identity");
            }
        }
    }

    let desired_identities: Vec<Uuid> = identities
        .iter()
        .map(|identity| identity.manifest.identity_id)
        .collect();
    sqlx::query(
        r#"
        UPDATE snowman_workforce_key_bindings b
        SET revoked_at=COALESCE(b.revoked_at, NOW())
        FROM snowman_workforce_identities i
        WHERE b.community_id=$1 AND b.community_id=i.community_id
          AND b.identity_id=i.identity_id AND b.revoked_at IS NULL
          AND i.provisioning_authority='workforce_bootstrap'
          AND NOT (i.identity_id=ANY($2::UUID[]))
        "#,
    )
    .bind(community_id)
    .bind(&desired_identities)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r#"
        UPDATE snowman_workforce_capability_grants g
        SET revoked_at=COALESCE(g.revoked_at, NOW())
        FROM snowman_workforce_identities i
        WHERE g.community_id=$1 AND g.community_id=i.community_id
          AND g.identity_id=i.identity_id AND g.revoked_at IS NULL
          AND i.provisioning_authority='workforce_bootstrap'
          AND NOT (i.identity_id=ANY($2::UUID[]))
        "#,
    )
    .bind(community_id)
    .bind(&desired_identities)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        r#"
        UPDATE snowman_workforce_identities
        SET status='revoked', revoked_at=COALESCE(revoked_at, NOW()), updated_at=NOW()
        WHERE community_id=$1 AND provisioning_authority='workforce_bootstrap'
          AND NOT (identity_id=ANY($2::UUID[]))
        "#,
    )
    .bind(community_id)
    .bind(&desired_identities)
    .execute(&mut *tx)
    .await?;

    let desired_models: Vec<String> = manifest
        .model_routes
        .iter()
        .map(|route| route.model_id.clone())
        .collect();
    sqlx::query(
        r#"
        UPDATE snowman_model_routes
        SET status='retired', updated_at=NOW()
        WHERE community_id=$1 AND status='active'
          AND provisioning_authority='workforce_bootstrap'
          AND NOT (model_id=ANY($2::TEXT[]))
        "#,
    )
    .bind(community_id)
    .bind(&desired_models)
    .execute(&mut *tx)
    .await?;
    for route in &manifest.model_routes {
        let evidence = decode_sha256(
            &route.evaluation_evidence_sha256,
            "evaluation_evidence_sha256",
        )?;
        let suited_roles: Vec<String> = route.suited_roles.iter().cloned().collect();
        let allowed_classifications: Vec<String> =
            route.allowed_classifications.iter().cloned().collect();
        let routed = sqlx::query(
            r#"
            INSERT INTO snowman_model_routes
              (community_id, model_id, gateway_url, suited_roles,
               allowed_classifications, quality_score, latency_score,
               max_cost_microusd_per_million_tokens, max_context_tokens,
               evaluation_evidence_sha256, status, evaluated_at,
               provisioning_authority)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'active',$11,
                    'workforce_bootstrap')
            ON CONFLICT (community_id, model_id) DO UPDATE SET
              gateway_url=EXCLUDED.gateway_url,
              suited_roles=EXCLUDED.suited_roles,
              allowed_classifications=EXCLUDED.allowed_classifications,
              quality_score=EXCLUDED.quality_score,
              latency_score=EXCLUDED.latency_score,
              max_cost_microusd_per_million_tokens=EXCLUDED.max_cost_microusd_per_million_tokens,
              max_context_tokens=EXCLUDED.max_context_tokens,
              evaluation_evidence_sha256=EXCLUDED.evaluation_evidence_sha256,
              status='active', evaluated_at=EXCLUDED.evaluated_at, updated_at=NOW()
            WHERE snowman_model_routes.provisioning_authority='workforce_bootstrap'
            RETURNING model_id
            "#,
        )
        .bind(community_id)
        .bind(&route.model_id)
        .bind(&route.gateway_url)
        .bind(&suited_roles)
        .bind(&allowed_classifications)
        .bind(route.quality_score)
        .bind(route.latency_score)
        .bind(route.max_cost_microusd_per_million_tokens)
        .bind(route.max_context_tokens)
        .bind(evidence.as_slice())
        .bind(route.evaluated_at)
        .fetch_optional(&mut *tx)
        .await?;
        if routed.is_none() {
            bail!("workforce model route conflicts with another provisioning authority");
        }
    }
    sqlx::query(
        r#"
        INSERT INTO snowman_workforce_bootstrap_receipts
          (community_id, manifest_sha256, identity_count, model_route_count,
           identity_broker_count, applied_at)
        VALUES ($1,$2,$3,$4,1,NOW())
        ON CONFLICT (community_id, manifest_sha256) DO UPDATE SET
          identity_broker_count=1, applied_at=NOW()
        "#,
    )
    .bind(community_id)
    .bind(manifest_sha256.as_slice())
    .bind(i32::try_from(identities.len())?)
    .bind(i32::try_from(manifest.model_routes.len())?)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(manifest_sha256)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let master_secret_arn = required_env("SNOWMAN_RDS_MASTER_SECRET_ARN")?;
    let runtime_secret_arn = required_env("SNOWMAN_RELAY_RUNTIME_SECRET_ARN")?;
    let runtime_role = required_env("SNOWMAN_RUNTIME_DB_ROLE")?;
    buzz_db::runtime_security::validate_role_name(&runtime_role)?;
    let agent_broker_secret_arn = required_env("SNOWMAN_AGENT_BROKER_RUNTIME_SECRET_ARN")?;
    let agent_broker_role = required_env("SNOWMAN_AGENT_BROKER_DB_ROLE")?;
    buzz_db::runtime_security::validate_role_name(&agent_broker_role)?;
    let agent_coordinator_secret_arn =
        required_env("SNOWMAN_AGENT_COORDINATOR_RUNTIME_SECRET_ARN")?;
    let agent_coordinator_role = required_env("SNOWMAN_AGENT_COORDINATOR_DB_ROLE")?;
    buzz_db::runtime_security::validate_role_name(&agent_coordinator_role)?;
    if [
        runtime_role.as_str(),
        agent_broker_role.as_str(),
        agent_coordinator_role.as_str(),
    ]
    .into_iter()
    .collect::<std::collections::BTreeSet<_>>()
    .len()
        != 3
    {
        bail!("relay, agent broker, and agent coordinator database roles must be distinct");
    }
    let owner_pubkey = required_env("SNOWMAN_RELAY_OWNER_PUBKEY")?.to_ascii_lowercase();
    validate_owner_pubkey(&owner_pubkey)?;
    let workforce_manifest = std::env::var("SNOWMAN_WORKFORCE_BOOTSTRAP_MANIFEST")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .map(|value| parse_workforce_manifest(&value))
        .transpose()?;

    let sdk = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
    let secrets = Client::new(&sdk);
    let master_json = get_secret(&secrets, &master_secret_arn).await?;
    let mut master: RdsMasterSecret =
        serde_json::from_str(&master_json).context("invalid RDS-managed master secret schema")?;
    let database = required_env("SNOWMAN_DATABASE_NAME").or_else(|_| {
        master
            .dbname
            .clone()
            .context("SNOWMAN_DATABASE_NAME is required")
    })?;
    let admin_url = database_url(&master, &database, &master.username, &master.password)?;

    let existing = existing_runtime_secret(&secrets, &runtime_secret_arn).await?;
    let (mut runtime_password, relay_private_key, git_hook_hmac_secret) =
        if let Some(existing) = &existing {
            let parsed = url::Url::parse(&existing.database_url)
                .context("runtime DATABASE_URL is not a URL")?;
            let password = decoded_url_password(&parsed)?;
            (
                Zeroizing::new(password),
                existing.relay_private_key.clone(),
                existing.git_hook_hmac_secret.clone(),
            )
        } else {
            (
                Zeroizing::new(random_hex()),
                Keys::generate().secret_key().display_secret().to_string(),
                random_hex(),
            )
        };
    let existing_agent_broker =
        existing_database_runtime_secret(&secrets, &agent_broker_secret_arn).await?;
    let mut agent_broker_password = if let Some(existing) = &existing_agent_broker {
        let parsed = url::Url::parse(&existing.database_url)
            .context("agent broker DATABASE_URL is not a URL")?;
        Zeroizing::new(decoded_url_password(&parsed)?)
    } else {
        Zeroizing::new(random_hex())
    };
    let existing_agent_coordinator =
        existing_database_runtime_secret(&secrets, &agent_coordinator_secret_arn).await?;
    let mut agent_coordinator_password = if let Some(existing) = &existing_agent_coordinator {
        let parsed = url::Url::parse(&existing.database_url)
            .context("agent coordinator DATABASE_URL is not a URL")?;
        Zeroizing::new(decoded_url_password(&parsed)?)
    } else {
        Zeroizing::new(random_hex())
    };

    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .context("could not connect using the RDS-managed migration identity")?;
    buzz_db::migration::run_migrations(&admin).await?;
    let workforce_receipt = if let Some(manifest) = &workforce_manifest {
        let identities = prepare_service_identities(&secrets, manifest).await?;
        Some(reconcile_workforce_manifest(&admin, manifest, &identities).await?)
    } else {
        None
    };
    buzz_db::runtime_security::provision_runtime_role(&admin, &runtime_role, &runtime_password)
        .await?;
    buzz_db::runtime_security::provision_agent_broker_role(
        &admin,
        &agent_broker_role,
        &agent_broker_password,
    )
    .await?;
    buzz_db::runtime_security::provision_agent_coordinator_role(
        &admin,
        &agent_coordinator_role,
        &agent_coordinator_password,
    )
    .await?;
    buzz_db::partition::ensure_future_partitions(&admin, 6).await?;

    let runtime_url = database_url(&master, &database, &runtime_role, &runtime_password)?;
    let runtime = PgPoolOptions::new()
        .max_connections(1)
        .connect(&runtime_url)
        .await
        .context("could not verify the provisioned runtime identity")?;
    buzz_db::runtime_security::verify_runtime_role(&runtime, &runtime_role).await?;
    runtime.close().await;

    let agent_broker_url = database_url(
        &master,
        &database,
        &agent_broker_role,
        &agent_broker_password,
    )?;
    let agent_broker = PgPoolOptions::new()
        .max_connections(1)
        .connect(&agent_broker_url)
        .await
        .context("could not verify the provisioned agent broker identity")?;
    buzz_db::runtime_security::verify_agent_broker_role(&agent_broker, &agent_broker_role).await?;
    agent_broker.close().await;

    let agent_coordinator_url = database_url(
        &master,
        &database,
        &agent_coordinator_role,
        &agent_coordinator_password,
    )?;
    let agent_coordinator = PgPoolOptions::new()
        .max_connections(1)
        .connect(&agent_coordinator_url)
        .await
        .context("could not verify the provisioned agent coordinator identity")?;
    buzz_db::runtime_security::verify_agent_coordinator_role(
        &agent_coordinator,
        &agent_coordinator_role,
    )
    .await?;
    agent_coordinator.close().await;

    let document = RelayRuntimeSecret {
        database_url: runtime_url.to_string(),
        relay_private_key,
        git_hook_hmac_secret,
        relay_owner_pubkey: owner_pubkey,
    };
    let mut encoded = serde_json::to_string(&document)?;
    secrets
        .put_secret_value()
        .secret_id(&runtime_secret_arn)
        .secret_string(encoded.clone())
        .send()
        .await
        .context("could not write the governed relay runtime secret")?;

    let mut agent_broker_document = serde_json::to_string(&DatabaseRuntimeSecret {
        database_url: agent_broker_url.to_string(),
    })?;
    secrets
        .put_secret_value()
        .secret_id(&agent_broker_secret_arn)
        .secret_string(agent_broker_document.clone())
        .send()
        .await
        .context("could not write the governed agent broker runtime secret")?;

    let mut agent_coordinator_document = serde_json::to_string(&DatabaseRuntimeSecret {
        database_url: agent_coordinator_url.to_string(),
    })?;
    secrets
        .put_secret_value()
        .secret_id(&agent_coordinator_secret_arn)
        .secret_string(agent_coordinator_document.clone())
        .send()
        .await
        .context("could not write the governed agent coordinator runtime secret")?;

    encoded.zeroize();
    agent_broker_document.zeroize();
    agent_coordinator_document.zeroize();
    agent_broker_password.zeroize();
    agent_coordinator_password.zeroize();
    runtime_password.zeroize();
    master.password.zeroize();
    if let Some(receipt) = workforce_receipt {
        println!(
            "Snowman Command Center bootstrap completed; workforce_manifest_sha256={}; no secret values were logged",
            hex::encode(receipt)
        );
    } else {
        println!("Snowman Command Center bootstrap completed; no secret values were logged");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(role: &str, identity_id: Uuid) -> ServiceIdentityManifest {
        ServiceIdentityManifest {
            identity_id,
            display_name: format!("Snowman {role}"),
            specialist_role: role.to_string(),
            capabilities: exact_capabilities(role).unwrap(),
            secret_arn: format!(
                "arn:aws:secretsmanager:us-west-2:111111111111:secret:snowman-{identity_id}"
            ),
            secret_kind: expected_secret_kind(role),
        }
    }

    fn workforce_manifest() -> WorkforceBootstrapManifest {
        let lead = Uuid::new_v4();
        let analyst = Uuid::new_v4();
        let delivery = Uuid::new_v4();
        let reviewer = Uuid::new_v4();
        WorkforceBootstrapManifest {
            schema_version: WORKFORCE_MANIFEST_SCHEMA.into(),
            community_id: Uuid::new_v4(),
            community_host: "aptive.staging.snowmanai.org".into(),
            identities: vec![
                identity("lead", lead),
                identity("governed_analyst", analyst),
                identity("client_delivery", delivery),
                identity("quality_risk_reviewer", reviewer),
                identity("scheduler", Uuid::new_v4()),
                identity("trigger", Uuid::new_v4()),
                identity("deadline_operations", Uuid::new_v4()),
            ],
            model_routes: vec![ModelRouteManifest {
                model_id: "snowman-specialist-v1".into(),
                gateway_url: "https://models.staging.internal.snowmanai.org/v1".into(),
                suited_roles: [
                    "lead",
                    "governed_analyst",
                    "client_delivery",
                    "quality_risk_reviewer",
                ]
                .into_iter()
                .map(str::to_string)
                .collect(),
                allowed_classifications: ["internal", "confidential", "restricted"]
                    .into_iter()
                    .map(str::to_string)
                    .collect(),
                quality_score: 900,
                latency_score: 700,
                max_cost_microusd_per_million_tokens: 0,
                max_context_tokens: 32_768,
                evaluation_evidence_sha256: "a".repeat(64),
                evaluated_at: Utc::now(),
            }],
            team: TeamManifest {
                lead,
                governed_analyst: analyst,
                client_delivery: delivery,
                quality_risk_reviewer: reviewer,
                model_overrides: TeamModelOverrides::default(),
            },
            identity_authority: IdentityAuthorityManifest {
                broker_id: "snowman-analyst360-identity".into(),
                provider: "google_workspace".into(),
                hosted_domain: "snowmanai.org".into(),
                tenant_id: "aptive".into(),
                client_id: "aptive".into(),
                project_id: "aptive".into(),
                signing_kms_key_arn:
                    "arn:aws:kms:us-west-2:111111111111:key/00000000-0000-0000-0000-000000000001"
                        .into(),
                max_session_seconds: 900,
                assurance_level: "mfa".into(),
                assurance_evidence_sha256: "b".repeat(64),
                assurance_evaluated_at: Utc::now(),
            },
        }
    }

    #[test]
    fn owner_key_is_exact_and_hex() {
        assert!(validate_owner_pubkey(
            "0000000000000000000000000000000000000000000000000000000000000001"
        )
        .is_ok());
        assert!(validate_owner_pubkey("abcd").is_err());
        assert!(validate_owner_pubkey(&"zz".repeat(32)).is_err());
    }

    #[test]
    fn database_url_encodes_credentials_and_requires_tls() {
        let master = RdsMasterSecret {
            username: "admin".into(),
            password: "unused".into(),
            host: "db.snowman.internal".into(),
            port: 5432,
            dbname: None,
        };
        let value = database_url(&master, "snowmancc", "relay_user", "p@ss:/word").unwrap();
        let parsed = url::Url::parse(&value).unwrap();
        assert_eq!(parsed.username(), "relay_user");
        assert_eq!(decoded_url_password(&parsed).unwrap(), "p@ss:/word");
        assert_eq!(parsed.query(), Some("sslmode=require"));
    }

    #[test]
    fn workforce_manifest_is_exactly_scoped_and_snowman_only() {
        let manifest = workforce_manifest();
        assert!(validate_workforce_manifest(&manifest).is_ok());

        let mut excess = manifest.clone();
        excess.identities[0]
            .capabilities
            .insert("filesystem.all".into());
        assert!(validate_workforce_manifest(&excess).is_err());

        let mut block_route = manifest;
        block_route.model_routes[0].gateway_url = "https://models.block.xyz/v1".into();
        assert!(validate_workforce_manifest(&block_route).is_err());
    }

    #[test]
    fn workforce_grant_ids_are_stable_and_domain_separated() {
        let parts: [&[u8]; 2] = [b"identity", b"analytics.query"];
        let first = deterministic_uuid(b"snowman.grant.v1", &parts);
        assert_eq!(first, deterministic_uuid(b"snowman.grant.v1", &parts));
        assert_ne!(first, deterministic_uuid(b"snowman.binding.v1", &parts));
        assert_eq!(first.get_version_num(), 5);
    }
}
