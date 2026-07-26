#![deny(unsafe_code)]

use anyhow::{bail, Context};
use aws_sdk_secretsmanager::Client;
use nostr::Keys;
use percent_encoding::percent_decode_str;
use rand::random;
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgPoolOptions;
use zeroize::{Zeroize, Zeroizing};

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

impl Drop for RelayRuntimeSecret {
    fn drop(&mut self) {
        self.database_url.zeroize();
        self.relay_private_key.zeroize();
        self.git_hook_hmac_secret.zeroize();
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let master_secret_arn = required_env("SNOWMAN_RDS_MASTER_SECRET_ARN")?;
    let runtime_secret_arn = required_env("SNOWMAN_RELAY_RUNTIME_SECRET_ARN")?;
    let runtime_role = required_env("SNOWMAN_RUNTIME_DB_ROLE")?;
    buzz_db::runtime_security::validate_role_name(&runtime_role)?;
    let owner_pubkey = required_env("SNOWMAN_RELAY_OWNER_PUBKEY")?.to_ascii_lowercase();
    validate_owner_pubkey(&owner_pubkey)?;

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

    let admin = PgPoolOptions::new()
        .max_connections(1)
        .connect(&admin_url)
        .await
        .context("could not connect using the RDS-managed migration identity")?;
    buzz_db::migration::run_migrations(&admin).await?;
    buzz_db::runtime_security::provision_runtime_role(&admin, &runtime_role, &runtime_password)
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

    encoded.zeroize();
    runtime_password.zeroize();
    master.password.zeroize();
    println!("Snowman Command Center bootstrap completed; no secret values were logged");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
