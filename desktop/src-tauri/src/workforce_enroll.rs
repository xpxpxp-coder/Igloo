use chrono::{Duration, Utc};
use url::Url;

pub(crate) const ACTION: &str = "enroll_workforce_session";
pub(crate) const AUDIENCE: &str = "snowman:workforce-identity";
pub(crate) const PROTOCOL: &str = "snowman-workforce-device-proof";
pub(crate) const PURPOSE: &str = "snowman-workforce-session-enrollment";
pub(crate) const VERSION: &str = "1";

fn bounded_identifier(value: &str) -> bool {
    (3..=200).contains(&value.len())
        && value.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_alphanumeric()
                || (index > 0 && matches!(byte, b'.' | b'_' | b':' | b'/' | b'-'))
        })
}

pub(crate) fn validate_request(
    assertion_id: &str,
    broker: &str,
    community: &str,
    purpose: &str,
    nonce: &str,
    verification_code: &str,
    origin: &str,
    expires_at: &str,
    protocol: &str,
    version: &str,
) -> Result<(), String> {
    crate::nostr_bind::validate_challenge_id(assertion_id)?;
    crate::nostr_bind::validate_nonce(nonce)?;
    crate::nostr_bind::validate_verification_code(verification_code)?;
    crate::nostr_bind::validate_origin(origin)?;
    crate::nostr_bind::validate_expires_at_format(expires_at)?;
    if !bounded_identifier(broker) {
        return Err("invalid workforce broker".into());
    }
    let community =
        uuid::Uuid::parse_str(community).map_err(|_| "invalid workforce community".to_string())?;
    if community.is_nil() {
        return Err("invalid workforce community".into());
    }
    if purpose != PURPOSE || protocol != PROTOCOL || version != VERSION {
        return Err("unsupported workforce enrollment protocol".into());
    }
    let parsed = Url::parse(origin).map_err(|error| format!("invalid origin: {error}"))?;
    let hostname = parsed.host_str().unwrap_or_default();
    if hostname != "snowmanai.org" && !hostname.ends_with(".snowmanai.org") {
        return Err("workforce enrollment origin must be Snowman controlled".into());
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn validate_signing_request(
    assertion_id: &str,
    broker: &str,
    community: &str,
    purpose: &str,
    nonce: &str,
    verification_code: &str,
    origin: &str,
    expires_at: &str,
    protocol: &str,
    version: &str,
) -> Result<(), String> {
    validate_request(
        assertion_id,
        broker,
        community,
        purpose,
        nonce,
        verification_code,
        origin,
        expires_at,
        protocol,
        version,
    )?;
    let expiry = crate::nostr_bind::validate_expires_at_format(expires_at)?;
    let now = Utc::now();
    if expiry <= now {
        return Err("expires_at is expired".into());
    }
    if expiry - now > Duration::seconds(330) {
        return Err("expires_at exceeds the workforce enrollment lifetime".into());
    }
    Ok(())
}
