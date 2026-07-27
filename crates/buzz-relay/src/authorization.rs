//! Snowman governed authorization seam.
//!
//! NIP-42 proves possession of a relay key. It does not, by itself, prove a
//! Snowman workforce identity or authorize every capability. This module is the
//! single relay-side transition from cryptographic authentication to
//! tenant-scoped role capabilities. The workforce binding resolver feeds this
//! seam; callers must not recreate role-to-scope mappings elsewhere.

use buzz_auth::{AuthContext, Scope};
use buzz_core::CommunityId;

use crate::state::AppState;

/// Resolve a live workforce principal and require one exact fine-grained
/// capability. This is the authorization boundary for Snowman REST control
/// planes; a Nostr signature or relay role alone never satisfies it.
pub async fn require_workforce_capability(
    state: &AppState,
    community: CommunityId,
    pubkey: &nostr::PublicKey,
    capability: &str,
    required_identity_type: Option<&str>,
) -> Result<buzz_db::workforce_identity::WorkforcePrincipal, String> {
    if !state.config.snowman_workforce_identity_required {
        return Err("Snowman workforce identity enforcement is disabled".to_string());
    }
    let principal = state
        .db
        .resolve_workforce_principal(community, pubkey.as_bytes())
        .await
        .map_err(|error| format!("workforce identity lookup failed: {error}"))?
        .ok_or_else(|| "relay key has no active Snowman workforce binding".to_string())?;
    if required_identity_type.is_some_and(|required| principal.identity_type != required) {
        return Err("workforce identity type is not authorized for this operation".to_string());
    }
    if !principal
        .capabilities
        .iter()
        .any(|granted| granted == capability)
    {
        return Err("Snowman workforce capability is not granted".to_string());
    }

    let member = state
        .db
        .get_relay_member(community, &pubkey.to_hex())
        .await
        .map_err(|error| format!("tenant role lookup failed: {error}"))?
        .ok_or_else(|| "workforce identity has no tenant membership".to_string())?;
    let member_role = if member.role == "bot" {
        "agent"
    } else {
        member.role.as_str()
    };
    if member_role != principal.role {
        return Err("workforce identity role differs from tenant membership".to_string());
    }
    Ok(principal)
}

/// Apply Snowman's tenant role scope policy to an authenticated context.
///
/// Returns `Ok(None)` when the compatibility mode is active. In governed mode,
/// returns the effective role or a generic error suitable for a fail-closed auth
/// response. A cryptographically delegated NIP-OA identity is always treated as
/// an agent and never inherits its owner's administrative scopes.
pub async fn apply_role_scopes(
    state: &AppState,
    community: CommunityId,
    auth: &mut AuthContext,
    delegated_owner: Option<&nostr::PublicKey>,
) -> Result<Option<&'static str>, String> {
    if !state.config.snowman_role_scopes {
        return Ok(None);
    }

    let workforce = if state.config.snowman_workforce_identity_required {
        Some(
            state
                .db
                .resolve_workforce_principal(community, auth.pubkey.as_bytes())
                .await
                .map_err(|error| format!("workforce identity lookup failed: {error}"))?
                .ok_or_else(|| "relay key has no active Snowman workforce binding".to_string())?,
        )
    } else {
        None
    };

    let (role, scopes) = if let Some(principal) = workforce {
        if delegated_owner.is_some()
            && (principal.identity_type != "service" || principal.role != "agent")
        {
            return Err("delegated relay key is not a Snowman agent identity".to_string());
        }
        if principal.identity_type == "service"
            && (principal.role != "agent" || principal.capabilities.is_empty())
        {
            return Err("service identity is not an active capability-bounded agent".to_string());
        }
        let member = state
            .db
            .get_relay_member(community, &auth.pubkey.to_hex())
            .await
            .map_err(|error| format!("role lookup failed: {error}"))?
            .ok_or_else(|| "authenticated identity has no tenant role".to_string())?;
        let member_role = if member.role == "bot" {
            "agent"
        } else {
            member.role.as_str()
        };
        if member_role != principal.role {
            return Err("workforce identity role differs from relay membership role".to_string());
        }
        let scopes = Scope::for_relay_role(&principal.role)
            .ok_or_else(|| "authenticated identity has an unsupported tenant role".to_string())?;
        let role = match principal.role.as_str() {
            "owner" => "owner",
            "admin" => "admin",
            "member" => "member",
            "guest" => "guest",
            "bot" | "agent" => "agent",
            _ => return Err("authenticated identity has an unsupported tenant role".to_string()),
        };
        (role, scopes)
    } else if delegated_owner.is_some() {
        ("agent", Scope::for_agent())
    } else {
        let member = state
            .db
            .get_relay_member(community, &auth.pubkey.to_hex())
            .await
            .map_err(|error| format!("role lookup failed: {error}"))?
            .ok_or_else(|| "authenticated identity has no tenant role".to_string())?;
        let scopes = Scope::for_relay_role(&member.role)
            .ok_or_else(|| "authenticated identity has an unsupported tenant role".to_string())?;
        let role = match member.role.as_str() {
            "owner" => "owner",
            "admin" => "admin",
            "member" => "member",
            "guest" => "guest",
            "bot" | "agent" => "agent",
            _ => return Err("authenticated identity has an unsupported tenant role".to_string()),
        };
        (role, scopes)
    };

    if scopes.is_empty() {
        return Err("authenticated identity has no capabilities".to_string());
    }
    auth.scopes = scopes;
    Ok(Some(role))
}
