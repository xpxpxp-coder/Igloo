use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use iroh::{EndpointAddr, RelayUrl, TransportAddr};
use mesh_llm_host_runtime::SignedBootstrapToken;

use super::MESH_IROH_RELAYS_ENV;

const MAX_INVITE_TOKEN_LEN: usize = 64 * 1024;
const MAX_BOOTSTRAP_ADDRS: usize = 8;
const MAX_ENDPOINT_TRANSPORT_ADDRS: usize = 16;

/// Locally configured iroh relay policy. Remote discovery may only advertise
/// relay URLs that this node was already configured to contact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum IrohRelayMode {
    /// Direct QUIC only; advertised endpoint tokens must not contain relays.
    Disabled,
    /// An explicit, locally configured relay allowlist.
    Custom(Vec<RelayUrl>),
}

pub(super) fn iroh_relay_mode() -> anyhow::Result<IrohRelayMode> {
    iroh_relay_mode_from(std::env::var(MESH_IROH_RELAYS_ENV).ok().as_deref())
}

pub(super) fn iroh_relay_mode_from(raw: Option<&str>) -> anyhow::Result<IrohRelayMode> {
    match raw.map(str::trim) {
        None | Some("") | Some("0") => Ok(IrohRelayMode::Disabled),
        Some("1") | Some("default") => anyhow::bail!(
            "public mesh relays are disabled; configure explicit Snowman relay origins in {MESH_IROH_RELAYS_ENV}"
        ),
        Some(list) => {
            let urls = list
                .split(',')
                .map(str::trim)
                .filter(|url| !url.is_empty())
                .map(parse_configured_relay_url)
                .collect::<anyhow::Result<Vec<_>>>()?;
            if urls.is_empty() {
                anyhow::bail!("{MESH_IROH_RELAYS_ENV} must contain at least one relay URL");
            }
            Ok(IrohRelayMode::Custom(urls))
        }
    }
}

fn parse_configured_relay_url(raw: &str) -> anyhow::Result<RelayUrl> {
    let parsed = url::Url::parse(raw)
        .map_err(|error| anyhow::anyhow!("invalid relay URL {raw:?}: {error}"))?;
    let secure = parsed.scheme() == "https";
    let local_http = parsed.scheme() == "http"
        && parsed.host().is_some_and(|host| match host {
            url::Host::Domain(domain) => domain.eq_ignore_ascii_case("localhost"),
            url::Host::Ipv4(ip) => ip.is_loopback(),
            url::Host::Ipv6(ip) => ip.is_loopback(),
        });
    if !secure && !local_http {
        anyhow::bail!(
            "relay URL {raw:?} must use https (http is allowed only for loopback development)"
        );
    }
    if !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
        || !matches!(parsed.path(), "" | "/")
    {
        anyhow::bail!(
            "relay URL {raw:?} must be an origin without credentials, path, query, or fragment"
        );
    }
    let snowman_controlled = parsed.host_str().is_some_and(|host| {
        host.eq_ignore_ascii_case("snowmanai.org")
            || host.to_ascii_lowercase().ends_with(".snowmanai.org")
            || host.eq_ignore_ascii_case("localhost")
    }) || parsed.host().is_some_and(|host| match host {
        url::Host::Ipv4(ip) => ip.is_loopback(),
        url::Host::Ipv6(ip) => ip.is_loopback(),
        url::Host::Domain(_) => false,
    });
    if !snowman_controlled {
        anyhow::bail!("relay URL {raw:?} is outside the Snowman-controlled snowmanai.org boundary");
    }
    raw.parse::<RelayUrl>()
        .map_err(|error| anyhow::anyhow!("invalid iroh relay URL {raw:?}: {error}"))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ValidatedEndpoint {
    pub endpoint_id: String,
    pub join_token: String,
}

pub(super) fn validate_advertised_endpoint(
    invite_token: &str,
) -> anyhow::Result<ValidatedEndpoint> {
    let mode = iroh_relay_mode()?;
    validate_advertised_endpoint_with_mode(invite_token, &mode)
}

pub(super) fn validate_advertised_endpoint_with_mode(
    invite_token: &str,
    mode: &IrohRelayMode,
) -> anyhow::Result<ValidatedEndpoint> {
    let token = invite_token.trim();
    if token.is_empty() {
        anyhow::bail!("mesh invite token is empty");
    }
    if token.len() > MAX_INVITE_TOKEN_LEN {
        anyhow::bail!("mesh invite token exceeds {MAX_INVITE_TOKEN_LEN} bytes");
    }
    let payload = URL_SAFE_NO_PAD
        .decode(token)
        .map_err(|error| anyhow::anyhow!("invalid mesh invite encoding: {error}"))?;

    if let Ok(mut addr) = serde_json::from_slice::<EndpointAddr>(&payload) {
        retain_usable_transports(&mut addr, mode)?;
        let endpoint_id = addr.id.to_string();
        let join_token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&addr)?);
        return Ok(ValidatedEndpoint {
            endpoint_id,
            join_token,
        });
    }

    let signed = serde_json::from_slice::<SignedBootstrapToken>(&payload)
        .map_err(|error| anyhow::anyhow!("invalid mesh invite payload: {error}"))?;
    signed
        .verify()
        .map_err(|reason| anyhow::anyhow!("invalid signed mesh invite: {}", reason.code()))?;
    if signed.serialized_addrs.is_empty() || signed.serialized_addrs.len() > MAX_BOOTSTRAP_ADDRS {
        anyhow::bail!(
            "signed mesh invite must contain 1..={MAX_BOOTSTRAP_ADDRS} endpoint addresses"
        );
    }
    let addrs = signed
        .serialized_addrs
        .iter()
        .map(|bytes| {
            serde_json::from_slice::<EndpointAddr>(bytes)
                .map_err(|error| anyhow::anyhow!("invalid signed endpoint address: {error}"))
        })
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Rewriting a signed token would invalidate its signature. Keep the signed
    // envelope intact only when every advertised transport is policy-approved;
    // mixed signed tokens fail closed rather than leaking rejected dial targets.
    for addr in &addrs {
        validate_signed_transports(addr, mode)?;
    }
    Ok(ValidatedEndpoint {
        endpoint_id: addrs[0].id.to_string(),
        join_token: token.to_string(),
    })
}

fn retain_usable_transports(addr: &mut EndpointAddr, mode: &IrohRelayMode) -> anyhow::Result<()> {
    validate_transport_count(addr)?;
    let mut rejections = Vec::new();
    addr.addrs
        .retain(|transport| match validate_transport(transport, mode) {
            Ok(()) => true,
            Err(error) => {
                rejections.push(error.to_string());
                false
            }
        });
    if addr.addrs.is_empty() {
        anyhow::bail!(
            "mesh endpoint has no usable transport address (all rejected: {})",
            rejections.join("; ")
        );
    }
    Ok(())
}

fn validate_signed_transports(addr: &EndpointAddr, mode: &IrohRelayMode) -> anyhow::Result<()> {
    validate_transport_count(addr)?;
    let mut usable = 0usize;
    for transport in &addr.addrs {
        match validate_transport(transport, mode) {
            Ok(()) => usable += 1,
            // mesh-llm currently signs its own port-0 placeholder alongside a
            // valid relay. It is non-dialable, so preserving it is safe and
            // necessary for stock signed tokens to remain usable.
            Err(_) if matches!(transport, TransportAddr::Ip(socket) if socket.port() == 0) => {}
            Err(error) => return Err(error),
        }
    }
    if usable == 0 {
        anyhow::bail!("signed mesh endpoint has no usable transport address");
    }
    Ok(())
}

fn validate_transport_count(addr: &EndpointAddr) -> anyhow::Result<()> {
    if addr.addrs.is_empty() || addr.addrs.len() > MAX_ENDPOINT_TRANSPORT_ADDRS {
        anyhow::bail!(
            "mesh endpoint must contain 1..={MAX_ENDPOINT_TRANSPORT_ADDRS} transport addresses"
        );
    }
    Ok(())
}

fn validate_transport(transport: &TransportAddr, mode: &IrohRelayMode) -> anyhow::Result<()> {
    match transport {
        TransportAddr::Relay(relay) if relay_allowed(relay, mode) => Ok(()),
        TransportAddr::Relay(relay) => anyhow::bail!("unapproved relay URL {relay}"),
        TransportAddr::Ip(socket) => validate_direct_socket(*socket),
        _ => anyhow::bail!("unsupported transport address"),
    }
}

fn relay_allowed(relay: &RelayUrl, mode: &IrohRelayMode) -> bool {
    match mode {
        IrohRelayMode::Disabled => false,
        IrohRelayMode::Custom(urls) => urls.contains(relay),
    }
}

fn validate_direct_socket(socket: std::net::SocketAddr) -> anyhow::Result<()> {
    let ip = socket.ip();
    let unsafe_target = socket.port() == 0
        || ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || match ip {
            std::net::IpAddr::V4(ip) => ip.is_link_local() || ip.is_broadcast(),
            std::net::IpAddr::V6(ip) => ip.is_unicast_link_local(),
        };
    if unsafe_target {
        anyhow::bail!("mesh endpoint advertises unsafe direct address {socket}");
    }
    Ok(())
}

#[cfg(test)]
pub(super) fn endpoint_token_for_test(
    transports: impl IntoIterator<Item = TransportAddr>,
) -> String {
    let mut addr = EndpointAddr::new(iroh::SecretKey::generate().public());
    addr.addrs.extend(transports);
    URL_SAFE_NO_PAD.encode(serde_json::to_vec(&addr).expect("serialize test endpoint"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configured_relays_require_safe_origins() {
        assert!(iroh_relay_mode_from(Some("https://relay.example")).is_ok());
        assert!(iroh_relay_mode_from(Some("http://127.0.0.1:3340")).is_ok());
        for invalid in [
            "http://relay.example",
            "https://user@relay.example",
            "https://relay.example/path",
            "https://relay.example?token=secret",
        ] {
            assert!(
                iroh_relay_mode_from(Some(invalid)).is_err(),
                "accepted unsafe relay {invalid}"
            );
        }
    }

    #[test]
    fn remote_relay_must_match_local_policy() {
        let allowed: RelayUrl = "https://relay.example".parse().unwrap();
        let other: RelayUrl = "https://other.example".parse().unwrap();
        let token = endpoint_token_for_test([TransportAddr::Relay(allowed.clone())]);
        assert!(validate_advertised_endpoint_with_mode(
            &token,
            &IrohRelayMode::Custom(vec![allowed])
        )
        .is_ok());
        assert!(validate_advertised_endpoint_with_mode(
            &token,
            &IrohRelayMode::Custom(vec![other])
        )
        .is_err());
        assert!(validate_advertised_endpoint_with_mode(&token, &IrohRelayMode::Disabled).is_err());
    }

    #[test]
    fn endpoint_with_one_good_and_one_junk_candidate_is_sanitized() {
        // A mesh-llm endpoint can advertise a usable relay alongside an
        // unusable direct IP. Keep the endpoint reachable, but never pass the
        // rejected candidate through to iroh's parallel dialer.
        let good_relay: RelayUrl = "https://mesh.snowmanai.org".parse().unwrap();
        let unsafe_socket = "169.254.169.254:80".parse().unwrap();
        let token = endpoint_token_for_test([
            TransportAddr::Relay(good_relay.clone()),
            TransportAddr::Ip(unsafe_socket),
        ]);
        let validated = validate_advertised_endpoint_with_mode(
            &token,
            &IrohRelayMode::Custom(vec![good_relay.clone()]),
        )
        .unwrap();
        let payload = URL_SAFE_NO_PAD.decode(validated.join_token).unwrap();
        let sanitized: EndpointAddr = serde_json::from_slice(&payload).unwrap();
        assert_eq!(
            sanitized.addrs,
            [TransportAddr::Relay(good_relay)].into_iter().collect()
        );
    }

    #[test]
    fn endpoint_with_all_junk_candidates_is_rejected() {
        // Guard: if EVERY candidate is unusable, the endpoint must still fail.
        let token = endpoint_token_for_test([
            TransportAddr::Ip("180.181.228.108:0".parse().unwrap()), // port 0
            TransportAddr::Ip("127.0.0.1:9337".parse().unwrap()),    // loopback
        ]);
        assert!(
            validate_advertised_endpoint_with_mode(&token, &IrohRelayMode::Disabled).is_err(),
            "endpoint with no usable candidate must be rejected"
        );
    }

    #[test]
    fn custom_mode_rejects_relay_outside_local_allowlist() {
        let unknown: RelayUrl = "https://not-a-real-relay.example".parse().unwrap();
        let allowed: RelayUrl = "https://mesh.snowmanai.org".parse().unwrap();
        assert!(!relay_allowed(
            &unknown,
            &IrohRelayMode::Custom(vec![allowed.clone()])
        ));
        let token = endpoint_token_for_test([TransportAddr::Relay(unknown)]);
        assert!(validate_advertised_endpoint_with_mode(
            &token,
            &IrohRelayMode::Custom(vec![allowed])
        )
        .is_err());
    }

    #[test]
    fn remote_endpoint_rejects_unsafe_direct_targets_and_oversized_tokens() {
        for socket in ["127.0.0.1:9337", "169.254.169.254:80", "0.0.0.0:1"] {
            let token = endpoint_token_for_test([TransportAddr::Ip(socket.parse().unwrap())]);
            assert!(
                validate_advertised_endpoint_with_mode(&token, &IrohRelayMode::Disabled).is_err(),
                "accepted unsafe target {socket}"
            );
        }
        let valid =
            endpoint_token_for_test([TransportAddr::Ip("192.168.1.20:47916".parse().unwrap())]);
        assert!(validate_advertised_endpoint_with_mode(&valid, &IrohRelayMode::Disabled).is_ok());
        assert!(validate_advertised_endpoint_with_mode(
            &"a".repeat(MAX_INVITE_TOKEN_LEN + 1),
            &IrohRelayMode::Disabled
        )
        .is_err());
    }

    #[test]
    fn accepts_verified_meshllm_signed_bootstrap_token_and_rejects_tampering() {
        use mesh_llm_host_runtime::crypto::OwnerKeypair;
        use mesh_llm_host_runtime::{
            MeshGenesisPolicy, MeshRequirements, SignedBootstrapToken, SignedMeshGenesisPolicy,
        };

        let owner = OwnerKeypair::generate();
        let policy = MeshGenesisPolicy::new(
            owner.owner_id(),
            1_717_171_717_000,
            MeshRequirements::default(),
        )
        .expect("create test mesh policy");
        let signed_policy =
            SignedMeshGenesisPolicy::sign(policy, &owner).expect("sign test mesh policy");
        let endpoint = EndpointAddr {
            id: iroh::SecretKey::generate().public(),
            addrs: [TransportAddr::Ip("192.168.1.20:47916".parse().unwrap())]
                .into_iter()
                .collect(),
        };
        let signed = SignedBootstrapToken::sign(
            vec![serde_json::to_vec(&endpoint).unwrap()],
            &signed_policy,
            None,
            &owner,
        )
        .expect("sign test bootstrap token");
        let token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&signed).unwrap());
        assert_eq!(
            validate_advertised_endpoint_with_mode(&token, &IrohRelayMode::Disabled)
                .unwrap()
                .endpoint_id,
            endpoint.id.to_string()
        );

        let good_relay: RelayUrl = "https://mesh.snowmanai.org".parse().unwrap();
        let relay_mode = IrohRelayMode::Custom(vec![good_relay.clone()]);
        let placeholder_endpoint = EndpointAddr {
            id: endpoint.id,
            addrs: [
                TransportAddr::Relay(good_relay.clone()),
                TransportAddr::Ip("180.181.228.108:0".parse().unwrap()),
            ]
            .into_iter()
            .collect(),
        };
        let placeholder_signed = SignedBootstrapToken::sign(
            vec![serde_json::to_vec(&placeholder_endpoint).unwrap()],
            &signed_policy,
            None,
            &owner,
        )
        .expect("sign placeholder test bootstrap token");
        let placeholder_token =
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&placeholder_signed).unwrap());
        assert!(
            validate_advertised_endpoint_with_mode(&placeholder_token, &relay_mode).is_ok(),
            "signed stock token with a port-0 placeholder must remain usable"
        );

        let mixed_endpoint = EndpointAddr {
            id: endpoint.id,
            addrs: [
                TransportAddr::Relay(good_relay),
                TransportAddr::Ip("169.254.169.254:80".parse().unwrap()),
            ]
            .into_iter()
            .collect(),
        };
        let mixed_signed = SignedBootstrapToken::sign(
            vec![serde_json::to_vec(&mixed_endpoint).unwrap()],
            &signed_policy,
            None,
            &owner,
        )
        .expect("sign mixed test bootstrap token");
        let mixed_token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&mixed_signed).unwrap());
        assert!(
            validate_advertised_endpoint_with_mode(&mixed_token, &relay_mode).is_err(),
            "signed mixed-candidate tokens must fail closed because they cannot be rewritten"
        );

        let mut tampered = signed;
        tampered.serialized_addrs[0] = serde_json::to_vec(&EndpointAddr {
            id: endpoint.id,
            addrs: [TransportAddr::Ip("192.168.1.21:47916".parse().unwrap())]
                .into_iter()
                .collect(),
        })
        .unwrap();
        let token = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&tampered).unwrap());
        assert!(validate_advertised_endpoint_with_mode(&token, &IrohRelayMode::Disabled).is_err());
    }
}
