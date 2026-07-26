# ADR 0004: Cloudflare-authenticated AWS ingress with no direct-origin bypass

- Status: Accepted for source implementation; live evidence pending
- Date: 2026-07-26
- Decision owner: Snowman AI sole-founder operator

## Decision

Public Command Center traffic enters through the Snowman Cloudflare zone and a
public AWS Application Load Balancer. The ALB is not a second public authority:
its security group accepts port 443 only from reviewed Cloudflare origin CIDRs,
and its HTTPS listener uses mutual-TLS `verify` mode against a version-pinned CA
bundle for a Snowman-specific Cloudflare authenticated-origin-pull certificate.

Use a custom zone-level or hostname-level Cloudflare certificate, not the shared
global certificate, because Cloudflare documents that the global certificate is
not exclusive to one account. AWS documents that ALB mutual-TLS verify mode
authenticates the client certificate against an S3-backed trust store. These two
controls, plus exact-host WAF enforcement, close both direct-IP and alternate
Cloudflare-account origin paths.

References:

- <https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/explanation/>
- <https://developers.cloudflare.com/ssl/origin-configuration/authenticated-origin-pull/set-up/>
- <https://docs.aws.amazon.com/elasticloadbalancing/latest/application/mutual-authentication.html>

## Source controls

- `edge_enabled=false` is the cost-controlled baseline; no ALB, WAF, trust
  store, or edge log bucket exists until an explicit reviewed plan enables it.
- Enabling the edge requires the public CA PEM and its independently reviewed
  SHA-256 digest. The private key never enters Terraform or AWS.
- The trust bundle and logs use private, encrypted S3 buckets. The trust store
  pins the exact S3 object version.
- The listener allows TLS 1.2/1.3, verifies the client certificate, preserves the
  host, and drops invalid headers.
- WAF blocks every host except the exact Snowman hostname, applies client-IP
  rate control using `CF-Connecting-IP` only after the Cloudflare network/mTLS
  gates, and applies AWS common/bad-input managed rules.
- Request sampling is disabled to avoid copying arbitrary request content into
  WAF samples. Encrypted, retained WAF logs redact authorization, cookies, and
  query strings; governed ALB access logs remain enabled.
- The ALB reaches only relay port 8080 and its readiness port 8081 through exact
  security-group references. It has no database, Valkey, worker, or model path.

## Activation evidence

Before DNS is proxied to the ALB, evidence must prove the Cloudflare account and
zone, hostname-specific client certificate, CA digest, reviewed Cloudflare IP
ranges, ACM hostname/certificate, immutable Terraform plan, WAF association,
and ALB log delivery. Negative tests must reject direct ALB requests, missing or
foreign client certificates, wrong Host headers, malformed headers, and sources
outside Cloudflare. Positive WebSocket, REST, media, health, and reconnect tests
must pass through the proxied Snowman hostname.

The Cloudflare certificate configuration and DNS proxy enablement require the
Snowman Cloudflare account. They are external-account activation actions, not
reasons to weaken the source boundary or enable the edge early.
