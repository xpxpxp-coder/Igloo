# Snowman private model gateway

Status: service, client contract, dormant AWS task boundary, private ingress
substrate, and local tests are implemented; inference deployment and staged
proof remain.

`snowman-model-gateway` is the only generative model boundary used by governed
Analyst 360 execution. Command Center clients and workforce workers never receive
a provider endpoint or credential and cannot call a model runtime directly.

## Enforced request path

1. Analyst resolves immutable evidence under its own tenant/client/project
   authority and submits only bounded governed artifact projections.
2. Analyst signs the exact canonical request with its asymmetric AWS KMS key.
3. The gateway verifies the exact principal/key binding, freshness and a
   one-time Valkey nonce, then re-evaluates tenant, client, project, specialist
   role, capability, classification, model, token and cost policy.
4. The route comes only from operations configuration. It must be a private
   `.internal`/`.local` HTTP origin, a Snowman-owned HTTPS origin, or an exact
   same-account SageMaker endpoint and inference component; request data can
   never select or override either coordinate.
5. The gateway invokes either a pinned OpenAI-compatible Snowman runtime with
   proxies and redirects disabled or SageMaker Runtime through the VPC interface
   endpoint and task-role SigV4 authentication. It accepts only JSON, enforces a
   hard response-size ceiling, rejects partial model output, validates exact
   usage/cost ceilings, and returns content and request digests.
6. Analyst revalidates every response coordinate and digest, packages the
   result under Analyst artifact authority, runs deterministic QA, and creates a
   human approval. Command Center receives only immutable artifact coordinates.

The gateway stores no prompt or output. Its dedicated Valkey identity can only
`SET` replay keys under `snowman:model-gateway:nonce:*` and `PING`. The dormant
ECS task runs without a public IP, as non-root, with a read-only root filesystem
and all Linux capabilities dropped. Its task role has only exact `kms:Verify`
and exact ElastiCache connection grants. SageMaker routes add only
`sagemaker:InvokeEndpoint` on their exact configured endpoint and inference
component ARNs; there is no wildcard inference permission.

The AWS root now also defines a default-off cross-account PrivateLink provider.
It uses an internal Network Load Balancer with Snowman TLS, endpoint-service
acceptance, and an exact Analyst-account principal allowlist. PrivateLink
traffic bypasses the NLB's empty client-ingress rule set only at the AWS service
boundary; the NLB security group can egress solely to the model-gateway security
group on port 8443. No public load balancer, public IP, CIDR ingress, peering, or
shared VPC is introduced.

Transient inference failure is now an explicit `503` contract with a bounded
`inference_unavailable` code, `retryable=true`, and `Retry-After: 60`. Analyst
derives one stable generation ID per exact job/model/role/capability tuple and
honors the retry floor, while permanent request, policy, authorization, replay,
and budget failures remain non-retryable. Lost-success response reconciliation
is still a separate production gate.

## Remaining production gates

- Provision and prove the Analyst interface endpoint plus its TLS/DNS identity;
  the provider-side PrivateLink substrate is now defined but remains dormant.
- Build, evaluate, pin, scan, sign, and deploy the Snowman-hosted inference
  images and weights into the now-defined hard-dormant private inference fleet.
  Hosted third-party inference remains prohibited.
- Prove the now-implemented stable generation and retry contract in staged
  scale-from-zero operation without duplicate charges or artifacts.
- Add response-receipt reconciliation to the Command Center spend ledger and a
  crash/retry test that proves a lost response cannot create untracked spend.
- Add saturation, timeout, cancellation, malformed-backend, cross-tenant,
  direct-egress denial, failover, and recovery tests in dormant staging.
- Export immutable route/catalog, image, KMS/IAM, network, test, and cost
  evidence before any desired count can be raised.

These gates prevent a production-readiness claim; they do not require a Block
service or any non-Snowman runtime endpoint.
