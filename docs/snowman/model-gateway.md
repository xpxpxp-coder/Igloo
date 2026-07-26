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
   same-account SageMaker endpoint; request data can never select or override it.
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
`sagemaker:InvokeEndpoint` on their exact configured endpoint ARNs; there is no
wildcard inference permission.

The AWS root now also defines a default-off cross-account PrivateLink provider.
It uses an internal Network Load Balancer with Snowman TLS, endpoint-service
acceptance, and an exact Analyst-account principal allowlist. PrivateLink
traffic bypasses the NLB's empty client-ingress rule set only at the AWS service
boundary; the NLB security group can egress solely to the model-gateway security
group on port 8443. No public load balancer, public IP, CIDR ingress, peering, or
shared VPC is introduced.

## Remaining production gates

- Provision and prove the Analyst interface endpoint plus its TLS/DNS identity;
  the provider-side PrivateLink substrate is now defined but remains dormant.
- Build, evaluate, pin, scan, sign, and deploy the Snowman-hosted inference
  images and model catalog. Hosted third-party inference remains prohibited.
- Add response-receipt reconciliation to the Command Center spend ledger and a
  crash/retry test that proves a lost response cannot create untracked spend.
- Add saturation, timeout, cancellation, malformed-backend, cross-tenant,
  direct-egress denial, failover, and recovery tests in dormant staging.
- Export immutable route/catalog, image, KMS/IAM, network, test, and cost
  evidence before any desired count can be raised.

These gates prevent a production-readiness claim; they do not require a Block
service or any non-Snowman runtime endpoint.
