# ADR 0004: Private specialist model fleet and scale-to-zero

- Status: Accepted for dormant staging implementation
- Date: 2026-07-26
- Decision owner: Snowman AI sole-founder operator

## Decision

Snowman's default specialist models run in the Snowman Command Center AWS
workload account as network-isolated SageMaker inference components. Each public
catalog route binds an exact endpoint and exact inference-component name. Images
come only from digest-pinned `snowman-inference/*` repositories in the same
account; weights come only from a content-addressed, object-locked, KMS-encrypted
Snowman S3 bucket. Agents, clients, and Analyst 360 never receive model runtime
coordinates or credentials and invoke only the KMS-authenticated private gateway.

The inference fleet uses a separate Terraform state and pinned provider set from
Command Center and Analyst 360. This limits the blast radius of the newer AWS
inference-component resource model. The fleet is hard-dormant by default and
requires separate foundation, endpoint, and activation gates.

Idle inference components and their managed endpoint instances may scale to
zero. A target-tracking policy handles normal load, while a step policy triggered
by `NoCapacityInvocationFailures` wakes a component from zero. This is a cost
control, not a latency claim: the first invocation at zero capacity fails while
AWS provisions capacity. The workforce must retry the same fenced generation ID
until its deadline without reserving or charging spend twice, creating duplicate
artifacts, or losing cancellation authority.

## Enforcement

- The model gateway validates and invokes operations-owned endpoint/component
  coordinates; caller data cannot select them.
- Gateway IAM lists exact endpoint and inference-component ARNs and contains no
  SageMaker wildcard action or resource for invocation.
- Model execution identities are distinct per catalog family and can read one
  exact model object and one exact ECR repository.
- Model containers have SageMaker network isolation and use only private Snowman
  subnets/security groups; data capture is disabled.
- Instance and copy maxima are bounded in Terraform, alarms reach the monitored
  Snowman operations topic, and all activation switches default false.

## Consequences

Snowman gains configurable best-fit models without sending prompts or outputs to
Block or a hosted model vendor. The tradeoff is operational ownership of model
images, weights, evaluation, GPU quotas, cold-start latency, patching, and cost.
A quality-critical route may later maintain warm minimum capacity, but only after
recorded latency/cost evidence and explicit configuration; it is not the default.

Production remains blocked until pinned images and weights exist, model/license
provenance and evaluations pass, cold-start retries and spend reconciliation are
proven in staging, and the launch evidence names the exact deployed resources.
