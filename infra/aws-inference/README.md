# Snowman private inference fleet

This is a separate Terraform state for Snowman-hosted specialist models. It is
separate from both Command Center and Analyst 360 so a provider upgrade or GPU
endpoint change cannot destabilize either application state. It uses AWS provider
6.56.0 because provider 5.100.0 cannot express the model-less endpoint
configuration required by inference components; AWS Cloud Control provider
1.94.0 supplies the inference-component resource.

Both activation switches default to false. `foundation_enabled` creates only an
object-locked, versioned, KMS-encrypted model bucket and one least-privilege
SageMaker execution identity per catalog family. `endpoints_enabled` additionally
requires `activation_approved`, exact private subnet/security-group coordinates,
a monitored operations topic, digest-pinned Snowman ECR images, content-addressed
model artifacts, and bounded GPU/copy counts.

Each endpoint starts with one instance because SageMaker endpoint creation
requires initial capacity. Managed scaling permits zero idle instances, and each
inference component starts with zero model copies. Application Auto Scaling uses
target tracking plus a `NoCapacityInvocationFailures` step policy to wake a cold
component. The first invocation during zero capacity is expected to fail while
AWS provisions capacity, which can take minutes; production acceptance therefore
requires the workforce to retry the same fenced generation id without double
charging, duplicating artifacts, or losing deadline state.

The model container has network isolation enabled, uses only private Snowman
subnets and the inference security group, can read one exact content-addressed
model object, and can pull one exact Snowman ECR repository. No data capture is
enabled, so prompts and outputs are not intentionally persisted by SageMaker.
The only wildcard role permissions are ECR authentication and EC2 VPC-interface
operations whose APIs do not support useful resource-level scoping; the workload
still has no NAT or internet route.

Do not enable endpoints until all model image signatures/SBOMs, weight digests,
usage rights, quality and safety evaluations, regional GPU quota, cold-start
retry tests, budget alarms, and restore/rollback evidence pass. Apply with a
dedicated inference backend and verified Snowman workload identity; never reuse
the Command Center or Analyst state backend key.
