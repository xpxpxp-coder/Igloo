# Snowman Command Center SLO and observability contract

## Boundary

CloudWatch encrypted stdout logs, Container Insights, AWS managed-service
metrics, and the Snowman operations topic are the authoritative AWS telemetry
path. OTLP remains unset in the checked-in task definitions. A future collector
may be enabled only at a private `snowmanai.org` endpoint or an AWS-owned X-Ray
endpoint in the exact workload account; the launch-evidence validator rejects
any other exporter. No Block-operated telemetry, crash, analytics, support, or
update surface is permitted.

Metrics, log attributes, dashboards, and notifications are control metadata
only. They may include opaque tenant/workspace/job/task/session/correlation IDs,
status, duration buckets, bounded counts, model route IDs, policy decisions, and
cost totals. They must never include tenant names, people, email addresses,
meeting coordinates, prompts, messages, transcripts, attachment or artifact
bodies, citations, query results, credentials, model output, or raw client data.
Hashing a low-entropy value such as an email address is not acceptable
redaction.

## Initial service levels

SLO periods begin only while a reviewed verification or production window is
active. Dormant periods are reported separately and never counted as success.

| Service indicator | Staging acceptance | Production objective | Paging condition |
|---|---:|---:|---|
| Authenticated command edge availability | 99.9% over a 7-day verification window | 99.9% rolling 30 days | Two consecutive 5-minute windows below 99% |
| Governed request admission, excluding valid policy denials | 99.5% over staged load | 99.9% rolling 30 days | Error ratio above 1% for 10 minutes |
| Accepted job status freshness | 99% within 60 seconds | 99% within 60 seconds | Oldest nonterminal update exceeds 5 minutes |
| Meeting admission decision after a sealed event revision | 99% within 30 seconds | 99% within 30 seconds | Queue age exceeds 2 minutes |
| Audit-chain verification and KMS-checkpoint continuity | 100% | 100% | Any gap, invalid signature, or checkpoint age breach |
| Cross-tenant denial tests | 100% denied with zero payload bytes | 100% | Any unexpected success or payload byte |
| Budget and capability enforcement | 100% | 100% | Any unreserved spend or unauthorized action |
| Restore integrity | 100% of scheduled drills | 100% | Any digest, tenant-fence, or smoke-test failure |

The sole-founder operator owns the monitored Snowman mailbox and dashboard.
There is no fictional rotation or second internal approver. The operations SNS
subscription must be confirmed and alarm delivery exercised before a manifest
can pass. Where an independent review is legally or contractually required, it
is recorded as an external evidence item rather than an invented employee.

## Required evidence

Every staging verification records dashboard JSON, alarm state and delivery
receipts, synthetic probe results, representative redaction tests, missing-data
behavior, dependency degradation, queue age, runtime cost, and correlation from
request through evidence receipt. Alert messages must be inspected to prove
that they contain identifiers and control state only. The report is stored as a
version-bound object in the Object Lock audit bucket and referenced by digest in
`snowman.launch-evidence.v1`.

The Terraform dashboard and error alarms are an operability baseline, not proof
that the SLOs pass. Exact service metrics, private synthetic probes, alarm
delivery, load behavior, and alert redaction remain mandatory staged drills.
