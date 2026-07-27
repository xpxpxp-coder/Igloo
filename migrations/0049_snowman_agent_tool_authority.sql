-- Durable, tenant-scoped authority and externally signed evidence for exact
-- agent tool actions. Raw prompts, tool input/output, shell strings, URLs,
-- credentials, client rows, transcripts, and provider payloads do not belong
-- in this control-plane ledger.

CREATE TABLE snowman_agent_tool_approvals (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    approval_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    job_id UUID NOT NULL,
    request_id UUID NOT NULL,
    task_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    action_sha256 BYTEA NOT NULL CHECK (octet_length(action_sha256) = 32),
    requested_by_identity_id UUID NOT NULL,
    approver_identity_id UUID NOT NULL,
    approver_capability_id TEXT NOT NULL CHECK (
        length(approver_capability_id) BETWEEN 1 AND 128 AND
        approver_capability_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'
    ),
    exceptional_control_id TEXT CHECK (
        exceptional_control_id IS NULL OR (
            length(exceptional_control_id) BETWEEN 1 AND 128 AND
            exceptional_control_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'
        )
    ),
    independence_required BOOLEAN NOT NULL DEFAULT FALSE,
    decision TEXT NOT NULL CHECK (decision IN ('approved','denied','revoked')),
    rationale_sha256 BYTEA NOT NULL CHECK (octet_length(rationale_sha256) = 32),
    decided_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, approval_id),
    UNIQUE (community_id, job_id, approval_id),
    FOREIGN KEY (community_id, job_id)
        REFERENCES snowman_agent_jobs(community_id, job_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, request_id, task_id)
        REFERENCES snowman_work_tasks(community_id, request_id, task_id) ON DELETE CASCADE,
    CHECK (expires_at > decided_at),
    CHECK ((exceptional_control_id IS NOT NULL) = independence_required),
    CHECK (NOT independence_required OR approver_identity_id <> requested_by_identity_id)
);

CREATE INDEX idx_snowman_agent_tool_approvals_exact
    ON snowman_agent_tool_approvals
       (community_id, job_id, task_id, generation, action_sha256, expires_at)
    WHERE decision = 'approved';

CREATE TABLE snowman_agent_tool_actions (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    action_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    request_id UUID NOT NULL,
    job_id UUID NOT NULL,
    task_id UUID NOT NULL,
    agent_identity_id UUID NOT NULL,
    service_identity_id UUID NOT NULL,
    requested_by_identity_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    lease_generation BIGINT NOT NULL CHECK (lease_generation > 0),
    lease_fence_sha256 BYTEA NOT NULL CHECK (octet_length(lease_fence_sha256) = 32),
    capability_id TEXT NOT NULL CHECK (
        length(capability_id) BETWEEN 1 AND 128 AND
        capability_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'
    ),
    tool_id TEXT NOT NULL CHECK (
        length(tool_id) BETWEEN 1 AND 128 AND
        tool_id ~ '^[A-Za-z0-9][A-Za-z0-9._-]*$'
    ),
    registry_sha256 BYTEA NOT NULL CHECK (octet_length(registry_sha256) = 32),
    classification TEXT NOT NULL CHECK (
        classification IN ('internal','confidential','restricted')
    ),
    minimization_evidence_sha256 BYTEA NOT NULL CHECK (
        octet_length(minimization_evidence_sha256) = 32
    ),
    input_sha256 BYTEA NOT NULL CHECK (octet_length(input_sha256) = 32),
    action_sha256 BYTEA NOT NULL CHECK (octet_length(action_sha256) = 32),
    approval_id UUID,
    impact TEXT NOT NULL CHECK (impact IN ('low','high','critical')),
    status TEXT NOT NULL CHECK (status IN (
        'authorized','indeterminate','succeeded','failed','cancelled','denied'
    )),
    deadline_at TIMESTAMPTZ NOT NULL,
    authorized_at TIMESTAMPTZ NOT NULL,
    invocation_started_at TIMESTAMPTZ,
    completed_at TIMESTAMPTZ,
    result_sha256 BYTEA CHECK (
        result_sha256 IS NULL OR octet_length(result_sha256) = 32
    ),
    redaction_evidence_sha256 BYTEA CHECK (
        redaction_evidence_sha256 IS NULL OR
        octet_length(redaction_evidence_sha256) = 32
    ),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, action_id),
    UNIQUE (community_id, job_id, action_id),
    FOREIGN KEY (community_id, job_id)
        REFERENCES snowman_agent_jobs(community_id, job_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, request_id, task_id)
        REFERENCES snowman_work_tasks(community_id, request_id, task_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, service_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    FOREIGN KEY (community_id, job_id, approval_id)
        REFERENCES snowman_agent_tool_approvals(community_id, job_id, approval_id),
    CHECK (deadline_at > authorized_at),
    CHECK (
        (impact = 'low' AND approval_id IS NULL) OR
        (impact IN ('high','critical') AND approval_id IS NOT NULL)
    ),
    CHECK (
        status <> 'authorized' OR (
            invocation_started_at IS NULL AND completed_at IS NULL AND
            result_sha256 IS NULL
        )
    ),
    CHECK (
        status <> 'indeterminate' OR (
            invocation_started_at IS NOT NULL AND completed_at IS NULL
        )
    ),
    CHECK (
        status NOT IN ('succeeded','failed','cancelled','denied') OR
        (completed_at IS NOT NULL AND result_sha256 IS NOT NULL AND
         redaction_evidence_sha256 IS NOT NULL)
    ),
    CHECK (
        status NOT IN ('cancelled','denied') OR invocation_started_at IS NULL
    )
);

CREATE INDEX idx_snowman_agent_tool_actions_live
    ON snowman_agent_tool_actions
       (community_id, job_id, status, deadline_at, action_id)
    WHERE status IN ('authorized','indeterminate');

CREATE INDEX idx_snowman_agent_tool_actions_lease
    ON snowman_agent_tool_actions
       (community_id, task_id, lease_generation, status);

-- Append-only evidence. Each receipt is signed with a dedicated asymmetric
-- KMS key and checkpointed outside PostgreSQL, so a database writer cannot
-- silently rewrite the chain and manufacture matching signatures/checkpoints.
CREATE TABLE snowman_agent_tool_receipts (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    receipt_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    job_id UUID NOT NULL,
    task_id UUID NOT NULL,
    generation BIGINT NOT NULL CHECK (generation > 0),
    action_id UUID NOT NULL,
    sequence BIGINT NOT NULL CHECK (sequence >= 0),
    status TEXT NOT NULL CHECK (status IN (
        'authorized','indeterminate','succeeded','failed','cancelled','denied'
    )),
    action_sha256 BYTEA NOT NULL CHECK (octet_length(action_sha256) = 32),
    result_sha256 BYTEA CHECK (
        result_sha256 IS NULL OR octet_length(result_sha256) = 32
    ),
    redaction_evidence_sha256 BYTEA NOT NULL CHECK (
        octet_length(redaction_evidence_sha256) = 32
    ),
    previous_receipt_sha256 BYTEA CHECK (
        previous_receipt_sha256 IS NULL OR
        octet_length(previous_receipt_sha256) = 32
    ),
    receipt_sha256 BYTEA NOT NULL CHECK (octet_length(receipt_sha256) = 32),
    signing_key_arn TEXT NOT NULL CHECK (
        length(signing_key_arn) BETWEEN 20 AND 2048 AND
        signing_key_arn ~ '^arn:aws:kms:[a-z0-9-]+:[0-9]{12}:key/[A-Za-z0-9._/-]+$'
    ),
    signature_algorithm TEXT NOT NULL CHECK (
        signature_algorithm IN ('ECDSA_SHA_256','RSASSA_PSS_SHA_256')
    ),
    signature BYTEA NOT NULL CHECK (octet_length(signature) BETWEEN 64 AND 16384),
    signature_sha256 BYTEA NOT NULL CHECK (octet_length(signature_sha256) = 32),
    external_checkpoint_sha256 BYTEA NOT NULL CHECK (
        octet_length(external_checkpoint_sha256) = 32
    ),
    occurred_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, receipt_id),
    UNIQUE (community_id, action_id, sequence),
    UNIQUE (community_id, action_id, receipt_sha256),
    FOREIGN KEY (community_id, action_id)
        REFERENCES snowman_agent_tool_actions(community_id, action_id) ON DELETE CASCADE,
    CHECK ((sequence = 0) = (previous_receipt_sha256 IS NULL)),
    CHECK (
        (status IN ('succeeded','failed','cancelled','denied')) =
        (result_sha256 IS NOT NULL)
    )
);

CREATE INDEX idx_snowman_agent_tool_receipts_chain
    ON snowman_agent_tool_receipts
       (community_id, action_id, sequence, receipt_sha256);

-- General relay and existing job/model/meeting roles must never inherit tool
-- action authority through future default grants.
REVOKE ALL ON TABLE snowman_agent_tool_approvals FROM PUBLIC;
REVOKE ALL ON TABLE snowman_agent_tool_actions FROM PUBLIC;
REVOKE ALL ON TABLE snowman_agent_tool_receipts FROM PUBLIC;
