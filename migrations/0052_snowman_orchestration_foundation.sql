-- Metadata-only control state for Snowman's continuously operating specialist
-- teams. This composes the existing workforce task/lease, coordinator, model,
-- tool, proactive-action, work-schedule, and Analyst 360 evidence boundaries.
-- It is not a second executor and stores no raw client data, prompt, mail,
-- transcript, provider endpoint, credential, or arbitrary tool input.

CREATE TABLE snowman_orchestration_projects (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL,
    project_id UUID NOT NULL,
    project_manifest_reference TEXT NOT NULL CHECK (
        project_manifest_reference ~ '^analyst360:sha256:[0-9a-f]{64}$'
    ),
    project_manifest_sha256 BYTEA NOT NULL CHECK (octet_length(project_manifest_sha256) = 32),
    deadline_at TIMESTAMPTZ,
    max_cost_microusd BIGINT NOT NULL CHECK (max_cost_microusd >= 0),
    status TEXT NOT NULL DEFAULT 'active' CHECK (
        status IN ('active','paused','completed','cancelled','archived')
    ),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, project_id),
    CHECK (deadline_at IS NULL OR deadline_at > created_at)
);

CREATE INDEX idx_snowman_orchestration_projects_status
    ON snowman_orchestration_projects (community_id, workspace_id, status, deadline_at);

CREATE TABLE snowman_orchestration_plans (
    community_id UUID NOT NULL REFERENCES communities(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    request_id UUID NOT NULL,
    project_id UUID,
    work_kind TEXT NOT NULL CHECK (work_kind IN (
        'user_request','project','deadline','recurring_analytics','next_best_action'
    )),
    generation BIGINT NOT NULL CHECK (generation > 0),
    supersedes_plan_id UUID,
    superseded_by_plan_id UUID,
    objective_sha256 BYTEA NOT NULL CHECK (octet_length(objective_sha256) = 32),
    classification TEXT NOT NULL CHECK (
        classification IN ('internal','confidential','restricted')
    ),
    plan_sha256 BYTEA NOT NULL CHECK (octet_length(plan_sha256) = 32),
    max_cost_microusd BIGINT NOT NULL CHECK (max_cost_microusd >= 0),
    automatic_execution_enabled BOOLEAN NOT NULL DEFAULT FALSE,
    minimum_confidence_basis_points INTEGER NOT NULL DEFAULT 10000 CHECK (
        minimum_confidence_basis_points BETWEEN 0 AND 10000
    ),
    minimum_value_basis_points INTEGER NOT NULL DEFAULT 10000 CHECK (
        minimum_value_basis_points BETWEEN 0 AND 10000
    ),
    maximum_risk_basis_points INTEGER NOT NULL DEFAULT 0 CHECK (
        maximum_risk_basis_points BETWEEN 0 AND 10000
    ),
    max_automatic_task_cost_microusd BIGINT NOT NULL DEFAULT 0 CHECK (
        max_automatic_task_cost_microusd >= 0
    ),
    deadline_at TIMESTAMPTZ NOT NULL,
    state TEXT NOT NULL DEFAULT 'draft' CHECK (
        state IN ('draft','active','paused','completed','cancelled','superseded')
    ),
    activated_at TIMESTAMPTZ,
    cancelled_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, plan_id),
    UNIQUE (community_id, plan_id, generation),
    UNIQUE (community_id, request_id, generation),
    FOREIGN KEY (community_id, request_id)
        REFERENCES snowman_work_requests(community_id, request_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, project_id)
        REFERENCES snowman_orchestration_projects(community_id, project_id),
    FOREIGN KEY (community_id, supersedes_plan_id)
        REFERENCES snowman_orchestration_plans(community_id, plan_id),
    FOREIGN KEY (community_id, superseded_by_plan_id)
        REFERENCES snowman_orchestration_plans(community_id, plan_id),
    CHECK ((generation = 1) = (supersedes_plan_id IS NULL)),
    CHECK (supersedes_plan_id IS NULL OR supersedes_plan_id <> plan_id),
    CHECK (superseded_by_plan_id IS NULL OR superseded_by_plan_id <> plan_id),
    CHECK ((state = 'cancelled') = (cancelled_at IS NOT NULL)),
    CHECK (deadline_at > created_at),
    CHECK (
        NOT automatic_execution_enabled OR
        (max_automatic_task_cost_microusd > 0 AND maximum_risk_basis_points < 10000)
    )
);

CREATE UNIQUE INDEX idx_snowman_orchestration_one_live_generation
    ON snowman_orchestration_plans (community_id, request_id)
    WHERE state IN ('active','paused');

CREATE TABLE snowman_orchestration_schedule_policies (
    community_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    recurring_schedule_reference TEXT CHECK (
        recurring_schedule_reference IS NULL OR
        recurring_schedule_reference ~ '^snowman:work-schedule:[0-9a-f-]{36}:generation:[1-9][0-9]*$'
    ),
    timezone TEXT NOT NULL CHECK (
        length(timezone) BETWEEN 3 AND 64 AND
        timezone ~ '^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)+$'
    ),
    timezone_database_version TEXT NOT NULL CHECK (
        length(timezone_database_version) BETWEEN 1 AND 64
    ),
    quiet_start_local_minute INTEGER NOT NULL CHECK (
        quiet_start_local_minute BETWEEN 0 AND 1439
    ),
    quiet_end_local_minute INTEGER NOT NULL CHECK (
        quiet_end_local_minute BETWEEN 0 AND 1439
    ),
    allow_deadline_reminders BOOLEAN NOT NULL DEFAULT FALSE,
    reminder_offsets_seconds INTEGER[] NOT NULL DEFAULT '{}' CHECK (
        cardinality(reminder_offsets_seconds) <= 16
    ),
    policy_sha256 BYTEA NOT NULL CHECK (octet_length(policy_sha256) = 32),
    PRIMARY KEY (community_id, plan_id),
    FOREIGN KEY (community_id, plan_id)
        REFERENCES snowman_orchestration_plans(community_id, plan_id) ON DELETE CASCADE
);

CREATE TABLE snowman_orchestration_personas (
    community_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    persona_id UUID NOT NULL,
    persona_version_sha256 BYTEA NOT NULL CHECK (octet_length(persona_version_sha256) = 32),
    service_identity_id UUID NOT NULL,
    specialist_role TEXT NOT NULL CHECK (length(specialist_role) BETWEEN 1 AND 128),
    model_id TEXT NOT NULL CHECK (length(model_id) BETWEEN 1 AND 256),
    model_route_revision BIGINT NOT NULL CHECK (model_route_revision > 0),
    maximum_classification TEXT NOT NULL CHECK (
        maximum_classification IN ('internal','confidential','restricted')
    ),
    max_cost_microusd BIGINT NOT NULL CHECK (max_cost_microusd >= 0),
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (community_id, plan_id, persona_id),
    UNIQUE (community_id, plan_id, service_identity_id),
    FOREIGN KEY (community_id, plan_id)
        REFERENCES snowman_orchestration_plans(community_id, plan_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, service_identity_id)
        REFERENCES snowman_workforce_identities(community_id, identity_id),
    FOREIGN KEY (community_id, model_id)
        REFERENCES snowman_model_routes(community_id, model_id)
);

CREATE TABLE snowman_orchestration_persona_capabilities (
    community_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    persona_id UUID NOT NULL,
    capability TEXT NOT NULL CHECK (
        length(capability) BETWEEN 3 AND 128 AND
        capability ~ '^[a-z][a-z0-9_]*(\.[a-z0-9_]+)+$' AND
        capability NOT LIKE '%.all' AND capability NOT LIKE '%*%' AND
        capability NOT IN ('shell.execute','network.unrestricted','filesystem.unrestricted')
    ),
    automatic_execution_allowed BOOLEAN NOT NULL DEFAULT FALSE,
    PRIMARY KEY (community_id, plan_id, persona_id, capability),
    FOREIGN KEY (community_id, plan_id, persona_id)
        REFERENCES snowman_orchestration_personas(community_id, plan_id, persona_id)
        ON DELETE CASCADE
);

CREATE TABLE snowman_orchestration_tasks (
    community_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    plan_generation BIGINT NOT NULL CHECK (plan_generation > 0),
    request_id UUID NOT NULL,
    task_id UUID NOT NULL,
    persona_id UUID NOT NULL,
    usefulness_sha256 BYTEA NOT NULL CHECK (octet_length(usefulness_sha256) = 32),
    confidence_basis_points INTEGER NOT NULL CHECK (confidence_basis_points BETWEEN 0 AND 10000),
    value_basis_points INTEGER NOT NULL CHECK (value_basis_points BETWEEN 0 AND 10000),
    risk_basis_points INTEGER NOT NULL CHECK (risk_basis_points BETWEEN 0 AND 10000),
    reversible BOOLEAN NOT NULL,
    approval_required BOOLEAN NOT NULL,
    automatic_execution_candidate BOOLEAN NOT NULL DEFAULT FALSE,
    max_cost_microusd BIGINT NOT NULL CHECK (max_cost_microusd >= 0),
    deadline_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (community_id, plan_id, task_id),
    UNIQUE (community_id, plan_id, plan_generation, task_id),
    UNIQUE (community_id, request_id, task_id),
    FOREIGN KEY (community_id, plan_id, plan_generation)
        REFERENCES snowman_orchestration_plans(community_id, plan_id, generation)
        ON DELETE CASCADE,
    FOREIGN KEY (community_id, request_id, task_id)
        REFERENCES snowman_work_tasks(community_id, request_id, task_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, plan_id, persona_id)
        REFERENCES snowman_orchestration_personas(community_id, plan_id, persona_id),
    CHECK (reversible OR approval_required),
    CHECK (NOT automatic_execution_candidate OR (reversible AND NOT approval_required))
);

CREATE TABLE snowman_orchestration_task_context_refs (
    community_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    task_id UUID NOT NULL,
    context_manifest_reference TEXT NOT NULL CHECK (
        context_manifest_reference ~ '^analyst360:sha256:[0-9a-f]{64}$'
    ),
    PRIMARY KEY (community_id, plan_id, task_id, context_manifest_reference),
    FOREIGN KEY (community_id, plan_id, task_id)
        REFERENCES snowman_orchestration_tasks(community_id, plan_id, task_id)
        ON DELETE CASCADE
);

CREATE TABLE snowman_orchestration_work_product_receipts (
    community_id UUID NOT NULL,
    workspace_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    plan_generation BIGINT NOT NULL CHECK (plan_generation > 0),
    task_id UUID NOT NULL,
    lease_generation BIGINT NOT NULL CHECK (lease_generation > 0),
    execution_snapshot_sha256 BYTEA NOT NULL CHECK (
        octet_length(execution_snapshot_sha256) = 32
    ),
    outcome TEXT NOT NULL CHECK (outcome IN ('succeeded','blocked','failed','cancelled')),
    handoff_manifest_reference TEXT NOT NULL CHECK (
        handoff_manifest_reference ~ '^analyst360:sha256:[0-9a-f]{64}$'
    ),
    handoff_manifest_sha256 BYTEA NOT NULL CHECK (octet_length(handoff_manifest_sha256) = 32),
    receipt_sha256 BYTEA NOT NULL CHECK (octet_length(receipt_sha256) = 32),
    actual_cost_microusd BIGINT NOT NULL CHECK (actual_cost_microusd >= 0),
    completed_at TIMESTAMPTZ NOT NULL,
    accepted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (community_id, plan_id, plan_generation, task_id),
    FOREIGN KEY (community_id, plan_id, plan_generation, task_id)
        REFERENCES snowman_orchestration_tasks(
            community_id, plan_id, plan_generation, task_id
        )
        ON DELETE CASCADE,
    CHECK (completed_at <= accepted_at + INTERVAL '5 minutes')
);

CREATE TABLE snowman_orchestration_receipt_refs (
    community_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    plan_generation BIGINT NOT NULL,
    task_id UUID NOT NULL,
    reference_kind TEXT NOT NULL CHECK (reference_kind IN ('artifact','evidence','execution')),
    immutable_reference TEXT NOT NULL,
    PRIMARY KEY (
        community_id, plan_id, plan_generation, task_id, reference_kind, immutable_reference
    ),
    FOREIGN KEY (community_id, plan_id, plan_generation, task_id)
        REFERENCES snowman_orchestration_work_product_receipts(
            community_id, plan_id, plan_generation, task_id
        ) ON DELETE CASCADE,
    CHECK (
        (reference_kind IN ('artifact','evidence') AND
         immutable_reference ~ '^analyst360:sha256:[0-9a-f]{64}$') OR
        (reference_kind = 'execution' AND
         immutable_reference ~ '^snowman:(agent-job|model-generation|tool-action):[0-9a-f-]{36}:generation:[1-9][0-9]*$')
    )
);

CREATE TABLE snowman_orchestration_next_action_assessments (
    community_id UUID NOT NULL,
    action_id UUID NOT NULL,
    plan_id UUID NOT NULL,
    task_id UUID,
    value_basis_points INTEGER NOT NULL CHECK (value_basis_points BETWEEN 0 AND 10000),
    risk_basis_points INTEGER NOT NULL CHECK (risk_basis_points BETWEEN 0 AND 10000),
    quiet_hours_deferred_until TIMESTAMPTZ,
    assessment_sha256 BYTEA NOT NULL CHECK (octet_length(assessment_sha256) = 32),
    PRIMARY KEY (community_id, action_id),
    FOREIGN KEY (community_id, action_id)
        REFERENCES snowman_proactive_actions(community_id, action_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, plan_id)
        REFERENCES snowman_orchestration_plans(community_id, plan_id) ON DELETE CASCADE,
    FOREIGN KEY (community_id, plan_id, task_id)
        REFERENCES snowman_orchestration_tasks(community_id, plan_id, task_id)
);

CREATE INDEX idx_snowman_orchestration_receipts_handoff
    ON snowman_orchestration_work_product_receipts (
        community_id, plan_id, plan_generation, accepted_at
    );
