import { z } from "zod";

import {
  parseTeamOperationsProjection,
  projectTeamOperationsSnapshot,
  type TeamOperationsApiProjection,
} from "./teamOperationsApiContract";
import {
  parseTeamOperationsSnapshot,
  type TeamOperationsSnapshot,
} from "./teamOperationsContract";

export type TeamOperationsLoadResult =
  | {
      kind: "empty";
      source: "live";
      message: string;
    }
  | {
      kind: "disabled";
      reason: string;
      requiredConnection: string;
    }
  | {
      kind: "ready";
      source: "fixture" | "live";
      snapshot: TeamOperationsSnapshot;
      controls: TeamOperationsControls;
    };

export type TeamOperationsAction =
  | "activate"
  | "pause"
  | "cancel"
  | "supersede";

export type TeamOperationsControls = Readonly<
  Record<TeamOperationsAction | "approve", boolean>
>;

export type TeamOperationsCommandResult = {
  receipt: {
    commandId: string;
    action: TeamOperationsAction | "approve" | "deny" | "create_request";
    status: string;
    digestSha256: string;
    recordedAt: string;
  };
  snapshot?: TeamOperationsSnapshot;
  controls?: TeamOperationsControls;
};

export type CreateGovernedRequestInput = {
  objective: string;
  classification: "internal" | "confidential" | "restricted";
  deadlineAt: string;
  maxCostMicrousd: number;
  contextReferences: string[];
};

export interface TeamOperationsAdapter {
  load(signal: AbortSignal): Promise<TeamOperationsLoadResult>;
  execute?(
    action: TeamOperationsAction,
    signal: AbortSignal,
  ): Promise<TeamOperationsCommandResult>;
  decideApproval?(
    approvalId: string,
    taskId: string,
    taskSnapshotSha256: string,
    decision: "approved" | "denied",
    signal: AbortSignal,
  ): Promise<TeamOperationsCommandResult>;
  createRequest?(
    input: CreateGovernedRequestInput,
    signal: AbortSignal,
  ): Promise<TeamOperationsCommandResult>;
}

type SignedEvent = Record<string, unknown>;

export type LiveTeamOperationsAdapterOptions = {
  orchestrationOrigin: string;
  relayOrigin: string;
  tenantId: string;
  workspaceId: string;
  signEvent(input: {
    kind: number;
    content: string;
    tags: string[][];
  }): Promise<SignedEvent>;
  fetcher?: typeof fetch;
};

const uuid = z.string().uuid();
const sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const apiReceiptSchema = z
  .object({
    schema_version: z.literal("snowman.orchestration.api-receipt.v1"),
    command_id: uuid,
    community_id: uuid,
    workspace_id: uuid,
    plan_id: uuid,
    plan_generation: z.number().int().positive(),
    status: z.enum(["applied", "duplicate"]),
    request_sha256: sha256,
    accepted_at: z.string().datetime({ offset: true }),
  })
  .strict();

const workforceApprovalReceiptSchema = z
  .object({
    schema_version: z.literal("snowman.work.task.approval.v1"),
    approval_id: uuid,
    request_id: uuid,
    task_id: uuid,
    decision: z.enum(["approved", "denied"]),
    expires_at: z.string().datetime({ offset: true }),
    inserted: z.boolean(),
  })
  .strict();

const workforceRequestReceiptSchema = z
  .object({
    schema_version: z.literal("snowman.work.request.accepted.v1"),
    request_id: uuid,
    status: z.string().min(1).max(64),
    inserted: z.boolean(),
    status_url: z.string().startsWith("/api/snowman/v1/work-requests/"),
  })
  .strict();

class TeamOperationsNotFoundError extends Error {}

function exactSnowmanOrigin(value: string): string {
  const url = new URL(value);
  const host = url.hostname.toLowerCase();
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.pathname !== "/" ||
    (host !== "snowmanai.org" && !host.endsWith(".snowmanai.org"))
  ) {
    throw new Error("Team operations requires an exact Snowman HTTPS origin.");
  }
  return url.origin;
}

async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest(
    "SHA-256",
    new TextEncoder().encode(value),
  );
  return [...new Uint8Array(digest)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

async function authorization(
  signEvent: LiveTeamOperationsAdapterOptions["signEvent"],
  method: "GET" | "POST",
  url: string,
  body?: string,
): Promise<string> {
  const tags = [
    ["u", url],
    ["method", method],
    ["nonce", crypto.randomUUID()],
  ];
  if (body !== undefined) tags.push(["payload", await sha256Hex(body)]);
  const event = await signEvent({ kind: 27235, content: "", tags });
  return `Nostr ${btoa(JSON.stringify(event))}`;
}

async function jsonResponse(response: Response): Promise<unknown> {
  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const message =
      typeof body === "object" &&
      body !== null &&
      "error" in body &&
      typeof body.error === "string"
        ? body.error
        : `HTTP ${response.status}`;
    throw new Error(`Governed team operation failed: ${message}`);
  }
  return body;
}

function controls(
  projection: TeamOperationsApiProjection,
): TeamOperationsControls {
  const capabilities = new Set(projection.authority.capabilities);
  return {
    activate:
      capabilities.has("orchestration.plans.activate") &&
      ["draft", "paused"].includes(projection.plan.state),
    pause:
      capabilities.has("orchestration.plans.pause") &&
      projection.plan.state === "active",
    cancel:
      capabilities.has("orchestration.plans.cancel") &&
      ["draft", "active", "paused"].includes(projection.plan.state),
    supersede:
      capabilities.has("orchestration.plans.supersede") &&
      projection.plan.supersedesPlanId !== null &&
      ["draft", "paused"].includes(projection.plan.state),
    approve: capabilities.has("workforce.tasks.approve"),
  };
}

function evidenceDigestInput(
  action: TeamOperationsAction,
  projection: TeamOperationsApiProjection,
  commandId: string,
): string {
  return [
    "snowman.command-center.lifecycle-evidence.v1",
    action,
    projection.tenantId,
    projection.workspaceId,
    projection.plan.planId,
    String(projection.plan.generation),
    commandId,
  ].join("\0");
}

export function createDisabledTeamOperationsAdapter(): TeamOperationsAdapter {
  return {
    async load() {
      return {
        kind: "disabled",
        reason:
          "The private Snowman orchestration origin and workspace are not configured in this build. No work is being started, approved, or cancelled from this screen.",
        requiredConnection:
          "Exact Snowman HTTPS orchestration origin, tenant, workspace, and live workforce session",
      };
    },
  };
}

export function createFixtureTeamOperationsAdapter(
  value: unknown,
): TeamOperationsAdapter {
  return {
    async load(signal) {
      if (signal.aborted) {
        throw new DOMException("The request was cancelled", "AbortError");
      }
      return {
        kind: "ready",
        source: "fixture",
        snapshot: parseTeamOperationsSnapshot(value),
        controls: {
          activate: false,
          pause: false,
          cancel: false,
          supersede: false,
          approve: false,
        },
      };
    },
  };
}

export function createLiveTeamOperationsAdapter(
  options: LiveTeamOperationsAdapterOptions,
): TeamOperationsAdapter {
  const orchestrationOrigin = exactSnowmanOrigin(options.orchestrationOrigin);
  const relayOrigin = exactSnowmanOrigin(options.relayOrigin);
  const tenantId = uuid.parse(options.tenantId);
  const workspaceId = uuid.parse(options.workspaceId);
  const fetcher = options.fetcher ?? fetch;
  const planPath = `/v1/tenants/${tenantId}/workspaces/${workspaceId}/plans`;
  let currentProjection: TeamOperationsApiProjection | null = null;

  const loadProjection = async (signal: AbortSignal) => {
    const url = `${orchestrationOrigin}${planPath}`;
    const response = await fetcher(url, {
      headers: {
        Authorization: await authorization(options.signEvent, "GET", url),
      },
      redirect: "error",
      signal,
    });
    if (response.status === 404) {
      throw new TeamOperationsNotFoundError(
        "No governed orchestration plan exists in this workspace yet.",
      );
    }
    const projection = parseTeamOperationsProjection(
      await jsonResponse(response),
    );
    if (
      projection.tenantId !== tenantId ||
      projection.workspaceId !== workspaceId
    ) {
      throw new Error("Team operations response crossed its bound workspace.");
    }
    currentProjection = projection;
    return projection;
  };

  const reload = async (signal: AbortSignal) =>
    projectTeamOperationsSnapshot(await loadProjection(signal));

  return {
    async load(signal) {
      let projection: TeamOperationsApiProjection;
      try {
        projection = await loadProjection(signal);
      } catch (error) {
        if (error instanceof TeamOperationsNotFoundError) {
          return {
            kind: "empty",
            source: "live",
            message: error.message,
          };
        }
        throw error;
      }
      return {
        kind: "ready",
        source: "live",
        snapshot: projectTeamOperationsSnapshot(projection),
        controls: controls(projection),
      };
    },
    async execute(action, signal) {
      const projection = currentProjection ?? (await loadProjection(signal));
      if (!controls(projection)[action]) {
        throw new Error(
          "This lifecycle action is not authorized for the live plan.",
        );
      }
      const commandId = crypto.randomUUID();
      const evidenceSha256 = await sha256Hex(
        evidenceDigestInput(action, projection, commandId),
      );
      const authority = projection.authority;
      const common = {
        schema_version: "snowman.orchestration.lifecycle.v1",
        command_id: commandId,
        service_identity_id: authority.identityId,
        service_principal: authority.principal,
        policy_generation: authority.policyGeneration,
      };
      const path = `${planPath}/${projection.plan.planId}/${action}`;
      let body: Record<string, unknown>;
      if (action === "cancel") {
        body = {
          ...common,
          schema_version: "snowman.orchestration.command.v1",
          plan_generation: projection.plan.generation,
          cancellation_evidence_sha256: evidenceSha256,
        };
      } else if (action === "supersede") {
        const supersededPlanId = projection.plan.supersedesPlanId;
        if (!supersededPlanId || projection.plan.generation <= 1) {
          throw new Error(
            "The replacement plan has no live supersession fence.",
          );
        }
        body = {
          ...common,
          superseded_plan_id: supersededPlanId,
          superseded_plan_generation: projection.plan.generation - 1,
          replacement_plan_generation: projection.plan.generation,
          automatic_execution_enabled:
            projection.plan.automaticExecutionEnabled,
          recurrence_enabled: projection.schedule?.recurrenceEnabled ?? false,
          evidence_sha256: evidenceSha256,
        };
      } else {
        body = {
          ...common,
          plan_generation: projection.plan.generation,
          automatic_execution_enabled:
            action === "activate" && projection.plan.automaticExecutionEnabled,
          recurrence_enabled:
            action === "activate" &&
            (projection.schedule?.recurrenceEnabled ?? false),
          evidence_sha256: evidenceSha256,
        };
      }
      const encoded = JSON.stringify(body);
      const url = `${orchestrationOrigin}${path}`;
      const response = await fetcher(url, {
        method: "POST",
        headers: {
          Authorization: await authorization(
            options.signEvent,
            "POST",
            url,
            encoded,
          ),
          "Content-Type": "application/json",
        },
        body: encoded,
        redirect: "error",
        signal,
      });
      const receipt = apiReceiptSchema.parse(await jsonResponse(response));
      if (
        receipt.community_id !== tenantId ||
        receipt.workspace_id !== workspaceId ||
        receipt.plan_id !== projection.plan.planId ||
        receipt.plan_generation !== projection.plan.generation
      ) {
        throw new Error("Lifecycle receipt crossed its bound plan generation.");
      }
      const snapshot = await reload(signal);
      return {
        receipt: {
          commandId: receipt.command_id,
          action,
          status: receipt.status,
          digestSha256: receipt.request_sha256,
          recordedAt: receipt.accepted_at,
        },
        snapshot,
        controls: currentProjection ? controls(currentProjection) : undefined,
      };
    },
    async decideApproval(
      approvalId,
      taskId,
      taskSnapshotSha256,
      decision,
      signal,
    ) {
      const projection = currentProjection ?? (await loadProjection(signal));
      sha256.parse(taskSnapshotSha256);
      const decidedAt = new Date();
      const expiresAt = new Date(
        Math.min(
          decidedAt.getTime() + 24 * 60 * 60 * 1_000,
          new Date(projection.plan.deadlineAt).getTime(),
        ),
      );
      const rationaleSha256 = await sha256Hex(
        [
          "snowman.command-center.approval-rationale.v1",
          decision,
          projection.plan.requestId,
          taskId,
          taskSnapshotSha256,
        ].join("\0"),
      );
      const body = JSON.stringify({
        approval_id: approvalId,
        task_snapshot_sha256: taskSnapshotSha256,
        decision,
        rationale_sha256: rationaleSha256,
        decided_at: decidedAt.toISOString(),
        expires_at: expiresAt.toISOString(),
      });
      const path = `/api/snowman/v1/work-requests/${projection.plan.requestId}/tasks/${taskId}/approval`;
      const url = `${relayOrigin}${path}`;
      const response = await fetcher(url, {
        method: "POST",
        headers: {
          Authorization: await authorization(
            options.signEvent,
            "POST",
            url,
            body,
          ),
          "Content-Type": "application/json",
        },
        body,
        redirect: "error",
        signal,
      });
      const receipt = workforceApprovalReceiptSchema.parse(
        await jsonResponse(response),
      );
      if (
        receipt.request_id !== projection.plan.requestId ||
        receipt.task_id !== taskId ||
        receipt.approval_id !== approvalId
      ) {
        throw new Error("Approval receipt crossed its bound task snapshot.");
      }
      const snapshot = await reload(signal);
      return {
        receipt: {
          commandId: receipt.approval_id,
          action: decision === "approved" ? "approve" : "deny",
          status: receipt.inserted ? "recorded" : "duplicate",
          digestSha256: rationaleSha256,
          recordedAt: decidedAt.toISOString(),
        },
        snapshot,
        controls: currentProjection ? controls(currentProjection) : undefined,
      };
    },
    async createRequest(input, signal) {
      const objective = input.objective.trim();
      if (!objective || new TextEncoder().encode(objective).length > 8_000) {
        throw new Error(
          "The governed request must contain 1–8,000 UTF-8 bytes.",
        );
      }
      if (
        !Number.isSafeInteger(input.maxCostMicrousd) ||
        input.maxCostMicrousd <= 0
      ) {
        throw new Error("The governed request budget is invalid.");
      }
      const body = JSON.stringify({
        objective,
        classification: input.classification,
        deadline_at: input.deadlineAt,
        max_cost_microusd: input.maxCostMicrousd,
        client_ready_delivery: true,
        context_references: input.contextReferences,
      });
      const url = `${relayOrigin}/api/snowman/v1/work-requests`;
      const idempotencyKey = crypto.randomUUID();
      const response = await fetcher(url, {
        method: "POST",
        headers: {
          Authorization: await authorization(
            options.signEvent,
            "POST",
            url,
            body,
          ),
          "Content-Type": "application/json",
          "Idempotency-Key": idempotencyKey,
        },
        body,
        redirect: "error",
        signal,
      });
      const receipt = workforceRequestReceiptSchema.parse(
        await jsonResponse(response),
      );
      return {
        receipt: {
          commandId: receipt.request_id,
          action: "create_request",
          status: receipt.inserted ? "accepted" : "duplicate",
          digestSha256: await sha256Hex(body),
          recordedAt: new Date().toISOString(),
        },
      };
    },
  };
}
