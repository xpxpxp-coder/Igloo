import { z } from "zod";

import {
  TEAM_OPERATIONS_VIEW_SCHEMA,
  parseTeamOperationsSnapshot,
  type TeamOperationsSnapshot,
} from "./teamOperationsContract";

export const TEAM_OPERATIONS_API_SCHEMA =
  "snowman.orchestration.team-operations.v1";

const uuid = z.string().uuid();
const timestamp = z.string().datetime({ offset: true });
const sha256 = z.string().regex(/^[0-9a-f]{64}$/);
const bounded = z.string().trim().min(1).max(256);
const analystReference = z.string().regex(/^analyst360:sha256:[0-9a-f]{64}$/);

const projectionSchema = z
  .object({
    schemaVersion: z.literal(TEAM_OPERATIONS_API_SCHEMA),
    generatedAt: timestamp,
    tenantId: uuid,
    workspaceId: uuid,
    authority: z
      .object({
        identityId: uuid,
        principal: z.string().regex(/^snowman:[a-z0-9][a-z0-9._-]{2,127}$/),
        policyGeneration: z.number().int().positive(),
        capabilities: z
          .array(
            z.enum([
              "orchestration.plans.activate",
              "orchestration.plans.pause",
              "orchestration.plans.cancel",
              "orchestration.plans.supersede",
              "workforce.tasks.approve",
            ]),
          )
          .max(5),
      })
      .strict(),
    plan: z
      .object({
        planId: uuid,
        requestId: uuid,
        workKind: z.enum([
          "user_request",
          "project",
          "deadline",
          "recurring_analytics",
          "next_best_action",
        ]),
        generation: z.number().int().positive(),
        supersedesPlanId: uuid.nullable(),
        state: z.enum([
          "draft",
          "active",
          "paused",
          "completed",
          "cancelled",
          "superseded",
        ]),
        classification: z.enum(["internal", "confidential", "restricted"]),
        maxCostMicrousd: z.number().int().nonnegative(),
        automaticExecutionEnabled: z.boolean(),
        deadlineAt: timestamp,
        createdAt: timestamp,
        updatedAt: timestamp,
      })
      .strict(),
    schedule: z
      .object({
        timezone: bounded,
        quietStartLocalMinute: z.number().int().min(0).max(1439),
        quietEndLocalMinute: z.number().int().min(0).max(1439),
        allowDeadlineReminders: z.boolean(),
        reminderOffsetsSeconds: z.array(z.number().int().min(60)).max(16),
        recurrenceEnabled: z.boolean(),
        recurrenceLocalMinute: z.number().int().min(0).max(1439).nullable(),
        recurrenceWeekdays: z.array(z.number().int().min(1).max(7)).max(7),
        nextFireAt: timestamp.nullable(),
      })
      .strict()
      .nullable(),
    personas: z
      .array(
        z
          .object({
            personaId: uuid,
            specialistRole: bounded,
            modelId: bounded,
            modelRouteReference: z
              .string()
              .regex(
                /^snowman:model-route:[0-9a-f-]{36}:revision:[1-9][0-9]*$/,
              ),
            maxCostMicrousd: z.number().int().nonnegative(),
            enabled: z.boolean(),
            capabilities: z.array(bounded).min(1).max(32),
          })
          .strict(),
      )
      .min(1)
      .max(32),
    tasks: z
      .array(
        z
          .object({
            taskId: uuid,
            personaId: uuid,
            dependsOn: z.array(uuid).max(16),
            status: bounded,
            approvalRequired: z.boolean(),
            requiredCapabilities: z.array(bounded).min(1).max(32),
            artifactTypes: z.array(bounded).min(1).max(8),
            maxCostMicrousd: z.number().int().nonnegative(),
            deadlineAt: timestamp,
            dispatchStatus: bounded.nullable(),
            reservedCostMicrousd: z.number().int().nonnegative(),
            accountedCostMicrousd: z.number().int().nonnegative(),
            executionSnapshotSha256: sha256,
          })
          .strict(),
      )
      .min(1)
      .max(128),
    receipts: z
      .array(
        z
          .object({
            taskId: uuid,
            outcome: z.enum(["succeeded", "blocked", "failed", "cancelled"]),
            handoffManifestReference: analystReference,
            receiptSha256: sha256,
            artifactReferences: z.array(analystReference).max(128),
            evidenceReferences: z.array(analystReference).max(128),
            actualCostMicrousd: z.number().int().nonnegative(),
            completedAt: timestamp,
          })
          .strict(),
      )
      .max(128),
    reminders: z
      .array(
        z
          .object({
            occurrenceId: uuid,
            dueAt: timestamp,
            deliveredAt: timestamp.nullable(),
            status: z.enum(["pending", "delivered", "cancelled", "expired"]),
          })
          .strict(),
      )
      .max(64),
    commands: z
      .array(
        z
          .object({
            commandId: uuid,
            commandKind: z.enum([
              "create_plan",
              "activate_plan",
              "pause_plan",
              "cancel_plan",
              "supersede_plan",
            ]),
            planGeneration: z.number().int().positive(),
            commandSha256: sha256,
            status: bounded,
            appliedAt: timestamp,
          })
          .strict(),
      )
      .max(64),
  })
  .strict();

export type TeamOperationsApiProjection = z.infer<typeof projectionSchema>;

export function parseTeamOperationsProjection(
  input: unknown,
): TeamOperationsApiProjection {
  return projectionSchema.parse(input);
}

function words(value: string): string {
  return value
    .split("_")
    .filter(Boolean)
    .map((part) => `${part[0]?.toUpperCase() ?? ""}${part.slice(1)}`)
    .join(" ");
}

function minuteLabel(minute: number): string {
  const hours = Math.floor(minute / 60);
  const suffix = hours >= 12 ? "PM" : "AM";
  const hour = hours % 12 || 12;
  return `${hour}:${String(minute % 60).padStart(2, "0")} ${suffix}`;
}

function stableReferenceUuid(reference: string, index: number): string {
  const source = reference.slice(-64).split("");
  source[31] = (index % 16).toString(16);
  source[12] = "4";
  source[16] = "8";
  const hex = source.join("").slice(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

function taskStatus(
  status: string,
  dispatchStatus: string | null,
  approvalRequired: boolean,
): TeamOperationsSnapshot["tasks"][number]["status"] {
  if (status === "cancelled") return "cancelled";
  if (status === "succeeded" || status === "completed") return "done";
  if (approvalRequired && ["pending", "waiting_approval"].includes(status)) {
    return "awaiting_approval";
  }
  if (
    ["failed", "dead_letter"].includes(status) ||
    dispatchStatus === "dead_letter"
  ) {
    return "blocked";
  }
  if (
    ["leased", "running"].includes(status) ||
    ["leased", "submitted"].includes(dispatchStatus ?? "")
  ) {
    return "working";
  }
  return "queued";
}

function progress(
  status: TeamOperationsSnapshot["tasks"][number]["status"],
): number {
  if (status === "done") return 100;
  if (status === "working") return 50;
  if (status === "awaiting_approval") return 25;
  return 0;
}

export function projectTeamOperationsSnapshot(
  input: unknown,
): TeamOperationsSnapshot {
  const projection = projectionSchema.parse(input);
  const receiptsByTask = new Map(
    projection.receipts.map((receipt) => [receipt.taskId, receipt]),
  );
  const tasks = projection.tasks.map((task) => {
    const status = taskStatus(
      task.status,
      task.dispatchStatus,
      task.approvalRequired,
    );
    const receipt = receiptsByTask.get(task.taskId);
    return {
      id: task.taskId,
      title: `${words(task.artifactTypes[0] ?? "governed work product")} · ${words(
        projection.personas.find(
          ({ personaId }) => personaId === task.personaId,
        )?.specialistRole ?? "specialist",
      )}`,
      specialistId: task.personaId,
      dependsOn: task.dependsOn,
      origin: "request" as const,
      status,
      approval: task.approvalRequired
        ? status === "awaiting_approval"
          ? ("pending" as const)
          : ("approved" as const)
        : ("not_required" as const),
      deadlineAt: task.deadlineAt,
      progressPercent: progress(status),
      expectedArtifactLabels: task.artifactTypes.map(words),
      evidenceCount: receipt?.evidenceReferences.length ?? 0,
      cost: {
        accountedMicrousd: task.accountedCostMicrousd,
        reservedMicrousd: task.reservedCostMicrousd,
        limitMicrousd: Math.max(task.maxCostMicrousd, 1),
      },
    };
  });
  const specialists = projection.personas.map((persona) => {
    const personaTasks = tasks.filter(
      ({ specialistId }) => specialistId === persona.personaId,
    );
    const currentTask = personaTasks.find(({ status }) =>
      ["working", "awaiting_approval", "blocked"].includes(status),
    );
    const done =
      personaTasks.length > 0 &&
      personaTasks.every(({ status }) => status === "done");
    return {
      id: persona.personaId,
      displayName: words(persona.specialistRole),
      roleLabel: words(persona.specialistRole),
      modelLabel: persona.modelId,
      capabilityLabels: persona.capabilities.map(words),
      status: done
        ? ("done" as const)
        : currentTask?.status === "working"
          ? ("working" as const)
          : currentTask?.status === "awaiting_approval"
            ? ("reviewing" as const)
            : currentTask
              ? ("waiting" as const)
              : ("queued" as const),
      currentTaskId: currentTask?.id ?? null,
      cost: {
        accountedMicrousd: personaTasks.reduce(
          (sum, task) => sum + task.cost.accountedMicrousd,
          0,
        ),
        reservedMicrousd: personaTasks.reduce(
          (sum, task) => sum + task.cost.reservedMicrousd,
          0,
        ),
        limitMicrousd: Math.max(persona.maxCostMicrousd, 1),
      },
    };
  });
  const nextTask = tasks.find(({ status }) =>
    ["working", "awaiting_approval", "queued", "blocked"].includes(status),
  );
  const nextReminder = projection.reminders.find(
    ({ status }) => status === "pending",
  );
  const latestHandoff = [...projection.receipts].sort((a, b) =>
    b.completedAt.localeCompare(a.completedAt),
  )[0];
  const classification = {
    internal: "Snowman internal",
    confidential: "Client confidential",
    restricted: "Restricted",
  } as const;
  const schedule = projection.schedule;
  const snapshot: TeamOperationsSnapshot = {
    schemaVersion: TEAM_OPERATIONS_VIEW_SCHEMA,
    generatedAt: projection.generatedAt,
    request: {
      id: projection.plan.requestId,
      title: `Governed ${words(projection.plan.workKind)} · ${projection.plan.requestId.slice(0, 8)}`,
      workKindLabel: words(projection.plan.workKind),
      classificationLabel: classification[projection.plan.classification],
      planId: projection.plan.planId,
      generation: projection.plan.generation,
      state: projection.plan.state,
      supersedesPlanId: projection.plan.supersedesPlanId,
      canCancel: ["draft", "active", "paused"].includes(projection.plan.state),
    },
    nextBestAction: {
      title: nextTask?.title ?? "No further work is currently authorized",
      reasonLabel:
        nextTask?.status === "awaiting_approval"
          ? "A live human decision is required before execution can continue."
          : nextTask?.status === "blocked"
            ? "The governed runtime reported a bounded block requiring review."
            : "Dependencies and current authority determine the next safe step.",
      disposition:
        nextTask?.status === "awaiting_approval"
          ? "approval_required"
          : nextTask?.status === "working"
            ? "automatic"
            : "waiting",
      dueAt: nextTask?.deadlineAt ?? projection.plan.deadlineAt,
    },
    schedule: {
      timezone: schedule?.timezone ?? "Server governed",
      quietHoursLabel: schedule
        ? `${minuteLabel(schedule.quietStartLocalMinute)}–${minuteLabel(
            schedule.quietEndLocalMinute,
          )}`
        : "No schedule policy",
      quietNow: false,
      nextReminderAt: nextReminder?.dueAt ?? null,
      recurrenceLabel: schedule?.recurrenceEnabled
        ? `Authorized on ${schedule.recurrenceWeekdays.length} day(s) at ${minuteLabel(
            schedule.recurrenceLocalMinute ?? 0,
          )}`
        : null,
    },
    cost: {
      accountedMicrousd: tasks.reduce(
        (sum, task) => sum + task.cost.accountedMicrousd,
        0,
      ),
      reservedMicrousd: tasks.reduce(
        (sum, task) => sum + task.cost.reservedMicrousd,
        0,
      ),
      limitMicrousd: Math.max(projection.plan.maxCostMicrousd, 1),
    },
    specialists,
    tasks,
    approvals: projection.tasks
      .filter(
        (task) =>
          task.approvalRequired &&
          taskStatus(task.status, task.dispatchStatus, true) ===
            "awaiting_approval",
      )
      .map((task) => ({
        id: task.taskId,
        taskId: task.taskId,
        title: `Review ${words(task.artifactTypes[0] ?? "specialist work")}`,
        reasonLabel: "Execution is fenced to this immutable task snapshot",
        expiresAt: task.deadlineAt,
        riskLabel: "moderate" as const,
        taskSnapshotSha256: task.executionSnapshotSha256,
      })),
    artifacts: projection.receipts.flatMap((receipt) =>
      receipt.artifactReferences.map((reference, index) => ({
        id: stableReferenceUuid(reference, index),
        taskId: receipt.taskId,
        label: `Accepted work product ${index + 1}`,
        typeLabel: "Analyst 360 artifact",
        status: "accepted" as const,
        immutableReference: reference,
        evidenceReference:
          receipt.evidenceReferences[index] ??
          receipt.evidenceReferences[0] ??
          receipt.handoffManifestReference,
      })),
    ),
    handoff: latestHandoff
      ? {
          immutableReference: latestHandoff.handoffManifestReference,
          updatedAt: latestHandoff.completedAt,
          coveragePercent: latestHandoff.outcome === "succeeded" ? 100 : 50,
          decisionCount: 0,
          openQuestionCount: latestHandoff.outcome === "blocked" ? 1 : 0,
          nextActionCount: nextTask ? 1 : 0,
          resumable: true,
        }
      : null,
    recentReceipts: [
      ...projection.commands.map((receipt) => ({
        id: receipt.commandId,
        kind: receipt.commandKind,
        status: receipt.status,
        digestSha256: receipt.commandSha256,
        recordedAt: receipt.appliedAt,
      })),
      ...projection.receipts.map((receipt) => ({
        id: receipt.taskId,
        kind: "work_product" as const,
        status: receipt.outcome,
        digestSha256: receipt.receiptSha256,
        recordedAt: receipt.completedAt,
      })),
    ].slice(0, 64),
  };
  return parseTeamOperationsSnapshot(snapshot);
}
