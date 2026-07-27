import { z } from "zod";

export const TEAM_OPERATIONS_VIEW_SCHEMA =
  "snowman.command-center.team-operations-view.v1";

const uuid = z.string().uuid();
const timestamp = z.string().datetime({ offset: true });
const boundedLabel = z.string().trim().min(1).max(160);
const sha256Reference = z
  .string()
  .regex(/^analyst360:sha256:[0-9a-f]{64}$/);

const costSchema = z
  .object({
    accountedMicrousd: z.number().int().nonnegative(),
    reservedMicrousd: z.number().int().nonnegative(),
    limitMicrousd: z.number().int().positive(),
  })
  .strict()
  .refine(
    (value) =>
      value.accountedMicrousd + value.reservedMicrousd <= value.limitMicrousd,
    "accounted and reserved cost must fit within the limit",
  );

const specialistSchema = z
  .object({
    id: uuid,
    displayName: boundedLabel,
    roleLabel: boundedLabel,
    modelLabel: boundedLabel,
    capabilityLabels: z.array(boundedLabel).min(1).max(8),
    status: z.enum(["queued", "working", "reviewing", "waiting", "done"]),
    currentTaskId: uuid.nullable(),
    cost: costSchema,
  })
  .strict();

const taskSchema = z
  .object({
    id: uuid,
    title: boundedLabel,
    specialistId: uuid,
    dependsOn: z.array(uuid).max(16),
    origin: z.enum(["request", "meeting", "proactive"]),
    status: z.enum([
      "queued",
      "working",
      "awaiting_approval",
      "blocked",
      "done",
      "cancelled",
      "superseded",
    ]),
    approval: z.enum(["not_required", "pending", "approved", "denied"]),
    deadlineAt: timestamp,
    progressPercent: z.number().int().min(0).max(100),
    expectedArtifactLabels: z.array(boundedLabel).min(1).max(8),
    evidenceCount: z.number().int().nonnegative(),
    cost: costSchema,
  })
  .strict();

const approvalSchema = z
  .object({
    id: uuid,
    taskId: uuid,
    title: boundedLabel,
    reasonLabel: boundedLabel,
    expiresAt: timestamp,
    riskLabel: z.enum(["low", "moderate", "high"]),
  })
  .strict();

const artifactSchema = z
  .object({
    id: uuid,
    taskId: uuid,
    label: boundedLabel,
    typeLabel: boundedLabel,
    status: z.enum(["draft", "in_review", "accepted"]),
    immutableReference: sha256Reference,
    evidenceReference: sha256Reference,
  })
  .strict();

export const teamOperationsSnapshotSchema = z
  .object({
    schemaVersion: z.literal(TEAM_OPERATIONS_VIEW_SCHEMA),
    generatedAt: timestamp,
    request: z
      .object({
        id: uuid,
        title: boundedLabel,
        workKindLabel: boundedLabel,
        classificationLabel: z.enum([
          "Snowman internal",
          "Client confidential",
          "Restricted",
        ]),
        planId: uuid,
        generation: z.number().int().positive(),
        state: z.enum([
          "draft",
          "active",
          "paused",
          "completed",
          "cancelled",
          "superseded",
        ]),
        supersedesPlanId: uuid.nullable(),
        canCancel: z.boolean(),
      })
      .strict(),
    nextBestAction: z
      .object({
        title: boundedLabel,
        reasonLabel: boundedLabel,
        disposition: z.enum(["automatic", "approval_required", "waiting"]),
        dueAt: timestamp,
      })
      .strict(),
    schedule: z
      .object({
        timezone: boundedLabel,
        quietHoursLabel: boundedLabel,
        quietNow: z.boolean(),
        nextReminderAt: timestamp.nullable(),
        recurrenceLabel: boundedLabel.nullable(),
      })
      .strict(),
    cost: costSchema,
    specialists: z.array(specialistSchema).min(1).max(32),
    tasks: z.array(taskSchema).min(1).max(128),
    approvals: z.array(approvalSchema).max(32),
    artifacts: z.array(artifactSchema).max(128),
    handoff: z
      .object({
        immutableReference: sha256Reference,
        updatedAt: timestamp,
        coveragePercent: z.number().int().min(0).max(100),
        decisionCount: z.number().int().nonnegative(),
        openQuestionCount: z.number().int().nonnegative(),
        nextActionCount: z.number().int().nonnegative(),
        resumable: z.boolean(),
      })
      .strict(),
  })
  .strict()
  .superRefine((snapshot, context) => {
    const specialists = new Set(snapshot.specialists.map(({ id }) => id));
    const tasks = new Set(snapshot.tasks.map(({ id }) => id));

    for (const specialist of snapshot.specialists) {
      if (specialist.currentTaskId && !tasks.has(specialist.currentTaskId)) {
        context.addIssue({
          code: "custom",
          message: "specialist current task is outside this snapshot",
        });
      }
    }

    for (const task of snapshot.tasks) {
      if (!specialists.has(task.specialistId)) {
        context.addIssue({
          code: "custom",
          message: "task specialist is outside this snapshot",
        });
      }
      if (task.dependsOn.some((dependency) => !tasks.has(dependency))) {
        context.addIssue({
          code: "custom",
          message: "task dependency is outside this snapshot",
        });
      }
    }

    for (const approval of snapshot.approvals) {
      if (!tasks.has(approval.taskId)) {
        context.addIssue({
          code: "custom",
          message: "approval task is outside this snapshot",
        });
      }
    }

    for (const artifact of snapshot.artifacts) {
      if (!tasks.has(artifact.taskId)) {
        context.addIssue({
          code: "custom",
          message: "artifact task is outside this snapshot",
        });
      }
    }
  });

export type TeamOperationsSnapshot = z.infer<
  typeof teamOperationsSnapshotSchema
>;
export type TeamOperationsTask = TeamOperationsSnapshot["tasks"][number];
export type TeamOperationsSpecialist =
  TeamOperationsSnapshot["specialists"][number];

export function parseTeamOperationsSnapshot(
  value: unknown,
): TeamOperationsSnapshot {
  return teamOperationsSnapshotSchema.parse(value);
}

export function summarizeTeamProgress(snapshot: TeamOperationsSnapshot) {
  const completedTasks = snapshot.tasks.filter(
    ({ status }) => status === "done",
  ).length;
  const activeTasks = snapshot.tasks.filter(({ status }) =>
    ["working", "awaiting_approval"].includes(status),
  ).length;
  const blockedTasks = snapshot.tasks.filter(
    ({ status }) => status === "blocked",
  ).length;
  const progressPercent = Math.round(
    snapshot.tasks.reduce((total, task) => total + task.progressPercent, 0) /
      snapshot.tasks.length,
  );

  return {
    activeTasks,
    blockedTasks,
    completedTasks,
    progressPercent,
    totalTasks: snapshot.tasks.length,
  };
}

export function formatMicrousd(value: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 2,
  }).format(value / 1_000_000);
}
