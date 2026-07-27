import {
  AlertCircle,
  BellRing,
  CalendarClock,
  Check,
  ChevronRight,
  Clock3,
  FileCheck2,
  GitBranch,
  Hand,
  History,
  LockKeyhole,
  Pause,
  Play,
  RotateCcw,
  ShieldCheck,
  Sparkles,
  UsersRound,
} from "lucide-react";
import * as React from "react";

import { cn } from "@/shared/lib/cn";
import { Badge } from "@/shared/ui/badge";
import { Button } from "@/shared/ui/button";
import { Card, CardContent, CardHeader } from "@/shared/ui/card";
import { Progress } from "@/shared/ui/progress";
import { SnowmanPulseMark } from "@/shared/ui/snowman-logo/SnowmanPulseMark";
import {
  formatMicrousd,
  summarizeTeamProgress,
  type TeamOperationsSnapshot,
  type TeamOperationsSpecialist,
  type TeamOperationsTask,
} from "./teamOperationsContract";

type DashboardProps = {
  controlsEnabled: boolean;
  snapshot: TeamOperationsSnapshot;
  source: "fixture";
};

const statusLabel: Record<TeamOperationsTask["status"], string> = {
  queued: "Queued",
  working: "Working",
  awaiting_approval: "Needs approval",
  blocked: "Blocked",
  done: "Complete",
  cancelled: "Cancelled",
  superseded: "Superseded",
};

function formatDateTime(value: string): string {
  return new Intl.DateTimeFormat(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(new Date(value));
}

function statusBadgeVariant(status: TeamOperationsTask["status"]) {
  if (status === "done") return "success" as const;
  if (status === "working") return "info" as const;
  if (status === "awaiting_approval" || status === "blocked") {
    return "warning" as const;
  }
  return "outline" as const;
}

function Metric({
  label,
  value,
}: {
  label: string;
  value: React.ReactNode;
}) {
  return (
    <div className="min-w-0 rounded-xl border border-white/40 bg-background/65 px-3 py-2.5 shadow-xs backdrop-blur dark:border-white/10">
      <p className="text-2xs font-semibold uppercase tracking-wide text-muted-foreground">
        {label}
      </p>
      <p className="mt-1 truncate text-base font-semibold">{value}</p>
    </div>
  );
}

function RequestHero({
  snapshot,
  controlsEnabled,
}: {
  snapshot: TeamOperationsSnapshot;
  controlsEnabled: boolean;
}) {
  const progress = summarizeTeamProgress(snapshot);
  const spent = snapshot.cost.accountedMicrousd + snapshot.cost.reservedMicrousd;
  const budgetPercent = Math.round((spent / snapshot.cost.limitMicrousd) * 100);
  const controlsDescriptionId = "team-operations-controls-description";

  return (
    <Card className="relative overflow-hidden border-sky-500/20 bg-linear-to-br from-sky-500/12 via-card to-emerald-500/10 shadow-sm">
      <div
        aria-hidden="true"
        className="absolute -right-16 -top-20 h-56 w-56 rounded-full bg-sky-400/15 blur-3xl"
      />
      <CardContent className="relative space-y-5 p-5 sm:p-6">
        <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
          <div className="flex min-w-0 gap-4">
            <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-2xl border border-sky-500/20 bg-background/70 text-sky-600 shadow-xs dark:text-sky-300">
              <SnowmanPulseMark className="h-8 w-8" pulse={false} />
            </div>
            <div className="min-w-0 space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <Badge variant="info">AI Workforce</Badge>
                <Badge variant="outline">{snapshot.request.workKindLabel}</Badge>
                <Badge variant="outline">
                  {snapshot.request.classificationLabel}
                </Badge>
              </div>
              <div>
                <h2 className="max-w-4xl text-xl font-semibold tracking-tight sm:text-2xl">
                  {snapshot.request.title}
                </h2>
                <p className="mt-1 text-sm text-muted-foreground">
                  Generation {snapshot.request.generation} · {progress.activeTasks}{" "}
                  active · {progress.completedTasks} of {progress.totalTasks}{" "}
                  tasks complete
                </p>
              </div>
            </div>
          </div>
          <div className="flex shrink-0 flex-wrap gap-2">
            <Button
              aria-describedby={controlsDescriptionId}
              disabled={!controlsEnabled}
              size="sm"
              variant="outline"
            >
              <Pause aria-hidden="true" />
              Pause
            </Button>
            <Button
              aria-describedby={controlsDescriptionId}
              disabled={!controlsEnabled || !snapshot.request.canCancel}
              size="sm"
              variant="destructive"
            >
              Cancel plan
            </Button>
          </div>
        </div>

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          <Metric label="Plan progress" value={`${progress.progressPercent}%`} />
          <Metric
            label="Team online"
            value={`${snapshot.specialists.filter(({ status }) => status !== "queued").length} of ${snapshot.specialists.length}`}
          />
          <Metric
            label="Approvals"
            value={snapshot.approvals.length || "Clear"}
          />
          <Metric
            label="Budget committed"
            value={`${formatMicrousd(spent)} · ${budgetPercent}%`}
          />
        </div>

        <div>
          <div className="mb-2 flex items-center justify-between gap-3 text-xs">
            <span className="font-medium">Overall completion</span>
            <span className="text-muted-foreground">
              {progress.blockedTasks > 0
                ? `${progress.blockedTasks} blocked`
                : "No blocked work"}
            </span>
          </div>
          <Progress
            aria-label="Overall plan completion"
            className="h-2.5 bg-sky-500/15 [&>div]:bg-sky-500 motion-reduce:[&>div]:transition-none"
            value={progress.progressPercent}
          />
        </div>
        <p className="sr-only" id={controlsDescriptionId}>
          Mutation controls are disabled in fixture preview mode. They require
          live tenant-scoped authorization and durable receipts.
        </p>
      </CardContent>
    </Card>
  );
}

function NextActionCard({ snapshot }: { snapshot: TeamOperationsSnapshot }) {
  const action = snapshot.nextBestAction;
  return (
    <Card className="border-emerald-500/25 bg-emerald-500/5">
      <CardContent className="flex flex-col gap-4 p-5 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          <div className="rounded-xl bg-emerald-500/15 p-2 text-emerald-600 dark:text-emerald-300">
            <Sparkles aria-hidden="true" className="h-5 w-5" />
          </div>
          <div className="min-w-0">
            <div className="flex flex-wrap items-center gap-2">
              <h3 className="text-sm font-semibold">Next best useful step</h3>
              <Badge
                variant={
                  action.disposition === "automatic" ? "success" : "warning"
                }
              >
                {action.disposition === "automatic"
                  ? "Safe to advance"
                  : "Human gate"}
              </Badge>
            </div>
            <p className="mt-1 text-base font-medium">{action.title}</p>
            <p className="mt-1 max-w-3xl text-sm text-muted-foreground">
              {action.reasonLabel} Due {formatDateTime(action.dueAt)}.
            </p>
          </div>
        </div>
        <div className="flex shrink-0 items-center gap-2 text-xs font-medium text-emerald-700 dark:text-emerald-300">
          <Play aria-hidden="true" className="h-4 w-4" />
          Policy evaluation passed
        </div>
      </CardContent>
    </Card>
  );
}

function SpecialistCard({
  specialist,
  currentTask,
}: {
  specialist: TeamOperationsSpecialist;
  currentTask?: TeamOperationsTask;
}) {
  const spent = specialist.cost.accountedMicrousd + specialist.cost.reservedMicrousd;
  return (
    <li className="rounded-xl border border-border/70 bg-background/65 p-4 shadow-xs">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-semibold">{specialist.displayName}</p>
          <p className="text-xs text-muted-foreground">
            {specialist.roleLabel}
          </p>
        </div>
        <span
          aria-label={`Status: ${specialist.status}`}
          className={cn(
            "mt-1 h-2.5 w-2.5 shrink-0 rounded-full",
            specialist.status === "working" && "bg-emerald-500",
            specialist.status === "reviewing" && "bg-sky-500",
            specialist.status === "waiting" && "bg-amber-500",
            specialist.status === "done" && "bg-emerald-500",
            specialist.status === "queued" && "bg-muted-foreground/40",
          )}
        />
      </div>
      <div className="mt-3 rounded-lg bg-muted/55 px-3 py-2">
        <p className="text-2xs font-semibold uppercase tracking-wide text-muted-foreground">
          Model route
        </p>
        <p className="mt-1 text-xs font-medium">{specialist.modelLabel}</p>
      </div>
      <div className="mt-3 flex flex-wrap gap-1.5">
        {specialist.capabilityLabels.map((capability) => (
          <span
            className="rounded-full border border-border/60 px-2 py-1 text-2xs text-muted-foreground"
            key={capability}
          >
            {capability}
          </span>
        ))}
      </div>
      <p className="mt-3 line-clamp-2 text-xs text-muted-foreground">
        {currentTask ? currentTask.title : "Ready for bounded work"}
      </p>
      <div className="mt-3 flex items-center justify-between text-2xs text-muted-foreground">
        <span>{formatMicrousd(spent)} committed</span>
        <span>{formatMicrousd(specialist.cost.limitMicrousd)} limit</span>
      </div>
    </li>
  );
}

function TeamCard({ snapshot }: { snapshot: TeamOperationsSnapshot }) {
  const taskById = new Map(snapshot.tasks.map((task) => [task.id, task]));
  return (
    <Card>
      <CardHeader className="flex-row items-start justify-between space-y-0 p-5 pb-3">
        <div>
          <div className="flex items-center gap-2">
            <UsersRound aria-hidden="true" className="h-4 w-4 text-sky-500" />
            <h3 className="font-semibold">Specialist team</h3>
          </div>
          <p className="mt-1 text-xs text-muted-foreground">
            One governed role, model route, and capability envelope per agent.
          </p>
        </div>
        <Badge variant="outline">{snapshot.specialists.length} agents</Badge>
      </CardHeader>
      <CardContent className="p-5 pt-2">
        <ul className="grid gap-3 sm:grid-cols-2">
          {snapshot.specialists.map((specialist) => (
            <SpecialistCard
              currentTask={
                specialist.currentTaskId
                  ? taskById.get(specialist.currentTaskId)
                  : undefined
              }
              key={specialist.id}
              specialist={specialist}
            />
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

function TaskPlan({ snapshot }: { snapshot: TeamOperationsSnapshot }) {
  const [selectedTaskId, setSelectedTaskId] = React.useState(
    () =>
      snapshot.tasks.find(({ status }) => status === "working")?.id ??
      snapshot.tasks[0]?.id,
  );
  const selectedTask = snapshot.tasks.find(({ id }) => id === selectedTaskId);
  const specialist = snapshot.specialists.find(
    ({ id }) => id === selectedTask?.specialistId,
  );

  return (
    <Card>
      <CardHeader className="p-5 pb-3">
        <div className="flex items-center justify-between gap-3">
          <div>
            <div className="flex items-center gap-2">
              <GitBranch aria-hidden="true" className="h-4 w-4 text-sky-500" />
              <h3 className="font-semibold">Dependency plan</h3>
            </div>
            <p className="mt-1 text-xs text-muted-foreground">
              Work advances only when dependencies, authority, and evidence are
              ready.
            </p>
          </div>
          <Badge variant="outline">Generation {snapshot.request.generation}</Badge>
        </div>
      </CardHeader>
      <CardContent className="grid gap-4 p-5 pt-2 lg:grid-cols-[minmax(0,1fr)_minmax(15rem,0.7fr)]">
        <ol aria-label="Specialist task plan" className="space-y-2">
          {snapshot.tasks.map((task, index) => (
            <li className="relative" key={task.id}>
              {index < snapshot.tasks.length - 1 ? (
                <div
                  aria-hidden="true"
                  className="absolute bottom-[-0.625rem] left-4 top-8 w-px bg-border"
                />
              ) : null}
              <button
                aria-current={selectedTaskId === task.id ? "step" : undefined}
                className={cn(
                  "relative flex w-full items-start gap-3 rounded-xl border px-3 py-3 text-left transition-colors motion-reduce:transition-none",
                  selectedTaskId === task.id
                    ? "border-sky-500/40 bg-sky-500/8"
                    : "border-border/60 bg-background/60 hover:bg-muted/45",
                )}
                onClick={() => setSelectedTaskId(task.id)}
                type="button"
              >
                <span
                  className={cn(
                    "z-10 flex h-8 w-8 shrink-0 items-center justify-center rounded-full border bg-background",
                    task.status === "done" &&
                      "border-emerald-500/40 text-emerald-600",
                    task.status === "working" &&
                      "border-sky-500/40 text-sky-600",
                  )}
                >
                  {task.status === "done" ? (
                    <Check aria-hidden="true" className="h-4 w-4" />
                  ) : task.status === "working" ? (
                    <Play aria-hidden="true" className="h-3.5 w-3.5" />
                  ) : (
                    <span className="text-xs font-semibold">{index + 1}</span>
                  )}
                </span>
                <span className="min-w-0 flex-1">
                  <span className="flex flex-wrap items-center gap-2">
                    <span className="text-sm font-medium">{task.title}</span>
                    {task.origin === "meeting" ? (
                      <Badge variant="outline">From meeting</Badge>
                    ) : null}
                  </span>
                  <span className="mt-1 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
                    <span>
                      {
                        snapshot.specialists.find(
                          ({ id }) => id === task.specialistId,
                        )?.displayName
                      }
                    </span>
                    <span aria-hidden="true">·</span>
                    <span>{task.progressPercent}%</span>
                    <span aria-hidden="true">·</span>
                    <span>{formatDateTime(task.deadlineAt)}</span>
                  </span>
                </span>
                <Badge variant={statusBadgeVariant(task.status)}>
                  {statusLabel[task.status]}
                </Badge>
              </button>
            </li>
          ))}
        </ol>

        {selectedTask ? (
          <aside
            aria-live="polite"
            className="rounded-xl border border-border/70 bg-muted/35 p-4"
          >
            <p className="text-2xs font-semibold uppercase tracking-wide text-muted-foreground">
              Selected task
            </p>
            <h4 className="mt-2 text-sm font-semibold">{selectedTask.title}</h4>
            <p className="mt-1 text-xs text-muted-foreground">
              Owned by {specialist?.displayName ?? "assigned specialist"}
            </p>
            <Progress
              aria-label={`${selectedTask.title} progress`}
              className="mt-4 h-2 motion-reduce:[&>div]:transition-none"
              value={selectedTask.progressPercent}
            />
            <dl className="mt-4 grid grid-cols-2 gap-3 text-xs">
              <div>
                <dt className="text-muted-foreground">Dependencies</dt>
                <dd className="mt-0.5 font-medium">
                  {selectedTask.dependsOn.length || "None"}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Evidence</dt>
                <dd className="mt-0.5 font-medium">
                  {selectedTask.evidenceCount} sources
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Task budget</dt>
                <dd className="mt-0.5 font-medium">
                  {formatMicrousd(selectedTask.cost.limitMicrousd)}
                </dd>
              </div>
              <div>
                <dt className="text-muted-foreground">Approval</dt>
                <dd className="mt-0.5 font-medium">
                  {selectedTask.approval === "not_required"
                    ? "Not required"
                    : selectedTask.approval}
                </dd>
              </div>
            </dl>
            <div className="mt-4">
              <p className="text-2xs font-semibold uppercase tracking-wide text-muted-foreground">
                Expected work products
              </p>
              <ul className="mt-2 space-y-1.5 text-xs">
                {selectedTask.expectedArtifactLabels.map((artifact) => (
                  <li className="flex items-center gap-2" key={artifact}>
                    <FileCheck2
                      aria-hidden="true"
                      className="h-3.5 w-3.5 text-sky-500"
                    />
                    {artifact}
                  </li>
                ))}
              </ul>
            </div>
          </aside>
        ) : null}
      </CardContent>
    </Card>
  );
}

function ApprovalQueue({
  snapshot,
  controlsEnabled,
}: {
  snapshot: TeamOperationsSnapshot;
  controlsEnabled: boolean;
}) {
  return (
    <Card>
      <CardHeader className="p-5 pb-3">
        <div className="flex items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Hand aria-hidden="true" className="h-4 w-4 text-amber-500" />
            <h3 className="font-semibold">Approval queue</h3>
          </div>
          <Badge variant={snapshot.approvals.length ? "warning" : "success"}>
            {snapshot.approvals.length || "Clear"}
          </Badge>
        </div>
      </CardHeader>
      <CardContent className="p-5 pt-2">
        {snapshot.approvals.length ? (
          <ul className="space-y-3">
            {snapshot.approvals.map((approval) => (
              <li
                className="rounded-xl border border-amber-500/25 bg-amber-500/5 p-3"
                key={approval.id}
              >
                <p className="text-sm font-medium">{approval.title}</p>
                <p className="mt-1 text-xs text-muted-foreground">
                  {approval.reasonLabel} · Expires {formatDateTime(approval.expiresAt)}
                </p>
                <div className="mt-3 flex gap-2">
                  <Button disabled={!controlsEnabled} size="xs">
                    Review
                  </Button>
                  <Button disabled={!controlsEnabled} size="xs" variant="outline">
                    Deny
                  </Button>
                </div>
              </li>
            ))}
          </ul>
        ) : (
          <p className="text-sm text-muted-foreground">
            No decisions are waiting for you.
          </p>
        )}
      </CardContent>
    </Card>
  );
}

function ArtifactCard({ snapshot }: { snapshot: TeamOperationsSnapshot }) {
  return (
    <Card>
      <CardHeader className="p-5 pb-3">
        <div className="flex items-center gap-2">
          <FileCheck2 aria-hidden="true" className="h-4 w-4 text-emerald-500" />
          <h3 className="font-semibold">Evidence-backed work products</h3>
        </div>
      </CardHeader>
      <CardContent className="p-5 pt-2">
        <ul className="divide-y divide-border/60">
          {snapshot.artifacts.map((artifact) => (
            <li
              className="flex items-center gap-3 py-3 first:pt-0 last:pb-0"
              key={artifact.id}
            >
              <div className="rounded-lg bg-muted p-2 text-muted-foreground">
                <FileCheck2 aria-hidden="true" className="h-4 w-4" />
              </div>
              <div className="min-w-0 flex-1">
                <p className="truncate text-sm font-medium">{artifact.label}</p>
                <p className="text-xs text-muted-foreground">
                  {artifact.typeLabel} · Evidence preserved
                </p>
              </div>
              <Badge
                variant={artifact.status === "accepted" ? "success" : "outline"}
              >
                {artifact.status.replace("_", " ")}
              </Badge>
            </li>
          ))}
        </ul>
      </CardContent>
    </Card>
  );
}

function ContinuityCard({ snapshot }: { snapshot: TeamOperationsSnapshot }) {
  return (
    <Card>
      <CardHeader className="p-5 pb-3">
        <div className="flex items-center gap-2">
          <RotateCcw aria-hidden="true" className="h-4 w-4 text-sky-500" />
          <h3 className="font-semibold">Continuity and memory</h3>
        </div>
      </CardHeader>
      <CardContent className="space-y-4 p-5 pt-2">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="text-sm font-medium">
              {snapshot.handoff.resumable
                ? "Replacement-ready handoff"
                : "Handoff needs attention"}
            </p>
            <p className="mt-1 text-xs text-muted-foreground">
              Updated {formatDateTime(snapshot.handoff.updatedAt)}
            </p>
          </div>
          <Badge variant={snapshot.handoff.resumable ? "success" : "warning"}>
            {snapshot.handoff.coveragePercent}% covered
          </Badge>
        </div>
        <Progress
          aria-label="Handoff memory coverage"
          className="motion-reduce:[&>div]:transition-none"
          value={snapshot.handoff.coveragePercent}
        />
        <div className="grid grid-cols-3 gap-2 text-center">
          <Metric label="Decisions" value={snapshot.handoff.decisionCount} />
          <Metric label="Open questions" value={snapshot.handoff.openQuestionCount} />
          <Metric label="Next steps" value={snapshot.handoff.nextActionCount} />
        </div>
        <p className="flex items-start gap-2 text-xs text-muted-foreground">
          <LockKeyhole aria-hidden="true" className="mt-0.5 h-3.5 w-3.5 shrink-0" />
          Context remains an immutable Analyst-managed digest; this screen does
          not retain raw client data, transcripts, or mailbox content.
        </p>
      </CardContent>
    </Card>
  );
}

function ScheduleAndAuthority({ snapshot }: { snapshot: TeamOperationsSnapshot }) {
  return (
    <Card>
      <CardHeader className="p-5 pb-3">
        <div className="flex items-center gap-2">
          <CalendarClock aria-hidden="true" className="h-4 w-4 text-sky-500" />
          <h3 className="font-semibold">24/7 operating guardrails</h3>
        </div>
      </CardHeader>
      <CardContent className="space-y-3 p-5 pt-2 text-sm">
        <div className="flex items-start gap-3 rounded-xl bg-muted/45 p-3">
          <Clock3 aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0" />
          <div>
            <p className="font-medium">Quiet hours</p>
            <p className="text-xs text-muted-foreground">
              {snapshot.schedule.quietHoursLabel} · {snapshot.schedule.timezone}
              {snapshot.schedule.quietNow ? " · Quiet now" : " · Active now"}
            </p>
          </div>
        </div>
        <div className="flex items-start gap-3 rounded-xl bg-muted/45 p-3">
          <BellRing aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0" />
          <div>
            <p className="font-medium">Reminders and recurrence</p>
            <p className="text-xs text-muted-foreground">
              {snapshot.schedule.recurrenceLabel ?? "No recurrence"}
              {snapshot.schedule.nextReminderAt
                ? ` · Next reminder ${formatDateTime(snapshot.schedule.nextReminderAt)}`
                : ""}
            </p>
          </div>
        </div>
        <div className="flex items-start gap-3 rounded-xl bg-muted/45 p-3">
          <History aria-hidden="true" className="mt-0.5 h-4 w-4 shrink-0" />
          <div>
            <p className="font-medium">Cancellation and supersession</p>
            <p className="text-xs text-muted-foreground">
              Current generation {snapshot.request.generation}
              {snapshot.request.supersedesPlanId
                ? " replaced an earlier plan with its evidence preserved."
                : " is the original plan."}
            </p>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export function TeamOperationsDashboard({
  controlsEnabled,
  snapshot,
  source,
}: DashboardProps) {
  return (
    <section aria-labelledby="team-operations-title" className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h2 className="text-lg font-semibold tracking-tight" id="team-operations-title">
            Team operations
          </h2>
          <p className="text-sm text-muted-foreground">
            Requests, specialist work, approvals, evidence, and continuity in one governed view.
          </p>
        </div>
        {source === "fixture" ? (
          <div
            className="flex items-center gap-2 rounded-full border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-xs text-amber-700 dark:text-amber-300"
            role="status"
          >
            <AlertCircle aria-hidden="true" className="h-3.5 w-3.5" />
            Preview data · controls disabled
          </div>
        ) : null}
      </div>

      <RequestHero controlsEnabled={controlsEnabled} snapshot={snapshot} />
      <NextActionCard snapshot={snapshot} />

      <div className="grid items-start gap-4 xl:grid-cols-[minmax(0,1.55fr)_minmax(20rem,0.85fr)]">
        <div className="space-y-4">
          <TaskPlan snapshot={snapshot} />
          <TeamCard snapshot={snapshot} />
        </div>
        <div className="space-y-4">
          <ApprovalQueue
            controlsEnabled={controlsEnabled}
            snapshot={snapshot}
          />
          <ArtifactCard snapshot={snapshot} />
          <ContinuityCard snapshot={snapshot} />
          <ScheduleAndAuthority snapshot={snapshot} />
        </div>
      </div>

      <div className="flex flex-col gap-3 rounded-xl border border-sky-500/20 bg-sky-500/5 p-4 text-sm sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-start gap-3">
          <ShieldCheck
            aria-hidden="true"
            className="mt-0.5 h-4 w-4 shrink-0 text-sky-600"
          />
          <div>
            <p className="font-medium">Governed by Snowman authority</p>
            <p className="mt-0.5 text-xs text-muted-foreground">
              Tenant isolation, bounded capabilities, spend ceilings, evidence
              references, and human gates remain in force for every step.
            </p>
          </div>
        </div>
        <span className="flex shrink-0 items-center gap-1 text-xs font-medium text-sky-700 dark:text-sky-300">
          View launch gates
          <ChevronRight aria-hidden="true" className="h-3.5 w-3.5" />
        </span>
      </div>
    </section>
  );
}
