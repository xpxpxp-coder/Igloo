import { AlertTriangle, LockKeyhole, ServerOff } from "lucide-react";
import * as React from "react";

import { useCommunities } from "@/features/communities/useCommunities";
import { relayHttpFromWs } from "@/shared/api/inviteHelpers";
import { signRelayEvent } from "@/shared/api/tauri";
import { Button } from "@/shared/ui/button";
import { Card, CardContent } from "@/shared/ui/card";
import { Input } from "@/shared/ui/input";
import { Skeleton } from "@/shared/ui/skeleton";
import { Textarea } from "@/shared/ui/textarea";
import {
  createDisabledTeamOperationsAdapter,
  createFixtureTeamOperationsAdapter,
  createLiveTeamOperationsAdapter,
  type TeamOperationsCommandResult,
  type CreateGovernedRequestInput,
  type TeamOperationsAdapter,
  type TeamOperationsLoadResult,
} from "./teamOperationsAdapter";
import {
  createTeamOperationsE2eAdapter,
  isTeamOperationsE2eEnabled,
  type TeamOperationsE2eConfig,
} from "./teamOperationsE2eAdapter";
import { teamOperationsFixture } from "./teamOperationsFixture";

const TeamOperationsDashboard = React.lazy(async () => {
  const module = await import("./TeamOperationsDashboard");
  return { default: module.TeamOperationsDashboard };
});

type TeamOperationsE2eWindow = Window & {
  __BUZZ_E2E__?: TeamOperationsE2eConfig & {
    teamOperationsFixture?: boolean;
  };
};

const noTeamOperationsControls = {
  activate: false,
  approve: false,
  cancel: false,
  pause: false,
  supersede: false,
} as const;

function createDefaultAdapter(
  tenantId: string | undefined,
  relayUrl: string | undefined,
): TeamOperationsAdapter {
  const e2e = (window as TeamOperationsE2eWindow).__BUZZ_E2E__;
  if (isTeamOperationsE2eEnabled(import.meta.env.MODE, e2e)) {
    return createTeamOperationsE2eAdapter(e2e.teamOperationsScenario);
  }
  if (import.meta.env.MODE === "e2e" && e2e?.teamOperationsFixture === true) {
    return createFixtureTeamOperationsAdapter(teamOperationsFixture);
  }
  const orchestrationOrigin = import.meta.env.VITE_SNOWMAN_ORCHESTRATION_ORIGIN;
  const workspaceId = import.meta.env.VITE_SNOWMAN_WORKSPACE_ID;
  if (orchestrationOrigin && workspaceId && tenantId && relayUrl) {
    try {
      return createLiveTeamOperationsAdapter({
        orchestrationOrigin,
        relayOrigin: `${relayHttpFromWs(relayUrl).replace(/\/+$/, "")}/`,
        tenantId,
        workspaceId,
        signEvent: async (input) =>
          (await signRelayEvent(input)) as unknown as Record<string, unknown>,
      });
    } catch {
      return createDisabledTeamOperationsAdapter();
    }
  }
  return createDisabledTeamOperationsAdapter();
}

function TeamOperationsLoading() {
  return (
    <section aria-label="Team operations" className="space-y-4">
      <Skeleton className="h-36 w-full rounded-2xl" />
      <div className="grid gap-4 lg:grid-cols-3">
        <Skeleton className="h-56 rounded-2xl lg:col-span-2" />
        <Skeleton className="h-56 rounded-2xl" />
      </div>
    </section>
  );
}

function OperationStatus({
  notice,
  pendingAction,
}: {
  notice: string | null;
  pendingAction: string | null;
}) {
  return (
    <p
      aria-atomic="true"
      aria-live="polite"
      className="sr-only"
      data-testid="team-operations-live-status"
      role="status"
    >
      {pendingAction
        ? `${pendingAction} in progress.`
        : (notice ?? "Team operations are ready.")}
    </p>
  );
}

function DisabledTeamOperations({
  reason,
  requiredConnection,
}: Extract<TeamOperationsLoadResult, { kind: "disabled" }>) {
  return (
    <section aria-labelledby="team-operations-disabled-title">
      <Card className="overflow-hidden border-sky-500/20 bg-linear-to-br from-sky-500/8 via-card to-emerald-500/8">
        <CardContent className="grid gap-5 p-5 sm:p-6 lg:grid-cols-[minmax(0,1fr)_auto] lg:items-center">
          <div className="flex min-w-0 gap-4">
            <div className="flex h-11 w-11 shrink-0 items-center justify-center rounded-xl border border-sky-500/20 bg-sky-500/10 text-sky-600 dark:text-sky-300">
              <ServerOff aria-hidden="true" className="h-5 w-5" />
            </div>
            <div className="min-w-0 space-y-2">
              <div className="flex flex-wrap items-center gap-2">
                <h2
                  className="text-lg font-semibold tracking-tight"
                  id="team-operations-disabled-title"
                >
                  AI Workforce command view
                </h2>
                <span className="rounded-full border border-amber-500/30 bg-amber-500/10 px-2 py-1 text-xs font-medium text-amber-700 dark:text-amber-300">
                  Connection off
                </span>
              </div>
              <p className="max-w-3xl text-sm leading-6 text-muted-foreground">
                {reason}
              </p>
              <div className="flex items-start gap-2 text-xs text-muted-foreground">
                <LockKeyhole
                  aria-hidden="true"
                  className="mt-0.5 h-3.5 w-3.5 shrink-0"
                />
                <span>Required: {requiredConnection}.</span>
              </div>
            </div>
          </div>
          <Button
            aria-describedby="team-operations-disabled-note"
            disabled
            size="sm"
            variant="outline"
          >
            Start a governed request
          </Button>
          <p className="sr-only" id="team-operations-disabled-note">
            This control stays disabled until the private orchestration API and
            mutation receipts are configured and verified.
          </p>
        </CardContent>
      </Card>
    </section>
  );
}

function GovernedRequestComposer({
  disabled,
  onCreate,
}: {
  disabled: boolean;
  onCreate(input: CreateGovernedRequestInput): void;
}) {
  const [open, setOpen] = React.useState(false);
  const [objective, setObjective] = React.useState("");
  const [classification, setClassification] =
    React.useState<CreateGovernedRequestInput["classification"]>(
      "confidential",
    );
  const [deadline, setDeadline] = React.useState("");
  const [budget, setBudget] = React.useState("25");
  const objectiveRef = React.useRef<HTMLTextAreaElement>(null);
  const triggerRef = React.useRef<HTMLButtonElement>(null);

  React.useEffect(() => {
    if (open) objectiveRef.current?.focus();
  }, [open]);

  const close = () => {
    setOpen(false);
    requestAnimationFrame(() => triggerRef.current?.focus());
  };

  if (!open) {
    return (
      <div className="flex justify-end">
        <Button
          aria-controls="governed-request-composer"
          aria-expanded="false"
          disabled={disabled}
          onClick={() => setOpen(true)}
          ref={triggerRef}
          size="sm"
        >
          Start a governed request
        </Button>
      </div>
    );
  }
  return (
    <Card>
      <CardContent className="p-5">
        <form
          aria-busy={disabled}
          className="grid gap-4 lg:grid-cols-2"
          id="governed-request-composer"
          onSubmit={(event) => {
            event.preventDefault();
            const dollars = Number(budget);
            if (!objective.trim() || !deadline || !Number.isFinite(dollars))
              return;
            onCreate({
              objective,
              classification,
              deadlineAt: new Date(deadline).toISOString(),
              maxCostMicrousd: Math.round(dollars * 1_000_000),
              contextReferences: [],
            });
          }}
        >
          <div className="space-y-2 lg:col-span-2">
            <label className="text-sm font-medium" htmlFor="governed-objective">
              What outcome should the team produce?
            </label>
            <Textarea
              disabled={disabled}
              id="governed-objective"
              maxLength={8000}
              onChange={(event) => setObjective(event.target.value)}
              placeholder="Describe the outcome without pasting raw client rows, mailbox content, or transcripts."
              ref={objectiveRef}
              required
              value={objective}
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium" htmlFor="governed-deadline">
              Deadline
            </label>
            <Input
              disabled={disabled}
              id="governed-deadline"
              onChange={(event) => setDeadline(event.target.value)}
              required
              type="datetime-local"
              value={deadline}
            />
          </div>
          <div className="space-y-2">
            <label className="text-sm font-medium" htmlFor="governed-budget">
              Maximum budget (USD)
            </label>
            <Input
              disabled={disabled}
              id="governed-budget"
              min="0.01"
              onChange={(event) => setBudget(event.target.value)}
              required
              step="0.01"
              type="number"
              value={budget}
            />
          </div>
          <div className="space-y-2">
            <label
              className="text-sm font-medium"
              htmlFor="governed-classification"
            >
              Classification
            </label>
            <select
              className="h-9 w-full rounded-lg border border-input/40 bg-background px-3 text-sm"
              disabled={disabled}
              id="governed-classification"
              onChange={(event) =>
                setClassification(
                  event.target
                    .value as CreateGovernedRequestInput["classification"],
                )
              }
              value={classification}
            >
              <option value="internal">Snowman internal</option>
              <option value="confidential">Client confidential</option>
              <option value="restricted">Restricted</option>
            </select>
          </div>
          <p className="self-end text-xs text-muted-foreground">
            Context is attached later through immutable Analyst 360 references.
          </p>
          <div className="flex flex-wrap justify-end gap-2 lg:col-span-2">
            <Button onClick={close} type="button" variant="ghost">
              Close
            </Button>
            <Button disabled={disabled} type="submit">
              Authorize planning
            </Button>
          </div>
        </form>
      </CardContent>
    </Card>
  );
}

export function TeamOperationsPanel({
  adapter,
}: {
  adapter?: TeamOperationsAdapter;
}) {
  const { activeCommunity } = useCommunities();
  const resolvedAdapter = React.useMemo(
    () =>
      adapter ??
      createDefaultAdapter(activeCommunity?.id, activeCommunity?.relayUrl),
    [activeCommunity?.id, activeCommunity?.relayUrl, adapter],
  );
  const [result, setResult] = React.useState<TeamOperationsLoadResult | null>(
    null,
  );
  const [error, setError] = React.useState<string | null>(null);
  const [notice, setNotice] = React.useState<string | null>(null);
  const [pendingAction, setPendingAction] = React.useState<string | null>(null);
  const errorRef = React.useRef<HTMLDivElement>(null);

  React.useEffect(() => {
    if (error) errorRef.current?.focus();
  }, [error]);

  React.useEffect(() => {
    const controller = new AbortController();
    setResult(null);
    setError(null);
    void resolvedAdapter.load(controller.signal).then(
      (nextResult) => {
        if (!controller.signal.aborted) setResult(nextResult);
      },
      (loadError: unknown) => {
        if (!controller.signal.aborted) {
          setError(
            loadError instanceof Error
              ? loadError.message
              : "The team operations snapshot could not be loaded.",
          );
        }
      },
    );
    return () => controller.abort();
  }, [resolvedAdapter]);

  const runAction = React.useCallback(
    async (
      label: string,
      operation: (signal: AbortSignal) => Promise<TeamOperationsCommandResult>,
    ) => {
      const controller = new AbortController();
      setPendingAction(label);
      setError(null);
      setNotice(null);
      try {
        const command = await operation(controller.signal);
        const nextSnapshot = command.snapshot;
        if (nextSnapshot) {
          setResult((current) =>
            current?.kind === "ready"
              ? {
                  ...current,
                  snapshot: nextSnapshot,
                  controls: command.controls ?? current.controls,
                }
              : {
                  kind: "ready",
                  source: "live",
                  snapshot: nextSnapshot,
                  controls: command.controls ?? noTeamOperationsControls,
                },
          );
        }
        setNotice(`${label} receipt: ${command.receipt.status}.`);
      } catch (actionError) {
        setError(
          actionError instanceof Error
            ? actionError.message
            : "The governed operation failed closed.",
        );
      } finally {
        setPendingAction(null);
      }
    },
    [],
  );

  if (error) {
    return (
      <Card
        className="border-destructive/30 outline-none focus-visible:ring-2 focus-visible:ring-ring"
        data-testid="team-operations-error"
        ref={errorRef}
        role="alert"
        tabIndex={-1}
      >
        <CardContent className="flex items-start gap-3 p-5 text-sm">
          <AlertTriangle
            aria-hidden="true"
            className="mt-0.5 h-4 w-4 shrink-0 text-destructive"
          />
          <div>
            <p className="font-medium">Team operations are unavailable</p>
            <p className="mt-1 text-muted-foreground">{error}</p>
          </div>
        </CardContent>
      </Card>
    );
  }

  if (!result) return <TeamOperationsLoading />;
  if (result.kind === "disabled") {
    return <DisabledTeamOperations {...result} />;
  }
  if (result.kind === "empty") {
    return (
      <section
        aria-labelledby="team-operations-empty-title"
        className="space-y-4"
        data-testid="team-operations-empty"
      >
        <OperationStatus notice={notice} pendingAction={pendingAction} />
        <Card>
          <CardContent className="p-5">
            <h2 className="font-semibold" id="team-operations-empty-title">
              AI Workforce command view
            </h2>
            <p className="mt-1 text-sm text-muted-foreground">
              {result.message}
            </p>
          </CardContent>
        </Card>
        <GovernedRequestComposer
          disabled={!resolvedAdapter.createRequest || pendingAction !== null}
          onCreate={(input) => {
            if (!resolvedAdapter.createRequest) return;
            void runAction(
              "Governed request",
              (signal) =>
                resolvedAdapter.createRequest?.(input, signal) ??
                Promise.reject(new Error("Request creation is unavailable.")),
            );
          }}
        />
      </section>
    );
  }

  return (
    <div
      aria-busy={pendingAction !== null}
      className="min-w-0 space-y-4"
      data-testid="team-operations-surface"
    >
      <OperationStatus notice={notice} pendingAction={pendingAction} />
      <GovernedRequestComposer
        disabled={!resolvedAdapter.createRequest || pendingAction !== null}
        onCreate={(input) => {
          if (!resolvedAdapter.createRequest) return;
          void runAction(
            "Governed request",
            (signal) =>
              resolvedAdapter.createRequest?.(input, signal) ??
              Promise.reject(new Error("Request creation is unavailable.")),
          );
        }}
      />
      <React.Suspense fallback={<TeamOperationsLoading />}>
        <TeamOperationsDashboard
          controls={result.controls}
          notice={notice}
          pendingAction={pendingAction}
          snapshot={result.snapshot}
          source={result.source}
          onAction={(action) => {
            if (!resolvedAdapter.execute) return;
            void runAction(
              action,
              (signal) =>
                resolvedAdapter.execute?.(action, signal) ??
                Promise.reject(
                  new Error("Lifecycle controls are unavailable."),
                ),
            );
          }}
          onApproval={(approval, decision) => {
            if (!resolvedAdapter.decideApproval) return;
            void runAction(
              decision,
              (signal) =>
                resolvedAdapter.decideApproval?.(
                  crypto.randomUUID(),
                  approval.taskId,
                  approval.taskSnapshotSha256,
                  decision,
                  signal,
                ) ??
                Promise.reject(new Error("Approval controls are unavailable.")),
            );
          }}
        />
      </React.Suspense>
    </div>
  );
}
