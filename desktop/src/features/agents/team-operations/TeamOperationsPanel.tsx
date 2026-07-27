import { AlertTriangle, LockKeyhole, ServerOff } from "lucide-react";
import * as React from "react";

import { Button } from "@/shared/ui/button";
import { Card, CardContent } from "@/shared/ui/card";
import { Skeleton } from "@/shared/ui/skeleton";
import {
  createDisabledTeamOperationsAdapter,
  createFixtureTeamOperationsAdapter,
  type TeamOperationsAdapter,
  type TeamOperationsLoadResult,
} from "./teamOperationsAdapter";
import { teamOperationsFixture } from "./teamOperationsFixture";

const TeamOperationsDashboard = React.lazy(async () => {
  const module = await import("./TeamOperationsDashboard");
  return { default: module.TeamOperationsDashboard };
});

type TeamOperationsE2eWindow = Window & {
  __BUZZ_E2E__?: { teamOperationsFixture?: boolean };
};

function createDefaultAdapter(): TeamOperationsAdapter {
  const e2e = (window as TeamOperationsE2eWindow).__BUZZ_E2E__;
  if (import.meta.env.MODE === "e2e" && e2e?.teamOperationsFixture === true) {
    return createFixtureTeamOperationsAdapter(teamOperationsFixture);
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

export function TeamOperationsPanel({
  adapter,
}: {
  adapter?: TeamOperationsAdapter;
}) {
  const resolvedAdapter = React.useMemo(
    () => adapter ?? createDefaultAdapter(),
    [adapter],
  );
  const [result, setResult] =
    React.useState<TeamOperationsLoadResult | null>(null);
  const [error, setError] = React.useState<string | null>(null);

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

  if (error) {
    return (
      <Card className="border-destructive/30" role="alert">
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

  return (
    <React.Suspense fallback={<TeamOperationsLoading />}>
      <TeamOperationsDashboard
        controlsEnabled={false}
        snapshot={result.snapshot}
        source={result.source}
      />
    </React.Suspense>
  );
}
