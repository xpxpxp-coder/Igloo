import {
  parseTeamOperationsSnapshot,
  type TeamOperationsSnapshot,
} from "./teamOperationsContract";

export type TeamOperationsLoadResult =
  | {
      kind: "disabled";
      reason: string;
      requiredConnection: string;
    }
  | {
      kind: "ready";
      source: "fixture";
      snapshot: TeamOperationsSnapshot;
    };

export interface TeamOperationsAdapter {
  load(signal: AbortSignal): Promise<TeamOperationsLoadResult>;
}

export function createDisabledTeamOperationsAdapter(): TeamOperationsAdapter {
  return {
    async load() {
      return {
        kind: "disabled",
        reason:
          "The governed orchestration read API is not connected in this build. No work is being started, approved, or cancelled from this screen.",
        requiredConnection:
          "Private tenant-scoped orchestration snapshot and mutation receipts",
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
      };
    },
  };
}
