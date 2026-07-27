import type {
  TeamOperationsAction,
  TeamOperationsAdapter,
  TeamOperationsCommandResult,
  TeamOperationsControls,
} from "./teamOperationsAdapter";
import type { TeamOperationsSnapshot } from "./teamOperationsContract";
import { teamOperationsFixture } from "./teamOperationsFixture";

export type TeamOperationsE2eScenario =
  | "ready"
  | "empty"
  | "load_failure"
  | "action_failure";

export type TeamOperationsE2eConfig = {
  teamOperationsScenario?: TeamOperationsE2eScenario;
};

export function isTeamOperationsE2eEnabled(
  mode: string,
  config: TeamOperationsE2eConfig | undefined,
): config is Required<TeamOperationsE2eConfig> {
  return mode === "e2e" && config?.teamOperationsScenario !== undefined;
}

const fullControls: TeamOperationsControls = {
  activate: true,
  approve: true,
  cancel: true,
  pause: true,
  supersede: true,
};

function controlsFor(snapshot: TeamOperationsSnapshot): TeamOperationsControls {
  return {
    ...fullControls,
    activate: ["draft", "paused"].includes(snapshot.request.state),
    pause: snapshot.request.state === "active",
    cancel:
      snapshot.request.canCancel &&
      ["draft", "active", "paused"].includes(snapshot.request.state),
    supersede:
      snapshot.request.supersedesPlanId !== null &&
      ["draft", "paused"].includes(snapshot.request.state),
  };
}

function commandResult(
  action: TeamOperationsCommandResult["receipt"]["action"],
  snapshot: TeamOperationsSnapshot,
  ordinal: number,
): TeamOperationsCommandResult {
  return {
    controls: controlsFor(snapshot),
    receipt: {
      action,
      commandId: `70000000-0000-4000-8000-${ordinal.toString().padStart(12, "0")}`,
      digestSha256: ordinal.toString(16).padStart(64, "0"),
      recordedAt: `2026-07-27T16:${ordinal.toString().padStart(2, "0")}:00Z`,
      status: "applied",
    },
    snapshot,
  };
}

/**
 * Deterministic operator harness for browser E2E only. The caller must guard
 * construction with `isTeamOperationsE2eEnabled(import.meta.env.MODE, ...)`.
 */
export function createTeamOperationsE2eAdapter(
  scenario: TeamOperationsE2eScenario,
): TeamOperationsAdapter {
  let snapshot = structuredClone(teamOperationsFixture);
  let commandOrdinal = 1;

  const failActionIfConfigured = () => {
    if (scenario === "action_failure") {
      throw new Error(
        "The deterministic governed operation failed closed for verification.",
      );
    }
  };

  return {
    async load(signal) {
      if (signal.aborted) {
        throw new DOMException("The request was cancelled", "AbortError");
      }
      if (scenario === "load_failure") {
        throw new Error(
          "The deterministic team operations snapshot could not be loaded.",
        );
      }
      if (scenario === "empty") {
        return {
          kind: "empty",
          message:
            "No governed orchestration plan exists in this workspace yet.",
          source: "live",
        };
      }
      return {
        controls: controlsFor(snapshot),
        kind: "ready",
        snapshot,
        source: "live",
      };
    },
    async createRequest(input, signal) {
      if (signal.aborted) {
        throw new DOMException("The request was cancelled", "AbortError");
      }
      failActionIfConfigured();
      snapshot = {
        ...snapshot,
        approvals: [],
        request: {
          ...snapshot.request,
          generation: 1,
          state: "draft",
          supersedesPlanId: null,
          title: input.objective.trim(),
        },
      };
      return commandResult("create_request", snapshot, commandOrdinal++);
    },
    async execute(action: TeamOperationsAction, signal) {
      if (signal.aborted) {
        throw new DOMException("The request was cancelled", "AbortError");
      }
      failActionIfConfigured();
      const state =
        action === "activate"
          ? "active"
          : action === "pause"
            ? "paused"
            : action === "cancel"
              ? "cancelled"
              : snapshot.request.state;
      snapshot = {
        ...snapshot,
        request: {
          ...snapshot.request,
          canCancel: action === "cancel" ? false : snapshot.request.canCancel,
          state,
        },
      };
      return commandResult(action, snapshot, commandOrdinal++);
    },
    async decideApproval(
      _approvalId,
      taskId,
      _taskSnapshotSha256,
      decision,
      signal,
    ) {
      if (signal.aborted) {
        throw new DOMException("The request was cancelled", "AbortError");
      }
      failActionIfConfigured();
      snapshot = {
        ...snapshot,
        approvals: snapshot.approvals.filter(
          (approval) => approval.taskId !== taskId,
        ),
        tasks: snapshot.tasks.map((task) =>
          task.id === taskId
            ? {
                ...task,
                approval: decision,
                status: decision === "approved" ? "working" : "blocked",
              }
            : task,
        ),
      };
      return commandResult(
        decision === "approved" ? "approve" : "deny",
        snapshot,
        commandOrdinal++,
      );
    },
  };
}
