import assert from "node:assert/strict";
import test from "node:test";

import {
  createTeamOperationsE2eAdapter,
  isTeamOperationsE2eEnabled,
} from "./teamOperationsE2eAdapter.ts";

test("operator harness is impossible to enable outside the E2E build mode", () => {
  const config = { teamOperationsScenario: "ready" };

  assert.equal(isTeamOperationsE2eEnabled("production", config), false);
  assert.equal(isTeamOperationsE2eEnabled("development", config), false);
  assert.equal(isTeamOperationsE2eEnabled("e2e", config), true);
  assert.equal(isTeamOperationsE2eEnabled("e2e", undefined), false);
});

test("empty scenario deterministically accepts a request and returns a plan", async () => {
  const adapter = createTeamOperationsE2eAdapter("empty");
  const controller = new AbortController();

  assert.equal((await adapter.load(controller.signal)).kind, "empty");
  const result = await adapter.createRequest?.(
    {
      classification: "confidential",
      contextReferences: [],
      deadlineAt: "2026-07-30T18:00:00.000Z",
      maxCostMicrousd: 25_000_000,
      objective: "Prepare the governed client follow-up",
    },
    controller.signal,
  );

  assert.equal(result?.receipt.action, "create_request");
  assert.equal(result?.snapshot?.request.state, "draft");
  assert.equal(
    result?.snapshot?.request.title,
    "Prepare the governed client follow-up",
  );
  assert.equal(result?.controls?.activate, true);
});

test("approval and lifecycle scenarios mutate only the projected metadata", async () => {
  const adapter = createTeamOperationsE2eAdapter("ready");
  const controller = new AbortController();
  const loaded = await adapter.load(controller.signal);
  assert.equal(loaded.kind, "ready");
  if (loaded.kind !== "ready") return;

  const approval = loaded.snapshot.approvals[0];
  const approved = await adapter.decideApproval?.(
    approval.id,
    approval.taskId,
    approval.taskSnapshotSha256,
    "approved",
    controller.signal,
  );
  assert.equal(approved?.snapshot?.approvals.length, 0);
  assert.equal(approved?.receipt.action, "approve");

  const paused = await adapter.execute?.("pause", controller.signal);
  assert.equal(paused?.snapshot?.request.state, "paused");
  assert.equal(paused?.controls?.activate, true);
});
