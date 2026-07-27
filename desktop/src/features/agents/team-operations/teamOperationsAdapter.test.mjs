import assert from "node:assert/strict";
import test from "node:test";

import {
  createDisabledTeamOperationsAdapter,
  createFixtureTeamOperationsAdapter,
  createLiveTeamOperationsAdapter,
} from "./teamOperationsAdapter.ts";
import { teamOperationsFixture } from "./teamOperationsFixture.ts";

test("production adapter is honestly disabled and exposes no mutation surface", async () => {
  const adapter = createDisabledTeamOperationsAdapter();
  const result = await adapter.load(new AbortController().signal);

  assert.equal(result.kind, "disabled");
  assert.match(result.reason, /not configured/i);
  assert.equal("approve" in adapter, false);
  assert.equal("cancel" in adapter, false);
  assert.equal("start" in adapter, false);
});

const tenantId = "10000000-0000-4000-8000-000000000001";
const workspaceId = "10000000-0000-4000-8000-000000000002";
const planId = "10000000-0000-4000-8000-000000000003";
const requestId = "10000000-0000-4000-8000-000000000004";
const personaId = "20000000-0000-4000-8000-000000000001";
const taskId = "30000000-0000-4000-8000-000000000001";

function liveProjection(overrides = {}) {
  return {
    schemaVersion: "snowman.orchestration.team-operations.v1",
    generatedAt: "2026-07-27T15:30:00Z",
    tenantId,
    workspaceId,
    authority: {
      identityId: "40000000-0000-4000-8000-000000000001",
      principal: "snowman:founder.command-center",
      policyGeneration: 2,
      capabilities: [
        "orchestration.plans.pause",
        "orchestration.plans.cancel",
        "workforce.tasks.approve",
      ],
    },
    plan: {
      planId,
      requestId,
      workKind: "user_request",
      generation: 2,
      supersedesPlanId: null,
      state: "active",
      classification: "confidential",
      maxCostMicrousd: 5_000_000,
      automaticExecutionEnabled: true,
      deadlineAt: "2026-07-29T15:30:00Z",
      createdAt: "2026-07-27T14:30:00Z",
      updatedAt: "2026-07-27T15:30:00Z",
    },
    schedule: null,
    personas: [
      {
        personaId,
        specialistRole: "evidence_analyst",
        modelId: "snowman-analysis-route",
        modelRouteReference:
          "snowman:model-route:50000000-0000-4000-8000-000000000001:revision:3",
        maxCostMicrousd: 5_000_000,
        enabled: true,
        capabilities: ["analytics.governed"],
      },
    ],
    tasks: [
      {
        taskId,
        personaId,
        dependsOn: [],
        status: "running",
        approvalRequired: false,
        requiredCapabilities: ["analytics.governed"],
        artifactTypes: ["evidence_workbook"],
        maxCostMicrousd: 5_000_000,
        deadlineAt: "2026-07-29T15:30:00Z",
        dispatchStatus: "submitted",
        reservedCostMicrousd: 500_000,
        accountedCostMicrousd: 100_000,
        executionSnapshotSha256: "a".repeat(64),
      },
    ],
    receipts: [],
    reminders: [],
    commands: [],
    ...overrides,
  };
}

function signedEvent() {
  return {
    id: "b".repeat(64),
    pubkey: "c".repeat(64),
    created_at: 1_785_168_000,
    kind: 27235,
    tags: [],
    content: "",
    sig: "d".repeat(128),
  };
}

test("live adapter binds reads to exact Snowman tenant and workspace", async () => {
  const calls = [];
  const adapter = createLiveTeamOperationsAdapter({
    orchestrationOrigin: "https://orchestration.internal.snowmanai.org/",
    relayOrigin: "https://aptive.snowmanai.org/",
    tenantId,
    workspaceId,
    signEvent: async () => signedEvent(),
    fetcher: async (url, init) => {
      calls.push({ url, init });
      return Response.json(liveProjection());
    },
  });
  const result = await adapter.load(new AbortController().signal);

  assert.equal(result.kind, "ready");
  assert.equal(result.source, "live");
  assert.equal(result.controls.pause, true);
  assert.equal(result.controls.activate, false);
  assert.equal(result.snapshot.request.planId, planId);
  assert.equal(
    calls[0].url,
    `https://orchestration.internal.snowmanai.org/v1/tenants/${tenantId}/workspaces/${workspaceId}/plans`,
  );
  assert.match(calls[0].init.headers.Authorization, /^Nostr /);
  assert.equal(calls[0].init.redirect, "error");
});

test("live lifecycle mutation verifies the generation receipt and refreshes", async () => {
  let calls = 0;
  const adapter = createLiveTeamOperationsAdapter({
    orchestrationOrigin: "https://orchestration.internal.snowmanai.org/",
    relayOrigin: "https://aptive.snowmanai.org/",
    tenantId,
    workspaceId,
    signEvent: async () => signedEvent(),
    fetcher: async (_url, init) => {
      calls += 1;
      if (init?.method === "POST") {
        return Response.json({
          schema_version: "snowman.orchestration.api-receipt.v1",
          command_id: JSON.parse(init.body).command_id,
          community_id: tenantId,
          workspace_id: workspaceId,
          plan_id: planId,
          plan_generation: 2,
          status: "applied",
          request_sha256: "e".repeat(64),
          accepted_at: "2026-07-27T15:31:00Z",
        });
      }
      return Response.json(liveProjection());
    },
  });
  await adapter.load(new AbortController().signal);
  const command = await adapter.execute("pause", new AbortController().signal);

  assert.equal(command.receipt.action, "pause");
  assert.equal(command.receipt.status, "applied");
  assert.equal(command.snapshot.request.planId, planId);
  assert.equal(calls, 3);
});

test("live adapter fails closed on non-Snowman origins and cross-scope projections", async () => {
  assert.throws(() =>
    createLiveTeamOperationsAdapter({
      orchestrationOrigin: "https://api.block.xyz/",
      relayOrigin: "https://aptive.snowmanai.org/",
      tenantId,
      workspaceId,
      signEvent: async () => signedEvent(),
    }),
  );
  const adapter = createLiveTeamOperationsAdapter({
    orchestrationOrigin: "https://orchestration.internal.snowmanai.org/",
    relayOrigin: "https://aptive.snowmanai.org/",
    tenantId,
    workspaceId,
    signEvent: async () => signedEvent(),
    fetcher: async () =>
      Response.json(
        liveProjection({
          workspaceId: "90000000-0000-4000-8000-000000000009",
        }),
      ),
  });
  await assert.rejects(
    adapter.load(new AbortController().signal),
    /crossed its bound workspace/i,
  );
});

test("fixture adapter validates before returning renderable data", async () => {
  const adapter = createFixtureTeamOperationsAdapter(teamOperationsFixture);
  const result = await adapter.load(new AbortController().signal);

  assert.equal(result.kind, "ready");
  assert.equal(result.source, "fixture");
  assert.equal(
    result.snapshot.request.title,
    teamOperationsFixture.request.title,
  );
});

test("fixture adapter respects cancellation before parsing", async () => {
  const controller = new AbortController();
  controller.abort();
  const adapter = createFixtureTeamOperationsAdapter(teamOperationsFixture);

  await assert.rejects(adapter.load(controller.signal), {
    name: "AbortError",
  });
});
