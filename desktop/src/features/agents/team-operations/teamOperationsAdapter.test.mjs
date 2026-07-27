import assert from "node:assert/strict";
import test from "node:test";

import {
  createDisabledTeamOperationsAdapter,
  createFixtureTeamOperationsAdapter,
} from "./teamOperationsAdapter.ts";
import { teamOperationsFixture } from "./teamOperationsFixture.ts";

test("production adapter is honestly disabled and exposes no mutation surface", async () => {
  const adapter = createDisabledTeamOperationsAdapter();
  const result = await adapter.load(new AbortController().signal);

  assert.equal(result.kind, "disabled");
  assert.match(result.reason, /not connected/i);
  assert.equal("approve" in adapter, false);
  assert.equal("cancel" in adapter, false);
  assert.equal("start" in adapter, false);
});

test("fixture adapter validates before returning renderable data", async () => {
  const adapter = createFixtureTeamOperationsAdapter(teamOperationsFixture);
  const result = await adapter.load(new AbortController().signal);

  assert.equal(result.kind, "ready");
  assert.equal(result.source, "fixture");
  assert.equal(result.snapshot.request.title, teamOperationsFixture.request.title);
});

test("fixture adapter respects cancellation before parsing", async () => {
  const controller = new AbortController();
  controller.abort();
  const adapter = createFixtureTeamOperationsAdapter(teamOperationsFixture);

  await assert.rejects(adapter.load(controller.signal), {
    name: "AbortError",
  });
});
