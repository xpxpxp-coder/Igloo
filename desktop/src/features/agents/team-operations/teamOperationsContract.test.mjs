import assert from "node:assert/strict";
import test from "node:test";

import {
  formatMicrousd,
  parseTeamOperationsSnapshot,
  summarizeTeamProgress,
} from "./teamOperationsContract.ts";
import { teamOperationsFixture } from "./teamOperationsFixture.ts";

test("fixture is a bounded, internally consistent team operations view", () => {
  const parsed = parseTeamOperationsSnapshot(teamOperationsFixture);
  assert.equal(parsed.request.generation, 3);
  assert.equal(parsed.specialists.length, 4);
  assert.equal(parsed.tasks.length, 4);
  assert.equal(parsed.tasks.find((task) => task.origin === "meeting")?.status, "done");
});

test("progress summarizes the dependency plan without counting artifact bodies", () => {
  assert.deepEqual(summarizeTeamProgress(teamOperationsFixture), {
    activeTasks: 2,
    blockedTasks: 0,
    completedTasks: 1,
    progressPercent: 51,
    totalTasks: 4,
  });
  assert.equal(formatMicrousd(2_870_000), "$2.87");
});

test("strict parsing rejects accidental raw client or transcript fields", () => {
  assert.throws(() =>
    parseTeamOperationsSnapshot({
      ...teamOperationsFixture,
      rawTranscript: "must remain in Analyst 360",
    }),
  );
});

test("artifact coordinates must remain immutable Analyst references", () => {
  assert.throws(() =>
    parseTeamOperationsSnapshot({
      ...teamOperationsFixture,
      artifacts: [
        {
          ...teamOperationsFixture.artifacts[0],
          immutableReference: "https://files.example.com/client-output",
        },
      ],
    }),
  );
});

test("cross-snapshot task, persona, approval, and artifact references fail closed", () => {
  const unknownId = "90000000-0000-4000-8000-000000000009";
  assert.throws(() =>
    parseTeamOperationsSnapshot({
      ...teamOperationsFixture,
      tasks: [
        {
          ...teamOperationsFixture.tasks[0],
          specialistId: unknownId,
          dependsOn: [unknownId],
        },
      ],
      approvals: [
        { ...teamOperationsFixture.approvals[0], taskId: unknownId },
      ],
      artifacts: [
        { ...teamOperationsFixture.artifacts[0], taskId: unknownId },
      ],
    }),
  );
});

test("cost projections cannot exceed the governed ceiling", () => {
  assert.throws(() =>
    parseTeamOperationsSnapshot({
      ...teamOperationsFixture,
      cost: {
        accountedMicrousd: 10_000_000,
        reservedMicrousd: 3_000_000,
        limitMicrousd: 12_000_000,
      },
    }),
  );
});
