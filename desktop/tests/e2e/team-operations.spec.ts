import { expect, test, type Page } from "@playwright/test";

import type { TeamOperationsE2eScenario } from "../../src/features/agents/team-operations/teamOperationsE2eAdapter";
import { waitForAnimations } from "../helpers/animations";
import { installMockBridge } from "../helpers/bridge";

async function openTeamOperations(
  page: Page,
  scenario: TeamOperationsE2eScenario,
) {
  await installMockBridge(page, undefined, {
    relayWsUrl: "wss://relay.snowmanai.org",
  });
  await page.goto("/", { waitUntil: "domcontentloaded" });
  await page.evaluate((teamOperationsScenario) => {
    const testWindow = window as Window & {
      __BUZZ_E2E__?: Record<string, unknown>;
    };
    testWindow.__BUZZ_E2E__ = {
      ...(testWindow.__BUZZ_E2E__ ?? {}),
      teamOperationsScenario,
    };
  }, scenario);
  const fatalError = page.getByRole("button", { name: "Show Error" });
  if (await fatalError.isVisible()) {
    await fatalError.click();
    throw new Error(
      `App bootstrap failed: ${await page.locator("body").innerText()}`,
    );
  }
  await page.evaluate(() => {
    window.location.hash = "/agents";
  });
  await expect(page).toHaveURL(/#\/agents$/);
  await expect(
    page
      .getByTestId("team-operations-dashboard")
      .or(page.getByTestId("team-operations-empty"))
      .or(page.getByTestId("team-operations-error")),
  ).toBeVisible();
}

test("creates a governed request from an empty workspace with keyboard focus and a live receipt", async ({
  page,
}) => {
  await openTeamOperations(page, "empty");

  await expect(page.getByTestId("team-operations-empty")).toContainText(
    "No governed orchestration plan exists",
  );
  const trigger = page.getByRole("button", {
    name: "Start a governed request",
  });
  await trigger.focus();
  await page.keyboard.press("Enter");

  const objective = page.getByLabel("What outcome should the team produce?");
  await expect(objective).toBeFocused();
  await objective.fill("Prepare a governed client follow-up package");
  await page.getByLabel("Deadline").fill("2026-07-30T18:00");
  await page.getByLabel("Maximum budget (USD)").fill("40");
  await page.getByLabel("Classification").selectOption("confidential");
  await page.getByRole("button", { name: "Authorize planning" }).click();

  await expect(page.getByTestId("team-operations-dashboard")).toContainText(
    "Prepare a governed client follow-up package",
  );
  await expect(page.getByTestId("team-operations-live-status")).toHaveText(
    "Governed request receipt: applied.",
  );
  await expect(page.getByRole("button", { name: "Activate" })).toBeEnabled();
});

test("approval and lifecycle controls expose specific names and update the governed projection", async ({
  page,
}) => {
  await openTeamOperations(page, "ready");

  const approve = page.getByRole("button", {
    name: /Approve Release the approved evidence set/,
  });
  await expect(approve).toBeEnabled();
  await approve.focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByText("No decisions are waiting for you."),
  ).toBeVisible();
  await expect(page.getByTestId("team-operations-live-status")).toHaveText(
    "approved receipt: applied.",
  );

  const pause = page.getByRole("button", { name: "Pause" });
  await pause.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("button", { name: "Activate" })).toBeEnabled();
  await expect(page.getByTestId("team-operations-live-status")).toHaveText(
    "pause receipt: applied.",
  );

  const task = page.getByRole("button", {
    name: /Build the executive narrative and client-ready work products/,
  });
  await task.focus();
  await page.keyboard.press("Enter");
  await expect(task).toHaveAttribute("aria-current", "step");
  await expect(page.getByText("Owned by Aurora")).toBeVisible();
});

test("load and command failures fail closed, announce the error, and move focus", async ({
  page,
}) => {
  await openTeamOperations(page, "load_failure");
  const loadError = page.getByTestId("team-operations-error");
  await expect(loadError).toHaveAttribute("role", "alert");
  await expect(loadError).toBeFocused();
  await expect(loadError).toContainText("could not be loaded");

  await page.goto("/", { waitUntil: "domcontentloaded" });
  await page.evaluate(() => {
    const testWindow = window as Window & {
      __BUZZ_E2E__?: Record<string, unknown>;
    };
    testWindow.__BUZZ_E2E__ = {
      ...(testWindow.__BUZZ_E2E__ ?? {}),
      teamOperationsScenario: "action_failure",
    };
    window.location.hash = "/agents";
  });
  await expect(page.getByTestId("team-operations-dashboard")).toBeVisible();
  await page.getByRole("button", { name: "Pause" }).click();

  const actionError = page.getByTestId("team-operations-error");
  await expect(actionError).toBeFocused();
  await expect(actionError).toContainText("failed closed");
  await expect(page.getByTestId("team-operations-dashboard")).toHaveCount(0);
});

test("small viewport and reduced motion remain readable without horizontal overflow", async ({
  page,
}) => {
  await page.setViewportSize({ height: 844, width: 390 });
  await page.emulateMedia({ reducedMotion: "reduce" });
  await openTeamOperations(page, "ready");
  await waitForAnimations(page);

  const dashboard = page.getByTestId("team-operations-dashboard");
  await expect(dashboard).toBeVisible();
  expect(
    await page.evaluate(
      () => document.documentElement.scrollWidth <= window.innerWidth,
    ),
  ).toBe(true);
  const firstTask = page
    .getByRole("list", { name: "Specialist task plan" })
    .getByRole("button")
    .first();
  await expect(firstTask).toHaveCSS("transition-duration", "0s");
});

test("renders metadata only and makes no request to a Block-controlled origin", async ({
  page,
}) => {
  const networkOrigins: string[] = [];
  page.on("request", (request) => networkOrigins.push(request.url()));
  await openTeamOperations(page, "ready");

  const text = await page.getByTestId("team-operations-dashboard").innerText();
  expect(text).not.toContain("analyst360:sha256:");
  expect(text).not.toMatch(/[0-9a-f]{64}/);
  expect(text).not.toContain("raw_client_rows");
  expect(text).not.toContain("mailbox_body");
  expect(text).not.toContain("transcript_text");
  expect(
    networkOrigins.some((url) => /block\.xyz|github\.com\/block/i.test(url)),
  ).toBe(false);
});
