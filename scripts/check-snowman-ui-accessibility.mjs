#!/usr/bin/env node

import { readFileSync } from "node:fs";

const requirements = [
  [
    "desktop/src/app/AppShell.tsx",
    [
      'href="#snowman-main-content"',
      'id="snowman-main-content"',
      "tabIndex={-1}",
    ],
  ],
  [
    "desktop/src/features/huddle/components/HuddleBar.tsx",
    [
      'aria-label="Huddle controls"',
      'aria-atomic="true"',
      'aria-live="polite"',
    ],
  ],
  [
    "desktop/src/features/projects/ui/ProjectsAgentPromptPage.tsx",
    ['aria-live="polite"', 'role="status"', 'aria-hidden="true"'],
  ],
  [
    "desktop/src/shared/styles/globals/components.css",
    [".snowman-skip-link", "prefers-reduced-motion: reduce"],
  ],
  [
    "web/src/app/routes/root.tsx",
    [
      'href="#snowman-main-content"',
      'id="snowman-main-content"',
      "tabIndex={-1}",
    ],
  ],
  [
    "web/src/shared/styles/globals.css",
    [
      ":focus-visible",
      "prefers-reduced-motion: reduce",
      "animation-duration: 1ms",
    ],
  ],
  [
    "web/src/features/repos/ui/ReposPage.tsx",
    ['aria-busy="true"', 'role="status"', "Loading repositories"],
  ],
  [
    "admin-web/src/App.tsx",
    [
      'href="#snowman-operations-main"',
      'id="snowman-operations-main"',
      'role="status"',
    ],
  ],
  [
    "admin-web/src/styles.css",
    [
      ":focus-visible",
      "prefers-reduced-motion: reduce",
      "animation-duration: 1ms",
    ],
  ],
  [
    "mobile/lib/features/channels/agent_activity/agent_activity_sheet.dart",
    [
      "MediaQuery.disableAnimationsOf(context)",
      "liveRegion: true",
      "Agent activity connection:",
    ],
  ],
];

const failures = [];
for (const [path, fragments] of requirements) {
  const source = readFileSync(path, "utf8");
  for (const fragment of fragments) {
    if (!source.includes(fragment))
      failures.push(`${path}: missing ${fragment}`);
  }
}

if (failures.length > 0) {
  console.error("Snowman UI accessibility contract failed:\n");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(
  `Snowman UI accessibility contract passed (${requirements.length} surfaces).`,
);
