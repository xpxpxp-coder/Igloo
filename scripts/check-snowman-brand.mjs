#!/usr/bin/env node

import { createHash } from "node:crypto";
import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const read = (path) => readFileSync(resolve(root, path), "utf8");
const identity = JSON.parse(read("product/identity.json"));
const brandAssets = JSON.parse(read("product/brand-assets.json"));
const failures = [];

if (brandAssets.schema_version !== 1 || !Array.isArray(brandAssets.assets)) {
  failures.push("product/brand-assets.json: unsupported asset manifest");
}

const required = new Map([
  [
    "desktop/src-tauri/tauri.conf.json",
    `"productName": "${identity.command_center_name}"`,
  ],
  [
    "desktop/src-tauri/tauri.conf.json",
    `"identifier": "${identity.desktop_bundle_id}"`,
  ],
  [
    "desktop/src-tauri/Info.plist",
    `<string>${identity.command_center_name}</string>`,
  ],
  [
    "mobile/android/app/build.gradle.kts",
    `applicationId = "${identity.desktop_bundle_id}"`,
  ],
  [
    "mobile/android/app/src/main/AndroidManifest.xml",
    `android:label="${identity.mobile_name}"`,
  ],
  [
    "mobile/ios/Runner/Info.plist",
    `<string>${identity.mobile_name}</string>`,
  ],
  [
    "mobile/ios/Runner/Info.plist",
    `<string>${identity.primary_deep_link_scheme}</string>`,
  ],
  ["web/index.html", `<title>${identity.command_center_name}</title>`],
  [
    "Dockerfile",
    `org.opencontainers.image.title="${identity.command_center_name}"`,
  ],
  ["crates/buzz-cli/src/lib.rs", `Snowman 360 CLI`],
  ["crates/buzz-admin/src/main.rs", `Snowman Operations administration`],
  [".github/workflows/release.yml", identity.desktop_release_tag],
  [".github/workflows/release.yml", identity.desktop_app_bundle_name],
  [
    ".github/workflows/docker.yml",
    `org.opencontainers.image.title=${identity.command_center_name}`,
  ],
  ["admin-web/src/App.tsx", "{ADMIN_NAME}"],
  ["mobile/lib/app.dart", "title: SnowmanProduct.mobileName"],
]);
for (const [path, fragment] of required) {
  if (!read(path).includes(fragment)) {
    failures.push(
      `${path}: missing generated product contract ${JSON.stringify(fragment)}`,
    );
  }
}

const visibleFiles = [
  "admin-web/src/App.tsx",
  "desktop/src/features/onboarding/welcomeKickoff.ts",
  "desktop/src/features/onboarding/welcomeGuide.ts",
  "desktop/src/features/onboarding/ui/MachineOnboardingFlow.tsx",
  "desktop/src/features/onboarding/ui/CommunityOnboardingFlow.tsx",
  "desktop/src/features/onboarding/ui/DefaultConfigStep.tsx",
  "desktop/src/features/onboarding/ui/IdentityKeyHelpDialog.tsx",
  "desktop/src/features/onboarding/ui/KeyringLockedScreen.tsx",
  "desktop/src/features/onboarding/ui/RecoveryScreen.tsx",
  "desktop/src/features/onboarding/ui/ProfileStep.tsx",
  "desktop/src/features/settings/UpdateChecker.tsx",
  "desktop/src/features/settings/ui/MobilePairingCard.tsx",
  "desktop/src/features/settings/ui/ProfileSettingsCard.tsx",
  "desktop/src/features/settings/ui/SendFeedbackDialog.tsx",
  "desktop/src/features/settings/ui/SignOutSection.tsx",
  "desktop/src/features/notifications/hooks.ts",
  "desktop/src/features/local-archive/ui/localArchiveKinds.ts",
  "desktop/src/features/projects/ui/CreateProjectDialog.tsx",
  "desktop/src/features/agents/ui/PersonaModelField.tsx",
  "desktop/src/features/agents/ui/agentSessionToolCatalog.ts",
  "desktop/src/features/agents/ui/agentSessionToolClassifier.ts",
  "desktop/src/features/agents/ui/agentSessionTranscriptHelpers.ts",
  "desktop/src/features/profile/ui/NostrBindConsentDialog.tsx",
  "desktop/src/features/profile/ui/AnimatedAvatarCapture.tsx",
  "mobile/lib/app.dart",
  "mobile/lib/features/pairing/pairing_page.dart",
  "web/src/features/invite/ui/InvitePage.tsx",
  "web/src/features/invite/ui/InviteJoinPolicyNotice.tsx",
  "web/src/features/repos/ui/ReposPage.tsx",
  "crates/buzz-cli/src/lib.rs",
  "crates/buzz-admin/src/main.rs",
  "desktop/src-tauri/src/managed_agents/nest_agents.md",
  "desktop/src-tauri/src/managed_agents/nest_skill.md",
];
const forbiddenVisible = [
  /Welcome to Buzz/i,
  /Buzz Admin/i,
  /Buzz mobile app/i,
  /Buzz website/i,
  /Buzz deployment/i,
  /relaunch Buzz/i,
  /Restart Buzz/i,
  /Take me to Buzz/i,
  /Accept invite in Buzz/i,
  /alt=["']Buzz["']/i,
  />\s*Buzz\s*</i,
  /Buzz Desktop/i,
  /Buzz-native/i,
  /bee-garden/i,
  /Reads workflow state from Buzz/i,
  /Buzz will choose an available shared model/i,
  /Add agents in the Buzz desktop app/i,
  /# Buzz CLI Skill/i,
];
for (const path of visibleFiles) {
  const source = read(path);
  for (const pattern of forbiddenVisible) {
    if (pattern.test(source))
      failures.push(`${path}: visible legacy brand ${pattern}`);
  }
}

const releaseSurfaceFiles = [
  ".github/workflows/release.yml",
  ".github/workflows/docker.yml",
  "desktop/src-tauri/Info.plist",
  ".github/workflows/signed-macos-canary.yml",
];
const forbiddenReleaseSurface = [
  /Buzz Desktop/i,
  /Buzz\.app/i,
  /buzz-desktop-latest/i,
  /SPROUT_UPDATER/i,
  /github\.com\/block\//i,
  /ghcr\.io\/block\//i,
  /block\/apple-codesign-action/i,
  /Buzz\.app/i,
  /Buzz_[^\n]*signed\.dmg/i,
  /buzz-macos-canary/i,
];
for (const path of releaseSurfaceFiles) {
  const source = read(path);
  for (const pattern of forbiddenReleaseSurface) {
    if (pattern.test(source)) {
      failures.push(`${path}: retired release identity or endpoint ${pattern}`);
    }
  }
}

const operationalSurfaces = [
  "README.md",
  "docker-compose.yml",
  "docker-compose.harness.yml",
  "deploy/charts/buzz/Chart.yaml",
  "deploy/charts/buzz/README.md",
  "deploy/charts/buzz/values.schema.json",
  "deploy/charts/buzz/templates/NOTES.txt",
];
const forbiddenOperationalSurface = [
  /github\.com\/block\//i,
  /ghcr\.io\/block\//i,
  /block\.xyz/i,
  /squareup\//i,
  /com\.buzz\.(service|env|volume|network)/i,
  /container_name:\s*buzz-/i,
  /name:\s*buzz-(postgres|minio|prometheus)-data/i,
  /name:\s*buzz-net/i,
  /# Buzz Helm Chart/i,
  /name:\s*Block/i,
];
for (const path of operationalSurfaces) {
  const source = read(path);
  for (const pattern of forbiddenOperationalSurface) {
    if (pattern.test(source)) {
      failures.push(`${path}: legacy operational brand or endpoint ${pattern}`);
    }
  }
}

for (const [path, fragment] of [
  ["docker-compose.yml", "name: snowman-command-center"],
  ["docker-compose.yml", 'ai.snowman.environment: "development"'],
  ["docker-compose.harness.yml", "name: snowman-command-center-harness"],
  [
    ".github/workflows/signed-macos-canary.yml",
    "Snowman_Command_Center_${VERSION}_aarch64-signed.dmg",
  ],
  ["deploy/charts/buzz/Chart.yaml", "Snowman Command Center"],
]) {
  if (!read(path).includes(fragment)) {
    failures.push(`${path}: missing Snowman operational identity ${fragment}`);
  }
}

if (
  !read("desktop/src/shared/theme/theme-loader.ts").includes(
    'return "Snowman Ice"',
  )
) {
  failures.push("desktop theme aliases must render Snowman labels");
}
if (read("admin-web/public/favicon.svg").includes("bee-mask")) {
  failures.push("admin favicon still contains the legacy bee mark");
}
if (
  !read("mobile/pubspec.yaml").includes(
    "assets/images/snowman-command-center.svg",
  )
) {
  failures.push("mobile bundle does not declare the Snowman mark");
}
if (
  !read("web/src/features/invite/ui/InvitePage.tsx").includes(
    "`snowman://join?",
  )
) {
  failures.push(
    "browser invitations do not generate the primary Snowman deep-link scheme",
  );
}
if (
  read("web/src/features/invite/ui/InvitePage.tsx").includes("`buzz://join?")
) {
  failures.push(
    "browser invitations still generate the legacy deep-link scheme",
  );
}

const retiredAssets = [
  "desktop/public/buzz.svg",
  "desktop/public/landing/buzz-wordmark.png",
  "desktop/src-tauri/icons/buzz-source.png",
  "mobile/assets/images/buzz-icon.png",
  "desktop/public/onboarding/starter-team/fizz.png",
  "desktop/public/onboarding/starter-team/honey.png",
  "desktop/public/onboarding/starter-team/bumble.png",
  "docs/assets/sprout.png",
  "docs/assets/sprout-icon.png",
];
for (const path of retiredAssets) {
  if (existsSync(resolve(root, path))) {
    failures.push(`${path}: retired legacy brand asset exists`);
  }
}

for (const asset of brandAssets.assets) {
  const absolute = resolve(root, asset.path);
  if (!existsSync(absolute)) {
    failures.push(`${asset.path}: declared Snowman brand asset is missing`);
    continue;
  }
  const actual = createHash("sha256")
    .update(readFileSync(absolute))
    .digest("hex");
  if (actual !== asset.sha256) {
    failures.push(`${asset.path}: Snowman brand asset digest drifted`);
  }
}

const iconDigests = new Map([
  [
    "desktop/src-tauri/icons/icon.png",
    "f7ba8c7ccca8e766aa873bc49d81c5e331c67566059f89a6c0b56a1a17bccc7a",
  ],
  [
    "desktop/public/app-icon@2x.png",
    "b67e64a80ddbd66127a949b434dc243685ccbbd3df1c38e793598612b912ce8e",
  ],
  [
    "mobile/android/app/src/main/res/mipmap-xxxhdpi/ic_launcher.png",
    "f51818d5203899050de509e642df7d9a6e05bea20b648f196530e981f8fa18b5",
  ],
  [
    "mobile/ios/Runner/Assets.xcassets/AppIcon.appiconset/Icon-App-1024x1024@1x.png",
    "d271493e82dc2fb53320a83ba66769e41776020e3f2806b471c638c37f9b3810",
  ],
]);
for (const [path, expected] of iconDigests) {
  const absolute = resolve(root, path);
  if (!existsSync(absolute)) {
    failures.push(`${path}: Snowman packaged icon is missing`);
    continue;
  }
  const actual = createHash("sha256")
    .update(readFileSync(absolute))
    .digest("hex");
  if (actual !== expected)
    failures.push(`${path}: Snowman packaged icon drifted`);
}

if (failures.length) {
  console.error("Snowman brand check failed:");
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}
console.log(
  `Snowman brand check passed for ${visibleFiles.length} visible authority files`,
);
