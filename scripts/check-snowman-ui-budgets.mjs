#!/usr/bin/env node

import { existsSync, readdirSync, readFileSync } from "node:fs";
import { basename, join, resolve } from "node:path";
import { gzipSync } from "node:zlib";

const budgets = {
  desktop: {
    entryGzipBytes: 950_000,
    totalGzipBytes: 6_500_000,
    maxJsAssets: 450,
  },
  web: { entryGzipBytes: 300_000, totalGzipBytes: 310_000, maxJsAssets: 8 },
  "admin-web": {
    entryGzipBytes: 75_000,
    totalGzipBytes: 80_000,
    maxJsAssets: 4,
  },
};

const surface = process.argv[2];
if (!(surface in budgets)) {
  console.error(
    `Usage: check-snowman-ui-budgets.mjs <${Object.keys(budgets).join("|")}> [dist]`,
  );
  process.exit(2);
}

const dist = resolve(process.argv[3] ?? join(surface, "dist"));
const assets = join(dist, "assets");
if (!existsSync(assets)) {
  console.error(`${surface}: build output is missing at ${assets}`);
  process.exit(1);
}

const js = readdirSync(assets)
  .filter((name) => name.endsWith(".js"))
  .map((name) => {
    const gzipBytes = gzipSync(readFileSync(join(assets, name)), {
      level: 9,
    }).byteLength;
    return { name, gzipBytes };
  });
const entry = js
  .filter(({ name }) => name.startsWith("index-"))
  .sort((left, right) => right.gzipBytes - left.gzipBytes)[0];
const totalGzipBytes = js.reduce((total, asset) => total + asset.gzipBytes, 0);
const budget = budgets[surface];
const failures = [];

if (!entry) failures.push("no index JavaScript entry chunk was emitted");
if (entry && entry.gzipBytes > budget.entryGzipBytes) {
  failures.push(
    `entry ${basename(entry.name)} is ${entry.gzipBytes} gzip bytes (budget ${budget.entryGzipBytes})`,
  );
}
if (totalGzipBytes > budget.totalGzipBytes) {
  failures.push(
    `all JavaScript is ${totalGzipBytes} gzip bytes (budget ${budget.totalGzipBytes})`,
  );
}
if (js.length > budget.maxJsAssets) {
  failures.push(
    `${js.length} JavaScript assets emitted (budget ${budget.maxJsAssets})`,
  );
}

if (failures.length > 0) {
  console.error(`${surface} UI performance budget failed:\n`);
  for (const failure of failures) console.error(`- ${failure}`);
  process.exit(1);
}

console.log(
  `${surface} UI budget passed: entry=${entry.gzipBytes}B gzip total=${totalGzipBytes}B assets=${js.length}.`,
);
