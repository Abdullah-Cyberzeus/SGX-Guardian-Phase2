#!/usr/bin/env node
// Phase 12 release gate: fail the build if the production bundle exceeds
// the PDF's 5 MB target (docs/Guardian_PWA_Complete_Implementation_Plan.md
// §Phase 11 Performance tasks). Previously this was only ever checked
// manually via `npm run build` + `du` (see
// docs/Guardian_PWA_Phase_11_Verification_Log.md) — this makes it an
// enforced, repeatable CI step instead.

import { readdirSync, statSync } from "node:fs";
import { resolve, join } from "node:path";
import { fileURLToPath } from "node:url";

const distDir = resolve(fileURLToPath(new URL("..", import.meta.url)), "dist");
const BUDGET_BYTES = 5 * 1024 * 1024; // 5 MiB, matching the plan's stated target

function walk(dir) {
  let total = 0;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      total += walk(path);
    } else {
      total += statSync(path).size;
    }
  }
  return total;
}

function main() {
  let totalBytes;
  try {
    totalBytes = walk(distDir);
  } catch (error) {
    console.error(`[check-bundle-size] could not read dist/ (${error.message}) — run \`npm run build\` first.`);
    process.exit(1);
  }

  const totalKiB = (totalBytes / 1024).toFixed(0);
  const budgetKiB = (BUDGET_BYTES / 1024).toFixed(0);

  if (totalBytes > BUDGET_BYTES) {
    console.error(
      `[check-bundle-size] dist/ is ${totalKiB} KiB, over the ${budgetKiB} KiB (5 MB) budget.`,
    );
    process.exit(1);
  }

  console.log(`[check-bundle-size] dist/ is ${totalKiB} KiB (budget: ${budgetKiB} KiB). OK.`);
}

main();
