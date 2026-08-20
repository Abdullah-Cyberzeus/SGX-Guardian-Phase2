#!/usr/bin/env node
// Phase 12 release gate: fail the build if any asset the service worker's
// `discoverShellAssets()` would try to precache is missing from `dist/`.
//
// The service worker (public/sw.js) discovers what to precache at INSTALL
// time, in the browser, against a live server — so a missing hashed JS/CSS
// chunk only surfaces as a broken offline shell once a real user hits it.
// This script runs the exact same discovery rules against the *built*
// dist/index.html + dist/asset-manifest.json, offline, so a bad build
// fails CI instead of a user's install.
//
// Keep the CORE list, same-origin/static filters, and HTML/manifest
// scanning here in sync with `discoverShellAssets()` in public/sw.js — this
// is a deliberate, intentionally small duplication (the service worker
// can't easily import a shared module without becoming a module worker,
// which is a bigger change than this release-gate script warrants) rather
// than a divergent reimplementation.

import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const distDir = resolve(fileURLToPath(new URL("..", import.meta.url)), "dist");

const CORE = ["/", "/manifest.json", "/asset-manifest.json", "/favicon.png", "/icon-192.png", "/icon-512.png"];
const isStatic = (pathname) =>
  pathname.startsWith("/assets/") || /\.(?:js|css|woff2?|png|jpg|jpeg|svg|webp|ico)$/i.test(pathname);

function discoverShellAssetPaths(html, manifestAssets) {
  const urls = new Set(CORE);
  for (const match of html.matchAll(/(?:src|href)=["']([^"']+)["']/g)) {
    const url = new URL(match[1], "http://shell.invalid/");
    if (isStatic(url.pathname)) urls.add(url.pathname + url.search);
  }
  for (const asset of Array.isArray(manifestAssets) ? manifestAssets : []) {
    const url = new URL(String(asset), "http://shell.invalid/");
    if (isStatic(url.pathname)) urls.add(url.pathname + url.search);
  }
  return [...urls];
}

function main() {
  const indexPath = resolve(distDir, "index.html");
  const manifestPath = resolve(distDir, "asset-manifest.json");
  if (!existsSync(indexPath)) {
    console.error(`[validate-precache] dist/index.html not found — run \`npm run build\` first.`);
    process.exit(1);
  }

  const html = readFileSync(indexPath, "utf8");
  const manifest = existsSync(manifestPath)
    ? JSON.parse(readFileSync(manifestPath, "utf8"))
    : { assets: [] };

  const assetPaths = discoverShellAssetPaths(html, manifest.assets);
  const missing = assetPaths.filter((path) => {
    if (path === "/") return false; // index.html itself, already confirmed present
    const [pathname] = path.split("?");
    return !existsSync(resolve(distDir, `.${pathname}`));
  });

  if (missing.length > 0) {
    console.error(
      `[validate-precache] ${missing.length} shell asset(s) referenced by index.html/asset-manifest.json ` +
        `are missing from dist/ — the offline install would fail for these on a real device:\n` +
        missing.map((path) => `  - ${path}`).join("\n"),
    );
    process.exit(1);
  }

  console.log(`[validate-precache] ${assetPaths.length} shell asset(s) verified present in dist/.`);
}

main();
