import { defineConfig, type Plugin } from 'vitest/config'
import path from 'path'
import tailwindcss from '@tailwindcss/vite'
import react from '@vitejs/plugin-react'

// Phase 10 (Internet-Independent Admin Console Hardening): VITE_API_URL
// should stay unset in production builds so the console calls same-origin
// `/api/v1` — no public-Internet dependency. It's a legitimate escape hatch
// for local dev tunneling (ngrok, etc.), so this only warns, never fails
// the build.
function warnOnNonLocalApiUrl(): Plugin {
  return {
    name: 'sgx-warn-non-local-api-url',
    configResolved(config) {
      const apiUrl = process.env.VITE_API_URL;
      if (!apiUrl || config.command !== 'build') return;
      const isLocal = apiUrl.startsWith('/')
        || /^https?:\/\/(localhost|127\.0\.0\.1|\[::1\]|[^/]+\.local)(:\d+)?\/?/i.test(apiUrl);
      if (!isLocal) {
        console.warn(
          `\n[sgx-warn-non-local-api-url] VITE_API_URL is set to "${apiUrl}" for this ` +
          `production build — the Admin Console will call a remote host instead of ` +
          `same-origin /api/v1, breaking Internet-independence. Leave VITE_API_URL ` +
          `unset for production builds.\n`,
        );
      }
    },e
  };
}

function pwaAssetManifest(): Plugin {
  return {
    name: 'sgx-pwa-asset-manifest',
    generateBundle(_, bundle) {
      const assets = Object.values(bundle)
        .map((entry) => `/${entry.fileName}`)
        .filter((fileName) => /\.(?:js|css|woff2?|png|jpg|jpeg|svg|webp|ico)$/i.test(fileName))
        .sort();
      this.emitFile({
        type: 'asset',
        fileName: 'asset-manifest.json',
        source: JSON.stringify({ assets }, null, 2),
      });
    },
  };
}

export default defineConfig({
  define: {
    __APP_VERSION__: JSON.stringify(process.env.npm_package_version || 'dev'),
  },
  plugins: [
    // The React and Tailwind plugins are both required for Make, even if
    // Tailwind is not being actively used – do not remove them
    react(),
    tailwindcss(),
    pwaAssetManifest(),
    warnOnNonLocalApiUrl(),
  ],
  resolve: {
    alias: {
      // Alias @ to the src directory
      '@': path.resolve(__dirname, './src'),
    },
  },

  // File types to support raw imports. Never add .css, .tsx, or .ts files to this.
  assetsInclude: ['**/*.svg', '**/*.csv'],
  server: {
    // VITE_DEV_PORT / VITE_API_TARGET let you point this dev server at any
    // node (nodeA/B/C) without touching this file — see the three commands
    // in the project notes. Defaults preserve this branch's current setup.
    port: Number(process.env.VITE_DEV_PORT) || 3000,
    strictPort: true,

    proxy: {
      '/api/v1': {
        target: process.env.VITE_API_TARGET || 'http://127.0.0.1:8443',
        changeOrigin: true,
        ws: true,
      },
    },
  },

  // Phase 12: unit tests (`npm run test:unit`) — separate from the
  // Playwright E2E suite (`npm test`). jsdom + fake-indexeddb give the
  // pwa/db and pwa/crypto modules a real IndexedDB/WebCrypto-shaped
  // environment without a browser.
  test: {
    environment: 'jsdom',
    setupFiles: ['./src/pwa/testSetup.ts'],
    include: ['src/**/*.test.{ts,tsx}'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'json-summary'],
      // The 85% gate below tracks the plan's "crypto, validation,
      // messaging, and file modules" line specifically — data/orchestration
      // modules that mix in React rendering (NotificationContext's
      // Provider) or wide external-service fan-out (syncCoordinator,
      // vault/maintenance) aren't reasonably unit-testable to that bar
      // without a component-rendering harness this suite doesn't have yet;
      // their pure/exported logic is still tested (see
      // NotificationContext.test.ts, notificationLocalPrefs.test.ts) but
      // isn't held to the hard threshold below.
      include: [
        'src/pwa/db/database.ts',
        'src/pwa/db/messageRepository.ts',
        'src/pwa/db/pendingRepository.ts',
        'src/pwa/crypto/vault.ts',
        'src/pwa/sync/pendingReplay.ts',
        'src/pwa/sync/conflict.ts',
        'src/app/utils/authorization.ts',
        'src/app/components/circle-topology/circleMembership.ts',
        'src/app/components/circle-topology/nodeTelemetry.ts',
        'src/app/components/circle-topology/palette.ts',
        'src/app/components/circle-topology/useCircleTopology.ts',
        'src/app/components/topology/lib/geospatial.ts',
        'src/app/components/topology/lib/topology.ts',
        'src/app/config/cylenium.ts',
        'src/app/utils/cyleniumAuth.ts',
        'src/app/screens/auth/CyleniumCallback.tsx',
      ],
      exclude: ['**/*.test.{ts,tsx}'],
      thresholds: {
        lines: 85,
        functions: 85,
        'src/app/components/circle-topology/{circleMembership,nodeTelemetry,palette,useCircleTopology}.ts': {
          lines: 90,
          functions: 90,
        },
        'src/app/components/topology/lib/{geospatial,topology}.ts': {
          lines: 90,
          functions: 90,
        },
        'src/app/{config/cylenium.ts,utils/cyleniumAuth.ts,screens/auth/CyleniumCallback.tsx}': {
          lines: 91,
          functions: 91,
        },
      },
    },
  },
})