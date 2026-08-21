import { useEffect, useState } from "react";
import { RouterProvider } from "react-router";
import { router } from "./routes";
import { Toaster } from "sonner";
import { PwaUpdatePrompt } from "./components/PwaUpdatePrompt";
import api from "./services/api";
import { purgeAndShowBrowserOffline, purgeOfflineShell } from "../pwa/offlineCleanup";

const APP_VERSION = __APP_VERSION__;
const SERVICE_WORKER_READY_TIMEOUT_MS = 8_000;
const LEGACY_OFFLINE_MODE_CACHE_KEY = "sgx_offline_mode_enabled";
const PREVIOUS_OFFLINE_MODE_CACHE_KEY = "sgx_offline_mode_enabled_v2";
const OFFLINE_MODE_CACHE_KEY = "sgx_offline_mode_enabled_v3";

function offlineModeEnabled(value: unknown) {
  return value === true || value === 1 || value === "1";
}

function rememberOfflineMode(value: unknown) {
  localStorage.removeItem(LEGACY_OFFLINE_MODE_CACHE_KEY);
  localStorage.removeItem(PREVIOUS_OFFLINE_MODE_CACHE_KEY);
  localStorage.setItem(OFFLINE_MODE_CACHE_KEY, offlineModeEnabled(value) ? "1" : "0");
}

function cachedOfflineModeEnabled() {
  localStorage.removeItem(LEGACY_OFFLINE_MODE_CACHE_KEY);
  localStorage.removeItem(PREVIOUS_OFFLINE_MODE_CACHE_KEY);
  return localStorage.getItem(OFFLINE_MODE_CACHE_KEY) === "1";
}

async function guardianOfflineModeState(): Promise<"enabled" | "disabled" | "unreachable"> {
  try {
    const response = await fetch(api.publicUrl("/node/status"), {
      cache: "no-store",
      signal: AbortSignal.timeout(1500),
    });
    if (!response.ok) return "disabled";
    const status = await response.json();
    rememberOfflineMode(status?.offlineMode);
    return offlineModeEnabled(status?.offlineMode) ? "enabled" : "disabled";
  } catch {
    return "unreachable";
  }
}

async function waitForServiceWorkerReady() {
  return Promise.race<ServiceWorkerRegistration | null>([
    navigator.serviceWorker.ready,
    new Promise((resolve) => window.setTimeout(() => resolve(null), SERVICE_WORKER_READY_TIMEOUT_MS)),
  ]);
}

function usePWA() {
  const [waiting, setWaiting] = useState<ServiceWorker | null>(null);
  const [registrationError, setRegistrationError] = useState<string | null>(null);
  const [offlineReady, setOfflineReady] = useState(true);
  useEffect(() => {
    const isIframe = window.self !== window.top;
    const isFigmaPreview =
      window.location.hostname.includes("figma.site") ||
      window.location.hostname.includes("figmaiframepreview") ||
      window.location.hostname.includes("makeproxy");

    // Embedded design previews are not the deployed Guardian application.
    if ((isIframe || isFigmaPreview) && "serviceWorker" in navigator) {
      setOfflineReady(true);
      navigator.serviceWorker.getRegistrations().then((registrations) => {
        registrations.forEach((reg) => {
          reg.unregister();
          console.log("[SW] Unregistered stale service worker in non-prod env");
        });
      });
      return;
    }

    // Inject <link rel="manifest"> into <head>
    if (!document.querySelector('link[rel="manifest"]')) {
      const link = document.createElement("link");
      link.rel = "manifest";
      link.href = "/manifest.json";
      document.head.appendChild(link);
    }

    // theme-color meta is owned by ThemeProvider so it tracks light/dark.

    // Set apple-mobile-web-app meta tags for iOS
    const appleMeta = [
      { name: "apple-mobile-web-app-capable", content: "yes" },
      { name: "apple-mobile-web-app-status-bar-style", content: "black-translucent" },
      { name: "apple-mobile-web-app-title", content: "SG-X Guardian" },
      { name: "mobile-web-app-capable", content: "yes" },
    ];
    appleMeta.forEach(({ name, content }) => {
      if (!document.querySelector(`meta[name="${name}"]`)) {
        const meta = document.createElement("meta");
        meta.name = name;
        meta.content = content;
        document.head.appendChild(meta);
      }
    });

    // Set viewport for mobile-first
    const viewport = document.querySelector('meta[name="viewport"]');
    if (!viewport) {
      const meta = document.createElement("meta");
      meta.name = "viewport";
      meta.content = "width=device-width, initial-scale=1, viewport-fit=cover";
      document.head.appendChild(meta);
    } else {
      viewport.setAttribute("content", "width=device-width, initial-scale=1, viewport-fit=cover");
    }

    if (!window.isSecureContext) {
      setRegistrationError(
        `The origin ${window.location.origin} is not browser-trusted. Use trusted HTTPS nodea.guardian, nodeb.guardian, or nodec.guardian`,
      );
      return;
    }

    // Register the offline worker only when the Guardian explicitly enables
    // offline mode. When disabled, remove the worker so a stopped node produces
    // the browser's normal "site can't be reached" page instead of cached UI.
    if ("serviceWorker" in navigator) {
      setOfflineReady(false);
      guardianOfflineModeState()
        .then(async (state) => {
          if (state === "unreachable") {
            if (cachedOfflineModeEnabled()) {
              setOfflineReady(true);
              return waitForServiceWorkerReady().catch(() => null);
            }
            await purgeAndShowBrowserOffline();
            return null;
          }
          if (state === "disabled") {
            rememberOfflineMode(0);
            await purgeOfflineShell();
            setOfflineReady(true);
            if (navigator.serviceWorker.controller) window.location.reload();
            return null;
          }
          return navigator.serviceWorker.register(`/sw.js?v=${encodeURIComponent(APP_VERSION)}`, {
            scope: "/",
            updateViaCache: "none",
          });
        })
        .then((reg) => {
          if (!reg) return null;
          console.log("[SW] Registered, scope:", reg.scope);
          setRegistrationError(null);
          if (reg.waiting) {
            if (navigator.serviceWorker.controller) setWaiting(reg.waiting);
            else reg.waiting.postMessage({ type: "SKIP_WAITING" });
          }
          reg.addEventListener("updatefound", () => {
            const worker = reg.installing;
            worker?.addEventListener("statechange", () => {
              if (worker.state !== "installed") return;
              // Complete the very first installation immediately. Existing
              // controlled clients still get the explicit safe-update prompt.
              if (navigator.serviceWorker.controller) setWaiting(worker);
              else worker.postMessage({ type: "SKIP_WAITING" });
            });
          });
          return waitForServiceWorkerReady();
        })
        .then((ready) => {
          if (!ready) {
            setOfflineReady(true);
            return;
          }
          console.log("[SW] Offline shell installed and ready");
          setOfflineReady(true);
          // Best-effort protection from storage-pressure eviction. Browsers
          // that do not expose this API continue with normal IndexedDB rules.
          void navigator.storage?.persist?.().catch(() => false);
        })
        .catch((err) => {
          const message = err instanceof Error ? err.message : String(err);
          setRegistrationError(message);
          console.warn("[SW] Registration failed:", message);
        });
    } else {
      setRegistrationError("This browser does not support service workers");
    }
    const reloadForController = () => window.location.reload();
    navigator.serviceWorker?.addEventListener("controllerchange", reloadForController);
    return () => navigator.serviceWorker?.removeEventListener("controllerchange", reloadForController);
  }, []);
  return {
    applyUpdate: waiting ? () => waiting.postMessage({ type: "SKIP_WAITING" }) : null,
    registrationError,
    offlineReady,
  };
}

export default function App() {
  const { applyUpdate, registrationError, offlineReady } = usePWA();

  return (
    <>
      <RouterProvider router={router} />
      {applyUpdate && <PwaUpdatePrompt apply={applyUpdate} />}
      {registrationError && (
        <div role="alert" className="fixed bottom-20 left-1/2 z-[100] w-[min(92vw,560px)] -translate-x-1/2 rounded-lg border border-red-500/40 bg-zinc-950 px-4 py-3 text-sm text-red-300 shadow-xl">
          Offline installation failed: {registrationError}. Keep Guardian connected and open this page from a trusted HTTPS origin (or localhost), then reload.
        </div>
      )}
      {!registrationError && !offlineReady && (
        <div role="status" className="fixed bottom-20 left-1/2 z-[99] -translate-x-1/2 rounded-full border border-border bg-zinc-950/95 px-4 py-2 text-xs text-zinc-300 shadow-lg">
          Preparing offline access… keep Guardian connected
        </div>
      )}
      <Toaster
        theme="dark"
        position="top-center"
        toastOptions={{
          style: {
            background: "var(--card)",
            color: "var(--foreground)",
            border: "1px solid var(--border)",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
          },
          classNames: {
            description: "!text-zinc-300",
            success: "!bg-zinc-900 !text-emerald-400 !border-emerald-800",
            error: "!bg-zinc-900 !text-red-400 !border-red-800",
          },
        }}
      />
    </>
  );
}
