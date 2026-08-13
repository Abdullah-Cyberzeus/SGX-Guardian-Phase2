import { useEffect, useState } from "react";
import { RouterProvider } from "react-router";
import { router } from "./routes";
import { Toaster } from "sonner";
import { PwaUpdatePrompt } from "./components/PwaUpdatePrompt";

const APP_VERSION = __APP_VERSION__;

function usePWA() {
  const [waiting, setWaiting] = useState<ServiceWorker | null>(null);
  useEffect(() => {
    const isIframe = window.self !== window.top;
    const isFigmaPreview =
      window.location.hostname.includes("figma.site") ||
      window.location.hostname.includes("figmaiframepreview") ||
      window.location.hostname.includes("makeproxy");

    // Embedded design previews are not the deployed Guardian application.
    if ((isIframe || isFigmaPreview) && "serviceWorker" in navigator) {
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

    // Register Service Worker (production only)
    if ("serviceWorker" in navigator) {
      navigator.serviceWorker
        .register(`/sw.js?v=${encodeURIComponent(APP_VERSION)}`, { scope: "/" })
        .then((reg) => {
          console.log("[SW] Registered, scope:", reg.scope);
          if (reg.waiting) setWaiting(reg.waiting);
          reg.addEventListener("updatefound", () => {
            const worker = reg.installing;
            worker?.addEventListener("statechange", () => {
              if (worker.state === "installed" && navigator.serviceWorker.controller) setWaiting(worker);
            });
          });
        })
        .catch((err) => {
          console.warn("[SW] Registration skipped:", err.message);
        });
    }
    const reloadForController = () => window.location.reload();
    navigator.serviceWorker?.addEventListener("controllerchange", reloadForController);
    return () => navigator.serviceWorker?.removeEventListener("controllerchange", reloadForController);
  }, []);
  return waiting ? () => waiting.postMessage({ type: "SKIP_WAITING" }) : null;
}

export default function App() {
  const applyUpdate = usePWA();

  return (
    <>
      <RouterProvider router={router} />
      {applyUpdate && <PwaUpdatePrompt apply={applyUpdate} />}
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
