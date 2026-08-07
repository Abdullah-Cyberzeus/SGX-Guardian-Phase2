import { useEffect } from "react";
import { RouterProvider } from "react-router";
import { router } from "./routes";
import { Toaster } from "sonner";

function usePWA() {
  useEffect(() => {
    const isIframe = window.self !== window.top;
    const isLoopbackHost =
      window.location.hostname === "localhost" ||
      window.location.hostname === "127.0.0.1" ||
      window.location.hostname === "[::1]";
    const isFigmaPreview =
      window.location.hostname.includes("figma.site") ||
      window.location.hostname.includes("figmaiframepreview") ||
      window.location.hostname.includes("makeproxy");

    // In loopback and preview environments, stale service workers are more
    // harmful than helpful because they can keep serving old route chunks.
    if ((isIframe || isFigmaPreview || isLoopbackHost) && "serviceWorker" in navigator) {
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
        .register("/sw.js", { scope: "/" })
        .then((reg) => {
          console.log("[SW] Registered, scope:", reg.scope);
        })
        .catch((err) => {
          console.warn("[SW] Registration skipped:", err.message);
        });
    }
  }, []);
}

export default function App() {
  usePWA();

  return (
    <>
      <RouterProvider router={router} />
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
