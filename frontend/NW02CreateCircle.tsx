import { Outlet } from "react-router";
import { BottomNav } from "../components/BottomNav";
import { OfflineBanner } from "../components/OfflineBanner";
import { AppSidebar } from "../components/AppSidebar";
import { Suspense, useState } from "react";
import { Loader2 } from "lucide-react";

/** Shown in the content area while a route's code chunk loads. */
const routeFallback = (
  <div className="flex w-full items-center justify-center" style={{ minHeight: "50dvh" }}>
    <Loader2 className="animate-spin" size={26} style={{ color: "var(--primary)" }} />
  </div>
);

export function MainLayout() {
  const [isOffline] = useState(false);

  return (
    <>
      {/* ── Mobile layout (< 768px) ── centered card with bottom nav */}
      <div
        className="md:hidden flex justify-center"
        style={{ minHeight: "100dvh", backgroundColor: "#000" }}
      >
        <div
          className="relative w-full flex flex-col"
          style={{ maxWidth: "440px", height: "100dvh", backgroundColor: "var(--background)" }}
        >
          {isOffline && <OfflineBanner lastSeen="3 min ago" />}
          <main
            className="flex-1 overflow-y-auto overflow-x-hidden"
            style={{ WebkitOverflowScrolling: "touch" }}
          >
            <Suspense fallback={routeFallback}><Outlet /></Suspense>
          </main>
          <BottomNav />
        </div>
      </div>

      {/* ── Tablet layout (768px–1279px) ── collapsed sidebar + scrollable content */}
      <div
        className="hidden md:flex lg:hidden"
        style={{ height: "100dvh", backgroundColor: "var(--background)" }}
      >
        {isOffline && (
          <div className="fixed top-0 z-50" style={{ left: "64px", right: 0 }}>
            <OfflineBanner lastSeen="3 min ago" />
          </div>
        )}
        <AppSidebar variant="collapsed" />
        {/* main fills remaining space; screens that need split-panels set h-full themselves */}
        <main
          className="flex-1 flex flex-col"
          style={{ minWidth: 0, height: "100dvh", overflow: "hidden" }}
        >
          <Suspense fallback={routeFallback}><Outlet /></Suspense>
        </main>
      </div>

      {/* ── Desktop layout (1280px+) ── expanded sidebar + content */}
      <div
        className="hidden lg:flex"
        style={{ height: "100dvh", backgroundColor: "var(--background)" }}
      >
        {isOffline && (
          <div className="fixed top-0 z-50" style={{ left: "240px", right: 0 }}>
            <OfflineBanner lastSeen="3 min ago" />
          </div>
        )}
        <AppSidebar variant="expanded" />
        <main
          className="flex-1 flex flex-col"
          style={{ minWidth: 0, height: "100dvh", overflow: "hidden" }}
        >
          <Suspense fallback={routeFallback}><Outlet /></Suspense>
        </main>
      </div>
    </>
  );
}
