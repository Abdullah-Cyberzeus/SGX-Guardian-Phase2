import { useEffect, useState } from "react";
import { Navigate, Outlet, useLocation } from "react-router";
import { Loader2 } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { isOnline, useMeshLifecycle } from "../contexts/MeshLifecycleContext";

export function ProtectedRoute() {
  const { session, loading } = useAuth();
  const { lifecycle, loading: meshLoading } = useMeshLifecycle();
  const location = useLocation();

  // P1.7: a mesh-gated request anywhere in the app can 409 mid-session (the
  // poll/WS in MeshLifecycleContext have not caught up yet, or this is the
  // very first request after a lifecycle change) — `services/api.ts`
  // dispatches this event on exactly that response, and this is the one place
  // that turns it into a redirect, so every mesh-gated screen gets it for
  // free rather than each one handling its own 409.
  const [forceSetupRedirect, setForceSetupRedirect] = useState(false);
  useEffect(() => {
    const onNotEnrolled = () => setForceSetupRedirect(true);
    window.addEventListener("sgx:mesh-not-enrolled", onNotEnrolled);
    return () => window.removeEventListener("sgx:mesh-not-enrolled", onNotEnrolled);
  }, []);
  // A fresh navigation to an already-mesh-required route should re-evaluate
  // against the current lifecycle rather than a stale redirect flag from a
  // previous visit.
  useEffect(() => {
    setForceSetupRedirect(false);
  }, [location.pathname]);

  if (loading || (session && meshLoading)) {
    return (
      <div
        className="flex min-h-[100dvh] items-center justify-center"
        style={{ backgroundColor: "var(--background)" }}
      >
        <div className="flex items-center gap-3 text-sm text-muted-foreground">
          <Loader2 className="animate-spin" size={18} />
          Restoring Guardian session...
        </div>
      </div>
    );
  }

  if (!session) {
    return <Navigate to="/login" replace state={{ returnTo: `${location.pathname}${location.search}` }} />;
  }

  // /setup (and its children, e.g. /setup/create — P2.4) are themselves
  // reached through this guard (auth still required to get there) but must
  // not redirect back to /setup — that would be a no-op loop for /setup
  // itself, and for /setup/create it would bounce the operator off the
  // Create Mesh Circle screen immediately, since this Guardian is by
  // definition still not ONLINE while creating its first circle.
  const alreadyAtSetup = location.pathname === "/setup" || location.pathname.startsWith("/setup/");
  if (!alreadyAtSetup && (forceSetupRedirect || !isOnline(lifecycle?.state))) {
    return <Navigate to="/setup" replace />;
  }

  return <Outlet />;
}
