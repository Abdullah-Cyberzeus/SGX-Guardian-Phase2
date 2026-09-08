import { Navigate, Outlet, useLocation, useNavigate } from "react-router";
import { LockKeyhole } from "lucide-react";
import { useAuth } from "../contexts/AuthContext";
import { homePathForRole, isAdminRole, isMemberRole, memberCanOpenPath } from "../utils/authorization";

/**
 * Frontend route boundary for role-appropriate navigation.
 * Backend scope middleware remains the security boundary; this component
 * prevents members from seeing or preloading administrative screens.
 */
export function RoleAccessRoute() {
  const { session } = useAuth();
  const location = useLocation();
  const navigate = useNavigate();
  const role = session?.user.role;

  if (isAdminRole(role)) return <Outlet />;
  if (isMemberRole(role)) {
    const hasCircleAccess = (session?.circleIds.length || 0) > 0;
    if (!hasCircleAccess && location.pathname !== "/join-circle") {
      return <Navigate to="/join-circle" replace />;
    }
    return memberCanOpenPath(location.pathname)
      ? <Outlet />
      : (
        <main className="grid min-h-[100dvh] place-items-center bg-background p-6">
          <section className="w-full max-w-md rounded-xl border border-border bg-card p-6 text-center shadow-sm" role="alert">
            <div className="mx-auto grid h-12 w-12 place-items-center rounded-full bg-destructive/10 text-destructive">
              <LockKeyhole size={22} />
            </div>
            <h1 className="mt-4 text-xl font-semibold">Access restricted</h1>
            <p className="mt-2 text-sm leading-6 text-muted-foreground">
              This page changes Guardian administration. Your member session can use Messages, Calls, Contacts, Files, and Settings only.
            </p>
            <button className="mt-5 rounded-md bg-primary px-4 py-2 text-sm font-semibold text-primary-foreground" onClick={() => navigate(homePathForRole(role), { replace: true })}>
              Return to member dashboard
            </button>
          </section>
        </main>
      );
  }

  return <Navigate to="/login" replace />;
}
