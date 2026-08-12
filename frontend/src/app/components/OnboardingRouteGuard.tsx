import { Navigate, Outlet } from "react-router";
import { useAuth } from "../contexts/AuthContext";
import { homePathForRole, isMemberRole } from "../utils/authorization";

function hasCompletedOnboarding() {
  return localStorage.getItem("sgx_onboarded") === "1";
}

export function OnboardingEntryRoute() {
  const { session, loading } = useAuth();

  if (loading) return null;

  if (session && hasCompletedOnboarding()) {
    return <Navigate to={homePathForRole(session.user.role)} replace />;
  }

  if (session && isMemberRole(session.user.role)) {
    return <Navigate to={homePathForRole(session.user.role)} replace />;
  }

  if (session) {
    return <Navigate to="/onboarding/pairing" replace />;
  }

  return <Outlet />;
}

export function AuthenticatedOnboardingRoute() {
  const { session, loading } = useAuth();

  if (loading) return null;

  if (!session) {
    return <Navigate to="/signup" replace />;
  }

  if (hasCompletedOnboarding()) {
    return <Navigate to={homePathForRole(session.user.role)} replace />;
  }

  if (isMemberRole(session.user.role)) {
    return <Navigate to={homePathForRole(session.user.role)} replace />;
  }

  return <Outlet />;
}
