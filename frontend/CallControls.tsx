import { Navigate, Outlet } from "react-router";
import { useAuth } from "../contexts/AuthContext";

function hasCompletedOnboarding() {
  return localStorage.getItem("sgx_onboarded") === "1";
}

export function OnboardingEntryRoute() {
  const { session, loading } = useAuth();

  if (loading) return null;

  if (session && hasCompletedOnboarding()) {
    return <Navigate to="/home" replace />;
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
    return <Navigate to="/home" replace />;
  }

  return <Outlet />;
}