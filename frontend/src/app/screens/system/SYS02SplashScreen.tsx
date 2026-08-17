import { useEffect } from "react";
import { useNavigate } from "react-router";
import { CervaisLogo } from "../../components/CervaisLogo";
import { useAuth } from "../../contexts/AuthContext";

export function SYS02SplashScreen() {
  const navigate = useNavigate();
  const { session, loading } = useAuth();

  useEffect(() => {
    if (loading) return;

    let cancelled = false;

    const checkAuth = () => {
      if (cancelled) return;

      if (session) {
        // Authenticated user → go straight to dashboard
        setTimeout(() => {
          if (!cancelled) navigate("/home", { replace: true });
        }, 1800);
      } else if (localStorage.getItem("sgx_onboarded")) {
        // Returning users without a session must choose how to sign in. Cylenium
        // authorization is only started by its explicit button on the login page.
        setTimeout(() => {
          if (!cancelled) navigate("/login", { replace: true });
        }, 1800);
      } else {
        // First time → full onboarding
        setTimeout(() => {
          if (!cancelled) navigate("/onboarding", { replace: true });
        }, 1800);
      }
    };

    checkAuth();
    return () => { cancelled = true; };
  }, [navigate, session, loading]);

  return (
    <div
      className="flex flex-col items-center justify-center"
      style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}
    >
      <div className="flex flex-col items-center gap-6">
        <CervaisLogo width={160} />
        <div className="flex flex-col items-center gap-1">
          <h1
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xl)",
              fontWeight: 700,
              color: "var(--foreground)",
              letterSpacing: "-0.02em",
              lineHeight: 1.2,
            }}
          >
            SG-X Guardian
          </h1>
          <span
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-medium)",
              color: "var(--muted-foreground)",
              letterSpacing: "0.12em",
            }}
          >
            Security Platform
          </span>
        </div>

        {/* Loading bar */}
        <div
          className="rounded-full overflow-hidden"
          style={{ width: "120px", height: "3px", backgroundColor: "var(--muted)" }}
        >
          <div
            className="h-full rounded-full"
            style={{
              backgroundColor: "var(--primary)",
              animation: "loadbar 1.6s ease-in-out forwards",
              width: "0%",
            }}
          />
        </div>
      </div>

      <style>{`
        @keyframes loadbar {
          0% { width: 0%; }
          60% { width: 75%; }
          90% { width: 92%; }
          100% { width: 100%; }
        }
      `}</style>
    </div>
  );
}
