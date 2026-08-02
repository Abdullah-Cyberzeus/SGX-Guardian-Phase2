import { Suspense } from "react";
import { Outlet } from "react-router";
import { Loader2 } from "lucide-react";

export function OnboardingLayout() {
  return (
    // On mobile: full width natural flow
    // On tablet/desktop: centered card with backdrop
    <div
      className="flex justify-center items-start"
      style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}
    >
      <div
        className="relative w-full flex flex-col"
        style={{
          maxWidth: "440px",
        }}
      >
        <style>{`
          @media (min-width: 768px) {
            .onboarding-card { max-width: 560px !important; }
          }
          @media (min-width: 1280px) {
            .onboarding-card { max-width: 480px !important; }
          }
        `}</style>
        <div className="onboarding-card w-full flex flex-col" style={{ minHeight: "100dvh" }}>
          <Suspense
            fallback={
              <div className="flex flex-1 items-center justify-center">
                <Loader2 className="animate-spin" size={26} style={{ color: "var(--primary)" }} />
              </div>
            }
          >
            <Outlet />
          </Suspense>
        </div>
      </div>
    </div>
  );
}