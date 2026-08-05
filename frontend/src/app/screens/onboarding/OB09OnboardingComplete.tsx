import { useEffect, useState } from "react";
import { useNavigate } from "react-router";
import { Check, Shield, User, Copy, Users, Loader2, Cloud } from "lucide-react";

const baseItems = [
  { icon: Shield, label: "Guardian connected", duration: 600 },
  { icon: User, label: "Account created", duration: 900 },
  { icon: Copy, label: "DID copied", duration: 700 },
  { icon: Users, label: "Circle created", duration: 800 },
];

export function OB09OnboardingComplete() {
  const navigate = useNavigate();
  const cyleniumConnected = localStorage.getItem("sgx_cylenium_connected") === "1";

  const items = cyleniumConnected
    ? [...baseItems, { icon: Cloud, label: "Cylenium Cloud connected", duration: 650 }]
    : baseItems;

  const [completedSteps, setCompletedSteps] = useState(0);
  const [currentStep, setCurrentStep] = useState(0);
  const [animDone, setAnimDone] = useState(false);

  useEffect(() => {
    let elapsed = 0;
    items.forEach((item, i) => {
      setTimeout(() => {
        setCurrentStep(i);
        setTimeout(() => {
          setCompletedSteps(i + 1);
          if (i === items.length - 1) {
            setTimeout(() => setAnimDone(true), 300);
          }
        }, item.duration);
      }, elapsed);
      elapsed += item.duration + 150;
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  return (
    <div
      className="flex flex-col items-center px-6"
      style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}
    >
      {/* Celebration glow */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background: "radial-gradient(ellipse 80% 50% at 50% 10%, color-mix(in srgb, var(--chart-2) 10%, transparent) 0%, transparent 70%)",
        }}
      />

      <div className="flex flex-col items-center flex-1 mt-16 z-10">
        {/* Success checkmark */}
        <div
          className="rounded-full flex items-center justify-center mb-6"
          style={{
            width: "96px", height: "96px",
            backgroundColor: "color-mix(in srgb, var(--chart-2) 15%, transparent)",
            border: "2px solid color-mix(in srgb, var(--chart-2) 35%, transparent)",
            animation: animDone ? "popIn 0.35s ease-out forwards" : undefined,
          }}
        >
          <Check size={48} strokeWidth={2.5} style={{ color: "var(--chart-2)" }} />
        </div>

        <h2
          className="text-center mb-2"
          style={{
            fontFamily: "Inter, sans-serif", fontSize: "32px", fontWeight: 700,
            color: "var(--foreground)", letterSpacing: "-0.02em", lineHeight: 1.2,
          }}
        >
          You're all set.
        </h2>
        <p
          className="text-center mb-10"
          style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}
        >
          SG-X Guardian is ready to protect your network.
        </p>

        {/* Checklist */}
        <div
          className="w-full rounded-lg border border-border overflow-hidden"
          style={{ backgroundColor: "var(--card)" }}
        >
          {items.map(({ icon: Icon, label }, i) => {
            const isComplete = completedSteps > i;
            const isActive = currentStep === i && !isComplete;
            const isCylenium = label === "Cylenium Cloud connected";
            return (
              <div
                key={i}
                className="flex items-center gap-3 px-4 py-4"
                style={{
                  borderBottom: i < items.length - 1 ? "1px solid var(--border)" : undefined,
                  backgroundColor: isCylenium && isComplete
                    ? "color-mix(in srgb, var(--primary) 4%, transparent)"
                    : undefined,
                  transition: "background-color 0.4s ease",
                }}
              >
                <div
                  className="rounded-full flex items-center justify-center flex-shrink-0"
                  style={{
                    width: "32px", height: "32px",
                    backgroundColor: isComplete
                      ? isCylenium
                        ? "color-mix(in srgb, var(--primary) 18%, transparent)"
                        : "color-mix(in srgb, var(--chart-2) 15%, transparent)"
                      : isActive
                      ? "color-mix(in srgb, var(--primary) 15%, transparent)"
                      : "var(--muted)",
                    border: `1.5px solid ${
                      isComplete
                        ? isCylenium ? "var(--primary)" : "var(--chart-2)"
                        : isActive ? "var(--primary)" : "var(--border)"
                    }`,
                    transition: "background-color 0.3s ease, border-color 0.3s ease",
                  }}
                >
                  {isComplete ? (
                    <Check size={14} style={{ color: isCylenium ? "var(--primary)" : "var(--chart-2)" }} />
                  ) : isActive ? (
                    <Loader2 size={14} style={{ color: "var(--primary)", animation: "spin 1s linear infinite" }} />
                  ) : (
                    <div style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: "var(--muted-foreground)", opacity: 0.4 }} />
                  )}
                </div>
                <div className="flex items-center gap-2 flex-1">
                  <span
                    style={{
                      fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)",
                      fontWeight: isActive ? "var(--font-weight-medium)" : "var(--font-weight-normal)",
                      color: isComplete ? "var(--foreground)" : isActive ? "var(--foreground)" : "var(--muted-foreground)",
                      transition: "color 0.3s ease",
                    }}
                  >
                    {label}
                  </span>
                  {isCylenium && isComplete && (
                    <span
                      style={{
                        fontFamily: "Inter, sans-serif", fontSize: "10px", fontWeight: "var(--font-weight-semibold)",
                        color: "var(--primary)", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)",
                        padding: "2px 6px", borderRadius: "var(--radius-sm)",
                        border: "1px solid color-mix(in srgb, var(--primary) 25%, transparent)",
                        flexShrink: 0,
                      }}
                    >
                      CERVAIS
                    </span>
                  )}
                  {!isComplete && !isActive && (
                    <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", opacity: 0.5 }}>
                      · pending
                    </span>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </div>

      <div className="w-full pb-10 z-10">
        <button
          onClick={() => {
            localStorage.setItem("sgx_onboarded", "1");
            navigate("/home", { replace: true });
          }}
          className="w-full flex items-center justify-center transition-opacity active:opacity-80"
          style={{
            height: "56px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)",
            fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)",
            borderRadius: "var(--radius)", border: "none", cursor: "pointer",
            boxShadow: "0 0 24px color-mix(in srgb, var(--primary) 25%, transparent)",
            opacity: animDone ? 1 : 0.4, transition: "opacity 0.4s ease",
          }}
        >
          Go to Dashboard
        </button>
      </div>

      <style>{`
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes popIn { 0%{transform:scale(0.9)} 60%{transform:scale(1.07)} 100%{transform:scale(1)} }
      `}</style>
    </div>
  );
}
