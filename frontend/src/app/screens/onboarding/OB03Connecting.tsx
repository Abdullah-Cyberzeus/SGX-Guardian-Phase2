import { useEffect, useState, useRef } from "react";
import { useNavigate, useLocation } from "react-router";
import { ProgressDots } from "../../components/ProgressDots";
import { Check, Loader2, AlertTriangle } from "lucide-react";
import { deviceService, type PairingStatus } from "../../services/deviceService";
import { toast } from "sonner";

const POLL_INTERVAL_MS = 2000;
const MAX_WAIT_MS = 120_000; // 2 minutes timeout

interface StepState {
  label: string;
  key: keyof PairingStatus | "done";
  status: "pending" | "active" | "done" | "failed";
}

const makeSteps = (): StepState[] => [
  { label: "Pairing proof verified", key: "apiConsumed", status: "active" },
  { label: "Bootstrapping Guardian node", key: "bootstrapConsumed", status: "pending" },
  { label: "Establishing secure mesh", key: "done", status: "pending" },
];

export function OB03Connecting() {
  const navigate = useNavigate();
  const location = useLocation();
  const serial: string | undefined = (location.state as any)?.serial;

  const [steps, setSteps] = useState<StepState[]>(makeSteps());
  const [error, setError] = useState<string | null>(null);
  const [pairingStatus, setPairingStatus] = useState<PairingStatus | null>(null);
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const startRef = useRef(Date.now());

  // If no serial passed (e.g. reached via old nav), use fake steps
  const noSerial = !serial;

  useEffect(() => {
    if (noSerial) {
      // Fallback: animate fake steps as before
      let elapsed = 0;
      const durations = [1200, 1800, 1600];
      durations.forEach((dur, i) => {
        setTimeout(() => {
          setSteps((prev) => prev.map((s, idx) => idx === i ? { ...s, status: "active" } : s));
          setTimeout(() => {
            setSteps((prev) => prev.map((s, idx) => idx === i ? { ...s, status: "done" } : idx === i + 1 ? { ...s, status: "active" } : s));
            if (i === durations.length - 1) {
              setTimeout(() => navigate("/onboarding/success"), 400);
            }
          }, dur);
        }, elapsed);
        elapsed += dur + 200;
      });
      return;
    }

    // Poll pairing status
    const poll = async () => {
      if (Date.now() - startRef.current > MAX_WAIT_MS) {
        clearInterval(pollRef.current!);
        setError("Pairing timed out. Please try again.");
        setSteps((prev) => prev.map((s) => s.status === "active" ? { ...s, status: "failed" } : s));
        return;
      }

      try {
        const data = await deviceService.getPairingStatus(serial!);
        setPairingStatus(data);

        setSteps((prev) => {
          const next = [...prev];
          // Step 0: apiConsumed
          if (data.apiConsumed) next[0] = { ...next[0], status: "done" };
          // Step 1: bootstrapConsumed
          if (data.apiConsumed && !data.bootstrapConsumed) next[1] = { ...next[1], status: "active" };
          if (data.bootstrapConsumed) next[1] = { ...next[1], status: "done" };
          // Step 2: completed
          if (data.status === "completed") {
            next[2] = { ...next[2], status: "done" };
          } else if (data.bootstrapConsumed) {
            next[2] = { ...next[2], status: "active" };
          }
          // failed
          if (data.status === "failed") {
            next.forEach((s, i) => { if (s.status === "active") next[i] = { ...s, status: "failed" }; });
          }
          return next;
        });

        if (data.status === "completed") {
          clearInterval(pollRef.current!);
          setTimeout(() => navigate("/onboarding/success"), 600);
        } else if (data.status === "failed") {
          clearInterval(pollRef.current!);
          setError("Pairing failed. Please try again.");
        }
      } catch (e: any) {
        // 404 means status not yet available â€” keep polling
        if (!e.message?.includes("404") && !e.message?.includes("NOT_FOUND")) {
          console.warn("Pairing status poll error:", e.message);
        }
      }
    };

    poll(); // immediate first call
    pollRef.current = setInterval(poll, POLL_INTERVAL_MS);
    return () => clearInterval(pollRef.current!);
  }, [serial, navigate, noSerial]);

  return (
    <div
      className="flex flex-col items-center"
      style={{ minHeight: "100dvh", backgroundColor: "var(--background)", padding: "0 24px" }}
    >
      <div className="pt-12 pb-6 flex flex-col items-center w-full">
        <ProgressDots total={3} current={2} />
      </div>

      {/* Pulsing indicator */}
      <div className="flex flex-col items-center mt-8 mb-10">
        <div
          className="rounded-full flex items-center justify-center"
          style={{
            width: "80px",
            height: "80px",
            backgroundColor: error
              ? "color-mix(in srgb, var(--destructive) 15%, transparent)"
              : "color-mix(in srgb, var(--primary) 15%, transparent)",
            animation: error ? undefined : "pulse 2s ease-in-out infinite",
          }}
        >
          <div
            className="rounded-full flex items-center justify-center"
            style={{
              width: "52px",
              height: "52px",
              backgroundColor: error
                ? "color-mix(in srgb, var(--destructive) 25%, transparent)"
                : "color-mix(in srgb, var(--primary) 25%, transparent)",
            }}
          >
            {error ? (
              <AlertTriangle size={24} style={{ color: "var(--destructive)" }} />
            ) : (
              <Loader2 size={24} style={{ color: "var(--primary)", animation: "spin 1s linear infinite" }} />
            )}
          </div>
        </div>

        <h2
          className="mt-6 text-center"
          style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: error ? "var(--destructive)" : "var(--foreground)" }}
        >
          {error ? "Pairing Failed" : "Connecting to Guardianâ€¦"}
        </h2>

        {serial && !error && (
          <p
            className="mt-1 text-center"
            style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--primary)", fontWeight: "var(--font-weight-semibold)" }}
          >
            {serial}
          </p>
        )}

        <p
          className="mt-2 text-center"
          style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: error ? "var(--destructive)" : "var(--muted-foreground)" }}
        >
          {error ?? "Polling pairing status every 2 secondsâ€¦"}
        </p>
      </div>

      {/* Progress steps */}
      <div
        className="w-full rounded-lg border border-border overflow-hidden"
        style={{ backgroundColor: "var(--card)" }}
      >
        {steps.map((step, i) => {
          const isComplete = step.status === "done";
          const isActive = step.status === "active";
          const isFailed = step.status === "failed";
          return (
            <div
              key={i}
              className="flex items-center gap-3 px-4 py-4"
              style={{ borderBottom: i < steps.length - 1 ? "1px solid var(--border)" : undefined }}
            >
              <div
                className="rounded-full flex items-center justify-center flex-shrink-0"
                style={{
                  width: "28px",
                  height: "28px",
                  backgroundColor: isComplete
                    ? "color-mix(in srgb, var(--chart-2) 20%, transparent)"
                    : isFailed
                    ? "color-mix(in srgb, var(--destructive) 15%, transparent)"
                    : isActive
                    ? "color-mix(in srgb, var(--primary) 15%, transparent)"
                    : "var(--muted)",
                  border: `1.5px solid ${isComplete ? "var(--chart-2)" : isFailed ? "var(--destructive)" : isActive ? "var(--primary)" : "var(--border)"}`,
                }}
              >
                {isComplete ? (
                  <Check size={13} style={{ color: "var(--chart-2)" }} />
                ) : isFailed ? (
                  <AlertTriangle size={13} style={{ color: "var(--destructive)" }} />
                ) : isActive ? (
                  <Loader2 size={13} style={{ color: "var(--primary)", animation: "spin 1s linear infinite" }} />
                ) : (
                  <div style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: "var(--muted-foreground)", opacity: 0.4 }} />
                )}
              </div>
              <span
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  fontWeight: isActive ? "var(--font-weight-medium)" : "var(--font-weight-normal)",
                  color: isComplete ? "var(--chart-2)" : isFailed ? "var(--destructive)" : isActive ? "var(--foreground)" : "var(--muted-foreground)",
                }}
              >
                {step.label}
                {!isComplete && !isActive && !isFailed && (
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", marginLeft: "6px", opacity: 0.5 }}>
                    Â· pending
                  </span>
                )}
              </span>
            </div>
          );
        })}
      </div>

      {/* Error retry */}
      {error && (
        <button
          onClick={() => navigate("/onboarding/pairing")}
          style={{
            marginTop: "24px",
            height: "48px",
            width: "100%",
            backgroundColor: "var(--primary)",
            color: "var(--primary-foreground)",
            border: "none",
            borderRadius: "var(--radius)",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            fontWeight: "var(--font-weight-semibold)",
            cursor: "pointer",
          }}
        >
          Try Again
        </button>
      )}

      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        @keyframes pulse { 0%, 100% { transform: scale(1); opacity: 1; } 50% { transform: scale(1.06); opacity: 0.85; } }
      `}</style>
    </div>
  );
}