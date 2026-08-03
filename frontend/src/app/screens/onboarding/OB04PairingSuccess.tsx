import { useNavigate } from "react-router";
import { ProgressDots } from "../../components/ProgressDots";
import { CheckCircle, Wifi } from "lucide-react";
import { mockGuardian } from "../../data/mockData";

export function OB04PairingSuccess() {
  const navigate = useNavigate();

  return (
    <div
      className="flex flex-col items-center px-6"
      style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}
    >
      <div className="pt-12 pb-6 w-full flex flex-col items-center">
        <ProgressDots total={3} current={2} />
      </div>

      <div className="flex flex-col items-center flex-1 mt-6 w-full">
        {/* Success icon */}
        <div
          className="rounded-full flex items-center justify-center mb-6"
          style={{
            width: "88px",
            height: "88px",
            backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)",
            border: "2px solid color-mix(in srgb, var(--primary) 35%, transparent)",
          }}
        >
          <CheckCircle size={44} style={{ color: "var(--primary)" }} />
        </div>

        <h2
          className="text-center mb-1"
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xl)",
            fontWeight: "var(--font-weight-semibold)",
            color: "var(--foreground)",
          }}
        >
          Guardian Connected
        </h2>
        <p
          className="text-center mb-8"
          style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}
        >
          Your device is paired and ready
        </p>

        {/* Device card */}
        <div
          className="w-full rounded-lg border border-border p-5"
          style={{ backgroundColor: "var(--card)" }}
        >
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xl)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--foreground)",
              marginBottom: "4px",
            }}
          >
            {mockGuardian.name}
          </p>

          <p
            style={{
              fontFamily: "JetBrains Mono, monospace",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
              marginBottom: "16px",
              wordBreak: "break-all",
            }}
          >
            {mockGuardian.deviceId}
          </p>

          <div
            className="h-px w-full mb-4"
            style={{ backgroundColor: "var(--border)" }}
          />

          <div className="flex flex-col gap-2">
            {[
              { label: "Connection", value: mockGuardian.connectionType },
              { label: "Firmware", value: mockGuardian.firmware },
              { label: "Signal", value: `${mockGuardian.signal}%` },
            ].map(({ label, value }) => (
              <div key={label} className="flex items-center justify-between">
                <span
                  style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}
                >
                  {label}
                </span>
                <div className="flex items-center gap-1.5">
                  {label === "Connection" && <Wifi size={13} style={{ color: "var(--chart-2)" }} />}
                  <span
                    style={{
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-sm)",
                      fontWeight: "var(--font-weight-medium)",
                      color: "var(--foreground)",
                    }}
                  >
                    {value}
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="w-full pb-10">
        <button
          onClick={() => navigate("/onboarding/did")}
          className="w-full flex items-center justify-center transition-opacity active:opacity-80"
          style={{
            height: "52px",
            backgroundColor: "var(--primary)",
            color: "var(--primary-foreground)",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-base)",
            fontWeight: "var(--font-weight-semibold)",
            borderRadius: "var(--radius)",
            border: "none",
            cursor: "pointer",
          }}
        >
          Continue
        </button>
      </div>
    </div>
  );
}