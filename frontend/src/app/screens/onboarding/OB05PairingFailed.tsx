import { useNavigate } from "react-router";
import { ProgressDots } from "../../components/ProgressDots";
import { XCircle } from "lucide-react";

export function OB05PairingFailed() {
  const navigate = useNavigate();

  return (
    <div
      className="flex flex-col items-center px-6"
      style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}
    >
      <div className="pt-12 pb-6 w-full flex flex-col items-center">
        <ProgressDots total={3} current={2} />
      </div>

      <div className="flex flex-col items-center flex-1 mt-6">
        <div
          className="rounded-full flex items-center justify-center mb-6"
          style={{
            width: "88px",
            height: "88px",
            backgroundColor: "color-mix(in srgb, var(--destructive) 12%, transparent)",
            border: "2px solid color-mix(in srgb, var(--destructive) 30%, transparent)",
          }}
        >
          <XCircle size={44} style={{ color: "var(--destructive)" }} />
        </div>

        <h2
          className="text-center mb-2"
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xl)",
            fontWeight: "var(--font-weight-semibold)",
            color: "var(--foreground)",
          }}
        >
          Couldn't Connect to Guardian
        </h2>

        <p
          className="text-center mb-8"
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            color: "var(--muted-foreground)",
            maxWidth: "260px",
            lineHeight: 1.6,
          }}
        >
          Ensure your Guardian device is powered on and within Bluetooth or WiFi range.
        </p>

        {/* Troubleshooting tips */}
        <div
          className="w-full rounded-lg border border-border p-4 mb-6"
          style={{ backgroundColor: "var(--card)" }}
        >
          <p
            className="mb-3"
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-semibold)",
              color: "var(--muted-foreground)",
              letterSpacing: "0.08em",
            }}
          >
            Check these items
          </p>
          {[
            "Guardian device is powered on (LED is solid blue)",
            "You are within 10 feet of the Guardian",
            "Guardian is not already paired to another phone",
            "Bluetooth and WiFi are enabled on this device",
          ].map((tip, i) => (
            <div key={i} className="flex items-start gap-2 mb-2">
              <div
                style={{
                  width: "5px",
                  height: "5px",
                  borderRadius: "50%",
                  backgroundColor: "var(--primary)",
                  marginTop: "6px",
                  flexShrink: 0,
                }}
              />
              <p
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-sm)",
                  color: "var(--foreground)",
                }}
              >
                {tip}
              </p>
            </div>
          ))}
        </div>
      </div>

      <div className="w-full pb-10 flex flex-col gap-3">
        <button
          onClick={() => navigate("/onboarding/pairing")}
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
          Try Again
        </button>

        <button
          onClick={() => {}}
          className="w-full flex items-center justify-center transition-opacity active:opacity-80"
          style={{
            height: "48px",
            backgroundColor: "var(--secondary)",
            color: "var(--secondary-foreground)",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            fontWeight: "var(--font-weight-medium)",
            borderRadius: "var(--radius)",
            border: "1px solid var(--border)",
            cursor: "pointer",
          }}
        >
          Get Help
        </button>

        <button
          onClick={() => navigate("/onboarding/did")}
          className="flex items-center justify-center transition-opacity active:opacity-60"
          style={{
            height: "44px",
            background: "none",
            border: "none",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            color: "var(--muted-foreground)",
            cursor: "pointer",
            textDecoration: "underline",
            textDecorationStyle: "dotted",
            textUnderlineOffset: "3px",
          }}
        >
          Skip for now
        </button>
      </div>
    </div>
  );
}
