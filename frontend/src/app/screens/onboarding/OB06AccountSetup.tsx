import { toast } from "sonner";
import { useLocation, useNavigate } from "react-router";
import { ProgressDots } from "../../components/ProgressDots";
import { Eye, EyeOff, Check, X, Loader2, Shield, ExternalLink, Copy } from "lucide-react";
import { useAuth } from "../../contexts/AuthContext";
import { useCurrentUser } from "../../hooks/useCurrentUser";
import { useState } from "react";

const MIN_PASSWORD_LENGTH = 12;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

const isValidEmail = (value: string) => EMAIL_PATTERN.test(value.trim());

const requirements = [
  { label: "At least 12 characters", test: (p: string) => p.length >= MIN_PASSWORD_LENGTH },
  { label: "One uppercase letter", test: (p: string) => /[A-Z]/.test(p) },
  { label: "One number", test: (p: string) => /[0-9]/.test(p) },
  { label: "One special character", test: (p: string) => /[^a-zA-Z0-9]/.test(p) },
];

// Cylenium outcome states after OAuth
type CyleniumState =
  | "idle"
  | "loading"
  | "success-new"       // new user, green check, auto-advance
  | "success-enterprise" // enterprise, show DID + admin note
  | "failed";           // quiet failure

const SHORT_ALIAS = "TX-042-MR";
const ONBOARDING_SERIAL_KEY = "sgx_onboarding_serial";
const ONBOARDING_METHOD_KEY = "sgx_onboarding_method";

type OnboardingSignupMethod = "serial" | "qr-upload" | "qr-camera";

const SIGNUP_METHOD_LABELS: Record<OnboardingSignupMethod, string> = {
  serial: "Serial number",
  "qr-upload": "Uploaded QR code",
  "qr-camera": "Camera scan",
};

export function OB06AccountSetup() {
  const navigate = useNavigate();
  const location = useLocation();
  const routeState = location.state as { serial?: string; signupMethod?: OnboardingSignupMethod } | null;
  const { signIn, signUp, startCyleniumSignIn } = useAuth();
  const { name: currentUserName, did } = useCurrentUser();
  const [mode, setMode] = useState<"create" | "login">("create");
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [cyleniumState, setCyleniumState] = useState<CyleniumState>("idle");
  const [didCopied, setDidCopied] = useState(false);
  const [guardianSerial] = useState(() => {
    const fromRoute = typeof routeState?.serial === "string" ? routeState.serial : "";
    return (fromRoute || sessionStorage.getItem(ONBOARDING_SERIAL_KEY) || "").trim().toUpperCase();
  });
  const signupMethod = (routeState?.signupMethod || sessionStorage.getItem(ONBOARDING_METHOD_KEY) || "serial") as OnboardingSignupMethod;
  const signupMethodLabel = SIGNUP_METHOD_LABELS[signupMethod] ?? SIGNUP_METHOD_LABELS.serial;

  const emailValid = isValidEmail(email);
  const showEmailError = email.trim().length > 0 && !emailValid;
  const allMet = requirements.every((r) => r.test(password));
  const canSubmit = emailValid && (mode === "login" ? password.length >= 6 : allMet && name.trim().length > 1);

  const handleSubmit = async () => {
    if (!canSubmit || loading) return;
    setLoading(true);

    if (mode === "create") {
      const { error } = await signUp(email.trim(), password, name.trim());
      if (error) {
        toast.error(error);
        setLoading(false);
        return;
      }
      if (guardianSerial) {
        localStorage.setItem(ONBOARDING_SERIAL_KEY, guardianSerial);
        localStorage.setItem(ONBOARDING_METHOD_KEY, signupMethod);
      }
      navigate("/onboarding/pairing", { replace: true });
    } else {
      const { error } = await signIn(email, password);
      if (error) {
        toast.error(error);
        setLoading(false);
        return;
      }
      localStorage.setItem("sgx_onboarded", "1");
      navigate("/home", { replace: true });
    }

    setLoading(false);
  };

  const handleCylenium = () => {
    setCyleniumState("loading");
    startCyleniumSignIn("/onboarding/pairing");
  };

  const handleCopyDID = () => {
    navigator.clipboard.writeText(did).catch(() => { });
    setDidCopied(true);
    setTimeout(() => setDidCopied(false), 2000);
  };

  // Cylenium success-new overlay
  if (cyleniumState === "success-new") {
    return (
      <div
        className="flex flex-col items-center justify-center px-6 gap-5"
        style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}
      >
        <div
          className="rounded-full flex items-center justify-center"
          style={{
            width: "88px", height: "88px",
            backgroundColor: "color-mix(in srgb, var(--chart-2) 15%, transparent)",
            border: "2px solid color-mix(in srgb, var(--chart-2) 35%, transparent)",
            animation: "popIn 0.35s ease-out forwards",
          }}
        >
          <Check size={44} strokeWidth={2.5} style={{ color: "var(--chart-2)" }} />
        </div>
        <div className="text-center">
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "6px" }}>
            Cylenium account connected
          </p>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.6 }}>
            Your Guardian will sync automatically with Cylenium Cloud.
          </p>
        </div>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
          Continuing...
        </p>
        <style>{`@keyframes popIn { 0%{transform:scale(0.85)} 60%{transform:scale(1.08)} 100%{transform:scale(1)} }`}</style>
      </div>
    );
  }

  // Cylenium enterprise state
  if (cyleniumState === "success-enterprise") {
    return (
      <div
        className="flex flex-col"
        style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}
      >
        <div className="flex flex-col items-center px-6 pt-14 pb-6 gap-4">
          <div
            className="rounded-full flex items-center justify-center"
            style={{ width: "72px", height: "72px", backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)", border: "2px solid color-mix(in srgb, var(--primary) 30%, transparent)" }}
          >
            <Shield size={32} style={{ color: "var(--primary)" }} />
          </div>
          <div className="text-center">
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "20px", fontWeight: 700, color: "var(--foreground)", letterSpacing: "-0.02em", marginBottom: "6px" }}>
              Welcome back
            </p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", marginBottom: "4px" }}>
              Guardian linked to Cylenium
            </p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.6 }}>
              Your IT admin needs to add this Guardian's DID to the Cervais admin console to complete setup.
            </p>
          </div>
        </div>

        <div className="px-5 flex flex-col gap-4 flex-1">
          {/* DID block */}
          <div>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "8px" }}>
              Your Guardian DID
            </p>
            <div
              className="rounded-lg border border-border p-4"
              style={{ backgroundColor: "var(--card)" }}
            >
              <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--foreground)", wordBreak: "break-all", lineHeight: 1.7, marginBottom: "12px" }}>
                {did || <span style={{ color: "var(--muted-foreground)" }}>No DID assigned yet</span>}
              </p>
              <button
                onClick={handleCopyDID}
                className="flex items-center gap-2 px-3 rounded-md transition-opacity active:opacity-70"
                style={{
                  height: "36px",
                  backgroundColor: didCopied ? "color-mix(in srgb, var(--chart-2) 15%, transparent)" : "color-mix(in srgb, var(--primary) 15%, transparent)",
                  color: didCopied ? "var(--chart-2)" : "var(--primary)",
                  border: "none", cursor: "pointer",
                  fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)",
                }}
              >
                {didCopied ? <Check size={13} /> : <Copy size={13} />}
                {didCopied ? "Copied!" : "Copy DID"}
              </button>
            </div>
          </div>

          {/* Admin docs link */}
          <a
            href="#"
            className="flex items-center gap-2 px-4 py-3 rounded-lg transition-opacity active:opacity-70"
            style={{
              backgroundColor: "var(--card)", border: "1px solid var(--border)",
              fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)",
              color: "var(--primary)", textDecoration: "none",
            }}
          >
            <ExternalLink size={15} style={{ flexShrink: 0 }} />
            View Admin Docs
          </a>
        </div>

        <div className="px-5 pb-10 pt-6">
          <button
            onClick={() => {
              localStorage.setItem("sgx_cylenium_connected", "1");
              navigate("/onboarding/pairing", { replace: true });
            }}
            className="w-full flex items-center justify-center gap-2 transition-opacity active:opacity-80"
            style={{
              height: "52px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)",
              fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)",
              borderRadius: "var(--radius)", border: "none", cursor: "pointer",
            }}
          >
            Continue
          </button>
        </div>
      </div>
    );
  }

  // Cylenium loading state
  if (cyleniumState === "loading") {
    return (
      <div
        className="flex flex-col items-center justify-center gap-5 px-6"
        style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}
      >
        <div
          className="rounded-full flex items-center justify-center"
          style={{ width: "72px", height: "72px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)", border: "1.5px solid color-mix(in srgb, var(--primary) 25%, transparent)" }}
        >
          <Loader2 size={32} style={{ color: "var(--primary)", animation: "spin 1s linear infinite" }} />
        </div>
        <div className="text-center">
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "4px" }}>
            Connecting to Cylenium...
          </p>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
            Complete the authentication in your browser.
          </p>
        </div>
        <style>{`@keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }`}</style>
      </div>
    );
  }

  // Main form
  return (
    <div
      className="flex flex-col"
      style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}
    >
      <div className="flex flex-col items-center px-6 pt-12 pb-6">
        <ProgressDots total={3} current={1} />
        <h2 className="mt-6 text-center" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xl)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
          Create your account
        </h2>
        <p className="mt-2 text-center" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", maxWidth: "300px", lineHeight: 1.5 }}>
          Sign up before pairing your Guardian.
        </p>
      </div>

      {/* Toggle */}
      <div className="px-5 mb-6">
        <div
          className="flex p-1 rounded-lg"
          style={{ backgroundColor: "var(--muted)", borderRadius: "var(--radius-card)" }}
        >
          {(["create", "login"] as const).map((m) => (
            <button
              key={m}
              onClick={() => setMode(m)}
              className="flex-1 flex items-center justify-center transition-all"
              style={{
                height: "40px",
                borderRadius: "var(--radius)",
                backgroundColor: mode === m ? "var(--card)" : "transparent",
                color: mode === m ? "var(--foreground)" : "var(--muted-foreground)",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                fontWeight: mode === m ? "var(--font-weight-semibold)" : "var(--font-weight-normal)",
                border: mode === m ? "1px solid var(--border)" : "none",
                cursor: "pointer",
                boxShadow: mode === m ? "var(--elevation-sm)" : "none",
              }}
            >
              {m === "create" ? "Create Account" : "Log In"}
            </button>
          ))}
        </div>
      </div>

      <div className="flex flex-col gap-4 px-5 flex-1">
        {/* {mode === "create" && guardianSerial && (
          <div
            className="rounded-lg border border-border p-4 flex items-start gap-3"
            style={{ backgroundColor: "var(--card)" }}
          >
            <div
              className="rounded-md flex items-center justify-center flex-shrink-0"
              style={{ width: "34px", height: "34px", backgroundColor: "color-mix(in srgb, var(--primary) 13%, transparent)" }}
            >
              <Shield size={16} style={{ color: "var(--primary)" }} />
            </div>
            <div className="min-w-0 flex-1">
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "5px" }}>
                GUARDIAN SELECTED
              </p>
              <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", color: "var(--foreground)", wordBreak: "break-all" }}>
                {guardianSerial}
              </p>
              <p className="mt-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                Source: {signupMethodLabel}
              </p>
            </div>
            <button
              onClick={() => navigate("/onboarding/pairing")}
              style={{ background: "none", border: "none", cursor: "pointer", color: "var(--primary)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)" }}
            >
              Change
            </button>
          </div>
        )} */}

        {/* Name (create only) */}
        {mode === "create" && (
          <div>
            <label
              style={{
                fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)",
                fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)",
                marginBottom: "6px", display: "block",
              }}
            >
              Full Name
            </label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="Your name"
              className="w-full px-4 outline-none"
              style={{
                height: "48px", backgroundColor: "var(--input-background)",
                border: "1.5px solid var(--border)", borderRadius: "var(--radius)",
                color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)",
              }}
            />
          </div>
        )}

        {/* Email */}
        <div>
          <label
            style={{
              fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)",
              marginBottom: "6px", display: "block",
            }}
          >
            Email Address
          </label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            placeholder="you@company.com"
            className="w-full px-4 outline-none"
            aria-invalid={showEmailError}
            style={{
              height: "48px", backgroundColor: "var(--input-background)",
              border: showEmailError ? "1.5px solid var(--destructive)" : "1.5px solid var(--border)", borderRadius: "var(--radius)",
              color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)",
            }}
          />
          {showEmailError && (
            <p className="mt-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--destructive)", lineHeight: 1.4 }}>
              Enter a valid email address.
            </p>
          )}
        </div>

        {/* Password */}
        <div>
          <label
            style={{
              fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-medium)", color: "var(--muted-foreground)",
              marginBottom: "6px", display: "block",
            }}
          >
            Password
          </label>
          <div className="relative">
            <input
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              placeholder={mode === "create" ? "Create a strong password" : "Your password"}
              className="w-full px-4 outline-none pr-12"
              style={{
                height: "48px", backgroundColor: "var(--input-background)",
                border: "1.5px solid var(--border)", borderRadius: "var(--radius)",
                color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)",
              }}
            />
            <button
              onClick={() => setShowPassword(!showPassword)}
              className="absolute right-3 top-1/2 -translate-y-1/2 flex items-center justify-center"
              style={{ width: "32px", height: "32px", background: "none", border: "none", cursor: "pointer" }}
            >
              {showPassword ? (
                <EyeOff size={16} style={{ color: "var(--muted-foreground)" }} />
              ) : (
                <Eye size={16} style={{ color: "var(--muted-foreground)" }} />
              )}
            </button>
          </div>
        </div>

        {/* Password requirements */}
        {mode === "create" && password.length === 0 && (
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>
            Requires 12+ chars, uppercase, number, and special character.
          </p>
        )}
        {mode === "create" && password.length > 0 && (
          <div className="rounded-lg p-3 border border-border" style={{ backgroundColor: "var(--card)" }}>
            <div className="flex flex-col gap-1.5">
              {requirements.map((req) => {
                const met = req.test(password);
                return (
                  <div key={req.label} className="flex items-center gap-2">
                    <div
                      className="rounded-full flex items-center justify-center flex-shrink-0"
                      style={{
                        width: "16px", height: "16px",
                        backgroundColor: met
                          ? "color-mix(in srgb, var(--chart-2) 20%, transparent)"
                          : "color-mix(in srgb, var(--destructive) 15%, transparent)",
                      }}
                    >
                      {met ? (
                        <Check size={9} style={{ color: "var(--chart-2)" }} />
                      ) : (
                        <X size={9} style={{ color: "var(--destructive)" }} />
                      )}
                    </div>
                    <span
                      style={{
                        fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)",
                        color: met ? "var(--chart-2)" : "var(--muted-foreground)",
                      }}
                    >
                      {req.label}
                    </span>
                  </div>
                );
              })}
            </div>
          </div>
        )}
      </div>

      <div className="px-5 pb-10 mt-6 flex flex-col gap-3">
        {/* Primary submit */}
        <button
          onClick={handleSubmit}
          className="w-full flex items-center justify-center gap-2 transition-opacity active:opacity-80"
          style={{
            height: "52px", backgroundColor: "var(--primary)", color: "var(--primary-foreground)",
            fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)",
            borderRadius: "var(--radius)", border: "none",
            cursor: canSubmit ? "pointer" : "default",
            opacity: canSubmit ? 1 : 0.45,
          }}
        >
          {loading ? <Loader2 size={18} style={{ animation: "spin 1s linear infinite" }} /> : (mode === "create" ? "Create Account" : "Log In")}
        </button>

        {/* Divider */}
        <div className="flex items-center gap-3">
          <div style={{ flex: 1, height: "1px", backgroundColor: "var(--border)" }} />
          <span
            style={{
              fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)", flexShrink: 0,
            }}
          >
            or
          </span>
          <div style={{ flex: 1, height: "1px", backgroundColor: "var(--border)" }} />
        </div>

        {/* Continue with Cylenium */}
        <button
          onClick={handleCylenium}
          className="w-full flex items-center justify-center gap-2.5 transition-opacity active:opacity-80"
          style={{
            height: "52px",
            backgroundColor: "transparent",
            color: "var(--foreground)",
            fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)",
            borderRadius: "var(--radius)",
            border: "1.5px solid var(--border)",
            cursor: "pointer",
          }}
        >
          {/* Cervais shield icon */}
          <div
            className="flex items-center justify-center rounded-md flex-shrink-0"
            style={{ width: "22px", height: "22px", backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)" }}
          >
            <Shield size={13} style={{ color: "var(--primary)" }} />
          </div>
          Continue with Cylenium
        </button>
      </div>

      <style>{`
        @keyframes spin { from{transform:rotate(0deg)} to{transform:rotate(360deg)} }
        @keyframes popIn { 0%{transform:scale(0.85)} 60%{transform:scale(1.08)} 100%{transform:scale(1)} }
      `}</style>
    </div>
  );
}

