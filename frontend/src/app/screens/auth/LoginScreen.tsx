import { useState } from "react";
import { useNavigate } from "react-router";
import { CervaisLogo } from "../../components/CervaisLogo";
import { Eye, EyeOff, Shield, Loader2 } from "lucide-react";
import { useAuth } from "../../contexts/AuthContext";
import { toast } from "sonner";

export function LoginScreen() {
  const navigate = useNavigate();
  const { signIn, startCyleniumSignIn } = useAuth();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [cyleniumLoading, setCyleniumLoading] = useState(false);

  const canSubmit = email.includes("@") && password.length >= 6;

  const handleLogin = async () => {
    if (!canSubmit || loading) return;
    setLoading(true);
    const { error } = await signIn(email, password);
    setLoading(false);
    if (error) {
      toast.error(error);
    } else {
      navigate("/home", { replace: true });
    }
  };

  const handleCylenium = () => {
    setCyleniumLoading(true);
    startCyleniumSignIn("/home");
  };

  return (
    <div
      className="relative flex flex-col items-center justify-center"
      style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}
    >
      {/* Background glow */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            "radial-gradient(ellipse 80% 45% at 50% 0%, color-mix(in srgb, var(--primary) 10%, transparent) 0%, transparent 70%)",
        }}
      />

      {/* Centered container */}
      <div className="w-full z-10" style={{ maxWidth: "400px" }}>

      {/* Header */}
      <div className="flex flex-col items-center pt-16 pb-8 px-6">
        <CervaisLogo width={120} />
        <h1
          className="mt-6 text-center"
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "28px",
            fontWeight: 700,
            color: "var(--foreground)",
            letterSpacing: "-0.02em",
            lineHeight: 1.2,
          }}
        >
          Welcome back
        </h1>
        <p
          className="mt-2 text-center"
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            color: "var(--muted-foreground)",
          }}
        >
          Sign in to your SG-X Guardian account
        </p>
      </div>

      {/* Form */}
      <div className="flex flex-col gap-4 px-6">
        {/* Email */}
        <div>
          <label
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-medium)",
              color: "var(--muted-foreground)",
              marginBottom: "6px",
              display: "block",
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
            style={{
              height: "52px",
              backgroundColor: "var(--input-background)",
              border: "1.5px solid var(--border)",
              borderRadius: "var(--radius)",
              color: "var(--foreground)",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-sm)",
            }}
          />
        </div>

        {/* Password */}
        <div>
          <label
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-medium)",
              color: "var(--muted-foreground)",
              marginBottom: "6px",
              display: "block",
            }}
          >
            Password
          </label>
          <div className="relative">
            <input
              type={showPassword ? "text" : "password"}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleLogin()}
              placeholder="Your password"
              className="w-full px-4 pr-12 outline-none"
              style={{
                height: "52px",
                backgroundColor: "var(--input-background)",
                border: "1.5px solid var(--border)",
                borderRadius: "var(--radius)",
                color: "var(--foreground)",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
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

        {/* Zero-trust badge */}
        <div
          className="flex items-center gap-2 px-3 py-2.5 rounded-lg"
          style={{
            backgroundColor: "color-mix(in srgb, var(--primary) 6%, transparent)",
            border: "1px solid color-mix(in srgb, var(--primary) 18%, transparent)",
          }}
        >
          <Shield size={13} style={{ color: "var(--primary)", flexShrink: 0 }} />
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
              lineHeight: 1.5,
            }}
          >
            End-to-end encrypted Â· Zero-knowledge auth Â· DID-verified session
          </p>
        </div>

        {/* Divider */}
        <div className="flex items-center gap-3">
          <div style={{ flex: 1, height: "1px", backgroundColor: "var(--border)" }} />
          <span
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
              flexShrink: 0,
            }}
          >
            or
          </span>
          <div style={{ flex: 1, height: "1px", backgroundColor: "var(--border)" }} />
        </div>

        {/* Continue with Cylenium */}
        <button
          onClick={handleCylenium}
          disabled={loading}
          className="w-full flex items-center justify-center gap-2.5 transition-opacity active:opacity-80"
          style={{
            height: "52px",
            backgroundColor: "transparent",
            color: "var(--foreground)",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            fontWeight: "var(--font-weight-semibold)",
            borderRadius: "var(--radius)",
            border: "1.5px solid var(--border)",
            cursor: loading ? "default" : "pointer",
            opacity: loading ? 0.6 : 1,
          }}
        >
          <div
            className="flex items-center justify-center rounded-md flex-shrink-0"
            style={{ width: "22px", height: "22px", backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)" }}
          >
            <Shield size={13} style={{ color: "var(--primary)" }} />
          </div>
          Continue with Cylenium
        </button>
      </div>

      {/* CTA */}
      <div className="px-6 pb-10 pt-6 flex flex-col gap-3">
        <button
          onClick={handleLogin}
          className="w-full flex items-center justify-center gap-2 transition-opacity active:opacity-80"
          style={{
            height: "52px",
            backgroundColor: "var(--primary)",
            color: "var(--primary-foreground)",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-base)",
            fontWeight: "var(--font-weight-semibold)",
            borderRadius: "var(--radius)",
            border: "none",
            cursor: canSubmit ? "pointer" : "default",
            opacity: canSubmit ? 1 : 0.45,
            boxShadow: canSubmit ? "0 0 24px color-mix(in srgb, var(--primary) 22%, transparent)" : "none",
          }}
        >
          {loading ? <Loader2 size={18} style={{ animation: "spin 1s linear infinite" }} /> : "Sign In"}
        </button>
        <button
          onClick={() => navigate("/signup")}
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
          Create account
        </button>
      </div>

      </div>{/* End centered container */}
      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
