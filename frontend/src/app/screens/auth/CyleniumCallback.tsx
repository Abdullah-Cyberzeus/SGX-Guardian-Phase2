import { useEffect, useMemo, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router";
import { AlertCircle, Loader2, Shield } from "lucide-react";
import { CervaisLogo } from "../../components/CervaisLogo";
import { useAuth } from "../../contexts/AuthContext";
import {
  CYLENIUM_PKCE_CODE_VERIFIER_KEY,
  clearStoredCyleniumState,
  readStoredCyleniumState,
  replaceWithCyleniumLogin,
} from "../../utils/cyleniumAuth";

const CYLENIUM_RETURN_TO_KEY = "sgx_cylenium_return_to";

function safeReturnTo(value: string | null): string {
  return value?.startsWith("/") && !value.startsWith("//") ? value : "/home";
}

function readStoredPkceVerifier(): string | null {
  return sessionStorage.getItem(CYLENIUM_PKCE_CODE_VERIFIER_KEY);
}

function clearStoredPkceVerifier() {
  sessionStorage.removeItem(CYLENIUM_PKCE_CODE_VERIFIER_KEY);
}

export function CyleniumCallback() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { completeCyleniumLogin } = useAuth();
  // AuthProvider updates its session during a successful exchange, which
  // rerenders the context and changes function identities. Keep the latest
  // callback in a ref so that rerender does not cancel this one-shot effect
  // before it can navigate away from the loading screen.
  const completeCyleniumLoginRef = useRef(completeCyleniumLogin);
  completeCyleniumLoginRef.current = completeCyleniumLogin;
  const startedRef = useRef(false);
  const [backendError, setBackendError] = useState<string | null>(null);
  const code = params.get("code");
  const returnedState = params.get("state");

  const result = useMemo(() => {
    const storedState = readStoredCyleniumState();

    if (!code) {
      return { valid: false, message: "Cylenium did not return an authorization code." };
    }
    if (!returnedState) {
      return { valid: false, message: "Cylenium did not return the sign-in state." };
    }
    if (!storedState) {
      return { valid: false, message: "SG-X could not find the original Cylenium sign-in state." };
    }
    if (returnedState !== storedState) {
      return { valid: false, message: "Cylenium sign-in state could not be verified." };
    }

    return { valid: true, message: "" };
  }, [code, returnedState]);
  const status = result.valid && !backendError ? "valid" : "invalid";

  useEffect(() => {
    if (!result.valid) {
      clearStoredCyleniumState();
      const timer = window.setTimeout(() => replaceWithCyleniumLogin(), 2200);
      return () => window.clearTimeout(timer);
    }

    if (startedRef.current) return;
    startedRef.current = true;

    let cancelled = false;
    const codeVerifier = readStoredPkceVerifier();

    async function exchangeCode() {
      const result = await completeCyleniumLoginRef.current(
        code ?? "",
        returnedState ?? "",
        codeVerifier,
      );
      if (cancelled) return;
      if (result.error) {
        clearStoredCyleniumState();
        setBackendError(result.error);
        return;
      }
      clearStoredCyleniumState();
      clearStoredPkceVerifier();
      const returnTo = safeReturnTo(sessionStorage.getItem(CYLENIUM_RETURN_TO_KEY));
      sessionStorage.removeItem(CYLENIUM_RETURN_TO_KEY);
      navigate(returnTo, { replace: true });
    }

    exchangeCode();
    return () => {
      cancelled = true;
    };
  }, [code, navigate, result.valid, returnedState]);

  return (
    <div
      className="relative flex flex-col items-center justify-center px-6"
      style={{ minHeight: "100dvh", backgroundColor: "var(--background)" }}
    >
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          background:
            "radial-gradient(ellipse 80% 45% at 50% 0%, color-mix(in srgb, var(--primary) 10%, transparent) 0%, transparent 70%)",
        }}
      />

      <div className="w-full z-10 flex flex-col items-center text-center" style={{ maxWidth: "400px" }}>
        <CervaisLogo width={120} />

        <div
          className="mt-8 rounded-full flex items-center justify-center"
          style={{
            width: "72px",
            height: "72px",
            backgroundColor:
              status === "invalid"
                ? "color-mix(in srgb, var(--destructive) 12%, transparent)"
                : "color-mix(in srgb, var(--primary) 12%, transparent)",
            border:
              status === "invalid"
                ? "1.5px solid color-mix(in srgb, var(--destructive) 25%, transparent)"
                : "1.5px solid color-mix(in srgb, var(--primary) 25%, transparent)",
          }}
        >
          {status === "invalid" ? (
            <AlertCircle size={32} style={{ color: "var(--destructive)" }} />
          ) : (
            <Shield size={32} style={{ color: "var(--primary)" }} />
          )}
        </div>

        {status === "invalid" ? (
          <>
            <h1
              className="mt-6"
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "24px",
                fontWeight: 700,
                color: "var(--foreground)",
                lineHeight: 1.2,
              }}
            >
              Cylenium sign-in failed
            </h1>
            <p
              className="mt-3"
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                color: "var(--muted-foreground)",
                lineHeight: 1.6,
              }}
            >
              {backendError || `${result.message} Returning to login...`}
            </p>
          </>
        ) : (
          <>
            <div className="mt-6 flex items-center justify-center gap-2">
              <Loader2 size={18} style={{ animation: "spin 1s linear infinite", color: "var(--primary)" }} />
              <h1
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "24px",
                  fontWeight: 700,
                  color: "var(--foreground)",
                  lineHeight: 1.2,
                }}
              >
                Signing you in with Cylenium...
              </h1>
            </div>
            <p
              className="mt-3"
              style={{
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-sm)",
                color: "var(--muted-foreground)",
                lineHeight: 1.6,
              }}
            >
              Completing secure authentication...
            </p>
          </>
        )}

        <button
          onClick={() => replaceWithCyleniumLogin()}
          className="mt-8 w-full flex items-center justify-center transition-opacity active:opacity-80"
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
          Return to login
        </button>
      </div>

      <style>{`@keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }`}</style>
    </div>
  );
}
