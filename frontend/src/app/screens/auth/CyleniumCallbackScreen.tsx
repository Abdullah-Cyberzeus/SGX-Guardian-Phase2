import { useEffect, useRef, useState } from "react";
import { Loader2, ShieldAlert } from "lucide-react";
import { useNavigate, useSearchParams } from "react-router";
import { useAuth } from "../../contexts/AuthContext";

const CYLENIUM_RETURN_TO_KEY = "sgx_cylenium_return_to";

function safeReturnTo(value: string | null): string {
  return value?.startsWith("/") && !value.startsWith("//") ? value : "/home";
}

export function CyleniumCallbackScreen() {
  const navigate = useNavigate();
  const [params] = useSearchParams();
  const { completeCyleniumSignIn, loading } = useAuth();
  const started = useRef(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    // Let AuthProvider finish its initial session check so it cannot race with
    // and clear the new session created by this callback.
    if (loading || started.current) return;
    started.current = true;

    const providerError = params.get("error_description") || params.get("error");
    const code = params.get("code");
    const state = params.get("state");
    if (providerError || !code || !state) {
      setError(providerError || "Cylenium returned an incomplete sign-in response.");
      return;
    }

    completeCyleniumSignIn(code, state).then((result) => {
      if (result.error) {
        setError(result.error);
        return;
      }
      const returnTo = params.get("returnTo") || sessionStorage.getItem(CYLENIUM_RETURN_TO_KEY);
      sessionStorage.removeItem(CYLENIUM_RETURN_TO_KEY);
      navigate(safeReturnTo(returnTo), { replace: true });
    });
  }, [completeCyleniumSignIn, loading, navigate, params]);

  return (
    <main className="flex min-h-[100dvh] flex-col items-center justify-center gap-4 px-6 text-center">
      {error ? (
        <>
          <ShieldAlert size={42} style={{ color: "var(--destructive)" }} />
          <h1 className="text-xl font-semibold">Cylenium sign-in failed</h1>
          <p className="max-w-sm text-sm" style={{ color: "var(--muted-foreground)" }}>{error}</p>
          <button className="mt-2 rounded-md px-5 py-3" style={{ background: "var(--primary)", color: "var(--primary-foreground)" }} onClick={() => navigate("/login", { replace: true })}>
            Return to sign in
          </button>
        </>
      ) : (
        <>
          <Loader2 size={36} className="animate-spin" style={{ color: "var(--primary)" }} />
          <h1 className="text-xl font-semibold">Completing secure sign-in</h1>
          <p className="text-sm" style={{ color: "var(--muted-foreground)" }}>Verifying your Cylenium identity…</p>
        </>
      )}
    </main>
  );
}
