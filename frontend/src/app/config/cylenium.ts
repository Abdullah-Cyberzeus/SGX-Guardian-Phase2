const defaultRedirectUri =
  typeof window === "undefined"
    ? "http://localhost:5173/auth/callback"
    : `${window.location.origin}/auth/callback`;

function readEnv(name: string): string {
  const value = import.meta.env[name];
  if (typeof value === "string" && value.trim().length > 0) {
    return value;
  }
  return "";
}

export const CYLENIUM_OIDC_CONFIG = {
  CYLENIUM_BASE_URL: readEnv("VITE_CYLENIUM_BASE_URL") || "http://localhost:4000",
  CYLENIUM_CLIENT_ID: readEnv("VITE_CYLENIUM_CLIENT_ID"),
  CYLENIUM_REDIRECT_URI: import.meta.env.VITE_CYLENIUM_REDIRECT_URI ?? defaultRedirectUri,
  CYLENIUM_SCOPE: import.meta.env.VITE_CYLENIUM_SCOPE ?? "openid profile email",
} as const;

export function isCyleniumConfigured(): boolean {
  return CYLENIUM_OIDC_CONFIG.CYLENIUM_CLIENT_ID.trim().length > 0;
}

export function cyleniumConfigErrorMessage(): string {
  return "Cylenium sign-in is not configured for this frontend. Set VITE_CYLENIUM_CLIENT_ID to enable it.";
}
