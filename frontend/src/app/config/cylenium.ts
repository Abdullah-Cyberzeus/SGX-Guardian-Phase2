const defaultRedirectUri =
  typeof window === "undefined"
    ? "http://localhost:5173/auth/callback"
    : `${window.location.origin}/auth/callback`;

function requiredEnv(name: string): string {
  const value = import.meta.env[name];
  if (typeof value === "string" && value.trim().length > 0) {
    return value;
  }

  throw new Error(
    `Missing Cylenium OIDC configuration: ${name} must be configured. Set ${name} to the client_id registered in Cylenium.`,
  );
}

export const CYLENIUM_OIDC_CONFIG = {
  CYLENIUM_BASE_URL: import.meta.env.VITE_CYLENIUM_BASE_URL ?? "http://localhost:4000",
  CYLENIUM_CLIENT_ID: requiredEnv("VITE_CYLENIUM_CLIENT_ID"),
  CYLENIUM_REDIRECT_URI: import.meta.env.VITE_CYLENIUM_REDIRECT_URI ?? defaultRedirectUri,
  CYLENIUM_SCOPE: import.meta.env.VITE_CYLENIUM_SCOPE ?? "openid profile email",
} as const;
