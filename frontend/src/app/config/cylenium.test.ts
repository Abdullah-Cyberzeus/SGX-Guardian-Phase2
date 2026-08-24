import { afterEach, describe, expect, it, vi } from "vitest";

const ENV_KEYS = [
  "VITE_CYLENIUM_BASE_URL",
  "VITE_CYLENIUM_CLIENT_ID",
  "VITE_CYLENIUM_REDIRECT_URI",
  "VITE_CYLENIUM_SCOPE",
] as const;

afterEach(() => {
  vi.unstubAllEnvs();
  vi.resetModules();
});

describe("Cylenium frontend configuration", () => {
  it("reads an explicitly configured Cylenium cloud tenant", async () => {
    vi.stubEnv("VITE_CYLENIUM_BASE_URL", "https://login.cylenium.example");
    vi.stubEnv("VITE_CYLENIUM_CLIENT_ID", "sgx-guardian");
    vi.stubEnv("VITE_CYLENIUM_REDIRECT_URI", "https://guardian.example/auth/callback");
    vi.stubEnv("VITE_CYLENIUM_SCOPE", "openid profile email circles");

    const module = await import("./cylenium");
    expect(module.CYLENIUM_OIDC_CONFIG).toEqual({
      CYLENIUM_BASE_URL: "https://login.cylenium.example",
      CYLENIUM_CLIENT_ID: "sgx-guardian",
      CYLENIUM_REDIRECT_URI: "https://guardian.example/auth/callback",
      CYLENIUM_SCOPE: "openid profile email circles",
    });
    expect(module.isCyleniumConfigured()).toBe(true);
  });

  it("rejects a missing or whitespace-only client identifier", async () => {
    for (const key of ENV_KEYS) vi.stubEnv(key, "");
    vi.stubEnv("VITE_CYLENIUM_CLIENT_ID", "   ");
    const module = await import("./cylenium");
    expect(module.isCyleniumConfigured()).toBe(false);
    expect(module.CYLENIUM_OIDC_CONFIG.CYLENIUM_BASE_URL).toBe("http://localhost:4000");
    expect(module.CYLENIUM_OIDC_CONFIG.CYLENIUM_SCOPE).toBe("");
    expect(module.cyleniumConfigErrorMessage()).toContain("VITE_CYLENIUM_CLIENT_ID");
  });
});
