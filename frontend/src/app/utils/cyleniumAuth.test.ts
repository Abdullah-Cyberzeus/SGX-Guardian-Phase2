import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  apiPost: vi.fn(),
  configured: true,
}));

vi.mock("../services/api", () => ({
  api: { post: mocks.apiPost },
}));

vi.mock("../config/cylenium", () => ({
  CYLENIUM_OIDC_CONFIG: {
    CYLENIUM_BASE_URL: "https://login.cylenium.example/base",
    CYLENIUM_CLIENT_ID: "sgx-client",
    CYLENIUM_REDIRECT_URI: "https://guardian.example/auth/callback",
    CYLENIUM_SCOPE: "openid profile email",
  },
  isCyleniumConfigured: () => mocks.configured,
  cyleniumConfigErrorMessage: () => "Cylenium is not configured",
}));

import {
  CYLENIUM_OIDC_STATE_KEY,
  CYLENIUM_PKCE_CODE_VERIFIER_KEY,
  buildCyleniumAuthorizeUrl,
  clearStoredCyleniumState,
  generateCyleniumCodeVerifier,
  prepareCyleniumLogin,
  readStoredCyleniumState,
  replaceWithCyleniumLogin,
  startCyleniumOidcRedirect,
  storeCyleniumCodeVerifier,
  storeCyleniumState,
} from "./cyleniumAuth";

beforeEach(() => {
  localStorage.clear();
  sessionStorage.clear();
  mocks.apiPost.mockReset();
  mocks.configured = true;
  vi.stubGlobal("crypto", {
    getRandomValues: vi.fn((bytes: Uint8Array) => {
      bytes.forEach((_, index) => { bytes[index] = index; });
      return bytes;
    }),
    subtle: {
      digest: vi.fn(async () => Uint8Array.from([251, 255]).buffer),
    },
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("Cylenium PKCE authorization", () => {
  it("generates a URL-safe 256-bit verifier", () => {
    const verifier = generateCyleniumCodeVerifier();
    expect(verifier).toHaveLength(43);
    expect(verifier).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(crypto.getRandomValues).toHaveBeenCalledOnce();
  });

  it("builds the complete authorization URL and stores the verifier", async () => {
    const value = await buildCyleniumAuthorizeUrl("state / value", "nonce-value");
    const url = new URL(value);
    expect(url.origin).toBe("https://login.cylenium.example");
    expect(url.pathname).toBe("/authorize");
    expect(Object.fromEntries(url.searchParams)).toMatchObject({
      client_id: "sgx-client",
      redirect_uri: "https://guardian.example/auth/callback",
      response_type: "code",
      scope: "openid profile email",
      state: "state / value",
      nonce: "nonce-value",
      source: "sgx",
      app: "sgx_guardian",
      code_challenge: "-_8",
      code_challenge_method: "S256",
      prompt: "login",
      max_age: "0",
    });
    expect(sessionStorage.getItem(CYLENIUM_PKCE_CODE_VERIFIER_KEY)).toBeTruthy();
  });

  it("binds server-issued state and nonce into the prepared redirect", async () => {
    mocks.apiPost.mockResolvedValue({
      state: "server-state",
      nonce: "server-nonce",
      expiresAt: 1_800_000_000,
    });
    const value = await prepareCyleniumLogin();
    const url = new URL(value);
    expect(mocks.apiPost).toHaveBeenCalledWith("/auth/oidc/cylenium/start");
    expect(url.searchParams.get("state")).toBe("server-state");
    expect(url.searchParams.get("nonce")).toBe("server-nonce");
    expect(sessionStorage.getItem(CYLENIUM_OIDC_STATE_KEY)).toBe("server-state");
    expect(localStorage.getItem(CYLENIUM_OIDC_STATE_KEY)).toBe("server-state");
  });

  it("fails closed before contacting the backend when configuration is absent", async () => {
    mocks.configured = false;
    await expect(startCyleniumOidcRedirect()).rejects.toThrow("Cylenium is not configured");
    await expect(replaceWithCyleniumLogin()).rejects.toThrow("Cylenium is not configured");
    expect(mocks.apiPost).not.toHaveBeenCalled();
  });
});

describe("Cylenium transient browser state", () => {
  it("stores state redundantly and prefers the session copy", () => {
    storeCyleniumState("state-1");
    localStorage.setItem(CYLENIUM_OIDC_STATE_KEY, "local-fallback");
    expect(readStoredCyleniumState()).toBe("state-1");
    expect(sessionStorage.getItem(CYLENIUM_OIDC_STATE_KEY)).toBe("state-1");
  });

  it("falls back to local storage and clears both copies", () => {
    localStorage.setItem(CYLENIUM_OIDC_STATE_KEY, "local-state");
    expect(readStoredCyleniumState()).toBe("local-state");
    clearStoredCyleniumState();
    expect(readStoredCyleniumState()).toBeNull();
  });

  it("stores a supplied PKCE verifier only in session storage", () => {
    storeCyleniumCodeVerifier("verifier-1");
    expect(sessionStorage.getItem(CYLENIUM_PKCE_CODE_VERIFIER_KEY)).toBe("verifier-1");
    expect(localStorage.getItem(CYLENIUM_PKCE_CODE_VERIFIER_KEY)).toBeNull();
  });
});
