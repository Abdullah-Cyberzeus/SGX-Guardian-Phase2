import { api } from "../services/api";
import { CYLENIUM_OIDC_CONFIG } from "../config/cylenium";

export const CYLENIUM_OIDC_STATE_KEY = "sgx_cylenium_oidc_state";
export const CYLENIUM_PKCE_CODE_VERIFIER_KEY = "sgx_cylenium_oidc_pkce_code_verifier";

interface CyleniumAuthorizeStartResponse {
  state: string;
  nonce: string;
  expiresAt: number;
}

function randomBase64Url(bytes: Uint8Array): string {
  const binary = Array.from(bytes, (byte) => String.fromCharCode(byte)).join("");
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

/**
 * Server-generated, server-bound `state`/`nonce` for this login attempt.
 * SG-X's backend stores the pair keyed by `state` before we ever redirect,
 * so the callback handler can look up the expected nonce itself instead of
 * trusting anything the browser sends back.
 */
async function startCyleniumAuthorization(): Promise<CyleniumAuthorizeStartResponse> {
  return api.post<CyleniumAuthorizeStartResponse>("/auth/oidc/cylenium/start");
}

export function generateCyleniumCodeVerifier(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return randomBase64Url(bytes);
}

async function sha256Base64Url(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return randomBase64Url(new Uint8Array(digest));
}

export function storeCyleniumCodeVerifier(codeVerifier: string) {
  sessionStorage.setItem(CYLENIUM_PKCE_CODE_VERIFIER_KEY, codeVerifier);
}

async function buildCyleniumAuthorizeUrl(state: string, nonce: string): Promise<string> {
  const codeVerifier = generateCyleniumCodeVerifier();
  const codeChallenge = await sha256Base64Url(codeVerifier);
  storeCyleniumCodeVerifier(codeVerifier);

  const authorizeUrl = new URL("/authorize", CYLENIUM_OIDC_CONFIG.CYLENIUM_BASE_URL);
  authorizeUrl.searchParams.set("client_id", CYLENIUM_OIDC_CONFIG.CYLENIUM_CLIENT_ID);
  authorizeUrl.searchParams.set("redirect_uri", CYLENIUM_OIDC_CONFIG.CYLENIUM_REDIRECT_URI);
  authorizeUrl.searchParams.set("response_type", "code");
  authorizeUrl.searchParams.set("scope", CYLENIUM_OIDC_CONFIG.CYLENIUM_SCOPE);
  authorizeUrl.searchParams.set("state", state);
  authorizeUrl.searchParams.set("nonce", nonce);
  authorizeUrl.searchParams.set("source", "sgx");
  authorizeUrl.searchParams.set("app", "sgx_guardian");
  authorizeUrl.searchParams.set("code_challenge", codeChallenge);
  authorizeUrl.searchParams.set("code_challenge_method", "S256");
  authorizeUrl.searchParams.set("prompt", "login");
  authorizeUrl.searchParams.set("max_age", "0");
  return authorizeUrl.toString();
}

async function beginCyleniumLogin(navigate: (url: string) => void) {
  const { state, nonce } = await startCyleniumAuthorization();
  storeCyleniumState(state);
  navigate(await buildCyleniumAuthorizeUrl(state, nonce));
}

export async function startCyleniumOidcRedirect() {
  await beginCyleniumLogin((url) => window.location.assign(url));
}

export async function replaceWithCyleniumLogin() {
  await beginCyleniumLogin((url) => window.location.replace(url));
}

export function storeCyleniumState(state: string) {
  sessionStorage.setItem(CYLENIUM_OIDC_STATE_KEY, state);
  localStorage.setItem(CYLENIUM_OIDC_STATE_KEY, state);
}

export function readStoredCyleniumState(): string | null {
  return (
    sessionStorage.getItem(CYLENIUM_OIDC_STATE_KEY) ||
    localStorage.getItem(CYLENIUM_OIDC_STATE_KEY)
  );
}

export function clearStoredCyleniumState() {
  sessionStorage.removeItem(CYLENIUM_OIDC_STATE_KEY);
  localStorage.removeItem(CYLENIUM_OIDC_STATE_KEY);
}
