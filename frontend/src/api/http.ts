const API_ROOT = import.meta.env.VITE_API_ROOT ?? import.meta.env.VITE_API_URL ?? "/api/v1";

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

interface ErrorEnvelope {
  error?: string | { code?: string; message?: string };
  message?: string;
}

export function errorMessage(body: unknown, fallback: string): string {
  if (!body || typeof body !== "object") return fallback;
  const envelope = body as ErrorEnvelope;
  if (typeof envelope.error === "string") return envelope.error;
  if (envelope.error && typeof envelope.error.message === "string") return envelope.error.message;
  if (typeof envelope.message === "string") return envelope.message;
  return fallback;
}

export function authToken(): string {
  // Member credentials are intentionally tab-scoped in sessionStorage;
  // administrative sessions retain the existing durable localStorage path.
  // Every legacy REST/SSE helper must use the same precedence as AuthContext.
  return sessionStorage.getItem("sgx_auth_token")
    ?? localStorage.getItem("sgx_auth_token")
    ?? "";
}

export function operationId(): string {
  return typeof crypto.randomUUID === "function"
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

export async function api<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? "GET").toUpperCase();
  const headers = new Headers(init.headers);
  if (!headers.has("X-SGX-Client")) headers.set("X-SGX-Client", "guardian-pwa");
  if (init.body != null && !headers.has("Content-Type")) headers.set("Content-Type", "application/json");
  if (authToken() && !headers.has("Authorization")) {
    headers.set("Authorization", `Bearer ${authToken()}`);
  }
  if (method !== "GET" && method !== "HEAD" && !headers.has("Idempotency-Key")) {
    headers.set("Idempotency-Key", operationId());
  }
  const response = await fetch(`${API_ROOT}${path}`, {
    ...init,
    headers,
  });
  const body = await response.json().catch(() => ({}));
  if (response.status === 401 && !path.startsWith("/auth/")) {
    window.dispatchEvent(new CustomEvent("sgx:unauthorized"));
  }
  if (!response.ok) throw new ApiError(response.status, errorMessage(body, `Request failed (${response.status})`));
  return body as T;
}

export function apiUrl(path: string): string { return `${API_ROOT}${path}`; }
