// Base API configuration and client with fallback support
import { monitoring } from './monitoring';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api/v1';

function shouldSendNgrokSkipHeader(url: string): boolean {
  try {
    return new URL(url, typeof window === 'undefined' ? 'http://localhost' : window.location.origin)
      .hostname
      .includes('ngrok');
  } catch {
    return false;
  }
}

interface RequestOptions extends RequestInit {
  params?: Record<string, string | number | boolean>;
  suppressUnauthorizedEvent?: boolean;
  idempotencyKey?: string;
  /** Overrides the default request timeout. Device commands need longer than a read,
   *  because Home Assistant blocks on the vendor cloud round-trip before replying. */
  timeoutMs?: number;
}

const DEFAULT_TIMEOUT_MS = 20_000;

export class ApiError extends Error {
  status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
  }
}

export type ApiFailureKind = 'guardian_unreachable' | 'timeout' | 'unauthorized' | 'forbidden' | 'server' | 'http';

function emitApiEvent(name: string, detail: Record<string, unknown>) {
  if (typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent(name, { detail }));
  }
}

function operationId() {
  return typeof crypto.randomUUID === 'function'
    ? crypto.randomUUID()
    : `${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function classifyFailure(status: number | null, message: string): ApiFailureKind {
  if (status === 401) return 'unauthorized';
  if (status === 403) return 'forbidden';
  if (status != null && status >= 500) return 'server';
  if (status != null) return 'http';
  if (message.toLowerCase().includes('timed out')) return 'timeout';
  return 'guardian_unreachable';
}

async function extractErrorMessage(response: Response): Promise<string> {
  const raw = await response.text().catch(() => '');
  if (!raw) return `HTTP ${response.status}`;
  try {
    const parsed = JSON.parse(raw);
    return (
      (typeof parsed.message === 'string' && parsed.message) ||
      (typeof parsed.error === 'string' && parsed.error) ||
      (typeof parsed.error?.message === 'string' && parsed.error.message) ||
      raw
    );
  } catch {
    return raw.trim() || `HTTP ${response.status}`;
  }
}

class ApiClient {
  private baseUrl: string;
  private isServerAvailable: boolean | null = null;
  private token: string | null = null;

  constructor(baseUrl: string) {
    this.baseUrl = baseUrl;
  }

  setToken(token: string | null) {
    this.token = token;
  }

  getToken(): string | null {
    return this.token;
  }

  publicUrl(endpoint: string, params?: Record<string, string | number | boolean>): string {
    return this.buildUrl(endpoint, params);
  }

  private buildUrl(endpoint: string, params?: Record<string, string | number | boolean>): string {
    const url = new URL(
      `${this.baseUrl}${endpoint}`,
      typeof window === 'undefined' ? 'http://localhost' : window.location.origin,
    );
    if (params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null) {
          url.searchParams.append(key, String(value));
        }
      });
    }
    return url.toString();
  }

  async checkServerHealth(): Promise<boolean> {
    try {
      const response = await fetch(`${this.baseUrl}/health`, {
        method: 'GET',
        signal: AbortSignal.timeout(2000), // 2 second timeout
      });
      this.isServerAvailable = response.ok;
      return this.isServerAvailable;
    } catch {
      this.isServerAvailable = false;
      return false;
    }
  }

  async request<T>(endpoint: string, options: RequestOptions = {}): Promise<T> {
    const { params, suppressUnauthorizedEvent, idempotencyKey, timeoutMs, ...fetchOptions } = options;
    const url = this.buildUrl(endpoint, params);
    const method = (fetchOptions.method || 'GET').toUpperCase();
    const t0 = performance.now();

    const isFormData = typeof FormData !== 'undefined' && fetchOptions.body instanceof FormData;
    const headers: Record<string, string> = {
      'X-SGX-Client': 'guardian-pwa',
      ...(shouldSendNgrokSkipHeader(url) ? { 'ngrok-skip-browser-warning': 'true' } : {}),
      ...(fetchOptions.headers as Record<string, string> | undefined)
    };
    if (this.token && !headers['Authorization']) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    if (method !== 'GET' && method !== 'HEAD' && !headers['Idempotency-Key']) {
      headers['Idempotency-Key'] = idempotencyKey || operationId();
    }
    // A bodyless GET does not need a content type. Omitting it also avoids an
    // unnecessary CORS preflight when the admin UI is hosted separately.
    if (fetchOptions.body != null && !isFormData && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    let response: Response;
    const timeout = new AbortController();
    const timeoutLimit = timeoutMs ?? DEFAULT_TIMEOUT_MS;
    const timeoutId = window.setTimeout(() => timeout.abort(), timeoutLimit);
    const suppliedSignal = fetchOptions.signal;
    const abortFromCaller = () => timeout.abort();
    suppliedSignal?.addEventListener('abort', abortFromCaller, { once: true });
    try {
      response = await fetch(url, { ...fetchOptions, headers, signal: timeout.signal });
    } catch (netErr) {
      const duration = Math.round(performance.now() - t0);
      const message = timeout.signal.aborted && !suppliedSignal?.aborted
        ? `Request timed out after ${Math.round(timeoutLimit / 1000)} seconds`
        : netErr instanceof Error ? netErr.message : 'Network error';
      monitoring.trackApiCall(method, endpoint, null, duration, message);
      emitApiEvent('sgx:api-failure', { endpoint, method, status: null, kind: classifyFailure(null, message), message });
      throw new Error(message);
    } finally {
      window.clearTimeout(timeoutId);
      suppliedSignal?.removeEventListener('abort', abortFromCaller);
    }

    const duration = Math.round(performance.now() - t0);

    if (!response.ok) {
      if (response.status === 401 && !endpoint.startsWith('/auth/') && !suppressUnauthorizedEvent) {
        window.dispatchEvent(new CustomEvent('sgx:unauthorized'));
      }
      const msg = await extractErrorMessage(response);
      monitoring.trackApiCall(method, endpoint, response.status, duration, msg);
      emitApiEvent('sgx:api-failure', { endpoint, method, status: response.status, kind: classifyFailure(response.status, msg), message: msg });
      throw new ApiError(msg, response.status);
    }

    monitoring.trackApiCall(method, endpoint, response.status, duration);
    emitApiEvent('sgx:api-success', { endpoint, method, status: response.status });
    return response.json();
  }

  async raw(endpoint: string, options: RequestOptions = {}): Promise<Response> {
    const { params, suppressUnauthorizedEvent, idempotencyKey, timeoutMs: _timeoutMs, ...fetchOptions } = options;
    const baseOrigin = new URL(
      this.baseUrl,
      typeof window === 'undefined' ? 'http://localhost' : window.location.origin,
    ).origin;
    // Some APIs return a ready-to-use root path such as
    // /api/v1/vault/files/:id/download. Do not append that to /api/v1 again.
    const url = endpoint.startsWith('/api/')
      ? new URL(endpoint, baseOrigin)
      : new URL(this.buildUrl(endpoint, params));
    if (endpoint.startsWith('/api/') && params) {
      Object.entries(params).forEach(([key, value]) => {
        if (value !== undefined && value !== null) url.searchParams.append(key, String(value));
      });
    }
    const headers: Record<string, string> = {
      'X-SGX-Client': 'guardian-pwa',
      ...(shouldSendNgrokSkipHeader(url.toString()) ? { 'ngrok-skip-browser-warning': 'true' } : {}),
      ...(fetchOptions.headers as Record<string, string> | undefined),
    };
    if (this.token && !headers.Authorization) headers.Authorization = `Bearer ${this.token}`;
    if ((fetchOptions.method || 'GET').toUpperCase() !== 'GET' && (fetchOptions.method || 'GET').toUpperCase() !== 'HEAD' && !headers['Idempotency-Key']) {
      headers['Idempotency-Key'] = idempotencyKey || operationId();
    }
    const response = await fetch(url.toString(), { ...fetchOptions, headers });
    if (!response.ok) {
      if (response.status === 401 && !endpoint.startsWith('/auth/') && !suppressUnauthorizedEvent) {
        window.dispatchEvent(new CustomEvent('sgx:unauthorized'));
      }
      const message = await extractErrorMessage(response);
      emitApiEvent('sgx:api-failure', { endpoint, method: fetchOptions.method || 'GET', status: response.status, kind: classifyFailure(response.status, message), message });
      throw new ApiError(message, response.status);
    }
    emitApiEvent('sgx:api-success', { endpoint, method: fetchOptions.method || 'GET', status: response.status });
    return response;
  }

  upload<T>(
    endpoint: string,
    body: FormData,
    options: {
      params?: Record<string, string | number | boolean>;
      signal?: AbortSignal;
      onProgress?: (loaded: number, total: number) => void;
      idempotencyKey?: string;
    } = {},
  ): Promise<T> {
    const url = this.buildUrl(endpoint, options.params);
    const started = performance.now();
    return new Promise<T>((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", url);
      xhr.responseType = "json";
      xhr.setRequestHeader("X-SGX-Client", "guardian-pwa");
      if (shouldSendNgrokSkipHeader(url)) xhr.setRequestHeader("ngrok-skip-browser-warning", "true");
      if (this.token) xhr.setRequestHeader("Authorization", `Bearer ${this.token}`);
      xhr.setRequestHeader("Idempotency-Key", options.idempotencyKey || operationId());
      const uploadFile = body.get("file");
      const fallbackTotal = uploadFile instanceof File ? uploadFile.size : 0;
      xhr.upload.onprogress = (event) => {
        options.onProgress?.(
          event.loaded,
          event.lengthComputable ? event.total : fallbackTotal,
        );
      };
      xhr.onerror = () => {
        monitoring.trackApiCall("POST", endpoint, null, Math.round(performance.now() - started), "Network error");
        emitApiEvent('sgx:api-failure', { endpoint, method: 'POST', status: null, kind: 'guardian_unreachable', message: 'Network error' });
        reject(new Error("Upload network connection failed"));
      };
      xhr.onabort = () => reject(new DOMException("Upload cancelled", "AbortError"));
      xhr.onload = () => {
        const response = xhr.response ?? (() => {
          try { return JSON.parse(xhr.responseText); } catch { return {}; }
        })();
        if (xhr.status >= 200 && xhr.status < 300) {
          monitoring.trackApiCall("POST", endpoint, xhr.status, Math.round(performance.now() - started));
          emitApiEvent('sgx:api-success', { endpoint, method: 'POST', status: xhr.status });
          resolve(response as T);
          return;
        }
        if (xhr.status === 401 && !endpoint.startsWith("/auth/")) {
          window.dispatchEvent(new CustomEvent("sgx:unauthorized"));
        }
        const message = response?.error?.message || response?.message || response?.error || `Upload failed (HTTP ${xhr.status})`;
        monitoring.trackApiCall("POST", endpoint, xhr.status, Math.round(performance.now() - started), String(message));
        emitApiEvent('sgx:api-failure', { endpoint, method: 'POST', status: xhr.status, kind: classifyFailure(xhr.status, String(message)), message: String(message) });
        reject(new Error(String(message)));
      };
      options.signal?.addEventListener("abort", () => xhr.abort(), { once: true });
      xhr.send(body);
    });
  }

  async get<T>(endpoint: string, params?: Record<string, string | number | boolean>): Promise<T> {
    return this.request<T>(endpoint, { method: 'GET', params });
  }

  async post<T>(endpoint: string, data?: unknown, options?: { timeoutMs?: number; suppressUnauthorizedEvent?: boolean }): Promise<T> {
    const body =
      data === undefined || data === null
        ? undefined
        : data instanceof FormData
          ? data
          : JSON.stringify(data);
    return this.request<T>(endpoint, { method: 'POST', body, timeoutMs: options?.timeoutMs, suppressUnauthorizedEvent: options?.suppressUnauthorizedEvent });
  }

  async put<T>(endpoint: string, data?: unknown): Promise<T> {
    const body =
      data === undefined || data === null
        ? undefined
        : data instanceof FormData
          ? data
          : JSON.stringify(data);
    return this.request<T>(endpoint, { method: 'PUT', body });
  }

  async patch<T>(endpoint: string, data?: unknown): Promise<T> {
    return this.request<T>(endpoint, {
      method: 'PATCH',
      body: data === undefined || data === null ? undefined : JSON.stringify(data),
    });
  }

  async delete<T>(endpoint: string): Promise<T> {
    return this.request<T>(endpoint, { method: 'DELETE' });
  }
}

export const api = new ApiClient(API_BASE_URL);

// Helper function to call API with fallback to mock data
export async function fetchWithFallback<T>(
  apiCall: () => Promise<T>,
  mockData: T,
  options?: { silent?: boolean }
): Promise<{ data: T; source: 'api' | 'mock' }> {
  try {
    const data = await apiCall();
    return { data, source: 'api' };
  } catch (error) {
    if (!options?.silent) {
      console.warn('API unavailable, using mock data:', error);
    }
    return { data: mockData, source: 'mock' };
  }
}

export default api;
