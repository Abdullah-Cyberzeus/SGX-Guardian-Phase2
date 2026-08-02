// Base API configuration and client with fallback support
import { monitoring } from './monitoring';

const API_BASE_URL = import.meta.env.VITE_API_URL || '/api';

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
    const { params, ...fetchOptions } = options;
    const url = this.buildUrl(endpoint, params);
    const method = (fetchOptions.method || 'GET').toUpperCase();
    const t0 = performance.now();

    const isFormData = typeof FormData !== 'undefined' && fetchOptions.body instanceof FormData;
    const headers: Record<string, string> = {
      ...(shouldSendNgrokSkipHeader(url) ? { 'ngrok-skip-browser-warning': 'true' } : {}),
      ...(fetchOptions.headers as Record<string, string> | undefined)
    };
    if (this.token && !headers['Authorization']) {
      headers['Authorization'] = `Bearer ${this.token}`;
    }
    // A bodyless GET does not need a content type. Omitting it also avoids an
    // unnecessary CORS preflight when the admin UI is hosted separately.
    if (fetchOptions.body != null && !isFormData && !headers['Content-Type']) {
      headers['Content-Type'] = 'application/json';
    }

    let response: Response;
    try {
      response = await fetch(url, { ...fetchOptions, headers });
    } catch (netErr) {
      const duration = Math.round(performance.now() - t0);
      monitoring.trackApiCall(method, endpoint, null, duration, netErr instanceof Error ? netErr.message : 'Network error');
      throw netErr;
    }

    const duration = Math.round(performance.now() - t0);

    if (!response.ok) {
      if (response.status === 401 && !endpoint.startsWith('/auth/')) {
        window.dispatchEvent(new CustomEvent('sgx:unauthorized'));
      }
      const error = await response.json().catch(() => ({ message: 'Request failed' }));
      // Backend wraps errors as { error: { code, message } }
      const msg =
        (typeof error.message === 'string' && error.message) ||
        (typeof error.error === 'string' && error.error) ||
        (typeof error.error?.message === 'string' && error.error.message) ||
        `HTTP ${response.status}`;
      monitoring.trackApiCall(method, endpoint, response.status, duration, msg);
      throw new Error(msg);
    }

    monitoring.trackApiCall(method, endpoint, response.status, duration);
    return response.json();
  }

  async raw(endpoint: string, options: RequestOptions = {}): Promise<Response> {
    const { params, ...fetchOptions } = options;
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
      ...(shouldSendNgrokSkipHeader(url.toString()) ? { 'ngrok-skip-browser-warning': 'true' } : {}),
      ...(fetchOptions.headers as Record<string, string> | undefined),
    };
    if (this.token && !headers.Authorization) headers.Authorization = `Bearer ${this.token}`;
    const response = await fetch(url.toString(), { ...fetchOptions, headers });
    if (!response.ok) {
      if (response.status === 401 && !endpoint.startsWith('/auth/')) {
        window.dispatchEvent(new CustomEvent('sgx:unauthorized'));
      }
      const error = await response.json().catch(() => ({ message: 'Request failed' }));
      throw new Error(String(error?.error?.message || error?.message || error?.error || `HTTP ${response.status}`));
    }
    return response;
  }

  upload<T>(
    endpoint: string,
    body: FormData,
    options: {
      params?: Record<string, string | number | boolean>;
      signal?: AbortSignal;
      onProgress?: (loaded: number, total: number) => void;
    } = {},
  ): Promise<T> {
    const url = this.buildUrl(endpoint, options.params);
    const started = performance.now();
    return new Promise<T>((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("POST", url);
      xhr.responseType = "json";
      if (shouldSendNgrokSkipHeader(url)) xhr.setRequestHeader("ngrok-skip-browser-warning", "true");
      if (this.token) xhr.setRequestHeader("Authorization", `Bearer ${this.token}`);
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
        reject(new Error("Upload network connection failed"));
      };
      xhr.onabort = () => reject(new DOMException("Upload cancelled", "AbortError"));
      xhr.onload = () => {
        const response = xhr.response ?? (() => {
          try { return JSON.parse(xhr.responseText); } catch { return {}; }
        })();
        if (xhr.status >= 200 && xhr.status < 300) {
          monitoring.trackApiCall("POST", endpoint, xhr.status, Math.round(performance.now() - started));
          resolve(response as T);
          return;
        }
        if (xhr.status === 401 && !endpoint.startsWith("/auth/")) {
          window.dispatchEvent(new CustomEvent("sgx:unauthorized"));
        }
        const message = response?.error?.message || response?.message || response?.error || `Upload failed (HTTP ${xhr.status})`;
        monitoring.trackApiCall("POST", endpoint, xhr.status, Math.round(performance.now() - started), String(message));
        reject(new Error(String(message)));
      };
      options.signal?.addEventListener("abort", () => xhr.abort(), { once: true });
      xhr.send(body);
    });
  }

  async get<T>(endpoint: string, params?: Record<string, string | number | boolean>): Promise<T> {
    return this.request<T>(endpoint, { method: 'GET', params });
  }

  async post<T>(endpoint: string, data?: unknown): Promise<T> {
    const body =
      data === undefined || data === null
        ? undefined
        : data instanceof FormData
          ? data
          : JSON.stringify(data);
    return this.request<T>(endpoint, { method: 'POST', body });
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
