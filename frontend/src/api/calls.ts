import { api, apiUrl, authToken, errorMessage, ApiError } from "./http";
import type { BrowserSignal, CallEvent, CallSession, MediaType, SignalKind } from "../features/calls/call.types";

export const callsApi = {
  active: () => api<{ calls: CallSession[]; total: number }>("/calls/active"),
  list: () => api<{ calls: CallSession[]; total: number }>("/calls"),
  history: () => api<{ calls: Array<{ id: string; kind: "direct" | "group" | string; outcome: string; media: MediaType[]; participant_ids: string[]; started_at: string; ended_at: string; duration_seconds: number }>; total: number }>("/calls/history"),
  initiate: (target_peer_id: string, media: MediaType[]) => api<{ session_id: string; status: string }>("/calls/initiate", { method: "POST", body: JSON.stringify({ target_peer_id, media }) }),
  accept: (sessionId: string, accepted_media: MediaType[]) => api<{ status: string }>(`/call/${sessionId}/accept`, { method: "POST", body: JSON.stringify({ accepted_media }) }),
  reject: (sessionId: string, reason = "declined") => api(`/call/${sessionId}/reject`, { method: "POST", body: JSON.stringify({ reason }) }),
  end: (session_id: string) => api(`/call/${session_id}/end`, { method: "POST", body: "{}" }),
  signal: (sessionId: string, type: SignalKind, payload: unknown, operation_id: string) => api(`/call/${sessionId}/signal`, {
    method: "POST",
    headers: { "Idempotency-Key": operation_id },
    body: JSON.stringify({ type, payload, operation_id }),
  }),
  signals: (sessionId: string, after: number) => api<{ signals: BrowserSignal[] }>(`/call/${sessionId}/signals?after=${after}`),
  mediaReady: (sessionId: string, dtlsFingerprint?: string) => api<{ status: string }>(`/call/${sessionId}/media-ready`, { method: "POST", body: JSON.stringify({ dtls_fingerprint: dtlsFingerprint }) }),
  quality: (sessionId: string, report: Record<string, number | string>) => api(`/call/${sessionId}/quality`, { method: "POST", body: JSON.stringify(report) }),
  iceServers: () => api<{ ice_servers: RTCIceServer[]; configured: boolean }>("/calls/ice-servers"),
};

export function openCallSignalSocket(
  sessionId: string,
  after: number,
  onSignal: (signal: BrowserSignal) => void,
  onState: (connected: boolean) => void,
): () => void {
  const endpoint = new URL(apiUrl(`/call/${sessionId}/ws`), window.location.origin);
  endpoint.protocol = endpoint.protocol === "https:" ? "wss:" : "ws:";
  endpoint.searchParams.set("after", String(after));
  if (authToken()) endpoint.searchParams.set("access_token", authToken());
  const socket = new WebSocket(endpoint);
  socket.onopen = () => onState(true);
  socket.onclose = () => onState(false);
  socket.onerror = () => onState(false);
  socket.onmessage = (event) => {
    try {
      const message = JSON.parse(String(event.data)) as { type?: string; signal?: BrowserSignal };
      if (message.type === "signal" && message.signal) onSignal(message.signal);
    } catch {
      // HTTP polling remains the compatibility fallback.
    }
  };
  return () => socket.close();
}

export async function streamCallEvents(signal: AbortSignal, onEvent: (event: CallEvent | { event: "resync" }) => void): Promise<void> {
  const token = authToken();
  const response = await fetch(apiUrl("/calls/events"), { headers: token ? { Authorization: `Bearer ${token}` } : {}, signal });
  if (!response.ok || !response.body) {
    if (response.status === 401) {
      window.dispatchEvent(new CustomEvent("sgx:unauthorized"));
    }
    const body: unknown = await response.json().catch(() => undefined);
    throw new ApiError(response.status, errorMessage(body, `Call event stream failed (${response.status})`));
  }
  const reader = response.body.getReader(); const decoder = new TextDecoder(); let buffer = "";
  while (!signal.aborted) {
    const { done, value } = await reader.read(); if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const chunks = buffer.split("\n\n"); buffer = chunks.pop() ?? "";
    for (const chunk of chunks) {
      let name = "message", data = "";
      for (const line of chunk.split("\n")) { if (line.startsWith("event:")) name = line.slice(6).trim(); if (line.startsWith("data:")) data += line.slice(5).trim(); }
      if (name === "resync") onEvent({ event: "resync" });
      else if (data) onEvent(JSON.parse(data) as CallEvent);
    }
  }
}
