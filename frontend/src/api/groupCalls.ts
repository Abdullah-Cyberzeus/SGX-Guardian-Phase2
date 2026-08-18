import { api, apiUrl, authToken } from "./http";
import type {
  GroupModerationAction, GroupSession, GroupSignal, MediaType, SignalKind,
} from "../features/calls/call.types";

export const groupCallsApi = {
  active: () => api<{ groups: GroupSession[]; total: number; local_device_id?: string }>("/group-calls/active"),
  create: (title: string, member_ids: string[], call_all: boolean, media: MediaType[]) =>
    api<{ session: GroupSession; failed_invites: string[] }>("/group-calls", {
      method: "POST", body: JSON.stringify({ title, member_ids, call_all, media }),
    }),
  join: (groupId: string) => api<GroupSession>(`/group-call/${groupId}/join`, { method: "POST", body: "{}" }),
  decline: (groupId: string) => api<GroupSession>(`/group-call/${groupId}/decline`, { method: "POST", body: "{}" }),
  leave: (groupId: string) => api<GroupSession>(`/group-call/${groupId}/leave`, { method: "POST", body: "{}" }),
  end: (groupId: string) => api<GroupSession>(`/group-call/${groupId}/end`, { method: "POST", body: "{}" }),
  moderate: (groupId: string, action: GroupModerationAction) =>
    api<GroupSession>(`/group-call/${groupId}/moderate`, { method: "POST", body: JSON.stringify(action) }),
  signal: (groupId: string, target_device_id: string, type: SignalKind, payload: unknown, operation_id: string) =>
    api(`/group-call/${groupId}/signal`, {
      method: "POST",
      headers: { "Idempotency-Key": operation_id },
      body: JSON.stringify({ target_device_id, type, payload, operation_id }),
    }),
  signals: (groupId: string, after: number) =>
    api<{ signals: GroupSignal[] }>(`/group-call/${groupId}/signals?after=${after}`),
  mediaReady: (groupId: string) =>
    api<GroupSession>(`/group-call/${groupId}/media-ready`, { method: "POST", body: "{}" }),
  heartbeat: (groupId: string) =>
    api<GroupSession>(`/group-call/${groupId}/heartbeat`, { method: "POST", body: "{}" }),
  iceServers: () => api<{ ice_servers: RTCIceServer[]; configured: boolean }>("/calls/ice-servers"),
};

export function openGroupSignalSocket(
  groupId: string,
  after: number,
  onSignal: (signal: GroupSignal) => void,
  onState: (connected: boolean) => void,
): () => void {
  const endpoint = new URL(apiUrl(`/group-call/${groupId}/ws`), window.location.origin);
  endpoint.protocol = endpoint.protocol === "https:" ? "wss:" : "ws:";
  endpoint.searchParams.set("after", String(after));
  endpoint.searchParams.set("access_token", authToken());
  const socket = new WebSocket(endpoint);
  socket.onopen = () => {
    onState(true);
    socket.send(JSON.stringify({ type: "heartbeat" }));
  };
  socket.onclose = () => onState(false);
  socket.onerror = () => onState(false);
  socket.onmessage = (event) => {
    try {
      const message = JSON.parse(String(event.data)) as { type?: string; signal?: GroupSignal };
      if (message.type === "signal" && message.signal) onSignal(message.signal);
    } catch {
      // Invalid messages are ignored; HTTP polling remains available as fallback.
    }
  };
  const heartbeat = window.setInterval(() => {
    if (socket.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ type: "heartbeat" }));
  }, 3_000);
  return () => {
    window.clearInterval(heartbeat);
    socket.close();
  };
}
