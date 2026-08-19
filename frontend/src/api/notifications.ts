import { api, apiUrl, authToken, errorMessage, ApiError } from "./http";

// Notifications — /api/v1/notifications/* (SSE push + REST history/prefs)
// Live delivery is Server-Sent Events (GET /notifications/stream), not a raw
// WebSocket — mirrors the fetch+ReadableStream pattern already used for
// /calls/events in ./calls.ts (browsers can't set an Authorization header on
// a native EventSource, so the stream is read manually).

export type NotificationCategory = "alerts" | "devices" | "circles";

export type NotificationKind =
  | "AlertHigh"
  | "AlertMedium"
  | "AlertLow"
  | "DeviceDiscovered"
  | "DevicePendingApproval"
  | "GuardianOffline"
  | "CircleNewMessage"
  | "CircleIncomingCall"
  | "CircleMemberJoined"
  | "CircleFileShared";

export type NotificationSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface NotificationItem {
  id: string;
  kind: NotificationKind | string;
  title: string;
  body: string;
  severity: NotificationSeverity | string;
  refId?: string;
  createdAt: string;
  read: boolean;
  /** DID of whoever caused this event. The notify bus has no per-client
   * delivery targeting — every connected client (admin + every browser
   * member) gets every event — so the client that originated it uses this
   * to skip showing itself its own notification. */
  actorDid?: string;
}

export interface AlertPrefs {
  high: boolean;
  medium: boolean;
  low: boolean;
}

export interface DevicePrefs {
  new_device: boolean;
  pending_approval: boolean;
  guardian_offline: boolean;
}

export interface CirclePrefs {
  new_message: boolean;
  incoming_call: boolean;
  member_joined: boolean;
}

export interface NotificationPrefs {
  alerts: AlertPrefs;
  devices: DevicePrefs;
  circles: CirclePrefs;
  sequence?: number;
}

/** Backend field casing for the event payload isn't pinned down in the docs; accept either. */
function pick(raw: Record<string, unknown>, ...keys: string[]): unknown {
  for (const key of keys) {
    if (raw[key] !== undefined && raw[key] !== null) return raw[key];
  }
  return undefined;
}

export function normalizeNotification(raw: unknown): NotificationItem {
  const r = (raw ?? {}) as Record<string, unknown>;
  return {
    id: String(pick(r, "id") ?? crypto.randomUUID()),
    kind: String(pick(r, "kind") ?? "AlertLow"),
    title: String(pick(r, "title") ?? "Notification"),
    body: String(pick(r, "body", "message") ?? ""),
    severity: String(pick(r, "severity") ?? "info"),
    refId: (pick(r, "ref_id", "refId") as string | undefined) ?? undefined,
    createdAt: String(pick(r, "created_at", "createdAt") ?? new Date().toISOString()),
    read: Boolean(pick(r, "read") ?? false),
    actorDid: (pick(r, "actor_did", "actorDid") as string | undefined) ?? undefined,
  };
}

function unwrapList(raw: unknown): unknown[] {
  if (Array.isArray(raw)) return raw;
  const r = raw as Record<string, unknown> | null;
  const nested = r?.notifications ?? r?.records ?? r?.items ?? r?.events;
  return Array.isArray(nested) ? nested : [];
}

export const notificationsApi = {
  history: async (): Promise<NotificationItem[]> => {
    const raw = await api<unknown>("/notifications");
    return unwrapList(raw).map(normalizeNotification);
  },
  unreadCount: () => api<{ unread: number }>("/notifications/unread-count"),
  markRead: (id: string) => api(`/notifications/${encodeURIComponent(id)}/read`, { method: "POST" }),
  markAllRead: () => api("/notifications/read-all", { method: "POST" }),
  getPrefs: () => api<NotificationPrefs>("/notifications/prefs"),
  putPrefs: (patch: Partial<NotificationPrefs>) =>
    api<NotificationPrefs>("/notifications/prefs", { method: "PUT", body: JSON.stringify(patch) }),
};

export interface NotificationStreamEvent {
  item: NotificationItem;
  eventId?: string;
}

/**
 * Reads GET /notifications/stream (SSE: "id: <n>\ndata: {...}\n\n" frames,
 * ":" heartbeat comments to hold the connection open). Resolves when the
 * stream ends or `signal` aborts; callers reconnect with the last seen
 * `eventId` as `Last-Event-ID` to replay missed events.
 */
export async function streamNotificationEvents(
  signal: AbortSignal,
  lastEventId: string | undefined,
  onEvent: (event: NotificationStreamEvent) => void,
): Promise<void> {
  const token = authToken();
  const headers: Record<string, string> = token ? { Authorization: `Bearer ${token}` } : {};
  if (lastEventId) headers["Last-Event-ID"] = lastEventId;

  const response = await fetch(apiUrl("/notifications/stream"), { headers, signal });
  if (!response.ok || !response.body) {
    if (response.status === 401) {
      window.dispatchEvent(new CustomEvent("sgx:unauthorized"));
    }
    const body: unknown = await response.json().catch(() => undefined);
    throw new ApiError(response.status, errorMessage(body, `Notification stream failed (${response.status})`));
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";

  while (!signal.aborted) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const frames = buffer.split("\n\n");
    buffer = frames.pop() ?? "";

    for (const frame of frames) {
      let id: string | undefined;
      let data = "";
      for (const line of frame.split("\n")) {
        if (line.startsWith("id:")) id = line.slice(3).trim();
        else if (line.startsWith("data:")) data += (data ? "\n" : "") + line.slice(5).trim();
      }
      if (!data) continue; // heartbeat-only frame
      try {
        const item = normalizeNotification(JSON.parse(data));
        onEvent({ item: id ? { ...item, id } : item, eventId: id ?? item.id });
      } catch {
        // Malformed frame; keep the connection alive.
      }
    }
  }
}
