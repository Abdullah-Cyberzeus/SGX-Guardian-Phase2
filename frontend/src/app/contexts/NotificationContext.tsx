import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { useAuth } from "./AuthContext";
import {
  notificationsApi,
  streamNotificationEvents,
  type NotificationItem,
  type NotificationPrefs,
} from "../../api/notifications";

const LAST_ID_KEY = "sgx_notify_last_id";
const MAX_ITEMS = 150;
const MAX_TOASTS = 4;
const RECONNECT_DELAY_MS = 4000;

export interface NotificationToast extends NotificationItem {
  toastId: string;
}

interface NotificationContextValue {
  items: NotificationItem[];
  unreadCount: number;
  prefs: NotificationPrefs | null;
  connected: boolean;
  toasts: NotificationToast[];
  refresh: () => Promise<void>;
  markRead: (id: string) => Promise<void>;
  markAllRead: () => Promise<void>;
  updatePrefs: (patch: Partial<NotificationPrefs>) => Promise<void>;
  dismissToast: (toastId: string) => void;
}

const Context = createContext<NotificationContextValue | null>(null);

function mergePrefs(prev: NotificationPrefs, patch: Partial<NotificationPrefs>): NotificationPrefs {
  return {
    ...prev,
    ...patch,
    alerts: { ...prev.alerts, ...(patch.alerts ?? {}) },
    devices: { ...prev.devices, ...(patch.devices ?? {}) },
    circles: { ...prev.circles, ...(patch.circles ?? {}) },
  };
}

/** Client-side enforcement in addition to the backend's preference filtering. */
export function notificationEnabled(prefs: NotificationPrefs | null, kind: string): boolean {
  if (!prefs) return true;
  switch (kind) {
    case "AlertHigh": return prefs.alerts.high;
    case "AlertMedium": return prefs.alerts.medium;
    case "AlertLow": return prefs.alerts.low;
    case "DeviceDiscovered": return prefs.devices.new_device;
    case "DevicePendingApproval": return prefs.devices.pending_approval;
    case "GuardianOffline": return prefs.devices.guardian_offline;
    case "CircleNewMessage":
    case "CircleFileShared": return prefs.circles.new_message;
    case "CircleIncomingCall": return prefs.circles.incoming_call;
    case "CircleMemberJoined": return prefs.circles.member_joined;
    default: return true;
  }
}

export function NotificationProvider({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  const [items, setItems] = useState<NotificationItem[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const [prefs, setPrefs] = useState<NotificationPrefs | null>(null);
  const [connected, setConnected] = useState(false);
  const [toasts, setToasts] = useState<NotificationToast[]>([]);
  const lastEventId = useRef<string | undefined>(localStorage.getItem(LAST_ID_KEY) ?? undefined);

  const refresh = useCallback(async () => {
    const [history, unread, currentPrefs] = await Promise.all([
      notificationsApi.history().catch(() => [] as NotificationItem[]),
      notificationsApi.unreadCount().catch(() => ({ unread: 0 })),
      notificationsApi.getPrefs().catch(() => null),
    ]);
    setItems(history.slice(0, MAX_ITEMS));
    setUnreadCount(unread.unread ?? 0);
    if (currentPrefs) setPrefs(currentPrefs);
  }, []);

  // Initial hydrate (and reset) whenever auth state changes.
  useEffect(() => {
    if (!session) {
      setItems([]);
      setUnreadCount(0);
      setPrefs(null);
      setConnected(false);
      setToasts([]);
      return;
    }
    refresh().catch(() => undefined);
  }, [session, refresh]);

  const pushToast = useCallback((item: NotificationItem) => {
    if (!notificationEnabled(prefs, item.kind)) return;
    const toastId = `${item.id}-${Date.now()}`;
    setToasts((prev) => [{ ...item, toastId }, ...prev].slice(0, MAX_TOASTS));
  }, [prefs]);

  // Immediately remove visible toasts when their preference is switched off.
  useEffect(() => {
    if (!prefs) return;
    setToasts((prev) => prev.filter((item) => notificationEnabled(prefs, item.kind)));
  }, [prefs]);

  const dismissToast = useCallback((toastId: string) => {
    setToasts((prev) => prev.filter((t) => t.toastId !== toastId));
  }, []);

  // Live SSE subscription — reconnects with backoff, resuming from the last
  // seen event id so a refresh/reconnect never drops a notification.
  useEffect(() => {
    if (!session) return;
    const abort = new AbortController();
    let retryTimer: number | undefined;
    let cancelled = false;

    const connect = () => {
      streamNotificationEvents(abort.signal, lastEventId.current, ({ item, eventId }) => {
        setConnected(true);
        if (eventId) {
          lastEventId.current = eventId;
          localStorage.setItem(LAST_ID_KEY, eventId);
        }
        if (!notificationEnabled(prefs, item.kind)) return;
        setItems((prev) => (prev.some((n) => n.id === item.id) ? prev : [item, ...prev].slice(0, MAX_ITEMS)));
        if (!item.read) setUnreadCount((c) => c + 1);
        pushToast(item);
      })
        .catch(() => undefined)
        .finally(() => {
          setConnected(false);
          if (!cancelled) retryTimer = window.setTimeout(connect, RECONNECT_DELAY_MS);
        });
    };
    connect();

    return () => {
      cancelled = true;
      abort.abort();
      if (retryTimer) window.clearTimeout(retryTimer);
    };
  }, [session, prefs, pushToast]);

  const markRead = useCallback(async (id: string) => {
    let wasUnread = false;
    setItems((prev) =>
      prev.map((n) => {
        if (n.id !== id) return n;
        wasUnread = !n.read;
        return { ...n, read: true };
      }),
    );
    if (wasUnread) setUnreadCount((c) => Math.max(0, c - 1));
    try {
      await notificationsApi.markRead(id);
    } catch {
      // Best-effort; the next refresh() reconciles server truth.
    }
  }, []);

  const markAllRead = useCallback(async () => {
    setItems((prev) => prev.map((n) => ({ ...n, read: true })));
    setUnreadCount(0);
    try {
      await notificationsApi.markAllRead();
    } catch {
      // Best-effort; the next refresh() reconciles server truth.
    }
  }, []);

  const updatePrefs = useCallback(async (patch: Partial<NotificationPrefs>) => {
    setPrefs((prev) => (prev ? mergePrefs(prev, patch) : prev));
    const next = await notificationsApi.putPrefs(patch);
    setPrefs(next);
  }, []);

  const value = useMemo<NotificationContextValue>(
    () => ({ items, unreadCount, prefs, connected, toasts, refresh, markRead, markAllRead, updatePrefs, dismissToast }),
    [items, unreadCount, prefs, connected, toasts, refresh, markRead, markAllRead, updatePrefs, dismissToast],
  );

  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export function useNotifications() {
  const ctx = useContext(Context);
  if (!ctx) throw new Error("useNotifications must be used within NotificationProvider");
  return ctx;
}
