// P1.7: exposes this Guardian's enrollment lifecycle (GET/WS /api/v1/mesh/lifecycle)
// to the rest of the app. `SYS02SplashScreen` uses it to route an authenticated
// but not-yet-ONLINE session to `/setup`, and `ProtectedRoute` listens for the
// `sgx:mesh-not-enrolled` event (dispatched by `services/api.ts` on a 409 from
// any mesh-gated route) to redirect there mid-session too.
//
// Poll **and** push, deliberately: the WebSocket pushes transitions
// immediately, but a poll keeps working even if the socket never connects (a
// captive-portal-ish LAN, a proxy that strips Upgrade headers) or silently
// drops without a close event — the same reasoning `chatService.ts`'s
// heartbeat/watchdog uses, just simpler, since lifecycle changes are rare and
// nothing here needs sub-second latency.
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "../services/api";
import { useAuth } from "./AuthContext";

export type LifecycleState =
  | "BOOT"
  | "INITIALIZING"
  | "UNENROLLED"
  | "CREATING_CIRCLE"
  | "DISCOVERING_CA"
  | "WAITING_FOR_CA_SELECTION"
  | "CONNECTING_TO_REMOTE_CA"
  | "ENROLLING"
  | "PENDING_APPROVAL"
  | "CERTIFICATE_RECEIVED"
  | "CERTIFICATE_VALIDATED"
  | "CIRCLE_MEMBER"
  | "ONLINE"
  | "REJECTED"
  | "ERROR";

export interface LifecycleProfileView {
  circleName: string;
  role: string;
  caFingerprint: string;
  overlayIp: string;
}

export interface LifecycleView {
  state: LifecycleState;
  since: string;
  detail?: string | null;
  profile?: LifecycleProfileView | null;
}

interface RawLifecycleProfile {
  circle_name: string;
  role: string;
  ca_fingerprint: string;
  overlay_ip: string;
}

interface RawLifecycleView {
  state: LifecycleState;
  since: string;
  detail?: string | null;
  profile?: RawLifecycleProfile | null;
}

function fromRaw(raw: RawLifecycleView): LifecycleView {
  return {
    state: raw.state,
    since: raw.since,
    detail: raw.detail ?? null,
    profile: raw.profile
      ? {
          circleName: raw.profile.circle_name,
          role: raw.profile.role,
          caFingerprint: raw.profile.ca_fingerprint,
          overlayIp: raw.profile.overlay_ip,
        }
      : null,
  };
}

export const TERMINAL_FAILURE_STATES: ReadonlySet<LifecycleState> = new Set(["ERROR", "REJECTED"]);

export function isOnline(state: LifecycleState | undefined | null): boolean {
  return state === "ONLINE";
}

interface MeshLifecycleContextValue {
  /** `null` until the first successful fetch resolves. */
  lifecycle: LifecycleView | null;
  /** True only for the very first fetch — later poll/WS updates never toggle it. */
  loading: boolean;
  /** Forces an immediate re-fetch, e.g. after the operator clicks Retry. */
  refresh: () => void;
}

const MeshLifecycleContext = createContext<MeshLifecycleContextValue | null>(null);

const POLL_INTERVAL_MS = 5_000;

export function MeshLifecycleProvider({ children }: { children: ReactNode }) {
  const { session } = useAuth();
  const [lifecycle, setLifecycle] = useState<LifecycleView | null>(null);
  const [loading, setLoading] = useState(true);
  const socketRef = useRef<WebSocket | null>(null);
  const reconnectTimerRef = useRef<number | undefined>(undefined);
  const pollTimerRef = useRef<number | undefined>(undefined);
  const stoppedRef = useRef(false);
  const hasSessionRef = useRef(false);

  const fetchOnce = async (): Promise<void> => {
    try {
      const raw = await api.request<RawLifecycleView>("/mesh/lifecycle");
      if (stoppedRef.current) return;
      setLifecycle(fromRaw(raw));
    } catch {
      // A fetch failure (Guardian briefly unreachable, a stale token) is not
      // fatal here — the poll timer and/or WS reconnect will retry. Leaving
      // `lifecycle` as its last-known value avoids flashing an error state on
      // every transient network hiccup.
    } finally {
      if (!stoppedRef.current) setLoading(false);
    }
  };

  useEffect(() => {
    hasSessionRef.current = Boolean(session);
  }, [session]);

  useEffect(() => {
    stoppedRef.current = false;

    if (!session) {
      // No session yet (fresh splash screen, logged out): nothing to poll —
      // `SYS02SplashScreen` does not need lifecycle state until a session
      // exists, per the plan's own routing rule ("no admin → onboarding").
      setLoading(false);
      return () => {
        stoppedRef.current = true;
      };
    }

    void fetchOnce();

    const connectSocket = () => {
      if (stoppedRef.current) return;
      const token = api.getToken();
      if (!token) return;
      const endpoint = new URL(api.publicUrl("/mesh/lifecycle/ws"));
      endpoint.protocol = endpoint.protocol === "https:" ? "wss:" : "ws:";
      endpoint.searchParams.set("access_token", token);
      const socket = new WebSocket(endpoint);
      socketRef.current = socket;

      socket.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data as string);
          if (payload?.type === "mesh.lifecycle.snapshot" && payload.lifecycle) {
            setLifecycle(fromRaw(payload.lifecycle as RawLifecycleView));
            setLoading(false);
          }
        } catch {
          // Malformed frame — ignore it, the next poll tick recovers.
        }
      };
      socket.onclose = () => {
        if (stoppedRef.current) return;
        reconnectTimerRef.current = window.setTimeout(connectSocket, 3_000);
      };
      socket.onerror = () => {
        socket.close();
      };
    };
    connectSocket();

    pollTimerRef.current = window.setInterval(() => void fetchOnce(), POLL_INTERVAL_MS);

    return () => {
      stoppedRef.current = true;
      socketRef.current?.close();
      socketRef.current = null;
      if (reconnectTimerRef.current) window.clearTimeout(reconnectTimerRef.current);
      if (pollTimerRef.current) window.clearInterval(pollTimerRef.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [session]);

  return (
    <MeshLifecycleContext.Provider
      value={{ lifecycle, loading, refresh: () => void fetchOnce() }}
    >
      {children}
    </MeshLifecycleContext.Provider>
  );
}

export function useMeshLifecycle() {
  const ctx = useContext(MeshLifecycleContext);
  if (!ctx) {
    throw new Error("useMeshLifecycle must be used within a MeshLifecycleProvider");
  }
  return ctx;
}
