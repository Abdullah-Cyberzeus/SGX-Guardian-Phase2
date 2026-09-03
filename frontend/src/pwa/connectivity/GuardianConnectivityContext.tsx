import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import api, { type ApiFailureKind } from "../../app/services/api";
import { cachedOfflineModeEnabled, useAuth } from "../../app/contexts/AuthContext";
import { pendingOperationCount } from "../sync/pendingReplay";
import { syncCoordinator } from "../sync/syncCoordinator";
import { syncStateRepository } from "../db/syncStateRepository";
import { purgeAndShowBrowserOffline } from "../offlineCleanup";

type ConnectivityStatus = "guardian_connected" | "reconnecting" | "guardian_offline" | "credential_revoked";

interface ConnectivityState {
  reachable: boolean;
  checking: boolean;
  reconnecting: boolean;
  revoked: boolean;
  status: ConnectivityStatus;
  lastSeen?: number;
  pendingCount: number;
  syncRunning: boolean;
  checkNow: () => Promise<void>;
  retryNow: () => Promise<void>;
}

const LAST_SEEN_KEY = "last_guardian_seen_at";
const BASE_DELAY_MS = 3_000;
const MAX_DELAY_MS = 60_000;
const HEALTH_PROBE_TIMEOUT_MS = 8_000;
const OFFLINE_FAILURE_THRESHOLD = 2;

const Context = createContext<ConnectivityState>({
  reachable: true,
  checking: true,
  reconnecting: false,
  revoked: false,
  status: "reconnecting",
  pendingCount: 0,
  syncRunning: false,
  checkNow: async () => {},
  retryNow: async () => {},
});

function delayWithJitter(failures: number) {
  const capped = Math.min(MAX_DELAY_MS, BASE_DELAY_MS * 2 ** Math.max(0, failures - 1));
  return Math.round(capped * (0.75 + Math.random() * 0.5));
}

function timeoutSignal(ms: number) {
  if ("timeout" in AbortSignal) return AbortSignal.timeout(ms);
  const controller = new AbortController();
  window.setTimeout(() => controller.abort(), ms);
  return controller.signal;
}

async function guardianHealthProbe() {
  // Reachability must answer only one question: is this Guardian's HTTP API alive?
  // Using the authenticated PWA endpoint made an expired/refreshing token, a slow
  // authorization lookup, or a CORS preflight look exactly like a dead node.
  const response = await fetch(api.publicUrl("/health"), {
    cache: "no-store",
    signal: timeoutSignal(HEALTH_PROBE_TIMEOUT_MS),
  });
  if (!response.ok) throw new Error("guardian health check failed");
}

export function GuardianConnectivityProvider({ children }: { children: ReactNode }) {
  const { session, forceSignOut } = useAuth();
  const [reachable, setReachable] = useState(true);
  const [checking, setChecking] = useState(true);
  const [revoked, setRevoked] = useState(false);
  const [lastSeen, setLastSeen] = useState<number | undefined>();
  const [pendingCount, setPendingCount] = useState(0);
  const [syncRunning, setSyncRunning] = useState(false);
  const failures = useRef(0);
  const wasReachable = useRef(true);
  const startupSyncQueued = useRef(false);
  const reachableRef = useRef(reachable);
  reachableRef.current = reachable;

  const refreshPendingCount = useCallback(async () => {
    setPendingCount(await pendingOperationCount().catch(() => 0));
  }, []);

  const markConnected = useCallback(async (triggerSync: boolean) => {
    failures.current = 0;
    setReachable(true);
    setRevoked(false);
    const now = Date.now();
    setLastSeen(now);
    await syncStateRepository.save({ key: LAST_SEEN_KEY, lastSuccessfulSync: now, value: now }).catch(() => {});
    await refreshPendingCount();
    const shouldSync = api.getToken() && (triggerSync || !startupSyncQueued.current);
    if (shouldSync) {
      const syncTrigger = startupSyncQueued.current ? "health_recovered" : "startup";
      startupSyncQueued.current = true;
      syncCoordinator.run(syncTrigger).catch(() => undefined).finally(() => void refreshPendingCount());
    }
  }, [refreshPendingCount]);

  const markOffline = useCallback((options: { forceSignOut?: boolean; purgeBrowserState?: boolean } = {}) => {
    failures.current += 1;
    // A single request or radio/network transition is not enough evidence to
    // declare the whole Guardian offline. The next scheduled probe confirms it.
    if (failures.current < OFFLINE_FAILURE_THRESHOLD) return;
    setReachable(false);
    if (options.forceSignOut && session && !cachedOfflineModeEnabled()) {
      void forceSignOut("Guardian node is offline. Please sign in again when it is reachable.");
    }
    if (options.purgeBrowserState && !cachedOfflineModeEnabled()) {
      void purgeAndShowBrowserOffline();
    }
  }, [forceSignOut, session]);

  const checkNow = useCallback(async () => {
    if (revoked) return;
    setChecking(true);
    try {
      await guardianHealthProbe();
      const recovered = !wasReachable.current;
      wasReachable.current = true;
      await markConnected(recovered);
    } catch (error) {
      if (error instanceof Error && error.message === "credential_revoked") {
        setRevoked(true);
        setReachable(false);
        window.dispatchEvent(new CustomEvent("sgx:unauthorized"));
      } else {
        wasReachable.current = false;
        markOffline({ forceSignOut: true, purgeBrowserState: true });
      }
    } finally {
      setChecking(false);
    }
  }, [markConnected, markOffline, revoked]);

  const retryNow = useCallback(async () => {
    failures.current = 0;
    await checkNow();
    if (api.getToken() && !syncCoordinator.isRunning()) {
      await syncCoordinator.run("manual").catch(() => undefined);
      await refreshPendingCount();
    }
  }, [checkNow, refreshPendingCount]);

  // checkNow/retryNow are read through refs so the polling loop below can be
  // armed exactly once at mount and keep ticking on its own schedule,
  // instead of being torn down and rebuilt (losing its pending timer) every
  // time an unrelated re-render hands it a new callback identity. That
  // used to make the periodic offline check unreliable while the tab sat
  // idle - only an explicit visibilitychange/focus/refresh reliably
  // detected a stopped Guardian node.
  const checkNowRef = useRef(checkNow);
  checkNowRef.current = checkNow;
  const retryNowRef = useRef(retryNow);
  retryNowRef.current = retryNow;

  useEffect(() => {
    syncStateRepository.get(LAST_SEEN_KEY)
      .then((record) => {
        const value = typeof record?.value === "number" ? record.value : record?.lastSuccessfulSync;
        if (value) setLastSeen(value);
      })
      .catch(() => {});
    void refreshPendingCount();
  }, [refreshPendingCount]);

  useEffect(() => {
    let cancelled = false;
    let timeoutId: number | undefined;

    const runCheck = () => {
      if (cancelled) return;
      void checkNowRef.current().finally(() => {
        if (cancelled) return;
        const delay = reachableRef.current ? BASE_DELAY_MS : delayWithJitter(failures.current);
        timeoutId = window.setTimeout(runCheck, delay);
      });
    };

    runCheck();

    const foreground = () => {
      if (document.visibilityState === "visible") void retryNowRef.current();
    };
    const backOnline = () => void retryNowRef.current();
    document.addEventListener("visibilitychange", foreground);
    window.addEventListener("focus", foreground);
    window.addEventListener("online", backOnline);
    return () => {
      cancelled = true;
      if (timeoutId) window.clearTimeout(timeoutId);
      document.removeEventListener("visibilitychange", foreground);
      window.removeEventListener("focus", foreground);
      window.removeEventListener("online", backOnline);
    };
  }, []);

  useEffect(() => {
    const memberSessionActive = () =>
      (session?.user.role?.toLowerCase() === "member" && Boolean(api.getToken()))
      || Boolean(sessionStorage.getItem("sgx_auth_token"));
    const success = () => void markConnected(false);
    const failure = (event: Event) => {
      const kind = (event as CustomEvent<{ kind?: ApiFailureKind }>).detail?.kind;
      // Endpoint-specific failures (for example a slow cloud-device command)
      // must not directly mark the Guardian offline. Confirm with /health.
      if (kind === "guardian_unreachable" || kind === "timeout") void checkNowRef.current();
      if (kind === "unauthorized") {
        if (memberSessionActive()) return;
        setRevoked(true);
        setReachable(false);
      }
    };
    const socket = (event: Event) => {
      const connected = Boolean((event as CustomEvent<{ connected?: boolean }>).detail?.connected);
      if (connected) void markConnected(true);
      // A feature socket can reconnect while the Guardian HTTP API remains
      // healthy, so verify node reachability instead of taking the socket as
      // proof that the entire Guardian is down.
      else void checkNowRef.current();
    };
    const syncState = (event: Event) => {
      setSyncRunning(Boolean((event as CustomEvent<{ running?: boolean }>).detail?.running));
      void refreshPendingCount();
    };
    const revokedEvent = () => {
      if (memberSessionActive()) return;
      setRevoked(true);
      setReachable(false);
    };

    window.addEventListener("sgx:api-success", success);
    window.addEventListener("sgx:api-failure", failure);
    window.addEventListener("sgx:socket-state", socket);
    window.addEventListener("sgx:sync-state", syncState);
    window.addEventListener("sgx:pending-operation", syncState);
    window.addEventListener("sgx:sync-revoked", revokedEvent);
    window.addEventListener("sgx:unauthorized", revokedEvent);
    return () => {
      window.removeEventListener("sgx:api-success", success);
      window.removeEventListener("sgx:api-failure", failure);
      window.removeEventListener("sgx:socket-state", socket);
      window.removeEventListener("sgx:sync-state", syncState);
      window.removeEventListener("sgx:pending-operation", syncState);
      window.removeEventListener("sgx:sync-revoked", revokedEvent);
      window.removeEventListener("sgx:unauthorized", revokedEvent);
    };
  }, [markConnected, refreshPendingCount, session]);

  const status: ConnectivityStatus = revoked
    ? "credential_revoked"
    : reachable
      ? "guardian_connected"
      : checking
        ? "reconnecting"
        : "guardian_offline";

  const value = useMemo(
    () => ({
      reachable,
      checking,
      reconnecting: !reachable && checking,
      revoked,
      status,
      lastSeen,
      pendingCount,
      syncRunning,
      checkNow,
      retryNow,
    }),
    [reachable, checking, revoked, status, lastSeen, pendingCount, syncRunning, checkNow, retryNow],
  );

  return <Context.Provider value={value}>{children}</Context.Provider>;
}

export const useGuardianConnectivity = () => useContext(Context);
