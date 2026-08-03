import { useSyncExternalStore } from "react";
import { toast } from "sonner";
import { discoveryService } from "../services/discoveryService";
import type { DiscoveryIntensity } from "../services/discoveryService";

/**
 * Module-level store for the in-flight discovery scan.
 *
 * The scan is triggered from the frontend but the backend exposes no
 * "is a scan running" endpoint, so the running state lives only in the client.
 * If that state lived inside the NW07Discovery component it would be destroyed
 * whenever the component unmounts — e.g. switching between Settings panels,
 * where the right pane swaps `<NW07Discovery/>` for another screen. Hoisting it
 * to module scope keeps the scan (banner, elapsed timer, button-disabled state,
 * completion toast, last-run record) alive across any navigation, and completes
 * correctly even if no Discovery component is mounted when the scan finishes.
 */

export type ScanKey = "default" | DiscoveryIntensity;

export interface ScanRun {
  key: ScanKey;
  label: string;
  startedAt: number; // epoch ms
  endedAt?: number; // epoch ms
  result?: "success" | "error";
  message?: string;
  target?: string;
}

/** Persisted record of the last scan triggered from this console. */
export interface LastRunRecord {
  key: ScanKey;
  label: string;
  at: number; // epoch ms
}

const LAST_RUN_STORAGE_KEY = "sgx.discovery.lastRun";

export function loadLastRun(): LastRunRecord | null {
  try {
    const raw = localStorage.getItem(LAST_RUN_STORAGE_KEY);
    return raw ? (JSON.parse(raw) as LastRunRecord) : null;
  } catch {
    return null;
  }
}

function saveLastRun(rec: LastRunRecord) {
  try {
    localStorage.setItem(LAST_RUN_STORAGE_KEY, JSON.stringify(rec));
  } catch {
    /* storage unavailable — non-fatal */
  }
}

/** How long the completed/failed banner lingers before auto-dismissing. */
const DISMISS_MS = 15000;

interface ScanState {
  run: ScanRun | null;
  lastRun: LastRunRecord | null;
  /** Bumped to Date.now() each time a scan finishes, so mounted screens can
   *  refetch inventory/summary/runs in response. */
  completedAt: number;
}

// A single immutable snapshot object; replaced (never mutated) on every change
// so useSyncExternalStore sees a new reference only when something changed.
let state: ScanState = { run: null, lastRun: loadLastRun(), completedAt: 0 };

const listeners = new Set<() => void>();
let dismissTimer: ReturnType<typeof setTimeout> | null = null;

function setState(patch: Partial<ScanState>) {
  state = { ...state, ...patch };
  for (const l of listeners) l();
}

function subscribe(cb: () => void): () => void {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

function getSnapshot(): ScanState {
  return state;
}

/** True while a scan is in flight (has started but not ended). */
export function isScanRunning(): boolean {
  return !!state.run && state.run.endedAt === undefined;
}

function finish(patch: Partial<ScanRun>, newLastRun?: LastRunRecord) {
  setState({
    run: state.run ? { ...state.run, endedAt: Date.now(), ...patch } : state.run,
    lastRun: newLastRun ?? state.lastRun,
    completedAt: Date.now(),
  });
  if (dismissTimer) clearTimeout(dismissTimer);
  dismissTimer = setTimeout(() => setState({ run: null }), DISMISS_MS);
}

/**
 * Kick off a discovery scan. No-op if one is already running. The returned
 * promise resolves when the scan settles, but callers can ignore it — the store
 * drives all UI updates regardless of who (if anyone) is listening.
 */
export async function startScan(key: ScanKey, label: string, target?: string): Promise<void> {
  if (isScanRunning()) return;
  if (dismissTimer) {
    clearTimeout(dismissTimer);
    dismissTimer = null;
  }
  setState({ run: { key, label, startedAt: Date.now(), target } });

  try {
    const result = await discoveryService.runScan(key === "default" ? undefined : key, target);
    const summary = (result.stdout || "").split("\n").find((l) => l.trim()) ?? "";
    if (result.success) {
      const rec: LastRunRecord = { key, label, at: Date.now() };
      saveLastRun(rec);
      toast.success("Discovery scan completed", { description: summary || undefined });
      finish({ result: "success", message: summary }, rec);
    } else {
      const msg = result.stderr || summary;
      toast.error("Scan reported a failure", { description: msg || undefined });
      finish({ result: "error", message: msg });
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : undefined;
    toast.error("Scan failed", { description: msg });
    finish({ result: "error", message: msg });
  }
}

export interface UseDiscoveryScan {
  /** Current or most-recently-finished scan (null once auto-dismissed). */
  run: ScanRun | null;
  /** The scan key while running, else null — for disabling scan buttons. */
  scanning: ScanKey | null;
  /** Last scan triggered from this console (survives reloads via localStorage). */
  lastRun: LastRunRecord | null;
  /** Timestamp of the last completed scan; changes signal "refetch now". */
  completedAt: number;
  /** Start a scan (ignored if one is already running). */
  startScan: (key: ScanKey, label: string, target?: string) => Promise<void>;
}

/** Subscribe to the shared discovery-scan state. */
export function useDiscoveryScan(): UseDiscoveryScan {
  const snap = useSyncExternalStore(subscribe, getSnapshot);
  const scanning = snap.run && snap.run.endedAt === undefined ? snap.run.key : null;
  return {
    run: snap.run,
    scanning,
    lastRun: snap.lastRun,
    completedAt: snap.completedAt,
    startScan,
  };
}
