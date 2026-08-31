import api from './api';

// Guardian Network Discovery (Sprint 6, NMP-series) — /api/v1/discovery/*
const DISCOVERY_SCAN_TIMEOUT_MS = 10 * 60 * 1000;

// ── Device inventory (GET /discovery/devices) ──────────────────────────────────

export interface OpenPort {
  port: number;
  protocol: string;
  service: string;
  product_version: string;
  cpe: string[];
  scripts: unknown[];
}

/** A single discovered device record from the Guardian inventory. */
export interface ConnectedDevice {
  device_id: string;
  ip: string;
  mac: string;
  vendor: string;
  hostname: string;
  os_fingerprint: string;
  os_cpe: string[];
  open_ports: OpenPort[];
  host_scripts: unknown[];
  /** approved | unauthorized | drifted (and other backend-defined states) */
  status: string;
  first_seen: string;
  last_seen: string;
  vuln_triaged: boolean;
  /** Present only after a scan run records it: stealth | standard | aggressive */
  last_scan_intensity?: DiscoveryIntensity | null;
}

// ── Device detail (GET /discovery/devices/{device_id}) ─────────────────────────
// Full ConnectedDevice (flattened) plus computed risk classification.

export type RiskLevel = 'critical' | 'high' | 'medium' | 'low' | 'unknown';

export interface DeviceDetail extends ConnectedDevice {
  risk_level: RiskLevel;
  /** Human-readable reasons behind the risk classification. */
  risk_reasons: string[];
  /** Port numbers that triggered the risk classification. */
  flagged_ports: number[];
}

// ── Inventory summary (GET /discovery/summary) ─────────────────────────────────

export interface InventorySummary {
  total: number;
  approved: number;
  unauthorized: number;
  drifted: number;
  stale: number;
  devices_with_open_ports: number;
  total_open_ports: number;
  critical_devices: number;
  high_risk_devices: number;
  medium_risk_devices: number;
  low_risk_devices: number;
  unknown_risk_devices: number;
  /** RFC-3339 timestamp of the most recently seen device; null when no inventory. */
  last_seen_at: string | null;
}

// ── Scan (POST /discovery/scan[/intensity]) ────────────────────────────────────

export type DiscoveryIntensity = 'stealth' | 'standard' | 'aggressive';

export interface DiscoveryScanResponse {
  success: boolean;
  stdout: string;
  stderr: string;
  timestamp: string;
}

// ── Approve (POST /discovery/approve) ──────────────────────────────────────────

export interface ApproveDeviceRequest {
  mac: string;
  label?: string;
}

export interface WhitelistDevice {
  mac: string;
  label: string;
  expected_os: string | null;
  expected_ports: number[];
  expected_ips: string[];
}

export interface ApproveDeviceResponse {
  success: boolean;
  created: boolean;
  inventory_updated: number;
  entry: WhitelistDevice;
}

// ── Whitelist (GET/PUT /discovery/whitelist) ───────────────────────────────────

export interface WhitelistDoc {
  version: string;
  devices: WhitelistDevice[];
}

// ── Schedule (GET/PUT /discovery/schedule) ─────────────────────────────────────

export interface ScheduleEntry {
  intensity: string;
  days?: ScheduleDay[];
  time?: string;
}

export type ScheduleFrequency = 'once' | 'daily' | 'weekly' | 'monthly' | 'custom';

export interface ScanScheduleProfile {
  id: string;
  frequency: ScheduleFrequency;
  intensity: string;
  days?: ScheduleDay[];
  day_of_month?: number | null;
  time?: string;
  timezone?: string;
}

export type ScheduleDay =
  | 'monday'
  | 'tuesday'
  | 'wednesday'
  | 'thursday'
  | 'friday'
  | 'saturday'
  | 'sunday';

export interface DiscoverySchedule {
  enabled: boolean;
  /** null means the scheduler auto-detects the active LAN CIDR at runtime */
  target_cidr: string | null;
  timeout_secs: number;
  exclude: string[];
  scan_schedules: ScanScheduleProfile[];
  schedules: {
    hourly: ScheduleEntry;
    daily: ScheduleEntry;
  };
  /** Present only for legacy YAML files */
  legacy_schedule_mode?: string;
  /** Optional — populated when backend exposes next-run estimates. */
  next_run_hourly?: string;
  next_run_daily?: string;
}

// ── Discovery run history (GET /discovery/runs?view=history) ───────────────────
// We request the richer `view=history` mode. Two shapes are handled so the FE
// works before AND after the backend implements the persisted history store:
//   • Raw archive entry (current default): { timestamp, unix_ts, source } —
//     a scan-completion timestamp only, no intensity/trigger/counts.
//   • History record (once implemented): a per-run record carrying run id,
//     start/finish, intensity, trigger, status, and device deltas.
// `mapDiscoveryRun` duck-types each entry and fills whatever fields are present.

export type ScheduleRunTrigger = 'hourly' | 'daily' | 'manual' | 'scheduled';
export type ScheduleRunStatus = 'success' | 'failure' | 'running';

/** Raw archive entry (`view=raw`, and today's `view=history` fallback). */
export interface DiscoveryRunEntry {
  /** RFC-3339 UTC timestamp of when this scan completed. */
  timestamp: string;
  unix_ts: number;
  /** "raw_xml" when sourced from the forensic XML store. */
  source: string;
}

/**
 * Persisted per-run history record (`view=history`, once implemented). All
 * fields optional: the exact contract isn't finalized backend-side, so we
 * accept the documented/anticipated field names and normalize defensively.
 */
export interface DiscoveryHistoryRun {
  run_id?: string;
  started_at?: string;
  finished_at?: string | null;
  completed_at?: string | null;
  timestamp?: string;
  unix_ts?: number;
  /** "manual" | "scheduled" | "raw_xml" */
  source?: string;
  schedule_kind?: 'hourly' | 'daily' | null;
  trigger?: ScheduleRunTrigger;
  intensity?: DiscoveryIntensity;
  status?: ScheduleRunStatus;
  success?: boolean;
  error?: string | null;
  error_message?: string;
  total_devices?: number;
  devices_found?: number;
  new_devices?: number;
  devices_new?: number;
  unauthorized?: number;
  devices_flagged?: number;
}

type DiscoveryRunAny = DiscoveryRunEntry | DiscoveryHistoryRun;

/** Envelope returned by `GET /discovery/runs`. May also arrive as a bare array. */
export interface DiscoveryRunsResponse {
  runs: DiscoveryRunAny[];
  /** Current device count from inventory, for context. */
  total_in_inventory?: number;
}

/**
 * UI view-model for a discovery run. Timestamp-based fields are authoritative;
 * intensity/trigger/counts are optional — populated from the history record
 * when present, otherwise enriched client-side from the locally-stored
 * manual-scan record when the timestamps line up.
 */
export interface ScheduleRun {
  run_id: string;
  started_at: string;
  finished_at: string | null;
  status: ScheduleRunStatus;
  /** Origin, e.g. "raw_xml" | "manual" | "scheduled". */
  source?: string;
  intensity?: DiscoveryIntensity;
  trigger?: ScheduleRunTrigger;
  devices_found?: number;
  devices_new?: number;
  devices_flagged?: number;
  error_message?: string;
}

/**
 * Normalize any run entry (raw archive OR history record) into the ScheduleRun
 * view-model by reading whichever fields are present.
 */
export function mapDiscoveryRun(r: DiscoveryRunAny): ScheduleRun {
  const h = r as DiscoveryHistoryRun;
  const started =
    h.started_at ??
    h.timestamp ??
    (h.unix_ts != null ? new Date(h.unix_ts * 1000).toISOString() : '');
  // Raw archive entries are completed scans: completion == the single timestamp.
  const finished =
    h.finished_at ?? h.completed_at ?? (h.started_at ? null : (h.timestamp ?? started));
  // Trigger: explicit field wins; else derive from source/schedule_kind.
  const trigger: ScheduleRunTrigger | undefined =
    h.trigger ??
    (h.source === 'manual'
      ? 'manual'
      : h.source === 'scheduled'
        ? (h.schedule_kind ?? 'scheduled')
        : undefined);
  const status: ScheduleRunStatus =
    h.status ?? (h.success === false ? 'failure' : !finished ? 'running' : 'success');
  return {
    run_id: h.run_id ?? String(h.unix_ts ?? started),
    started_at: started,
    finished_at: finished ?? started,
    status,
    source: h.source,
    intensity: h.intensity,
    trigger,
    devices_found: h.devices_found ?? h.total_devices,
    devices_new: h.devices_new ?? h.new_devices,
    devices_flagged: h.devices_flagged ?? h.unauthorized,
    error_message: h.error_message ?? h.error ?? undefined,
  };
}

/** Append `?target=<value>` when a non-empty target IP/CIDR is provided. */
function withTarget(path: string, target?: string): string {
  const trimmed = target?.trim();
  return trimmed ? `${path}?target=${encodeURIComponent(trimmed)}` : path;
}

// ── Service ────────────────────────────────────────────────────────────────────

export const discoveryService = {
  // GET /api/v1/discovery/devices — full Guardian device inventory
  getDevices: () => api.get<ConnectedDevice[]>('/discovery/devices'),

  // GET /api/v1/discovery/devices/{device_id} — full device detail + risk data
  getDevice: (deviceId: string) =>
    api.get<DeviceDetail>(`/discovery/devices/${encodeURIComponent(deviceId)}`),

  // GET /api/v1/discovery/summary — aggregate inventory stats + risk buckets
  getSummary: () => api.get<InventorySummary>('/discovery/summary'),

  // GET /api/v1/discovery/list — alias of discovery inventory list
  getList: () => api.get<ConnectedDevice[]>('/discovery/list'),

  // GET /api/v1/discovery/inventory/list — alias of discovery inventory list
  getInventoryList: () => api.get<ConnectedDevice[]>('/discovery/inventory/list'),

  // GET /api/v1/discovery/devices/unauthorized — unauthorized or drifted devices
  getUnauthorized: () => api.get<ConnectedDevice[]>('/discovery/devices/unauthorized'),

  // GET /api/v1/discovery/unauthorized — alias of unauthorized discovery list
  getUnauthorizedAlias: () => api.get<ConnectedDevice[]>('/discovery/unauthorized'),

  // POST /api/v1/discovery/scan — run scan using default ad-hoc intensity
  scan: (target?: string) =>
    api.request<DiscoveryScanResponse>(withTarget('/discovery/scan', target), {
      method: 'POST',
      timeoutMs: DISCOVERY_SCAN_TIMEOUT_MS,
    }),

  // POST /api/v1/discovery/scan/stealth
  scanStealth: (target?: string) =>
    api.request<DiscoveryScanResponse>(withTarget('/discovery/scan/stealth', target), {
      method: 'POST',
      timeoutMs: DISCOVERY_SCAN_TIMEOUT_MS,
    }),

  // POST /api/v1/discovery/scan/standard
  scanStandard: (target?: string) =>
    api.request<DiscoveryScanResponse>(withTarget('/discovery/scan/standard', target), {
      method: 'POST',
      timeoutMs: DISCOVERY_SCAN_TIMEOUT_MS,
    }),

  // POST /api/v1/discovery/scan/aggressive
  scanAggressive: (target?: string) =>
    api.request<DiscoveryScanResponse>(withTarget('/discovery/scan/aggressive', target), {
      method: 'POST',
      timeoutMs: DISCOVERY_SCAN_TIMEOUT_MS,
    }),

  /** Convenience dispatcher: run a scan at an explicit intensity (with an
   *  optional target IP/CIDR override), or the configured default. */
  runScan: (intensity?: DiscoveryIntensity, target?: string) => {
    switch (intensity) {
      case 'stealth':
        return discoveryService.scanStealth(target);
      case 'standard':
        return discoveryService.scanStandard(target);
      case 'aggressive':
        return discoveryService.scanAggressive(target);
      default:
        return discoveryService.scan(target);
    }
  },

  // POST /api/v1/discovery/approve — authorize a discovered device by MAC
  approve: (req: ApproveDeviceRequest) =>
    api.post<ApproveDeviceResponse>('/discovery/approve', req),

  // GET /api/v1/discovery/whitelist — whitelist YAML content as JSON
  getWhitelist: () => api.get<WhitelistDoc>('/discovery/whitelist'),

  // PUT /api/v1/discovery/whitelist — replace whitelist + refresh inventory
  putWhitelist: (doc: WhitelistDoc) =>
    api.put<WhitelistDoc>('/discovery/whitelist', doc),

  // GET /api/v1/discovery/schedule — scheduled Guardian discovery configuration
  getSchedule: () => api.get<DiscoverySchedule>('/discovery/schedule'),

  // PUT /api/v1/discovery/schedule — update scheduled discovery configuration
  putSchedule: (cfg: Partial<DiscoverySchedule>) =>
    api.put<DiscoverySchedule>('/discovery/schedule', cfg),

  // GET /api/v1/discovery/runs?view=history — persisted scan run history,
  // newest-first. Accepts either the { runs, total_in_inventory } envelope or a
  // bare array, and maps each entry (raw archive or history record) to the
  // ScheduleRun view-model the UI consumes.
  getScheduleRuns: () =>
    api
      .get<DiscoveryRunsResponse | DiscoveryRunAny[]>('/discovery/runs?view=history')
      .then((res) => {
        const list = Array.isArray(res) ? res : Array.isArray(res?.runs) ? res.runs : [];
        return list.map(mapDiscoveryRun);
      }),
};

export default discoveryService;
