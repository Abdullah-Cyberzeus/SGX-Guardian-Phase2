import api from './api';
import { guardianDisplayText } from '../utils/displayText';

// Guardian IDS/IPS (threat) — /api/v1/threat/* (Sprint, backend commit 1c8dd4c)

// ── Shared action envelope (mutations) ─────────────────────────────────────────
// Note: the threat action envelope uses camelCase `restartRequired`, unlike the
// discovery endpoints' snake_case fields.
export interface ThreatActionResponse {
  success: boolean;
  stdout: string;
  stderr: string;
  restartRequired: boolean;
  timestamp: string;
}

// ── Alerts (GET /threat/alerts) ────────────────────────────────────────────────

export type ThreatSeverity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type ThreatCategory =
  | 'malware'
  | 'exploit'
  | 'policy_violation'
  | 'reconnaissance'
  | 'anomaly'
  | 'other';

/** A parsed Guardian alert from the Guardian threat inventory. */
export interface ThreatAlert {
  /** Dedup id: SHA-256(sid || src_ip || dst_ip)[..16] hex. */
  alert_id: string;
  timestamp: string;
  src_ip: string;
  src_port: number;
  dst_ip: string;
  dst_port: number;
  protocol: string;
  signature_id: number;
  signature: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  rev: number;
  gid: number;
  event_type: string;
  blocked: boolean;
}

export interface ThreatAlertsFilters {
  /** default 500, max 10000 */
  limit?: number;
  /** case-insensitive: info | low | medium | high | critical */
  severity?: ThreatSeverity | string;
}

// ── Status (GET /threat/status) ────────────────────────────────────────────────

export interface ThreatStatus {
  /** Guardian threat service state: "active" | "inactive" | "unknown" */
  suricata: string;
  enabled: boolean;
  /** "alert_only" | "inline_block" */
  block_mode: string;
  alert_count: number;
  block_count: number;
}

// ── Blocks (GET/POST /threat/blocks, POST /threat/blocks/unblock) ──────────────

export interface ThreatBlocksResponse {
  blocked: string[];
}

// ── Config (GET/POST /threat/config) ───────────────────────────────────────────

export type ThreatBlockMode = 'alert_only' | 'inline_block';

export interface ThreatConfig {
  enabled: boolean;
  interface: string | null;
  eve_path: string;
  suricata_yaml: string;
  block_mode: ThreatBlockMode;
  /** seconds an auto-block lives before expiry */
  block_ttl_secs: number;
  /** CIDRs never auto-blocked */
  block_exempt: string[];
  /** rule auto-update cadence in hours; 0 = manual only */
  rule_update_hours: number;
}

/** Patch body for POST /threat/config — only supplied fields are applied. */
export interface ThreatConfigPatch {
  enabled?: boolean;
  block_mode?: ThreatBlockMode;
  rule_update_hours?: number;
  block_ttl_secs?: number;
  block_exempt?: string[];
}

// ── Service ────────────────────────────────────────────────────────────────────

function normalizeThreatAlert(alert: ThreatAlert): ThreatAlert {
  return {
    ...alert,
    protocol: guardianDisplayText(alert.protocol),
    signature: guardianDisplayText(alert.signature),
    event_type: guardianDisplayText(alert.event_type),
  };
}

export const threatService = {
  // GET /api/v1/threat/status — Guardian service state, block mode, counts
  getStatus: () => api.get<ThreatStatus>('/threat/status'),

  // GET /api/v1/threat/alerts — parsed Guardian alerts (404 until events exist)
  getAlerts: async (filters?: ThreatAlertsFilters) =>
    (await api.get<ThreatAlert[]>('/threat/alerts', filters as Record<string, string | number>)).map(normalizeThreatAlert),

  // GET /api/v1/threat/blocks — currently blocked IPs
  getBlocks: () => api.get<ThreatBlocksResponse>('/threat/blocks'),

  // POST /api/v1/threat/blocks — manually block an IP
  block: (ip: string) => api.post<ThreatActionResponse>('/threat/blocks', { ip }),

  // POST /api/v1/threat/blocks/unblock — remove one IP from the block list
  unblock: (ip: string) => api.post<ThreatActionResponse>('/threat/blocks/unblock', { ip }),

  // POST /api/v1/threat/rules/update — update Guardian rules + reload rules
  updateRules: () => api.post<ThreatActionResponse>('/threat/rules/update'),

  // POST /api/v1/threat/validate — validate Guardian threat config
  validate: () => api.post<ThreatActionResponse>('/threat/validate'),

  // GET /api/v1/threat/config — read current threat config
  getConfig: () => api.get<ThreatConfig>('/threat/config'),

  // POST /api/v1/threat/config — patch config (effective within ~5s)
  setConfig: (patch: ThreatConfigPatch) =>
    api.post<ThreatActionResponse>('/threat/config', patch),

  // POST /api/v1/threat/start — start Guardian threat service when offline
  start: () => api.post<ThreatActionResponse>('/threat/start'),
};

export default threatService;
