import api from './api';

export type AuditCategory =
  | 'Node' | 'Identity' | 'Did' | 'Vc' | 'Crl' | 'Attestation' | 'Policy'
  | 'Enforcement' | 'Network' | 'Tls' | 'Cryptography' | 'Cloud' | 'Discovery'
  | 'Geofence' | 'Vault' | 'Xfer' | 'Notify' | 'Circle' | 'Rules' | 'Dusage'
  | string;

export type AuditSeverity = 'Info' | 'Warning' | 'Critical' | string;

export type AuditAction =
  | 'Started' | 'Succeeded' | 'Failed' | 'Rejected' | 'Applied' | 'Revoked'
  | 'Rollback' | 'Created' | 'Loaded' | 'Exported' | 'Used' | 'Queued'
  | 'Detected' | 'Blocked' | 'Updated'
  | string;

export interface AuditEvent {
  timestamp: number; // unix seconds
  node_id: string;
  category: AuditCategory;
  severity: AuditSeverity;
  action: AuditAction;
  message: string;
}

export interface AuditLogEntry {
  event: AuditEvent;
  hash: string;
  previous_hash: string;
}

export interface AuditLogsFilters {
  category?: string;
  search?: string;
  node?: string;
  severity?: string;
  tail?: number;
}

export interface AuditLogsResponse {
  status: string;
  count: number;
  items: AuditLogEntry[];
}

export const auditLogService = {
  // GET /api/v1/audit/logs
  getAuditLogs: (filters?: AuditLogsFilters) =>
    api.get<AuditLogsResponse>('/audit/logs', filters as Record<string, string | number>),
};

export default auditLogService;
