import api from './api';

export interface Alert {
  id: string;
  severity: 'HIGH' | 'MEDIUM' | 'LOW';
  status: 'Active' | 'Acknowledged' | 'Blocked';
  title: string;
  description: string;
  eventType: string;
  timestamp: string;
  date: string;
  device: string;
  deviceIp: string;
  os: string;
  aiSummary: string;
  archived: boolean;
  rawTimestamp?: string;
  srcIp?: string;
  srcPort?: number;
  dstIp?: string;
  dstPort?: number;
  protocol?: string;
  signatureId?: number;
  signature?: string;
  category?: string;
  blocked?: boolean;
  originalEvidence?: string;
}

export interface AlertsResponse {
  alerts: Alert[];
  total: number;
  unread: number;
  timestamp: string;
}

export interface AlertFilters {
  severity?: string;
  status?: string;
  limit?: number;
}

export interface AlertSummary {
  total: number;
  bySeverity: {
    critical: number;
    warning: number;
    info: number;
  };
  byStatus: {
    unread: number;
    read: number;
    dismissed: number;
  };
  timestamp: string;
}

/** Keep raw alert evidence intact while presenting the product name in UI headings. */
export function guardianAlertHeading(value: string): string {
  if (!/suricata/i.test(value)) return value;
  return value.replace(/suricata/gi, 'Guardian');
}

interface ThreatAlertApi {
  alert_id: string;
  timestamp: string;
  src_ip: string;
  src_port?: number;
  dst_ip: string;
  dst_port?: number;
  protocol: string;
  signature_id?: number;
  signature: string;
  category: string;
  severity: string;
  event_type: string;
  blocked?: boolean;
  rev?: number;
  gid?: number;
}

function normalizeThreatAlert(alert: ThreatAlertApi): Alert {
  const severity = alert.severity === 'critical' || alert.severity === 'high'
    ? 'HIGH'
    : alert.severity === 'medium' ? 'MEDIUM' : 'LOW';
  const parsedTimestamp = new Date(alert.timestamp);
  const validTimestamp = !Number.isNaN(parsedTimestamp.getTime());
  return {
    id: alert.alert_id,
    severity,
    status: alert.blocked ? 'Blocked' : 'Active',
    title: alert.signature || 'Network threat detected',
    description: `${alert.category || 'Network'} event from ${alert.src_ip || 'unknown source'} to ${alert.dst_ip || 'unknown destination'}`,
    eventType: alert.event_type || alert.category || 'Threat alert',
    timestamp: validTimestamp ? parsedTimestamp.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }) : 'Unknown',
    date: validTimestamp ? parsedTimestamp.toLocaleDateString() : '',
    device: alert.src_ip || 'Unknown source',
    deviceIp: alert.src_ip || '',
    os: alert.protocol || 'Unknown protocol',
    aiSummary: `Guardian detected ${alert.signature || 'suspicious traffic'} targeting ${alert.dst_ip || 'an unknown destination'}.`,
    archived: false,
    rawTimestamp: alert.timestamp,
    srcIp: alert.src_ip,
    srcPort: alert.src_port,
    dstIp: alert.dst_ip,
    dstPort: alert.dst_port,
    protocol: alert.protocol,
    signatureId: alert.signature_id,
    signature: alert.signature,
    category: alert.category,
    blocked: !!alert.blocked,
    originalEvidence: [
      alert.event_type ? `Event type: ${alert.event_type}` : '',
      alert.signature ? `Signature: ${alert.signature}` : '',
      alert.signature_id ? `Signature ID: ${alert.signature_id}` : '',
      alert.src_ip || alert.dst_ip ? `Flow: ${alert.src_ip || 'unknown'}:${alert.src_port ?? 'any'} → ${alert.dst_ip || 'unknown'}:${alert.dst_port ?? 'any'} ${alert.protocol || ''}` : '',
      alert.gid ? `GID: ${alert.gid}` : '',
      alert.rev ? `Revision: ${alert.rev}` : '',
    ].filter(Boolean).join(' · '),
  };
}

export const alertService = {
  // The backend's implemented alert source is Suricata threat alerts.
  async getAll(filters?: AlertFilters): Promise<AlertsResponse> {
    const raw = await api.get<ThreatAlertApi[]>('/threat/alerts', {
      ...(filters?.severity ? { severity: filters.severity.toLowerCase() } : {}),
      ...(filters?.limit ? { limit: filters.limit } : {}),
    });
    const alerts = raw.map(normalizeThreatAlert);
    return { alerts, total: alerts.length, unread: alerts.length, timestamp: new Date().toISOString() };
  },

  // GET /api/alerts/:id
  getById: (id: string) => api.get<Alert>(`/alerts/${id}`),

  // PUT /api/alerts/:id/read
  markAsRead: (id: string) =>
    api.put<{ success: boolean; alertId: string; status: string }>(`/alerts/${id}/read`),

  // PUT /api/alerts/:id/dismiss
  dismiss: (id: string) =>
    api.put<{ success: boolean; alertId: string; status: string }>(`/alerts/${id}/dismiss`),

  // PUT /api/alerts/read-all
  markAllAsRead: () => api.put<{ success: boolean; message: string }>('/alerts/read-all'),

  // DELETE /api/alerts/:id
  delete: (id: string) => api.delete<{ success: boolean; message: string }>(`/alerts/${id}`),

  // GET /api/alerts/summary
  getSummary: () => api.get<AlertSummary>('/alerts/summary'),
};

export default alertService;
