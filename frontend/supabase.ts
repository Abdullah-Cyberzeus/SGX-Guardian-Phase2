import api from './api';

export interface Alert {
  id: string;
  severity: 'critical' | 'warning' | 'info';
  status: 'unread' | 'read' | 'dismissed';
  title: string;
  message: string;
  source: string;
  timestamp: string;
  metadata?: Record<string, unknown>;
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

export const alertService = {
  // GET /api/alerts
  getAll: (filters?: AlertFilters) =>
    api.get<AlertsResponse>('/alerts', filters as Record<string, string | number>),

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
