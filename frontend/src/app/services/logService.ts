import api from './api';

export interface LogEntry {
  id: string;
  timestamp: string;
  level: 'info' | 'warning' | 'error' | 'debug';
  source: string;
  message: string;
}

export interface LogsResponse {
  logs: LogEntry[];
  total: number;
  timestamp: string;
}

export interface LogFilters {
  level?: string;
  search?: string;
  limit?: number;
}

// Backend response shape
interface BackendLogsResponse {
  node: string;
  file: string;
  entries: {
    timestamp: string;
    level: string;
    message: string;
  }[];
  total: number;
  timestamp: string;
}

function normalizeLevel(level: string): 'info' | 'warning' | 'error' | 'debug' {
  const l = level.toLowerCase();
  if (l === 'warn' || l === 'warning') return 'warning';
  if (l === 'error' || l === 'err') return 'error';
  if (l === 'debug' || l === 'trace') return 'debug';
  return 'info';
}

function categorizeMessage(msg: string): string {
  const lower = msg.toLowerCase();
  if (lower.includes('attest')) return 'attestation';
  if (lower.includes('peer') || lower.includes('discover')) return 'peer';
  if (lower.includes('security') || lower.includes('tls') || lower.includes('cert')) return 'security';
  if (lower.includes('dkp') || lower.includes('key')) return 'dkp';
  if (lower.includes('policy')) return 'policy';
  return 'system';
}

export const logService = {
  // GET /api/logs - sgx-guardian logs
  getLogs: async (filters?: LogFilters): Promise<LogsResponse> => {
    const res = await api.get<BackendLogsResponse>('/logs', filters as Record<string, string | number>);
    const logs = (res.entries || []).map((entry, i) => ({
      id: `log_${String(i + 1).padStart(3, '0')}`,
      timestamp: entry.timestamp,
      level: normalizeLevel(entry.level),
      category: categorizeMessage(entry.message),
      node: res.node || 'nodeA',
      source: res.node || 'nodeA',
      message: entry.message,
      details: entry.message,
    }));
    return {
      logs,
      total: logs.length,
      timestamp: res.timestamp,
    };
  },

  // GET /api/logs/export
  exportLogs: async (format: 'json' | 'csv' = 'json') => {
    const response = await fetch(
      `${import.meta.env.VITE_API_URL || '/api'}/logs/export?format=${format}`
    );
    return response.blob();
  },

  // DELETE /api/logs
  clearLogs: () => api.delete<{ success: boolean; message: string }>('/logs'),
};

export default logService;
