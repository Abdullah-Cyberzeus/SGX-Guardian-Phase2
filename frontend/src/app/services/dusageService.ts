import api from './api';

export interface InterfaceUsage {
  iface: string;
  rx_bytes: number;
  tx_bytes: number;
  rx_total: number;
  tx_total: number;
}

export interface CategoryUsage {
  category: string;
  bytes: number;
}

export interface DeviceUsage {
  ip: string;
  rx_bytes: number;
  tx_bytes: number;
}

export interface UsageSnapshot {
  period: string;
  period_start: string;
  interfaces: InterfaceUsage[];
  categories: CategoryUsage[];
  devices: DeviceUsage[];
  total_bytes: number;
  quota_bytes: number | null;
  used_pct: number | null;
  usage_band: string;
  sampled_at: string;
}

export interface DusageQuota {
  quota_bytes: number;
  period: string;
  sequence: number;
}

export interface ResetResult {
  status: string;
  snapshot: UsageSnapshot;
}

export const dusageService = {
  // GET /api/v1/dusage/current
  getCurrent: () => api.get<UsageSnapshot>('/dusage/current'),

  // GET /api/v1/dusage/history
  getHistory: () => api.get<UsageSnapshot[]>('/dusage/history'),

  // GET /api/v1/dusage/quota - null when no quota has been set yet
  getQuota: () => api.get<DusageQuota | null>('/dusage/quota'),

  // PUT /api/v1/dusage/quota
  putQuota: (quotaBytes: number, period: string) =>
    api.put<DusageQuota>('/dusage/quota', { quota_bytes: quotaBytes, period }),

  // POST /api/v1/dusage/reset
  reset: () => api.post<ResetResult>('/dusage/reset'),
};

export default dusageService;
