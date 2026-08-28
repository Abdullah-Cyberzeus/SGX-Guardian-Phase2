import api from "./api";

export type RiskLevel = "critical" | "high" | "medium" | "low" | "unknown" | string;

export interface ScriptResult {
  id: string;
  output: string;
}

export interface OpenPort {
  port: number;
  protocol: string;
  service?: string | null;
  product_version?: string | null;
  cpe: string[];
  scripts: ScriptResult[];
}

export interface DeviceScores {
  security_score: number | null;
  security_reasons: string[];
  privacy_score: number | null;
  privacy_reasons: string[];
  privacy_basis: string;
  risk_level: RiskLevel;
  computed_at: string;
}

export interface ManagedDevice extends DeviceScores {
  device_id: string;
  ip?: string | null;
  mac?: string | null;
  vendor?: string | null;
  hostname?: string | null;
  display_name?: string | null;
  manual: boolean;
  monitoring_enabled: boolean;
  blocked: boolean;
  rejected: boolean;
  rejection_reason?: string | null;
  status?: string | null;
  os_fingerprint?: string | null;
  os_cpe: string[];
  open_ports: OpenPort[];
  host_scripts: ScriptResult[];
  first_seen?: string | null;
  last_seen?: string | null;
  last_scan_intensity?: string | null;
}

export interface ScoreDistribution {
  unavailable: number;
  poor: number;
  fair: number;
  good: number;
  excellent: number;
}

export interface ManagedDevicesSummary {
  total: number;
  manual: number;
  blocked: number;
  monitoring_enabled: number;
  critical_devices: number;
  high_risk_devices: number;
  medium_risk_devices: number;
  low_risk_devices: number;
  unknown_risk_devices: number;
  security_score_distribution: ScoreDistribution;
  privacy_score_distribution: ScoreDistribution;
}

export interface DeviceActionResponse {
  device_id: string;
  success: boolean;
  message: string;
}

export interface DeviceRecord {
  device_id: string;
  display_name?: string | null;
  manual: boolean;
  ip?: string | null;
  mac?: string | null;
  manufacturer?: string | null;
  monitoring_enabled: boolean;
  blocked: boolean;
  rejected: boolean;
  rejection_reason?: string | null;
  notes?: string | null;
  created_at: string;
  updated_at: string;
}

export interface AddManualDeviceRequest {
  display_name?: string;
  ip?: string;
  mac?: string;
  manufacturer?: string;
  notes?: string;
}

export interface DevicePatchRequest {
  display_name?: string | null;
  monitoring_enabled?: boolean;
  notes?: string | null;
}

export interface RejectDeviceRequest {
  reason?: string;
}

export type FirmwareAssessmentStatus = "verified" | "observed" | "unknown" | "unsupported";

export interface FirmwareEvidenceSource {
  source: string;
  value: string;
}

export interface FirmwareAssessment {
  status: FirmwareAssessmentStatus;
  vendor?: string | null;
  product?: string | null;
  version?: string | null;
  platform?: string | null;
  evidence_sources: FirmwareEvidenceSource[];
  confidence: number;
  integrity_verified: boolean;
  findings: string[];
  recommendations: string[];
}

export interface DeviceScanProgressTransition {
  step: number;
  step_label: string;
  state: string;
  timestamp: string;
}

export interface DeviceScanRun {
  scan_id: string;
  device_id: string;
  step: number;
  step_label: string;
  state: "running" | "complete" | "failed" | string;
  started_at: string;
  updated_at?: string | null;
  finished_at?: string | null;
  findings: string[];
  recommendations: string[];
  firmware_assessment?: FirmwareAssessment | null;
  progress_history: DeviceScanProgressTransition[];
}

const devicePath = (id: string) => `/managed-devices/${encodeURIComponent(id)}`;

export const managedDeviceService = {
  // GET /api/v1/managed-devices
  list: () => api.get<ManagedDevice[]>("/managed-devices"),

  // GET /api/v1/managed-devices/summary
  summary: () => api.get<ManagedDevicesSummary>("/managed-devices/summary"),

  // GET /api/v1/managed-devices/{device_id}
  detail: (id: string) => api.get<ManagedDevice>(devicePath(id)),

  // POST /api/v1/managed-devices
  addManual: (data: AddManualDeviceRequest) => api.post<DeviceRecord>("/managed-devices", data),

  // PATCH /api/v1/managed-devices/{device_id}
  edit: (id: string, data: DevicePatchRequest) => api.patch<DeviceRecord>(devicePath(id), data),

  // DELETE /api/v1/managed-devices/{device_id}
  remove: (id: string) => api.delete<DeviceActionResponse>(devicePath(id)),

  // POST /api/v1/managed-devices/{device_id}/scan
  startScan: (id: string) => api.post<DeviceScanRun>(`${devicePath(id)}/scan`),

  // GET /api/v1/managed-devices/{device_id}/scan/{scan_id}
  scanStatus: (id: string, scanId: string) => api.get<DeviceScanRun>(`${devicePath(id)}/scan/${encodeURIComponent(scanId)}`),

  // POST /api/v1/managed-devices/{device_id}/reject
  reject: (id: string, data?: RejectDeviceRequest) => api.post<DeviceActionResponse>(`${devicePath(id)}/reject`, data),

  // POST /api/v1/managed-devices/{device_id}/approve
  approve: (id: string) => api.post<DeviceActionResponse>(`${devicePath(id)}/approve`),

  // POST /api/v1/managed-devices/{device_id}/block
  block: (id: string) => api.post<DeviceActionResponse>(`${devicePath(id)}/block`),

  // POST /api/v1/managed-devices/{device_id}/unblock
  unblock: (id: string) => api.post<DeviceActionResponse>(`${devicePath(id)}/unblock`),
};

export default managedDeviceService;
