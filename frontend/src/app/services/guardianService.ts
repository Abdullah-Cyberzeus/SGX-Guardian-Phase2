import api from './api';

export interface GuardianInfo {
  nodeId: string;
  version: string;
  buildDate: string;
  commitHash: string;
  platform: string;
  arch: string;
  sgxVersion: string;
  enclaveId: string;
  capabilities: string[];
}

export interface GuardianHealth {
  status: 'healthy' | 'degraded' | 'unhealthy';
  checks: {
    enclave: string;
    attestation: string;
    keyManagement: string;
    peerNetwork: string;
  };
  timestamp: string;
}

export interface GuardianMetrics {
  attestationsPerHour: number;
  averageAttestationTime: number;
  activeConnections: number;
  memoryUsage: {
    heapUsed: number;
    heapTotal: number;
    external: number;
  };
  cpuUsage: number;
  timestamp: string;
}

export interface ThreatIntel {
  score: number;
  threats24h: number;
  blocked: number;
  lastUpdated: string;
}

// Backend response shape for /node/status
interface BackendNodeStatus {
  nodeId: string;
  deviceName: string;
  hostname: string;
  displayHostname: string;
  ip: string;
  port: number;
  publicKey: string;
  offlineMode: number;
  timestamp: string;
}

export const guardianService = {
  // GET /api/node/status - maps to dashboard guardian info
  // Backend has no /guardian/info, so we reuse /node/status
  getInfo: async () => {
    const res = await api.get<BackendNodeStatus>('/node/status');
    return {
      id: res.nodeId,
      nodeId: res.nodeId,
      name: res.deviceName || res.displayHostname || res.hostname || res.nodeId,
      deviceId: res.deviceName || res.nodeId,
      firmware: 'v1.0.0',
      uptime: 'Running',
      connectionType: 'Ethernet',
      signal: 100,
      peerCount: 0,
      status: 'online' as const,
      lastSeen: 'Just now',
      ip: res.ip,
      mac: 'N/A',
      model: 'SG-X Guardian',
      serialNumber: res.nodeId,
      hostname: res.displayHostname || res.hostname,
      port: res.port,
      publicKey: res.publicKey,
      offlineMode: res.offlineMode,
    };
  },

  updateDisplayInfo: (data: { deviceName?: string; displayHostname?: string }) =>
    api.patch<BackendNodeStatus>('/node/status', data),

  // GET /api/guardian/status
  getStatus: () => api.get<GuardianInfo & { node: unknown; uptime: number; timestamp: string }>(
    '/guardian/status'
  ),

  // GET /api/guardian/health
  getHealth: () => api.get<GuardianHealth>('/guardian/health'),

  // GET /api/guardian/metrics
  getMetrics: () => api.get<GuardianMetrics>('/guardian/metrics'),

  // POST /api/guardian/restart
  restart: () => api.post<{ success: boolean; message: string; expectedDowntime: string }>(
    '/guardian/restart'
  ),

  // GET /api/guardian/threat-intel - live security score, 24h alerts, active blocks
  getThreatIntel: () => api.get<ThreatIntel>('/guardian/threat-intel'),
};

export default guardianService;
