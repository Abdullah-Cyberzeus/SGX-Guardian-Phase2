import api from './api';
import { peerService } from './peerService';
import { transportService } from './transportService';
import { wifiService } from './wifiService';

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

interface BackendPwaHealth {
  status: 'guardian_connected' | 'reconnecting' | 'guardian_offline' | 'credential_revoked';
}

interface BackendTransportStatus {
  active: { name: string; transport: string } | null;
  lock: string | null;
}

interface BackendWifiMode {
  mode: 'off' | 'hotspot_only' | 'client_only' | 'dual';
  status: { state: string };
}

function clampSignal(value: number) {
  return Math.max(0, Math.min(100, Math.round(value)));
}

function deriveSignalStrength(
  health: BackendPwaHealth | null,
  transport: BackendTransportStatus | null,
  wifiMode: BackendWifiMode | null,
  offlineMode: number,
) {
  if (!health || health.status === 'guardian_offline' || health.status === 'credential_revoked') {
    return 0;
  }
  if (health.status === 'reconnecting') {
    return 35;
  }

  let score = 100;
  const activeTransport = transport?.active?.transport?.toLowerCase() || '';
  const wifiState = wifiMode?.status?.state || '';

  if (!transport?.active) {
    score -= 20;
  } else if (activeTransport === 'wifi') {
    if (['DualActive', 'ClientConnected'].includes(wifiState)) score -= 0;
    else if (['HotspotActive'].includes(wifiState)) score -= 15;
    else if (['ApplyingChange', 'HotspotStarting', 'ClientConnecting', 'DualStarting'].includes(wifiState)) {
      score -= 40;
    } else {
      score -= 20;
    }
  } else if (activeTransport === 'ethernet') {
    score -= 5;
  } else if (activeTransport === 'cellular') {
    score -= 12;
  } else if (activeTransport === 'satellite') {
    score -= 18;
  } else {
    score -= 10;
  }

  if (offlineMode > 0) score -= 20;
  if (wifiMode?.mode === 'off') score -= 10;
  if (wifiMode?.mode === 'hotspot_only') score -= 12;

  return clampSignal(score);
}

function deriveConnectionType(
  node: BackendNodeStatus,
  transport: BackendTransportStatus | null,
  wifiMode: BackendWifiMode | null,
) {
  if (transport?.active?.transport) return transport.active.transport;
  if (wifiMode?.mode === 'dual' || wifiMode?.mode === 'client_only' || wifiMode?.mode === 'hotspot_only') {
    return 'Wi-Fi';
  }
  if (node.offlineMode > 0) return 'Offline';
  return 'Ethernet';
}

export const guardianService = {
  // GET /api/node/status - maps to dashboard guardian info
  // Backend has no /guardian/info, so we reuse /node/status
  getInfo: async () => {
    const [res, health, transport, wifiMode] = await Promise.all([
      api.get<BackendNodeStatus>('/node/status'),
      api.get<BackendPwaHealth>('/pwa/health').catch(() => null),
      transportService.getStatus().catch(() => null),
      wifiService.getWifiMode().catch(() => null),
    ]);
    const peers = await peerService.getAll().catch(() => []);
    const signal = deriveSignalStrength(health, transport, wifiMode, res.offlineMode);
    return {
      id: res.nodeId,
      nodeId: res.nodeId,
      name: res.deviceName || res.displayHostname || res.hostname || res.nodeId,
      deviceId: res.deviceName || res.nodeId,
      firmware: 'v1.0.0',
      uptime: 'Running',
      connectionType: deriveConnectionType(res, transport, wifiMode),
      signal,
      peerCount: peers.length,
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
