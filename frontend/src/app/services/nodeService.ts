import api from './api';

export interface NodeStatus {
  hostname: string;
  port: number;
  publicKey: string;
  offlineMode: number;
  version: string;
  uptime: number;
  enclaveStatus: string;
  sgxEnabled: boolean;
  attestationMode: string;
  lastAttestation: string;
  peerCount: number;
}

export interface BootStatus {
  secure: boolean;
  chain: {
    stage: string;
    status: 'verified' | 'warning' | 'failed';
    hash: string;
    timestamp: string;
  }[];
  tpmEnabled: boolean;
  measuredBoot: boolean;
}

export interface RestartResponse {
  success: boolean;
  message: string;
  timestamp: string;
}

// Backend response shapes
interface BackendNodeStatus {
  nodeId: string;
  hostname: string;
  ip: string;
  port: number;
  publicKey: string;
  offlineMode: number;
  timestamp: string;
}

interface BackendBootStatus {
  habEnabled: boolean;
  deviceClosed: boolean;
  habEventsFound: boolean;
  deviceModel: string;
  kernelVersion: string;
  bootChainIntact: boolean;
  guardianBinaryHash: string | null;
  trustChain: { stage: string; status: string }[];
  timestamp: string;
}

export const nodeService = {
  // GET /api/node/status - sgx-guardian status
  getStatus: async (): Promise<NodeStatus> => {
    const res = await api.get<BackendNodeStatus>('/node/status');
    return {
      hostname: res.hostname,
      port: res.port,
      publicKey: res.publicKey,
      offlineMode: res.offlineMode,
      version: '1.0.0',
      uptime: 0,
      enclaveStatus: 'active',
      sgxEnabled: true,
      attestationMode: 'ECDSA-P256',
      lastAttestation: res.timestamp,
      peerCount: 0,
    };
  },

  // GET /api/node/boot-status - sgx-guardian boot-status
  getBootStatus: async () => {
    const res = await api.get<BackendBootStatus>('/node/boot-status');
    return {
      habEnabled: res.habEnabled,
      deviceClosed: res.deviceClosed,
      habEvents: res.habEventsFound ? 'Found' : 'None',
      deviceModel: res.deviceModel || 'Unknown',
      bootChain: res.bootChainIntact ? 'INTACT' as const : 'COMPROMISED' as const,
      binaryHash: res.guardianBinaryHash || 'N/A',
      lastChecked: res.timestamp,
      trustChain: (res.trustChain || []).map(step => ({
        name: step.stage,
        description: step.stage,
        status: step.status as 'verified' | 'pending' | 'failed',
      })),
    };
  },

  // POST /api/node/restart - sgx-guardian daemon restart
  restart: () => api.post<RestartResponse>('/node/restart'),
};

export default nodeService;
