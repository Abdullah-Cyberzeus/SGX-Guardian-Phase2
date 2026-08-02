import api from './api';

export interface DKPKey {
  id: string;
  type: string;
  status: 'active' | 'inactive' | 'revoked';
  createdAt: string;
  expiresAt: string;
  holder: string;
  shareIndex: number;
}

export interface DKPStatus {
  initialized: boolean;
  keyId: string;
  algorithm: string;
  threshold: number;
  shares: {
    total: number;
    active: number;
    threshold: number;
    holders: string[];
  };
  lastRotation: string;
  nextRotation: string;
  health: 'healthy' | 'warning' | 'critical';
}

export interface RotateResponse {
  success: boolean;
  message: string;
  newKeyId: string;
  timestamp: string;
}

export interface RevokeResponse {
  success: boolean;
  message: string;
  reason: string;
  timestamp: string;
}

export interface EmergencyRotationResult {
  success: boolean;
  message: string;
  reason: string;
  oldKeyId: string;
  newKeyId: string;
  rotatedAt: string;
  affectedPeers: number;
  requiresReAttestation: boolean;
}

// Backend response shape
interface BackendDkpStatus {
  totalVersions: number;
  activeVersion: number | null;
  se050Available: boolean;
  activePublicKeyPath: string | null;
  activePublicKeySize: number | null;
  keys: {
    version: number;
    keyId: string;
    algorithm: string;
    status: string;
    createdAt: string;
    rotatedFrom?: string;
  }[];
}

export const dkpService = {
  // GET /api/dkp/status - sgx-guardian dkp status
  getStatus: async () => {
    const res = await api.get<BackendDkpStatus>('/dkp/status');
    return {
      se050Available: res.se050Available,
      totalVersions: res.totalVersions,
      activeVersion: res.activeVersion,
      keys: (res.keys || []).map(k => ({
        version: k.version,
        keyId: k.keyId,
        algorithm: k.algorithm,
        status: k.status.toLowerCase() as 'active' | 'deprecated' | 'revoked',
        created: k.createdAt,
        rotatedFrom: k.rotatedFrom,
        revokedAt: undefined as string | undefined,
        revokeReason: undefined as string | undefined,
      })),
    };
  },

  // GET /api/dkp/keys
  getKeys: () => api.get<DKPKey[]>('/dkp/keys'),

  // POST /api/dkp/rotate - sgx-guardian dkp rotate
  rotate: () => api.post<RotateResponse>('/dkp/rotate'),

  // POST /api/dkp/revoke - sgx-guardian dkp revoke
  revoke: (version: number, reason?: string) =>
    api.post<RevokeResponse>('/dkp/revoke', { version, reason }),

  // POST /api/dkp/emergency-rotate - sgx-guardian dkp emergency-rotate
  emergencyRotate: (reason: string) =>
    api.post<EmergencyRotationResult>('/dkp/emergency-rotate', { reason }),

  // GET /api/dkp/shares
  getShares: () =>
    api.get<{ totalShares: number; activeShares: number; threshold: number; holders: string[] }>(
      '/dkp/shares'
    ),
};

export default dkpService;
