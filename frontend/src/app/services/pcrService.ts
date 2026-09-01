import api from './api';

export interface PCRRegister {
  index: number;
  value: string;
  baseline: string;
  status: 'match' | 'mismatch' | 'unknown';
  description: string;
  lastUpdated: string;
}

export interface PCRStatus {
  registers: PCRRegister[];
  totalRegisters: number;
  matchCount: number;
  mismatchCount: number;
  lastVerified: string;
  tpmVersion: string;
}

export interface PCRBaseline {
  id: string;
  createdAt: string;
  registers: {
    index: number;
    value: string;
    description: string;
  }[];
  version: string;
  hash: string;
}

export interface VerifyResult {
  success: boolean;
  verified: number;
  total: number;
  mismatches: {
    register: number;
    expected: string;
    actual: string;
  }[];
  verifiedAt: string;
}

export interface PCRHistoryEntry {
  id: string;
  timestamp: string;
  status: 'passed' | 'failed' | 'pass' | 'fail';
  registers?: number;
  mismatches?: number;
  matchCount?: number;
  totalCount?: number;
  reason?: string;
  peer?: string;
  verified?: boolean;
  nonceValid?: boolean;
  signatureValid?: boolean;
  pcrMatch?: boolean;
  bootChainOk?: boolean;
  freshnessOk?: boolean;
}

export type PCRVerificationResult = PCRHistoryEntry;

// Backend response shape
interface BackendPcrStatus {
  node: string;
  registers: {
    index: number;
    name: string;
    value: string;
  }[];
  compositeDigest: string;
  compositeSignature?: string;
  integrityStatus: string;
  deviceUid: string;
  keyVersion: number;
  measuredAt: string;
  schemaVersion: number;
}

export const pcrService = {
  // GET /api/pcr/status - sgx-guardian pcr status
  getStatus: async () => {
    const res = await api.get<BackendPcrStatus>('/pcr/status');
    // After verification the backend can report integrity as HEALTHY, PASS, or
    // DEGRADED — all three mean a baseline exists. Previously only HEALTHY and
    // DEGRADED counted, so a backend that returns PASS directly left every
    // register tagged 'no_baseline' and the dashboard showed a stale warning.
    const passStatuses = ['HEALTHY', 'PASS'];
    const hasBaseline = passStatuses.includes(res.integrityStatus) || res.integrityStatus === 'DEGRADED';
    const isHealthy = passStatuses.includes(res.integrityStatus);
    const registers = (res.registers || []).map(r => ({
      index: r.index,
      name: `PCR${r.index}`,
      description: r.name,
      currentValue: r.value,
      baselineValue: r.value,
      status: hasBaseline
        ? (isHealthy ? 'match' as const : 'mismatch' as const)
        : 'no_baseline' as const,
    }));
    return {
      registers,
      integrityStatus: res.integrityStatus === 'HEALTHY' ? 'PASS' : res.integrityStatus,
      compositeDigest: res.compositeDigest,
      dkpVersion: res.keyVersion,
      lastVerified: res.measuredAt,
      baselineExists: hasBaseline,
    };
  },

  // GET /api/pcr/baseline - sgx-guardian pcr baseline
  getBaseline: () => api.get<PCRBaseline>('/pcr/baseline'),

  // POST /api/pcr/verify - sgx-guardian pcr verify
  verify: () =>
    api.post<{ success: boolean; message: string; stdout: string; stderr: string; restartRequired: boolean; timestamp: string }>(
      '/pcr/baseline/verify',
      undefined,
      { timeoutMs: 120_000 },
    ),

  // POST /api/pcr/baseline/update
  updateBaseline: () =>
    api.post<{ success: boolean; message: string; timestamp: string }>(
      '/pcr/baseline/create',
      undefined,
      { timeoutMs: 120_000 },
    ),

  // GET /api/pcr/history
  getHistory: () => api.get<PCRHistoryEntry[]>('/pcr/history'),
};

export default pcrService;
