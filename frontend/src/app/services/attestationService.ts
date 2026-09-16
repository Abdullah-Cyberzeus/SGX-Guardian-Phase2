import api from './api';

export interface AttestationResult {
  id: string;
  peerId: string;
  peerIp?: string;
  peerName: string;
  status: 'passed' | 'failed' | 'pending';
  result?: 'success' | 'failed' | 'pending';
  timestamp: string;
  policyDigest?: string;
  enclaveHash: string;
  signerHash: string;
  productId: number;
  securityVersion: number;
  attributes: {
    debug: boolean;
    mode64bit: boolean;
    provisionKey: boolean;
    initToken: boolean;
  };
  tcbLevel: string;
  advisory?: string[];
}

export interface VerifyResponse {
  success: boolean;
  peerId: string;
  message: string;
  timestamp: string;
}

export interface AttestationHistory extends AttestationResult {
  history: {
    timestamp: string;
    status: string;
  }[];
}

// Backend response shape for GET /attestation
interface BackendLastAttestation {
  peerId: string;
  policyDigest: string;
  result: string;
  timestamp: string;
  peerDid?: string;
  virtualId?: string;
}

export interface PeerAttestationRecord {
  peerId: string;
  policyDigest: string;
  result: string;
  timestamp: string;
}

export const attestationService = {
  // GET /api/attestation - backend returns trusted peer attestation records.
  getResults: async (): Promise<AttestationResult[]> => {
    const res = await api.get<BackendLastAttestation[] | BackendLastAttestation>('/attestation');
    const records = Array.isArray(res) ? res : res.peerId || res.timestamp ? [res] : [];
    return records.map((record, index) => {
      const passed = ["pass", "passed", "success", "verified", "attested"].includes(record.result.toLowerCase());
      const failed = ["fail", "failed", "failure", "error", "rejected"].includes(record.result.toLowerCase());
      const status = passed ? "passed" : failed ? "failed" : "pending";
      const result = passed ? "success" : failed ? "failed" : "pending";
      return {
        id: `${record.peerId || record.peerDid || "attestation"}-${index}`,
        peerId: record.peerId,
        peerIp: record.peerId,
        peerName: record.peerId,
        policyDigest: record.policyDigest,
        result,
        status,
        timestamp: record.timestamp,
        enclaveHash: '',
        signerHash: '',
        productId: 0,
        securityVersion: 0,
        attributes: { debug: false, mode64bit: true, provisionKey: false, initToken: false },
        tcbLevel: 'UpToDate',
        details: {
          pcrMatch: passed,
          signatureValid: passed,
          policyMatch: passed,
        },
      } as AttestationResult;
    });
  },

  // GET /api/attestation?peer_did=... - last attestation result for one peer DID.
  // Returns null when the peer has no recorded attestation yet.
  getForPeer: async (peerDid: string): Promise<PeerAttestationRecord | null> => {
    try {
      const res = await api.get<BackendLastAttestation[] | BackendLastAttestation>('/attestation', { peer_did: peerDid });
      const record = Array.isArray(res) ? res[0] : res;
      if (!record || (!record.peerId && !record.timestamp)) return null;
      return { peerId: record.peerId, policyDigest: record.policyDigest, result: record.result, timestamp: record.timestamp };
    } catch {
      return null;
    }
  },

  // POST /api/attestation/verify
  verify: (peerId?: string) => api.post<VerifyResponse>('/attestation/verify', { peerId }),

  // GET /api/attestation/history
  getHistory: () => api.get<AttestationHistory[]>('/attestation/history'),
};

export default attestationService;
