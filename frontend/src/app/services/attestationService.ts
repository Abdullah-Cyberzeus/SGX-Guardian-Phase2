import api from './api';

export interface AttestationResult {
  id: string;
  peerId: string;
  peerName: string;
  status: 'passed' | 'failed' | 'pending';
  timestamp: string;
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
}

export interface PeerAttestationRecord {
  peerId: string;
  policyDigest: string;
  result: string;
  timestamp: string;
}

export const attestationService = {
  // GET /api/attestation - sgx-guardian attest (backend returns single object, UI expects array)
  getResults: async (): Promise<AttestationResult[]> => {
    try {
      const res = await api.get<BackendLastAttestation>('/attestation');
      if (!res.peerId && !res.timestamp) return [];
      return [{
        id: 'att_001',
        peerId: res.peerId,
        peerIp: res.peerId,
        peerName: res.peerId,
        policyDigest: res.policyDigest,
        result: res.result === 'pass' || res.result === 'success' ? 'success' : 'failed',
        status: res.result === 'pass' || res.result === 'success' ? 'passed' : 'failed',
        timestamp: res.timestamp,
        enclaveHash: '',
        signerHash: '',
        productId: 0,
        securityVersion: 0,
        attributes: { debug: false, mode64bit: true, provisionKey: false, initToken: false },
        tcbLevel: 'UpToDate',
        details: {
          pcrMatch: res.result === 'pass' || res.result === 'success',
          signatureValid: res.result === 'pass' || res.result === 'success',
          policyMatch: res.result === 'pass' || res.result === 'success',
        },
      } as any];
    } catch (err) {
      throw err;
    }
  },

  // GET /api/attestation?peer_did=... - last attestation result for one peer DID.
  // Returns null when the peer has no recorded attestation yet.
  getForPeer: async (peerDid: string): Promise<PeerAttestationRecord | null> => {
    try {
      const res = await api.get<BackendLastAttestation>('/attestation', { peer_did: peerDid });
      if (!res.peerId && !res.timestamp) return null;
      return { peerId: res.peerId, policyDigest: res.policyDigest, result: res.result, timestamp: res.timestamp };
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
