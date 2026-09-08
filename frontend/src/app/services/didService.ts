import api from './api';

export interface DIDStatus {
  did: string;
  method: string;
  methodVersion: string;
  createdAt: string;
  deactivatedAt: string | null;
  currentDkpVersion: number;
  se050UidSource: string;
  dikPubkeySha256B16: string;
  status: string;
}

export interface DIDResolveResult {
  did: string;
  status: string;
  publicKeyPreview: string;
  publicKeyBytes: number;
}

export interface DIDDeactivateResponse {
  ok: boolean;
  message: string;
  restartRequired: boolean;
}

export interface DIDDocumentSummary {
  did: string;
  controller: string;
  node_name: string;
  version: number;
  status: string;
  active_vms: number;
  revoked_vms: number;
  services: number;
  proof_vm: string;
}

export interface DIDDocumentVerificationMethod {
  id: string;
  type: string;
  controller: string;
  publicKeyJwk: {
    kty: string;
    crv: string;
    x: string;
    y: string;
    kid: string;
  };
}

export interface DIDDocumentService {
  id: string;
  type: string;
  serviceEndpoint: string;
}

export interface DIDDocumentProof {
  type: string;
  cryptosuite: string;
  verificationMethod: string;
  created: string;
  proofPurpose: string;
  proofValue: string;
}

export interface DIDDocumentRevokedVM {
  id: string;
  revokedAt: string;
  reason: string;
}

export interface DIDDocumentRaw {
  '@context': string[];
  id: string;
  controller: string;
  verificationMethod: DIDDocumentVerificationMethod[];
  authentication: string[];
  assertionMethod: string[];
  service: DIDDocumentService[];
  'sgx:nodeName': string;
  'sgx:created': string;
  'sgx:updated': string;
  'sgx:versionId': number;
  'sgx:methodSpecVersion': string;
  'sgx:status': string;
  'sgx:revokedVerificationMethod'?: DIDDocumentRevokedVM[];
  proof: DIDDocumentProof;
}

export interface DIDDocumentVerifyResponse {
  valid: boolean;
  version: number;
  message: string;
}

export interface DIDDocumentPublishResponse {
  success: boolean;
  did: string;
  version: number;
  ca_host: string;
  node_name: string;
  registry_peer_count?: number;
  message: string;
}

export interface DIDDocumentPeerSummary {
  did: string;
  node_name: string;
  version: number;
  status: string;
  services: number;
}

export interface DIDDocumentPeersResponse {
  count: number;
  peers: DIDDocumentPeerSummary[];
}

export const didService = {
  // GET /api/v1/did/status
  getStatus: () => api.get<DIDStatus>('/did/status'),

  // GET /api/v1/did/resolve
  resolve: () => api.get<DIDResolveResult>('/did/resolve'),

  // POST /api/v1/did/deactivate
  deactivate: (reason?: string, confirm = false) =>
    api.post<DIDDeactivateResponse>('/did/deactivate', { reason, confirm }),

  // GET /api/v1/did/document
  getDocument: () => api.get<DIDDocumentSummary>('/did/document'),

  // GET /api/v1/did/document/raw
  getDocumentRaw: () => api.get<DIDDocumentRaw>('/did/document/raw'),

  // POST /api/v1/did/document/verify
  verifyDocument: (path?: string) =>
    api.post<DIDDocumentVerifyResponse>('/did/document/verify', path ? { path } : {}),

  // POST /api/v1/did/document/publish
  publishDocument: (ca_host?: string, node_name?: string) =>
    api.post<DIDDocumentPublishResponse>('/did/document/publish', {
      ...(ca_host?.trim() ? { ca_host: ca_host.trim() } : {}),
      ...(node_name?.trim() ? { node_name: node_name.trim() } : {}),
    }),

  // GET /api/v1/did/document/peers
  getDocumentPeers: () => api.get<DIDDocumentPeersResponse>('/did/document/peers'),

  // GET /api/v1/did/document/peer
  getDocumentPeer: (did: string) =>
    api.get<DIDDocumentRaw>('/did/document/peer', { did }),
};

export default didService;
