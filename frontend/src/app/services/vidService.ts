import api from './api';

// ── GET /vid/show ──────────────────────────────────────────────────────────────
// Per API spec 3.59:
// VirtualID = SHA256(DID || CurrentDKP_PubKey || PCR_values || policy_digest || Nonce_I || Nonce_R)
// Session-bound; rotates when daemon refreshes the nonce pair (default 60s) or
// when any input (DID / DKP / PCR / policy) changes.

export type VidChangeReason =
  | 'initial_observation'
  | 'dkp_rotated'
  | 'pcr_changed'
  | 'policy_changed'
  | 'nonce_refreshed'
  | string;

export interface VidShowResponse {
  node: string;
  did: string;
  dkpBytes: number;
  dkpVersion: number;
  pcrDigest: string;
  policyDigest: string;
  nonceI: string;
  nonceR: string;
  virtualId: string;
  changeReason: VidChangeReason;
  sessionExpiresAt: string;
  sessionTtl: number;
}

// ── GET /vid/peers ─────────────────────────────────────────────────────────────

export interface VidPeer {
  did: string;
  nodeName?: string | null;
  virtualId: string;
  observedAt: string;
  lastRotationReason?: string;
}

export interface VidPeersResponse {
  peers: VidPeer[];
}

// ── Service ────────────────────────────────────────────────────────────────────

export const vidService = {
  // GET /api/v1/vid/show — single current nonce-bound VirtualID + session inputs
  show: () => api.get<VidShowResponse>('/vid/show'),

  // GET /api/v1/vid/peers — cached peer VirtualIDs
  peers: () => api.get<VidPeersResponse>('/vid/peers'),
};

export default vidService;
