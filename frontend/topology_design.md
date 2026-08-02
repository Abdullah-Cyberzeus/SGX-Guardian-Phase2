import api from './api';

// ── Shared VC shape ────────────────────────────────────────────────────────────

export interface VcCredentialStatus {
  id: string;
  type: string;
  statusPurpose: string;
  statusListIndex: string;
  statusListCredential: string;
}

export interface VcProof {
  type: string;
  verificationMethod: string;
  created: string;
  proofValue: string;
}

export interface VcCredentialSubject {
  id: string;
  role: string;
  permissions: string[];
  joinDate: string;
  circleId: string;
  membershipStatus: string;
}

export interface VerifiableCredential {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  expirationDate: string;
  credentialSubject: VcCredentialSubject;
  credentialStatus: VcCredentialStatus;
  proof: VcProof;
}

// ── Shared metadata item ───────────────────────────────────────────────────────

export interface VcMetaItem {
  vc_id: string;
  subject: string;
  issuer: string;
  role: string;
  circle_id: string;
  membership_status: string;
  issuance_date: string;
  expiration_date: string;
  status_list_index: string;
  revoked: boolean;
  source_scope: string;
}

// ── POST /vc/issue ─────────────────────────────────────────────────────────────

export interface IssueVcRequest {
  to: string;
  role?: 'owner' | 'member';
  permissions?: string[];
  days?: number;
}

export interface IssueVcResponse {
  status: string;
  message: string;
  vc_id: string;
  subject: string;
  role: string;
  expires: string;
  reused: boolean;
  vc: VerifiableCredential;
}

// ── POST /vc/renew ─────────────────────────────────────────────────────────────

export interface RenewVcRequest {
  id: string;
  days: number;
}

export interface RenewVcResponse {
  status: string;
  message: string;
  vc_id: string;
  old_expiration: string;
  new_expiration: string;
  vc: VerifiableCredential;
}

// ── POST /vc/revoke ────────────────────────────────────────────────────────────

export interface RevokeVcRequest {
  id: string;
  reason?: string;
}

export interface RevokeVcResponse {
  success: boolean;
  status: string;
  message: string;
  vc_id: string;
  revoked: boolean;
  reason: string;
}

// ── POST /vc/verify ────────────────────────────────────────────────────────────

export interface VerifyVcResponse {
  status: string;
  valid: boolean;
  vc_id: string;
  reason: string | null;
}

// ── GET /vc/show ───────────────────────────────────────────────────────────────

export interface VcShowFilters {
  scope?: 'issued' | 'own' | 'peers' | 'all';
  role?: 'owner' | 'member';
  status?: 'active' | 'revoked' | 'expired' | 'all';
}

export interface VcShowResponse {
  status: string;
  count: number;
  items: VcMetaItem[];
}

// ── GET /vc/status/{vc_id} ─────────────────────────────────────────────────────

export interface VcStatusResponse {
  status: string;
  id: string;
  vc_id: string;
  subject_did: string;
  issuer_did: string;
  active: boolean;
  revoked: boolean;
  expired: boolean;
  membership_status: string;
  status_list_index: string;
  reason: string | null;
}

// ── POST /vc/status-list/pull ──────────────────────────────────────────────────

export interface PullStatusListRequest {
  ca_host?: string;
}

export interface PullStatusListResponse {
  success: boolean;
  status: string;
  message: string;
  ca_host: string;
  issuer: string;
  sgx_next_index: number;
}

// ── GET /vc/files/issued|own|peers ─────────────────────────────────────────────

export interface VcFilesIssuedResponse {
  status: string;
  count: number;
  items: VcMetaItem[];
}

export interface VcFilesOwnResponse {
  status: string;
  count: number;
  items: VcMetaItem[];
}

export interface VcFilesPeersResponse {
  status: string;
  count: number;
  items: VcMetaItem[];
}

// ── GET /vc/status-list (spec 3.55) ────────────────────────────────────────────
// Returns the raw VC status-list credential as stored on disk.
// The structure is a W3C VC envelope; FE treats it as opaque JSON for display.

export interface VcStatusListResponse {
  '@context': string[];
  id: string;
  type: string[];
  issuer: string;
  issuanceDate: string;
  credentialSubject: {
    id: string;
    type: string;
    statusPurpose: string;
    encodedList: string;
  };
  proof: VcProof;
  sgxNextIndex: number;
}

// ── GET /vc/status-list-index (spec 3.56) ──────────────────────────────────────

export interface VcStatusListIndexResponse {
  next_index: number;
}

// ── GET /vc/summary (spec 3.57) ────────────────────────────────────────────────

export interface VcSummaryResponse {
  status: string;
  issued_total: number;
  own_total: number;
  peer_total: number;
  active_total: number;
  revoked_total: number;
  expired_total: number;
  next_index: number;
  owner_did: string;
  circle_id: string;
}

// ── GET /vc/audit (spec 3.58) ──────────────────────────────────────────────────

export interface VcAuditFilters {
  limit?: number;
  action?: string;
}

export type VcAuditAction =
  | 'VC_ISSUED'
  | 'VC_REUSED_NO_CHANGE'
  | 'VC_RENEWED'
  | 'VC_REVOKED'
  | 'VC_VERIFY_SUCCESS'
  | 'VC_VERIFY_FAILED'
  | 'VC_FILE_READ'
  | 'VC_SUMMARY_READ'
  | 'VC_STATUS_LIST_PULLED'
  | string;

export type VcAuditSeverity = 'Info' | 'Warn' | 'Error' | string;

export interface VcAuditItem {
  timestamp: number;
  node_id: string;
  severity: VcAuditSeverity;
  action: VcAuditAction;
  message: string;
}

export interface VcAuditResponse {
  status: string;
  count: number;
  items: VcAuditItem[];
}

// ── Service ────────────────────────────────────────────────────────────────────

export const vcService = {
  // POST /api/v1/vc/issue
  issue: (req: IssueVcRequest) =>
    api.post<IssueVcResponse>('/vc/issue', req),

  // POST /api/v1/vc/renew
  renew: (req: RenewVcRequest) =>
    api.post<RenewVcResponse>('/vc/renew', req),

  // POST /api/v1/vc/revoke
  revoke: (req: RevokeVcRequest) =>
    api.post<RevokeVcResponse>('/vc/revoke', req),

  // POST /api/v1/vc/verify
  verify: (id: string) =>
    api.post<VerifyVcResponse>('/vc/verify', { id }),

  // GET /api/v1/vc/show
  show: (filters?: VcShowFilters) =>
    api.get<VcShowResponse>('/vc/show', filters),

  // GET /api/v1/vc/status/{vc_id}
  getStatus: (vc_id: string) =>
    api.get<VcStatusResponse>(`/vc/status/${encodeURIComponent(vc_id)}`),

  // POST /api/v1/vc/status-list/pull
  pullStatusList: (req?: PullStatusListRequest) =>
    api.post<PullStatusListResponse>('/vc/status-list/pull', req ?? {}),

  // GET /api/v1/vc/files/issued
  getFilesIssued: () =>
    api.get<VcFilesIssuedResponse>('/vc/files/issued'),

  // GET /api/v1/vc/files/own
  getFilesOwn: () =>
    api.get<VcFilesOwnResponse>('/vc/files/own'),

  // GET /api/v1/vc/files/peers
  getFilesPeers: () =>
    api.get<VcFilesPeersResponse>('/vc/files/peers'),

  // GET /api/v1/vc/files/issued/{vc_id}
  getIssuedFile: (vc_id: string) =>
    api.get<VerifiableCredential>(`/vc/files/issued/${encodeURIComponent(vc_id)}`),

  // GET /api/v1/vc/files/own/{vc_id}
  getOwnFile: (vc_id: string) =>
    api.get<VerifiableCredential>(`/vc/files/own/${encodeURIComponent(vc_id)}`),

  // GET /api/v1/vc/files/peer/{did}
  getPeerFile: (did: string) =>
    api.get<VerifiableCredential>(`/vc/files/peer/${encodeURIComponent(did)}`),

  // GET /api/v1/vc/status-list
  getStatusList: () =>
    api.get<VcStatusListResponse>('/vc/status-list'),

  // GET /api/v1/vc/status-list-index
  getStatusListIndex: () =>
    api.get<VcStatusListIndexResponse>('/vc/status-list-index'),

  // GET /api/v1/vc/summary
  getSummary: () =>
    api.get<VcSummaryResponse>('/vc/summary'),

  // GET /api/v1/vc/audit
  getAudit: (filters?: VcAuditFilters) =>
    api.get<VcAuditResponse>('/vc/audit', filters),
};

export default vcService;
