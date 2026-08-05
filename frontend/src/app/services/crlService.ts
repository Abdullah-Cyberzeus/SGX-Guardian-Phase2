import api from './api';

export type CrlSeverity = 'critical' | 'high' | 'medium' | 'low';

export type CrlReason =
  | 'compromised'
  | 'lost'
  | 'stolen'
  | 'policy_violation'
  | 'administrative_removal'
  | 'voluntary_departure';

export interface CrlProof {
  type: string;
  cryptosuite: string;
  verificationMethod?: string;
  proofPurpose?: string;
  proofValue?: string;
  created?: string;
}

export interface CrlEntry {
  id?: string;
  revoked_did: string;
  device_id?: string;
  user_id?: string;
  circle_id?: string;
  reason: CrlReason | string;
  severity: CrlSeverity | string;
  timestamp?: string;
  revoker_did?: string;
  revoker_role?: 'owner' | 'member' | string;
  proof?: CrlProof;
  peers_notified?: string[];
  propagated?: boolean;
}

export interface CrlListResponse {
  status?: string;
  count: number;
  entries: CrlEntry[];
}

export interface CrlRootResponse {
  sequence: number;
  merkle_root: string;
}

export interface CrlVerifyResponse {
  ok: boolean;
  errors: string[];
}

export interface CrlCheckResponse {
  status?: string;
  did: string;
  revoked: boolean;
  entry?: CrlEntry | null;
}

export interface CrlRevokePayload {
  did: string;
  reason: CrlReason | string;
  severity: CrlSeverity | string;
  device_id?: string;
  user_id?: string;
  note?: string;
}

export interface CrlRevokeResponse {
  status?: string;
  message?: string;
  entry?: CrlEntry;
  sequence?: number;
  merkle_root?: string;
}

export interface CrlUnrevokeResponse {
  status?: string;
  message?: string;
  did: string;
  sequence?: number;
  merkle_root?: string;
}

export interface CrlGossipLastRound {
  direction?: string;
  peer_did?: string;
  peer_node?: string;
  merged?: number;
  sent?: number;
  merkle_root?: string;
  at?: string;
}

export interface CrlGossipStatusResponse {
  enabled?: boolean;
  port?: number;
  interval_secs?: number;
  threshold_pct?: number;
  self_did?: string;
  circle_id?: string;
  other_members?: number;
  threshold_count?: number;
  sequence?: number;
  merkle_root?: string;
  entries?: number;
  propagated?: number;
  rounds_initiated?: number;
  rounds_served?: number;
  entries_merged?: number;
  last_round?: CrlGossipLastRound | null;
}

export interface CrlGossipTriggerResponse {
  success?: boolean;
  peer_did?: string;
  peer_node?: string;
  merged?: number;
  pushed?: number;
  peer_merged?: number;
  merkle_root?: string;
  newly_propagated?: string[];
  message?: string;
}

export type CrlOperationalResponse = Record<string, unknown>;

export interface CrlOfflinePeerSyncState {
  last_seen_merkle_root?: string;
  last_seen_sequence?: number;
  last_sync_at?: string;
}

export interface CrlOfflineStatusResponse {
  enabled?: boolean;
  online?: boolean;
  sync_interval_secs?: number;
  flush_rounds?: number;
  max_retries?: number;
  pending?: number;
  sync_cycles?: number;
  reconnects?: number;
  entries_delivered?: number;
  entries_fetched?: number;
  peer_sync_state?: Record<string, CrlOfflinePeerSyncState>;
}

export interface CrlOfflineSyncResponse {
  online?: boolean;
  reachable_peers?: number;
  reconciled?: number;
  fetched?: number;
  delivered?: number;
  pending_remaining?: number;
}

export interface CrlEmergencyBroadcastPayload {
  did: string;
}

export interface CrlEmergencyBroadcastResponse {
  success?: boolean;
  revoked_did?: string;
  message?: string;
}

export interface CrlEmergencyDebugPayload {
  did: string;
}

type LooseCrlEntry = CrlEntry & {
  entry_id?: string;
  did?: string;
  peers?: string[];
};

function normalizeEntry(entry: LooseCrlEntry): CrlEntry {
  return {
    ...entry,
    id: entry.id ?? entry.entry_id,
    revoked_did: entry.revoked_did ?? entry.did ?? '',
    reason: String(entry.reason ?? '').toLowerCase(),
    severity: String(entry.severity ?? '').toLowerCase(),
    peers_notified: Array.isArray(entry.peers_notified)
      ? entry.peers_notified
      : Array.isArray(entry.peers)
        ? entry.peers
        : [],
    propagated: typeof entry.propagated === 'boolean' ? entry.propagated : false,
  };
}

function normalizeList(response: CrlListResponse): CrlListResponse {
  const entries = (response.entries ?? []).map((entry) => normalizeEntry(entry as LooseCrlEntry));
  return {
    ...response,
    count: typeof response.count === 'number' ? response.count : entries.length,
    entries,
  };
}

export const crlService = {
  // GET /api/v1/crl/list
  list: async () => normalizeList(await api.get<CrlListResponse>('/crl/list')),

  // GET /api/v1/crl/root
  root: () => api.get<CrlRootResponse>('/crl/root'),

  // POST /api/v1/crl/verify
  verify: async () => {
    const response = await api.post<CrlVerifyResponse>('/crl/verify');
    return { ...response, errors: response.errors ?? [] };
  },

  // GET /api/v1/crl/check?did=
  check: async (did: string) => {
    const response = await api.get<CrlCheckResponse>('/crl/check', { did });
    return {
      ...response,
      entry: response.entry ? normalizeEntry(response.entry as LooseCrlEntry) : response.entry,
    };
  },

  // GET /api/v1/crl/entry?id=
  getEntry: async (id: string) => normalizeEntry(await api.get<CrlEntry>('/crl/entry', { id }) as LooseCrlEntry),

  // POST /api/v1/crl/revoke
  revoke: async (payload: CrlRevokePayload) => {
    const response = await api.post<CrlRevokeResponse>('/crl/revoke', payload);
    return {
      ...response,
      entry: response.entry ? normalizeEntry(response.entry as LooseCrlEntry) : response.entry,
    };
  },

  // POST /api/v1/crl/unrevoke
  unrevoke: (did: string) => api.post<CrlUnrevokeResponse>('/crl/unrevoke', { did }),

  // CRL propagation operations
  gossipStatus: async () => {
    const response = await api.get<CrlGossipStatusResponse>('/crl/gossip/status');
    return { ...response, last_round: response.last_round ?? null };
  },
  triggerGossip: async () => {
    const response = await api.post<CrlGossipTriggerResponse>('/crl/gossip/trigger');
    return { ...response, newly_propagated: response.newly_propagated ?? [] };
  },
  emergencyStatus: () => api.get<CrlOperationalResponse>('/crl/emergency/status'),
  broadcastEmergency: async (payload: CrlEmergencyBroadcastPayload) => {
    const response = await api.raw('/crl/emergency/broadcast', {
      method: 'POST',
      params: { did: payload.did },
    });
    return response.json() as Promise<CrlEmergencyBroadcastResponse>;
  },
  emergencyNotifications: () => api.get<CrlOperationalResponse>('/crl/emergency/notifications'),
  getEmergencyDebugSession: (did: string) =>
    api.get<CrlOperationalResponse>('/crl/emergency/debug/session', { did }),
  seedEmergencyDebugSession: (payload: CrlEmergencyDebugPayload) =>
    api.post<CrlOperationalResponse>('/crl/emergency/debug/session', payload),
  offlineStatus: () => api.get<CrlOfflineStatusResponse>('/crl/offline/status'),
  offlinePending: () => api.get<CrlOperationalResponse>('/crl/offline/pending'),
  syncOffline: () => api.post<CrlOfflineSyncResponse>('/crl/offline/sync'),
};

export default crlService;
