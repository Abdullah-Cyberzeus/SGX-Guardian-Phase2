import api from './api';

function formatTimeAgo(isoDate: string): string {
  const diff = Date.now() - new Date(isoDate).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'Just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.floor(hours / 24)}d ago`;
}

export interface Peer {
  id: string;
  peerId: string;
  displayName: string;
  fullName?: string;
  deviceName: string;
  did?: string;
  ip: string;
  port: number;
  status: 'verified' | 'pending' | 'failed';
  role: string;
  memberType: string;
  joinDate?: string;
  lastSeen: string;
  lastSeenAgo: string;
  attestationCount: number;
  online: boolean;
  presenceStatus: 'online' | 'offline' | 'stale' | string;
  presenceStale: boolean;
  presenceExpiresAt?: string;
  heartbeatIntervalSeconds?: number;
  callAvailable: boolean;
  callUnavailableReason?: string;
}

export interface AttestResponse {
  success: boolean;
  peerId: string;
  message: string;
  timestamp: string;
}

interface PeersResponse {
  peers: Array<{
    peerId: string;
    displayName?: string;
    fullName?: string;
    deviceName?: string;
    did?: string;
    ip: string;
    status: string;
    role?: string;
    memberType?: string;
    joinDate?: string;
    lastSeen: string;
    online?: boolean;
    presenceStatus?: string;
    presenceStale?: boolean;
    presenceExpiresAt?: string;
    heartbeatIntervalSeconds?: number;
    callAvailable?: boolean;
    callUnavailableReason?: string;
  }>;
  total: number;
  timestamp: string;
}

interface ContactsResponse {
  contacts: PeersResponse['peers'];
  total: number;
  timestamp: string;
}

function normalizePeers(peers: PeersResponse['peers']): Peer[] {
  return peers.map((p, i) => ({
    id: `peer_${String(i + 1).padStart(3, '0')}`,
    peerId: p.peerId,
    displayName: p.displayName || p.peerId,
    fullName: p.fullName,
    deviceName: p.deviceName || p.peerId,
    did: p.did,
    ip: p.ip || '',
    port: 0,
    status: (p.status === 'verified' || p.status === 'trusted' || p.status === 'success'
      ? 'verified'
      : p.status === 'failed' ? 'failed' : 'pending') as Peer['status'],
    role: p.role || 'member',
    memberType: p.memberType || 'guardian',
    joinDate: p.joinDate,
    lastSeen: p.lastSeen,
    lastSeenAgo: p.lastSeen ? formatTimeAgo(p.lastSeen) : 'Unknown',
    attestationCount: 0,
    online: p.online ?? Boolean(p.lastSeen),
    presenceStatus: p.presenceStatus || (p.online ? 'online' : 'offline'),
    presenceStale: Boolean(p.presenceStale),
    presenceExpiresAt: p.presenceExpiresAt,
    heartbeatIntervalSeconds: p.heartbeatIntervalSeconds,
    callAvailable: p.callAvailable ?? true,
    callUnavailableReason: p.callUnavailableReason,
  }));
}

/** True when this peer opted to hide their online status (Guardian-enforced
 * privacy) — render as neutral "hidden," not "offline." */
export function presenceHidden(peer: Pick<Peer, "presenceStatus">): boolean {
  return peer.presenceStatus === "hidden";
}

export const peerService = {
  getLocalIdentity: () => api.get<{ did: string }>('/pwa/identity'),

  // GET /api/peers - sgx-guardian peers
  getAll: async (): Promise<Peer[]> => {
    const res = await api.get<PeersResponse>('/peers');
    return normalizePeers(res.peers || []);
  },

  // Member-safe communication roster. The backend deliberately omits IPs,
  // ports, topology, policy, and attestation internals from this response.
  getContacts: async (): Promise<Peer[]> => {
    const res = await api.get<ContactsResponse>('/pwa/contacts');
    return normalizePeers(res.contacts || []);
  },

  // GET /api/peers/:id
  getById: (id: string) => api.get<Peer>(`/peers/${id}`),

  // POST /api/peers/:id/attest
  attest: (id: string) => api.post<AttestResponse>(`/peers/${id}/attest`),
};

export default peerService;
