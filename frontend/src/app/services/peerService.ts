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
  did?: string;
  ip: string;
  port: number;
  status: 'verified' | 'pending' | 'failed';
  lastSeen: string;
  lastSeenAgo: string;
  attestationCount: number;
  online: boolean;
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
    did?: string;
    ip: string;
    status: string;
    lastSeen: string;
    online?: boolean;
    callAvailable?: boolean;
    callUnavailableReason?: string;
  }>;
  total: number;
  timestamp: string;
}

export const peerService = {
  // GET /api/peers - sgx-guardian peers
  getAll: async (): Promise<Peer[]> => {
    const res = await api.get<PeersResponse>('/peers');
    return (res.peers || []).map((p, i) => ({
      id: `peer_${String(i + 1).padStart(3, '0')}`,
      peerId: p.peerId,
      did: p.did,
      ip: p.ip,
      port: 0,
      status: (p.status === 'verified' || p.status === 'trusted' || p.status === 'success'
        ? 'verified'
        : p.status === 'failed' ? 'failed' : 'pending') as Peer['status'],
      lastSeen: p.lastSeen,
      lastSeenAgo: p.lastSeen ? formatTimeAgo(p.lastSeen) : 'Unknown',
      attestationCount: 0,
      online: p.online ?? Boolean(p.lastSeen),
      callAvailable: p.callAvailable ?? true,
      callUnavailableReason: p.callUnavailableReason,
    }));
  },

  // GET /api/peers/:id
  getById: (id: string) => api.get<Peer>(`/peers/${id}`),

  // POST /api/peers/:id/attest
  attest: (id: string) => api.post<AttestResponse>(`/peers/${id}/attest`),
};

export default peerService;
