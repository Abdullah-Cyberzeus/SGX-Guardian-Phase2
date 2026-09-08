import api from './api';

export function formatTimeAgo(isoDate: string): string {
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
  physicalIp?: string;
  overlayIp?: string;
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
    physicalIp?: string;
    physical_ip?: string;
    overlayIp?: string;
    overlay_ip?: string;
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

function syntheticBrowserMemberIp(seed: string): string {
  let hash = 2166136261;
  for (let i = 0; i < seed.length; i += 1) {
    hash ^= seed.charCodeAt(i);
    hash = Math.imul(hash, 16777619);
  }
  const third = ((hash >>> 8) % 254) + 1;
  const fourth = ((hash >>> 16) % 254) + 1;
  return `100.115.${third}.${fourth}`;
}

function usableBrowserMemberName(p: PeersResponse['peers'][number]): string | undefined {
  return [p.displayName, p.fullName, p.deviceName]
    .map((value) => value?.trim())
    .find((value) => value && !["browser", "pwa member device"].includes(value.toLowerCase()));
}

function normalizePeers(peers: PeersResponse['peers']): Peer[] {
  return peers.map((p, i) => {
    const memberType = p.memberType || 'guardian';
    const browserMember = memberType.toLowerCase() === 'browser';
    const browserName = browserMember ? usableBrowserMemberName(p) : undefined;
    const deviceName = browserName || p.deviceName || (browserMember ? 'PWA member' : p.peerId);
    const seed = p.did || p.peerId || String(i);
    return {
      id: `peer_${String(i + 1).padStart(3, '0')}`,
      peerId: p.peerId,
      displayName: browserName || p.displayName || deviceName || p.peerId,
      fullName: p.fullName || browserName,
      deviceName,
      did: p.did,
      ip: p.ip || (browserMember ? syntheticBrowserMemberIp(seed) : ''),
      physicalIp: p.physicalIp || p.physical_ip,
      overlayIp: p.overlayIp || p.overlay_ip,
      port: 0,
      status: (p.status === 'verified' || p.status === 'trusted' || p.status === 'success'
        ? 'verified'
        : p.status === 'failed' ? 'failed' : 'pending') as Peer['status'],
      role: p.role || 'member',
      memberType,
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
    };
  });
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
