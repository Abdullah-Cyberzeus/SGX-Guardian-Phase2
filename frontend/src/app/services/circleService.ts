import api from './api';

export type CircleStatus = 'active' | 'inactive' | 'archived';
export type CircleRole = 'owner' | 'member';

export interface CircleMember {
  did: string;
  id?: string;
  name?: string;
  email?: string;
  role: CircleRole;
  vcId?: string;
  issuerDid?: string;
  permissions?: string[];
  joinDate?: string;
  expirationDate?: string;
  membershipStatus?: 'active' | 'suspended' | 'revoked' | string;
  lifecycleState?: 'active' | 'expired' | 'revoked' | string;
  nodeHint?: string;
  status?: 'online' | 'offline' | string;
  joinedAt?: string;
}

export interface Circle {
  id: string;
  name: string;
  description?: string;
  ownerDid?: string;
  members?: CircleMember[];
  memberCount?: number;
  onlineCount?: number;
  status: CircleStatus;
  createdAt?: string;
  updatedAt?: string;
  settings?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface CircleInvite {
  id: string;
  token?: string;
  url?: string;
  qrPayload?: string;
  targetDid?: string;
  issuerDid?: string;
  circleId?: string;
  circleName?: string;
  state?: string;
  delivered?: boolean;
  deliveryError?: string | null;
  role?: CircleRole;
  status?: string;
  expiresAt?: string;
  createdAt?: string;
  createdBy?: string;
  [key: string]: unknown;
}

export interface JoinPreview {
  valid: boolean;
  circle?: Partial<Circle>;
  inviter?: string;
  role?: CircleRole;
  expiresAt?: string;
  message?: string;
  [key: string]: unknown;
}

export interface ParsedInviteMaterial {
  token: string;
  ownerHost: string;
}

export interface CircleMutationResult {
  success?: boolean;
  message?: string;
  circle?: Circle;
  [key: string]: unknown;
}

const encode = (value: string) => encodeURIComponent(value);

function listFrom<T>(payload: unknown, key: string): T[] {
  if (Array.isArray(payload)) return payload as T[];
  if (payload && typeof payload === 'object') {
    const record = payload as Record<string, unknown>;
    if (Array.isArray(record[key])) return record[key] as T[];
    if (record.data && typeof record.data === 'object') {
      const nested = record.data as Record<string, unknown>;
      if (Array.isArray(nested[key])) return nested[key] as T[];
    }
  }
  return [];
}

function entityFrom<T>(payload: unknown, key: string): T {
  if (payload && typeof payload === 'object' && key in payload) {
    return (payload as Record<string, T>)[key];
  }
  return payload as T;
}

function normalizeCircle(value: any): Circle {
  return {
    ...value,
    id: String(value?.id || value?.circleId || value?.circle_id || ''),
    name: String(value?.name || 'Unnamed Circle'),
    description: String(value?.description || ''),
    ownerDid: value?.ownerDid || value?.owner_did,
    status: String(value?.status || 'active').toLowerCase() as CircleStatus,
    createdAt: value?.createdAt || value?.created_at,
    updatedAt: value?.updatedAt || value?.updated_at,
  };
}

function normalizeMember(value: any): CircleMember {
  const did = String(value?.did || '');
  const nodeHint = value?.nodeHint || value?.node_hint;
  const lifecycle = String(value?.lifecycleState || value?.lifecycle_state || value?.state || value?.status || 'unknown').toLowerCase();
  const rawId = did.split(':').pop() || '';
  const fallbackName = rawId ? `Guardian ${rawId.slice(0, 6)}…${rawId.slice(-4)}` : 'Guardian member';
  return {
    ...value,
    id: String(value?.id || did || nodeHint || 'unknown-member'),
    name: String(value?.name || nodeHint || fallbackName),
    did,
    role: String(value?.role || 'member').toLowerCase() as CircleRole,
    nodeHint: nodeHint ? String(nodeHint) : undefined,
    status: lifecycle,
    joinedAt: value?.joinDate || value?.join_date || value?.joinedAt,
  };
}

function normalizeInvite(value: any): CircleInvite {
  const inviteBody = value?.invite && typeof value.invite === 'object' ? value.invite : {};
  const merged = { ...inviteBody, ...value };
  const circle = merged?.circle || {};
  let compactToken = merged?.token || merged?.tokenB64 || merged?.token_b64;
  const rawInviteId = merged?.id || merged?.inviteId || merged?.invite_id;
  if (!compactToken && merged?.proof && rawInviteId) {
    const bytes = new TextEncoder().encode(JSON.stringify(inviteBody && Object.keys(inviteBody).length ? inviteBody : merged));
    let binary = '';
    bytes.forEach((byte) => { binary += String.fromCharCode(byte); });
    compactToken = btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }
  return {
    ...merged,
    id: String(rawInviteId || ''),
    token: compactToken,
    url: merged?.url || merged?.link,
    qrPayload: merged?.qrPayload || merged?.qr_payload,
    targetDid: merged?.targetDid || merged?.target_did,
    issuerDid: merged?.issuerDid || merged?.issuer_did || merged?.createdBy || merged?.created_by,
    circleId: merged?.circleId || merged?.circle_id || circle?.id || circle?.circle_id,
    circleName: merged?.circleName || merged?.circle_name || circle?.name,
    state: String(merged?.state || merged?.status || '').toLowerCase(),
    delivered: typeof merged?.delivered === 'boolean' ? merged.delivered : undefined,
    deliveryError: merged?.deliveryError || merged?.delivery_error || null,
    role: String(merged?.role || 'member').toLowerCase() as CircleRole,
    expiresAt: merged?.expiresAt || merged?.expires_at,
    createdAt: merged?.createdAt || merged?.receivedAt || merged?.received_at || merged?.issuedAt || merged?.issued_at,
  };
}

export function parseInviteMaterial(value: string): ParsedInviteMaterial {
  const trimmed = value.trim();
  if (!trimmed) return { token: '', ownerHost: '' };
  if (trimmed.startsWith('sgx-guardian://')) {
    const url = new URL(trimmed);
    return {
      token: url.searchParams.get('token') || '',
      ownerHost: url.searchParams.get('owner_host') || '',
    };
  }
  return { token: trimmed, ownerHost: '' };
}

export const circleService = {
  // 1. GET /circles
  async getAll(): Promise<Circle[]> {
    const circles = listFrom<any>(await api.get<unknown>('/circles'), 'circles').map(normalizeCircle);
    return Promise.all(circles.map(async (circle) => {
      try {
        const members = listFrom<any>(await api.get<unknown>(`/circles/${encode(circle.id)}/members`), 'members').map(normalizeMember);
        const activeMembers = members.filter((member) => member.status !== 'revoked' && member.status !== 'expired');
        return { ...circle, members: activeMembers, memberCount: activeMembers.length, onlineCount: 0 };
      } catch {
        return { ...circle, members: [], memberCount: 0, onlineCount: 0 };
      }
    }));
  },

  // 2. POST /circles
  async create(data: { name: string; description?: string; settings?: Record<string, unknown> }): Promise<Circle> {
    return normalizeCircle(entityFrom<any>(await api.post<unknown>('/circles', data), 'circle'));
  },

  // 3. GET /circles/{id}
  async getById(id: string): Promise<Circle> {
    return normalizeCircle(entityFrom<any>(await api.get<unknown>(`/circles/${encode(id)}`), 'circle'));
  },

  // 4. PATCH /circles/{id}
  async update(id: string, data: { name?: string; description?: string; settings?: Record<string, unknown> }): Promise<Circle> {
    return normalizeCircle(entityFrom<any>(await api.patch<unknown>(`/circles/${encode(id)}`, data), 'circle'));
  },

  // 5. POST /circles/{id}/archive
  archive: (id: string) => api.post<CircleMutationResult>(`/circles/${encode(id)}/archive`),

  // POST /circles/{id}/unarchive
  unarchive: (id: string) => api.post<CircleMutationResult>(`/circles/${encode(id)}/unarchive`),

  // DELETE /circles/{id}
  remove: (id: string) => api.delete<CircleMutationResult>(`/circles/${encode(id)}`),

  // 6. GET /circles/{id}/members
  async getMembers(id: string): Promise<CircleMember[]> {
    return listFrom<any>(await api.get<unknown>(`/circles/${encode(id)}/members`), 'members').map(normalizeMember);
  },

  // 7. POST /circles/{id}/members
  addMember: (id: string, data: { did: string; role?: CircleRole }) =>
    api.post<CircleMutationResult>(`/circles/${encode(id)}/members`, data),

  // 8. PATCH /circles/{id}/members/{did}
  updateMember: (id: string, did: string, data: { role: CircleRole }) =>
    api.patch<CircleMutationResult>(`/circles/${encode(id)}/members/${encode(did)}`, data),

  // 9. DELETE /circles/{id}/members/{did}
  removeMember: (id: string, did: string) =>
    api.delete<CircleMutationResult>(`/circles/${encode(id)}/members/${encode(did)}`),

  // 10. GET /circles/{id}/invites
  async getInvites(id: string): Promise<CircleInvite[]> {
    return listFrom<any>(await api.get<unknown>(`/circles/${encode(id)}/invites`), 'invites').map(normalizeInvite);
  },

  // 11. POST /circles/{id}/invites
  async createInvite(id: string, data: { targetDid?: string; role?: CircleRole; expiresInMinutes?: number; maxUses?: number; ownerHost?: string; deliver?: boolean }): Promise<CircleInvite> {
    const body = data.targetDid
      ? { target_did: data.targetDid, role: data.role || 'member', deliver: data.deliver ?? false }
      : {
          role: data.role,
          expires_in_minutes: data.expiresInMinutes,
          max_uses: data.maxUses,
          owner_host: data.ownerHost,
          deliver: data.deliver,
        };
    const payload = await api.post<any>(`/circles/${encode(id)}/invites`, body);
    return normalizeInvite({ ...payload?.invite, ...payload });
  },

  async deliverInvite(id: string, inviteId: string): Promise<CircleInvite> {
    const payload = await api.post<any>(`/circles/${encode(id)}/invites/${encode(inviteId)}/deliver`);
    return normalizeInvite({ ...payload?.invite, ...payload });
  },

  // GET /circles/invites/inbox
  async getInviteInbox(): Promise<CircleInvite[]> {
    return listFrom<any>(await api.get<unknown>('/circles/invites/inbox'), 'invites').map(normalizeInvite);
  },

  acceptInvite: (inviteId: string) =>
    api.post<CircleMutationResult>(`/circles/invites/${encode(inviteId)}/accept`),

  rejectInvite: (inviteId: string) =>
    api.post<CircleMutationResult>(`/circles/invites/${encode(inviteId)}/reject`),

  // 12. DELETE /circles/{id}/invites/{invite_id}
  revokeInvite: (id: string, inviteId: string) =>
    api.delete<CircleMutationResult>(`/circles/${encode(id)}/invites/${encode(inviteId)}`),

  // 13. POST /circles/join/preview
  async previewJoin(token: string): Promise<JoinPreview> {
    const result = await api.post<any>('/circles/join/preview', { token_b64: token });
    return {
      ...result,
      valid: result?.status === 'success',
      circle: { id: result?.circle_id, name: result?.circle_name },
      inviter: result?.issuer_did,
      role: String(result?.role || 'member').toLowerCase() as CircleRole,
      expiresAt: result?.expires_at,
    };
  },

  // 14. POST /circles/join
  join: (token: string, ownerHost: string) => api.post<CircleMutationResult>('/circles/join', { token_b64: token, owner_host: ownerHost }),

  // 15. POST /circles/redeem
  redeem: (joinRequest: unknown) => api.post<CircleMutationResult>('/circles/redeem', joinRequest),
};

export default circleService;
