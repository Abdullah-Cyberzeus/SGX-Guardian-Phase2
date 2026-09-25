// enrollService (P4.6/P4.7/P4.8/P4.9) — LAN enrollment v2: joining a
// discovered circle, the CA-side request store/approval API, and join
// codes. Split from meshService.ts/meshDiscoveryService.ts the same way
// those were split from MeshLifecycleContext.tsx — each of these three
// files is its own phase's own concern.
import api from './api';

export interface JoinRequest {
  lanEndpoint: string;
  circleId: string;
  joinCode?: string;
}

export const joinService = {
  /** Kicks off the joiner flow in the background — progress shows up on
   * `GET /api/v1/mesh/lifecycle` (`useMeshLifecycle()`), the same way
   * Create Circle's own restart is observed. */
  join: async (req: JoinRequest): Promise<void> => {
    await api.request('/mesh/join', {
      method: 'POST',
      body: JSON.stringify({
        lan_endpoint: req.lanEndpoint,
        circle_id: req.circleId,
        join_code: req.joinCode || undefined,
      }),
    });
  },
};

export interface PolicyCheck {
  name: string;
  passed: boolean;
  detail: string;
}

export interface PolicyReport {
  checks: PolicyCheck[];
}

export type EnrollRequestState = 'pending' | 'approved' | 'rejected' | 'expired';

export interface EnrollRequest {
  requestId: string;
  state: EnrollRequestState;
  guardianId: string;
  subjectDid: string;
  hwBackend: string;
  hasJoinCode: boolean;
  autoApproved: boolean;
  sourceIp: string;
  createdAt: string;
  expiresAt: string;
  decidedAt: string | null;
  decisionReason: string | null;
  policyReport: PolicyReport;
}

interface BackendEnrollRequest {
  request_id: string;
  state: EnrollRequestState;
  submission: {
    guardian_id: string;
    hw_backend: string;
    join_code: string | null;
    did_document: { id: string };
  };
  policy_report: PolicyReport;
  auto_approved: boolean;
  source_ip: string;
  created_at: string;
  expires_at: string;
  decided_at: string | null;
  decision_reason: string | null;
}

function fromBackendRequest(b: BackendEnrollRequest): EnrollRequest {
  return {
    requestId: b.request_id,
    state: b.state,
    guardianId: b.submission.guardian_id,
    subjectDid: b.submission.did_document.id,
    hwBackend: b.submission.hw_backend,
    hasJoinCode: Boolean(b.submission.join_code),
    autoApproved: b.auto_approved,
    sourceIp: b.source_ip,
    createdAt: b.created_at,
    expiresAt: b.expires_at,
    decidedAt: b.decided_at,
    decisionReason: b.decision_reason,
    policyReport: b.policy_report,
  };
}

export const enrollRequestService = {
  list: async (): Promise<EnrollRequest[]> => {
    const res = await api.request<BackendEnrollRequest[]>('/mesh/enroll-requests');
    return res.map(fromBackendRequest);
  },
  approve: async (requestId: string): Promise<void> => {
    await api.request(`/mesh/enroll-requests/${encodeURIComponent(requestId)}/approve`, {
      method: 'POST',
    });
  },
  reject: async (requestId: string, reason?: string): Promise<void> => {
    await api.request(`/mesh/enroll-requests/${encodeURIComponent(requestId)}/reject`, {
      method: 'POST',
      body: JSON.stringify({ reason }),
    });
  },
};

export interface JoinCode {
  id: string;
  circleId: string;
  note: string | null;
  autoApproveRole: string | null;
  createdAt: string;
  expiresAt: string;
  usedAt: string | null;
  usedByGuardianId: string | null;
}

interface BackendJoinCode {
  id: string;
  circle_id: string;
  note: string | null;
  auto_approve_role: string | null;
  created_at: string;
  expires_at: string;
  used_at: string | null;
  used_by_guardian_id: string | null;
}

function fromBackendJoinCode(b: BackendJoinCode): JoinCode {
  return {
    id: b.id,
    circleId: b.circle_id,
    note: b.note,
    autoApproveRole: b.auto_approve_role,
    createdAt: b.created_at,
    expiresAt: b.expires_at,
    usedAt: b.used_at,
    usedByGuardianId: b.used_by_guardian_id,
  };
}

export interface CreatedJoinCode {
  id: string;
  code: string;
  expiresAt: string;
}

export const joinCodeService = {
  create: async (ttlMinutes: number, note?: string, autoApprove?: boolean): Promise<CreatedJoinCode> => {
    const res = await api.request<{ id: string; code: string; expires_at: string }>(
      '/mesh/join-codes',
      {
        method: 'POST',
        body: JSON.stringify({
          ttl_minutes: ttlMinutes,
          note: note || undefined,
          auto_approve_role: autoApprove ? 'member' : undefined,
        }),
      },
    );
    return { id: res.id, code: res.code, expiresAt: res.expires_at };
  },
  list: async (): Promise<JoinCode[]> => {
    const res = await api.request<BackendJoinCode[]>('/mesh/join-codes');
    return res.map(fromBackendJoinCode);
  },
  revoke: async (id: string): Promise<void> => {
    await api.request(`/mesh/join-codes/${encodeURIComponent(id)}`, { method: 'DELETE' });
  },
};
