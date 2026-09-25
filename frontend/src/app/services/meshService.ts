// meshService (P2.5) — the `/api/v1/mesh/circles` and `/api/v1/mesh/circle`
// calls. Split out from MeshLifecycleContext.tsx (P1.7), which only ever
// needed the lifecycle poll/WS endpoints; circle creation is enough of its
// own concern (a form, a multi-step progress screen) to warrant a service of
// its own, per the plan's own file list for this phase.
import api from './api';

export interface CircleEnrollmentPolicy {
  approval?: 'manual' | 'join_code_auto' | 'join_code_then_manual';
  attestation?: 'required' | 'preferred' | 'off';
  allowed_hw_backends?: string[];
  pcr_baselines?: string[];
  max_members?: number | null;
  cert_validity_days?: number;
  allow_roles?: string[];
}

export interface CreateCircleRequest {
  name: string;
  overlayCidr?: string;
  policy?: CircleEnrollmentPolicy;
}

export interface CreateCircleResult {
  circleId: string;
  circleName: string;
  caFingerprint: string;
  overlayCidr: string;
  overlayIp: string;
  /** The daemon restarts to actually bring Nebula up — see backend
   * mesh::ca's module doc for why. Always true today; kept as a field
   * rather than assumed so the frontend doesn't have to change if that
   * ever stops being how activation works. */
  restarting: boolean;
}

interface BackendCreateCircleResponse {
  circle_id: string;
  circle_name: string;
  ca_fingerprint: string;
  overlay_cidr: string;
  overlay_ip: string;
  restarting: boolean;
}

export interface CircleInfo {
  circleId: string;
  circleName: string;
  role: 'Ca' | 'Member' | string;
  caGuardianId: string;
  caFingerprint: string;
  overlayCidr: string;
  overlayIp: string;
  enrolledVia: string;
  enrolledAt: string;
}

interface BackendCircleView {
  circle_id: string;
  circle_name: string;
  role: string;
  ca_guardian_id: string;
  ca_fingerprint: string;
  overlay_cidr: string;
  overlay_ip: string;
  enrolled_via: string;
  enrolled_at: string;
}

function fromBackendCircle(b: BackendCircleView): CircleInfo {
  return {
    circleId: b.circle_id,
    circleName: b.circle_name,
    role: b.role,
    caGuardianId: b.ca_guardian_id,
    caFingerprint: b.ca_fingerprint,
    overlayCidr: b.overlay_cidr,
    overlayIp: b.overlay_ip,
    enrolledVia: b.enrolled_via,
    enrolledAt: b.enrolled_at,
  };
}

export const meshService = {
  createCircle: async (req: CreateCircleRequest): Promise<CreateCircleResult> => {
    const res = await api.request<BackendCreateCircleResponse>('/mesh/circles', {
      method: 'POST',
      body: JSON.stringify({
        name: req.name,
        overlay_cidr: req.overlayCidr,
        policy: req.policy,
      }),
    });
    return {
      circleId: res.circle_id,
      circleName: res.circle_name,
      caFingerprint: res.ca_fingerprint,
      overlayCidr: res.overlay_cidr,
      overlayIp: res.overlay_ip,
      restarting: res.restarting,
    };
  },

  getCircle: async (): Promise<CircleInfo | null> => {
    try {
      const res = await api.request<BackendCircleView>('/mesh/circle');
      return fromBackendCircle(res);
    } catch {
      // 404 while unenrolled is the expected, normal state here — every
      // other service in this codebase that models an optional resource
      // (e.g. didService when no DID exists yet) follows the same "null,
      // not a thrown error the caller has to unwrap" convention.
      return null;
    }
  },
};

export default meshService;
