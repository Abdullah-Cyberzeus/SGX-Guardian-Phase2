// meshDiscoveryService (P3.4) — the `/api/v1/mesh/discovery/*` calls SU03
// (P3.6) drives. Split out from meshService.ts the same way meshService
// itself was split from MeshLifecycleContext.tsx: LAN discovery is its own
// concern (a background scan, a poll loop, a manual-probe fallback), not
// just another circle CRUD call.
import api from './api';

export interface DiscoveredCa {
  circleId: string;
  circleName: string;
  caGuardianId: string;
  fingerprint: string;
  fingerprintWords: string;
  lanEndpoint: string;
  /** Whether the CA's signature (and freshness) on its own descriptor
   * checked out — the *only* thing this is based on. A spoofed advertiser
   * can still get an entry to appear (see backend `mesh::discovery`'s
   * module doc); it just can never make this true. */
  verified: boolean;
  policySummary: PolicySummary | null;
}

export interface PolicySummary {
  approval: 'manual' | 'join_code_auto' | 'join_code_then_manual';
  attestation: 'required' | 'preferred' | 'off';
}

interface BackendDiscoveredCa {
  circle_id: string;
  circle_name: string;
  ca_guardian_id: string;
  fingerprint: string;
  fingerprint_words: string;
  lan_endpoint: string;
  verified: boolean;
  policy_summary: PolicySummary | null;
}

function fromBackend(b: BackendDiscoveredCa): DiscoveredCa {
  return {
    circleId: b.circle_id,
    circleName: b.circle_name,
    caGuardianId: b.ca_guardian_id,
    fingerprint: b.fingerprint,
    fingerprintWords: b.fingerprint_words,
    lanEndpoint: b.lan_endpoint,
    verified: b.verified,
    policySummary: b.policy_summary,
  };
}

export type ScanStatus = 'running' | 'done';

export interface ScanResult {
  status: ScanStatus;
  results: DiscoveredCa[];
}

interface BackendScanResult {
  status: ScanStatus;
  results: BackendDiscoveredCa[];
}

export const meshDiscoveryService = {
  /** Starts a LAN scan (P3.3's 5s beacon collection window plus a fetch +
   * verify per candidate) and returns immediately with an id to poll. */
  startLanScan: async (): Promise<string> => {
    const res = await api.request<{ scan_id: string }>('/mesh/discovery/lan', {
      method: 'POST',
    });
    return res.scan_id;
  },

  /** Polls a scan started above. Callers are expected to keep polling while
   * `status === 'running'`. */
  getLanScan: async (scanId: string): Promise<ScanResult> => {
    const res = await api.request<BackendScanResult>(
      `/mesh/discovery/lan/${encodeURIComponent(scanId)}`,
    );
    return { status: res.status, results: res.results.map(fromBackend) };
  },

  /** Manual entry — fetch and verify one operator-supplied host:port
   * directly, for a LAN that blocks UDP broadcast/multicast. `null` if
   * nothing answered (not thrown — a failed probe is an expected outcome
   * the caller renders inline, not an error state). */
  probe: async (host: string, port: number): Promise<DiscoveredCa | null> => {
    try {
      const res = await api.request<BackendDiscoveredCa>('/mesh/discovery/probe', {
        method: 'POST',
        body: JSON.stringify({ host, port }),
      });
      return fromBackend(res);
    } catch {
      return null;
    }
  },
};

export default meshDiscoveryService;
