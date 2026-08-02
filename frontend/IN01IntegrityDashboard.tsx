import { useState, useEffect, useCallback, useRef } from 'react';
import { nodeService } from '../services/nodeService';
import { guardianService } from '../services/guardianService';
import { alertService } from '../services/alertService';
import { circleService } from '../services/circleService';
import { dkpService } from '../services/dkpService';
import { pcrService } from '../services/pcrService';
import { attestationService } from '../services/attestationService';
import { policyService } from '../services/policyService';
import { logService } from '../services/logService';
import { peerService } from '../services/peerService';
import { deviceService } from '../services/deviceService';
import { didService } from '../services/didService';
import { transportService } from '../services/transportService';
import { relayService } from '../services/relayService';
import { vcService } from '../services/vcService';
import type { VcShowFilters, VcAuditFilters } from '../services/vcService';
import { vidService } from '../services/vidService';
import { discoveryService } from '../services/discoveryService';
import { threatService } from '../services/threatService';
import type { ThreatAlertsFilters } from '../services/threatService';

interface UseApiDataResult<T> {
  data: T | null;
  loading: boolean;
  error: Error | null;
  source: 'api' | 'error';
  refetch: () => Promise<void>;
}

/**
 * Custom hook for fetching data from backend API (no mock fallback)
 */
export function useApiData<T>(
  apiCall: () => Promise<T>,
  options?: { autoFetch?: boolean; pollingInterval?: number }
): UseApiDataResult<T> {
  const [data, setData] = useState<T | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<Error | null>(null);
  const [source, setSource] = useState<'api' | 'error'>('api');
  const hasFetchedRef = useRef(false);

  const fetchData = useCallback(async (silent = false) => {
    if (!silent) {
      setLoading(true);
      setError(null);
    }

    try {
      const result = await apiCall();
      setData(result);
      setSource('api');
      if (silent) setError(null);
    } catch (err) {
      // On silent polls, keep last good data visible so the user doesn't
      // see a flash of error state when a single poll blips.
      if (!silent) {
        setError(err instanceof Error ? err : new Error('Unknown error'));
        setSource('error');
      }
    } finally {
      if (!silent) setLoading(false);
      hasFetchedRef.current = true;
    }
  }, [apiCall]);

  // refetch() is silent by design: it's only called after a user action
  // (toggle, save, generate, etc.) that already shows its own button/modal
  // loading state. Flipping `loading` to true here would unmount the whole
  // screen content (every screen has `if (loading) return <spinner>`) and
  // throw away scroll position right when the user just acted on something.
  const refetch = useCallback(() => fetchData(true), [fetchData]);

  useEffect(() => {
    if (options?.autoFetch !== false) {
      fetchData(false);
    }
    if (options?.pollingInterval) {
      const id = setInterval(() => {
        // Skip the very first interval tick if initial fetch hasn't landed yet
        if (!hasFetchedRef.current) return;
        // Silent refresh: don't toggle `loading`, so screens don't unmount
        // their content and lose scroll position on every poll.
        fetchData(true);
      }, options.pollingInterval);
      return () => clearInterval(id);
    }
  }, []);

  return { data, loading, error, source, refetch };
}

/**
 * Hook for node/guardian status
 */
export function useNodeStatus() {
  return useApiData(() => nodeService.getStatus());
}

/**
 * Hook for boot status
 */
export function useBootStatus() {
  return useApiData(() => nodeService.getBootStatus(), { pollingInterval: 30000 });
}

/**
 * Hook for DKP keys
 */
export function useDKPStatus() {
  return useApiData(() => dkpService.getStatus(), { pollingInterval: 30000 });
}

/**
 * Hook for PCR status
 */
export function usePCRStatus() {
  return useApiData(() => pcrService.getStatus(), { pollingInterval: 30000 });
}

export function usePCRBaseline() {
  return useApiData(() => pcrService.getBaseline());
}

export function usePCRHistory() {
  return useApiData(() => pcrService.getHistory(), { pollingInterval: 30000 });
}

/**
 * Hook for attestation results
 */
export function useAttestationResults() {
  return useApiData(() => attestationService.getResults(), { pollingInterval: 30000 });
}

/**
 * Hook for policies
 */
export function usePolicies() {
  return useApiData(() => policyService.getAll());
}

/**
 * Hook for logs
 */
export function useLogs(filters?: { level?: string; search?: string; limit?: number }) {
  return useApiData(() => logService.getLogs(filters), { pollingInterval: 10000 });
}

/**
 * Hook for peers
 */
export function usePeers() {
  return useApiData(() => peerService.getAll(), { pollingInterval: 15000 });
}

/**
 * Hook for guardian info (dashboard)
 */
export function useGuardianInfo() {
  return useApiData(() => guardianService.getInfo(), { pollingInterval: 15000 });
}

/**
 * Hook for threat intelligence (security health score)
 * Note: No backend endpoint exists yet - returns empty/default data
 */
export function useThreatIntel() {
  return useApiData(() => guardianService.getThreatIntel(), { pollingInterval: 30000 });
}

/**
 * Hook for alerts
 * Note: No backend endpoint exists yet - returns empty/default data
 */
export function useAlerts(filters?: { severity?: string; status?: string; limit?: number }) {
  return useApiData(() => alertService.getAll(filters), { pollingInterval: 15000 });
}

/**
 * Hook for circles
 * Note: No backend endpoint exists yet - returns empty/default data
 */
export function useCircles() {
  return useApiData(() => circleService.getAll(), { pollingInterval: 30000 });
}

/**
 * Hook for devices
 * Note: No backend endpoint exists yet - returns empty/default data
 */
export function useDevices(filters?: { status?: string; type?: string }) {
  return useApiData(() => deviceService.getAll(filters), { pollingInterval: 15000 });
}

/**
 * Hook for DID status
 */
export function useDIDStatus() {
  return useApiData(() => didService.getStatus(), { pollingInterval: 30000 });
}

/**
 * Hook for DID resolve
 */
export function useDIDResolve() {
  return useApiData(() => didService.resolve(), { pollingInterval: 30000 });
}

/**
 * Hook for transport list (all interfaces)
 */
export function useTransportList(node?: string) {
  return useApiData(() => transportService.getList(node), { pollingInterval: 15000 });
}

/**
 * Hook for active transport status
 */
export function useTransportStatus(node?: string) {
  return useApiData(() => transportService.getStatus(node), { pollingInterval: 15000 });
}

/**
 * Hook for relay node list
 */
export function useRelayList() {
  return useApiData(() => relayService.getList(), { pollingInterval: 10000 });
}

/**
 * Hook for lighthouse-role nodes from the lighthouse registry
 */
export function useLighthouseList() {
  return useApiData(() => relayService.getLighthouseList(), { pollingInterval: 10000 });
}

/**
 * Hook for pure member nodes (no relay, no lighthouse role)
 */
export function useMemberList() {
  return useApiData(() => relayService.getMemberList(), { pollingInterval: 10000 });
}

/**
 * Hook for dual relay+lighthouse nodes
 */
export function useRelayLighthouseList() {
  return useApiData(() => relayService.getRelayLighthouseList(), { pollingInterval: 10000 });
}

/**
 * Hook for local DID Document summary
 */
export function useDIDDocument() {
  return useApiData(() => didService.getDocument(), { pollingInterval: 60000 });
}

/**
 * Hook for raw local DID Document
 */
export function useDIDDocumentRaw() {
  return useApiData(() => didService.getDocumentRaw());
}

/**
 * Hook for cached peer DID Documents
 */
export function useDIDDocumentPeers() {
  return useApiData(() => didService.getDocumentPeers(), { pollingInterval: 15000 });
}

/**
 * Hook for listing VC metadata with optional scope/role/status filters
 */
export function useVCShow(filters?: VcShowFilters) {
  return useApiData(() => vcService.show(filters), { pollingInterval: 30000 });
}

/**
 * Hook for listing issued-VC file metadata
 */
export function useVCFilesIssued() {
  return useApiData(() => vcService.getFilesIssued(), { pollingInterval: 30000 });
}

/**
 * Hook for computed status of a single VC by id
 */
export function useVCStatus(vc_id: string | null) {
  return useApiData(() => vcService.getStatus(vc_id!), { autoFetch: !!vc_id });
}

/**
 * Hook for listing own-VC file metadata
 */
export function useVCFilesOwn() {
  return useApiData(() => vcService.getFilesOwn(), { pollingInterval: 30000 });
}

/**
 * Hook for listing peer-VC file metadata
 */
export function useVCFilesPeers() {
  return useApiData(() => vcService.getFilesPeers(), { pollingInterval: 30000 });
}

/**
 * Hook for the cached VC status-list credential
 */
export function useVCStatusList() {
  return useApiData(() => vcService.getStatusList(), { pollingInterval: 60000 });
}

/**
 * Hook for the VC status-list next-index counter
 */
export function useVCStatusListIndex() {
  return useApiData(() => vcService.getStatusListIndex(), { pollingInterval: 60000 });
}

/**
 * Hook for the VC dashboard summary (issued/own/peers/active/revoked/expired counts)
 */
export function useVCSummary() {
  return useApiData(() => vcService.getSummary(), { pollingInterval: 30000 });
}

/**
 * Hook for VC audit-log entries with optional filters
 */
export function useVCAudit(filters?: VcAuditFilters) {
  return useApiData(() => vcService.getAudit(filters), { pollingInterval: 30000 });
}

/**
 * Hook for the current nonce-bound VirtualID and its input digests
 */
export function useVidShow() {
  return useApiData(() => vidService.show(), { pollingInterval: 30000 });
}

/**
 * Hook for cached peer VirtualIDs
 */
export function useVidPeers() {
  return useApiData(() => vidService.peers(), { pollingInterval: 30000 });
}

/**
 * Hook for the full NMAP discovery device inventory
 */
export function useDiscoveryDevices() {
  return useApiData(() => discoveryService.getDevices(), { pollingInterval: 30000 });
}

/**
 * Hook for the aggregate discovery inventory summary (totals, open ports, risk
 * buckets, last_seen_at). 404s until the first scan has run.
 */
export function useDiscoverySummary() {
  return useApiData(() => discoveryService.getSummary(), { pollingInterval: 30000 });
}

// ── Threat / Suricata IDS ──────────────────────────────────────────────────────

/** Hook for Suricata service state, block mode, and alert/block counts. */
export function useThreatStatus() {
  return useApiData(() => threatService.getStatus(), { pollingInterval: 15000 });
}

/** Hook for parsed Suricata alerts (404s until Suricata produces events). */
export function useThreatAlerts(filters?: ThreatAlertsFilters) {
  return useApiData(() => threatService.getAlerts(filters), { pollingInterval: 15000 });
}

/** Hook for the currently blocked IP list. */
export function useThreatBlocks() {
  return useApiData(() => threatService.getBlocks(), { pollingInterval: 15000 });
}

/** Hook for the Guardian threat configuration. */
export function useThreatConfig() {
  return useApiData(() => threatService.getConfig(), { pollingInterval: 30000 });
}

/**
 * Hook for unauthorized / drifted discovered devices
 */
export function useUnauthorizedDevices() {
  return useApiData(() => discoveryService.getUnauthorized(), { pollingInterval: 30000 });
}

/**
 * Hook for the discovery whitelist document
 */
export function useDiscoveryWhitelist() {
  return useApiData(() => discoveryService.getWhitelist());
}

/**
 * Hook for the scheduled NMAP discovery configuration
 */
export function useDiscoverySchedule() {
  return useApiData(() => discoveryService.getSchedule());
}

/**
 * Hook for the history of scheduled NMAP discovery runs.
 * The backend endpoint may not yet be implemented — callers should treat an
 * error as "no data available" and fall back to derived signals.
 */
export function useDiscoveryScheduleRuns() {
  return useApiData(() => discoveryService.getScheduleRuns(), { pollingInterval: 60000 });
}
