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
import { auditLogService } from '../services/auditLogService';
import type { AuditLogsFilters } from '../services/auditLogService';
import { peerService, type Peer } from '../services/peerService';
import { didService } from '../services/didService';
import { transportService } from '../services/transportService';
import { relayService } from '../services/relayService';
import { vcService } from '../services/vcService';
import type { VcShowFilters, VcAuditFilters } from '../services/vcService';
import { vidService } from '../services/vidService';
import { discoveryService } from '../services/discoveryService';
import { threatService } from '../services/threatService';
import type { ThreatAlertsFilters } from '../services/threatService';
import { dusageService } from '../services/dusageService';
import { ruleService } from '../services/ruleService';
import { smartHomeService } from '../services/smartHomeService';
import { useAuth } from '../contexts/AuthContext';
import { isMemberRole } from '../utils/authorization';

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
 * Hook for audit logs (hash-chained audit trail)
 */
export function useAuditLogs(filters?: AuditLogsFilters) {
  return useApiData(() => auditLogService.getAuditLogs(filters), { pollingInterval: 10000 });
}

/**
 * Hook for peers
 */
export function usePeers() {
  return useApiData(() => peerService.getAll(), { pollingInterval: 15000 });
}

/**
 * Member-safe peer/contact roster: Nebula-attested Guardian peers merged with
 * browser Circle members (who never appear in the Nebula trust registry).
 * Shared by useCommunicationPeers and anything else (e.g. ChatUnreadContext)
 * that needs the same complete "who can I chat/call with" list as the chat
 * screens render, rather than the Guardian-only `peerService.getAll()` list.
 */
export async function fetchCommunicationPeers(isMember: boolean, guardianDid?: string): Promise<Peer[]> {
  if (isMember) return peerService.getContacts();
  // The raw Nebula trust registry (`/peers`) has no notion of presence
  // privacy at all — it's a network-level reachability probe. The
  // member-safe `/pwa/contacts` endpoint (open to admin/owner sessions too)
  // is the one place that actually applies each contact's `hide_presence`
  // preference, and it does so for *every* contact type — browser Circle
  // members and other paired Guardian devices alike (see
  // `pwa.rs::contacts`). Overlay all of it by DID rather than re-deriving
  // presence from the ungated raw peer list, and rather than restricting
  // the overlay to browser members only.
  const [peers, contacts] = await Promise.all([
    peerService.getAll(),
    peerService.getContacts().catch(() => [] as Peer[]),
  ]);
  const byDid = new Map(peers.filter((peer) => peer.did).map((peer) => [peer.did!, peer]));
  for (const contact of contacts) {
    if (!contact.did || contact.did === guardianDid) continue;
    byDid.set(contact.did, contact);
  }
  return [...byDid.values()];
}

/** Member-safe peers for chat, calls, and Contacts. */
export function useCommunicationPeers() {
  const { session } = useAuth();
  const member = isMemberRole(session?.user.role);
  return useApiData(
    () => fetchCommunicationPeers(member, session?.guardianDid),
    { pollingInterval: 15000 },
  );
}

/**
 * Hook for the alert-rules automation engine's rule registry
 */
export function useRules() {
  return useApiData(() => ruleService.getAll(), { pollingInterval: 20000 });
}

/**
 * Hook for the alert-rules execution history
 */
export function useRuleExecutions(limit?: number) {
  return useApiData(() => ruleService.getExecutions(limit), { pollingInterval: 20000 });
}

/**
 * Hook for the current-period data usage snapshot (bandwidth, categories, quota)
 */
export function useDusageCurrent() {
  return useApiData(() => dusageService.getCurrent(), { pollingInterval: 15000 });
}

/**
 * Hook for completed-period data usage history
 */
export function useDusageHistory() {
  return useApiData(() => dusageService.getHistory(), { pollingInterval: 30000 });
}

/**
 * Hook for the data usage quota (null when no quota has been set)
 */
export function useDusageQuota() {
  return useApiData(() => dusageService.getQuota(), { pollingInterval: 30000 });
}

/**
 * Hook for guardian info (dashboard)
 */
export function useGuardianInfo() {
  return useApiData(() => guardianService.getInfo(), { pollingInterval: 15000 });
}

/**
 * Hook for threat intelligence (security health score)
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
 */
export function useCircles() {
  return useApiData(() => circleService.getAll(), { pollingInterval: 30000 });
}

export function useCircleInviteInbox() {
  return useApiData(() => circleService.getInviteInbox(), { pollingInterval: 15000 });
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

// ── Smart Home / Home Assistant bridge (SGX Guardian) ──────────────────────

/** Hook for the broad device registry — screens filter/paginate client-side. */
export function useSmartHomeDevices() {
  return useApiData(() => smartHomeService.listDevices({ page: 1, per_page: 200 }), { pollingInterval: 15000 });
}

/** Hook for system-wide device health aggregate (total/online/offline/error). */
export function useSmartHomeDeviceHealth() {
  return useApiData(() => smartHomeService.getDeviceHealth(), { pollingInterval: 15000 });
}

/** Hook for the vendor integration registry (Google Nest, TP-Link Kasa). */
export function useSmartHomeIntegrations() {
  return useApiData(() => smartHomeService.listIntegrations(), { pollingInterval: 20000 });
}

/** Hook for automation rules — small rule sets, so screens filter/paginate client-side. */
export function useSmartHomeAutomations() {
  return useApiData(() => smartHomeService.listAutomations({ page: 1, per_page: 100 }), { pollingInterval: 20000 });
}

/** Hook for the notification feed — screens filter unread/severity client-side. */
export function useSmartHomeNotifications() {
  return useApiData(() => smartHomeService.listNotifications({ page: 1, per_page: 100 }), { pollingInterval: 15000 });
}

/**
 * Hook for the history of scheduled NMAP discovery runs.
 * The backend endpoint may not yet be implemented — callers should treat an
 * error as "no data available" and fall back to derived signals.
 */
export function useDiscoveryScheduleRuns() {
  return useApiData(() => discoveryService.getScheduleRuns(), { pollingInterval: 60000 });
}
