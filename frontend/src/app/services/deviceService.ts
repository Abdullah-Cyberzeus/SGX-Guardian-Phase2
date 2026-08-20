import api from './api';

// ── Paired device from GET /devices/paired ───────────────────────────────────
export interface PairedDevice {
  deviceId: string;
  serial: string;
  did: string;
  status: 'active' | 'pending_bootstrap' | string;
  nodeId: string;
}

function safeTrim(value: unknown): string {
  return String(value ?? '').trim();
}

/** Map raw GET /devices/paired array items (camelCase API fields). */
export function normalizePairedDevice(raw: unknown): PairedDevice | null {
  if (!raw || typeof raw !== 'object') return null;
  const record = raw as Record<string, unknown>;
  const deviceId = safeTrim(record.deviceId);
  if (!deviceId) return null;
  return {
    deviceId,
    serial: safeTrim(record.serial),
    did: safeTrim(record.did),
    status: safeTrim(record.status) || 'active',
    nodeId: safeTrim(record.nodeId),
  };
}

function parsePairedDeviceList(raw: unknown): PairedDevice[] {
  if (!Array.isArray(raw)) return [];
  return raw
    .map(normalizePairedDevice)
    .filter((device): device is PairedDevice => device !== null);
}

// ── Response from GET /devices/pairing-code ──────────────────────────────────
export interface PairingCodeResponse {
  serial: string;
  challenge: string;
  nonce: string;
  expiresAt: number;      // Unix timestamp seconds
  pairingCode: string;    // base64url — shown to physical device to sign
}

// ── Response from POST /devices/pair ────────────────────────────────────────
export interface PairResponse {
  deviceId: string;
  serial: string;
  did: string;
  status: string;
  nodeId: string;
}

export interface OnboardingProofResponse {
  proof: string;
}

// ── Response from POST /devices/{id}/unpair ──────────────────────────────────
export interface UnpairResponse {
  success: boolean;
  message: string;
}

// ── Response from GET /devices/pairing-status ────────────────────────────────
export interface PairingStatus {
  serial: string;
  status: 'pending' | 'completed' | 'failed' | string;
  apiConsumed: boolean;
  bootstrapConsumed: boolean;
  deviceId?: string;
  nodeId?: string;
  did?: string;
}

// ── Response from GET /devices/{deviceId} ────────────────────────────────────
export interface DeviceDetail {
  deviceId: string;
  serial: string;
  did: string;
  nodeId: string;
  status: string;
  bootstrapStatus: string;
  overlayIp?: string;
  attestationEndpoint?: string;
}

export interface PairedGuardianStatus {
  pairing: {
    deviceId: string;
    serial: string;
    status: string;
    pairedAt: string;
    reactivatedAt?: string;
    updatedAt?: string;
    method: string;
  };
  identity: {
    nodeName?: string;
    did: string;
    deviceFingerprint: string;
    dkpVersion?: number;
    didStatus: string;
    didUpdatedAt?: string;
  };
  runtime: { status: string; daemonStatus: string; uptimeSeconds?: number; lastSeen?: string };
  network: { physicalIp: string; interfaceName: string; transport: string };
  nebula: { status: string; overlayIp: string; role: string; trustedPeerCount?: number };
  hardware: { se050Status: string; dkpVersion?: number };
  security: {
    attestationStatus: string;
    attestationEndpoint?: string;
    pcrStatus: string;
    integrityStatus: string;
    secureBootStatus: string;
    policyStatus: string;
    policyDigest?: string;
    trustState: string;
  };
}

// ── Response from GET /discovery/devices ─────────────────────────────────────
export interface DiscoveredDevice {
  device_id: string;
  ip: string;
  mac: string;
  vendor: string;
  hostname: string;
  os_fingerprint: string;
  os_cpe: string[];
  open_ports: any[];
  status: string;
  first_seen: string;
  last_seen: string;
  vuln_triaged: boolean;
}

export const deviceService = {
  /**
   * GET /devices/paired
   * Returns paired Guardians for the authenticated user as a raw array.
   */
  listPairedDevices: async (): Promise<PairedDevice[]> => {
    const raw = await api.get<unknown>('/devices/paired');
    return parsePairedDeviceList(raw);
  },

  /**
   * GET /devices/unpaired
   * Returns unpaired Guardians for the authenticated user as a raw array.
   */
  listUnpairedDevices: async (): Promise<PairedDevice[]> => {
    const raw = await api.get<unknown>('/devices/unpaired');
    return parsePairedDeviceList(raw);
  },

  /**
   * GET /devices/all
   * Returns all Guardian records for stats only.
   */
  listAllDevices: async (): Promise<PairedDevice[]> => {
    const raw = await api.get<unknown>('/devices/all');
    return parsePairedDeviceList(raw);
  },

  listDevices: async (): Promise<PairedDevice[]> => {
    const raw = await api.get<unknown>('/devices/paired');
    return parsePairedDeviceList(raw);
  },

  /**
   * GET /discovery/devices
   * Returns full Guardian device inventory.
   */
  getDiscoveredDevices: (): Promise<DiscoveredDevice[]> =>
    api.get<DiscoveredDevice[]>('/discovery/devices'),

  /**
   * GET /devices/{deviceId}
   * Fetch one paired Guardian with bootstrap and mesh details.
   */
  getDevice: (deviceId: string): Promise<DeviceDetail> =>
    api.get<DeviceDetail>(`/devices/${deviceId}`),

  /** GET /devices/{deviceId}/status — real persisted/runtime Guardian status. */
  getGuardianStatus: (deviceId: string): Promise<PairedGuardianStatus> =>
    api.get<PairedGuardianStatus>(`/devices/${deviceId}/status`),

  /**
   * GET /devices/pairing-code?serial=X&ttl_secs=Y
   * Mints a time-limited pairing challenge for a device serial.
   */
  getPairingCode: (serial: string, ttl_secs?: number): Promise<PairingCodeResponse> => {
    const params: Record<string, string | number | boolean> = { serial };
    if (ttl_secs) params.ttl_secs = ttl_secs;
    return api.get<PairingCodeResponse>('/devices/pairing-code', params);
  },

  /**
   * POST /devices/onboarding-proof
   * Generates a local proof only for the initial onboarding serial flow.
   */
  getOnboardingProof: (pairingCode: string): Promise<OnboardingProofResponse> =>
    api.post<OnboardingProofResponse>('/devices/onboarding-proof', { pairingCode }),

  /**
   * POST /devices/pair
   * Binds a device using a signed pairing proof from the physical device.
   */
  pairDevice: (serial: string, proof: string): Promise<PairResponse> =>
    api.post<PairResponse>('/devices/pair', { serial, proof }),

  /**
   * POST /devices/{id}/unpair
   * Removes a paired device binding.
   */
  unpairDevice: (deviceId: string): Promise<UnpairResponse> =>
    api.post<UnpairResponse>(`/devices/${deviceId}/unpair`),

  /**
   * GET /devices/pairing-status?serial=X
   * Poll pairing and bootstrap progress for a serial.
   */
  getPairingStatus: (serial: string): Promise<PairingStatus> =>
    api.get<PairingStatus>('/devices/pairing-status', { serial }),
};

export default deviceService;
