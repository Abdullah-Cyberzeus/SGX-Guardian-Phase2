import api from './api';

// ── Paired device from GET /devices ─────────────────────────────────────────
export interface PairedDevice {
  deviceId: string;
  serial: string;
  did: string;
  status: 'active' | 'pending_bootstrap' | string;
  nodeId: string;
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
   * GET /devices
   * Returns all paired Guardians for the authenticated user.
   */
  listDevices: (): Promise<PairedDevice[]> =>
    api.get<PairedDevice[]>('/devices'),

  /**
   * GET /discovery/devices
   * Returns full NMAP device inventory.
   */
  getDiscoveredDevices: (): Promise<DiscoveredDevice[]> =>
    api.get<DiscoveredDevice[]>('/discovery/devices'),

  /**
   * GET /devices/{deviceId}
   * Fetch one paired Guardian with bootstrap and mesh details.
   */
  getDevice: (deviceId: string): Promise<DeviceDetail> =>
    api.get<DeviceDetail>(`/devices/${deviceId}`),

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
