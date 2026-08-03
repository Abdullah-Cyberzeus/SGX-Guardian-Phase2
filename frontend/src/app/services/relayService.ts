import api from './api';

export interface RelayNode {
  node: string;
  overlayIp: string;
  active: boolean;
  relayEnabled?: boolean;
  lighthouseEnabled?: boolean;
  maxPeers: number;
  maxBandwidthMbps: number;
  currentMbps: number;
}

// Lighthouse/member entries omit relay runtime fields (peers/bandwidth)
export interface RegistryNode {
  node: string;
  overlayIp: string;
  active: boolean;
  relayEnabled: boolean;
  lighthouseEnabled: boolean;
}

export interface RelayListResponse {
  relays: RelayNode[];
}

export interface LighthouseListResponse {
  lighthouses: RegistryNode[];
}

export interface MemberListResponse {
  members: RegistryNode[];
}

export interface RelayLighthouseListResponse {
  relayLighthouses: RelayNode[];
}

export interface RelayLimitsResponse {
  ok: boolean;
  node: string;
  maxPeers: number;
  maxBandwidthMbps: number;
  pcrSafe: boolean;
}

export interface RelayToggleResponse {
  ok: boolean;
  node: string;
  enabled: boolean;
  message: string;
}

export const relayService = {
  // GET /api/v1/relay/list
  getList: () => api.get<RelayListResponse>('/relay/list'),

  // GET /api/v1/lighthouse/list
  getLighthouseList: () => api.get<LighthouseListResponse>('/lighthouse/list'),

  // GET /api/v1/member/list
  getMemberList: () => api.get<MemberListResponse>('/member/list'),

  // GET /api/v1/relay-lighthouse/list
  getRelayLighthouseList: () =>
    api.get<RelayLighthouseListResponse>('/relay-lighthouse/list'),

  // POST /api/v1/relay/limits
  setLimits: (node: string, maxPeers: number, maxBandwidthMbps: number) =>
    api.post<RelayLimitsResponse>('/relay/limits', { node, maxPeers, maxBandwidthMbps }),

  // POST /api/v1/relay/toggle
  toggle: (node: string, enabled: boolean) =>
    api.post<RelayToggleResponse>('/relay/toggle', { node, enabled }),

  // POST /api/v1/lighthouse/toggle
  toggleLighthouse: (node: string, enabled: boolean) =>
    api.post<RelayToggleResponse>('/lighthouse/toggle', { node, enabled }),
};

export default relayService;
