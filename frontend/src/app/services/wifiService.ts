import api, { fetchWithFallback } from './api';

export interface WifiModeResponse {
  mode: 'hotspot_only' | 'client_only' | 'dual';
  module1: {
    role: 'ap';
    ssid: string;
    band: string;
  };
  module2: {
    role: 'client';
    connected_ssid: string | null;
    signal_dbm: number | null;
  };
  security: {
    zero_trust_active: boolean;
    suricata_running: boolean;
  };
}

export interface WifiModePayload {
  mode: string;
  module1?: {
    ssid: string;
    password: string;
    band: string;
  };
  module2?: {
    ssid: string;
    password: string;
  };
}

export interface ScannedNetwork {
  ssid: string;
  signal_dbm: number;
  band: string;
  security: string;
}

export interface WifiScanResponse {
  networks: ScannedNetwork[];
}

export interface WifiClient {
  mac: string;
  hostname: string;
  ip: string;
  signal_dbm: number;
}

export interface WifiClientsResponse {
  clients: WifiClient[];
}

const mockWifiMode: WifiModeResponse = {
  mode: 'dual',
  module1: { role: 'ap', ssid: 'ARMIA', band: '2.4GHz' },
  module2: { role: 'client', connected_ssid: 'HotelGuest', signal_dbm: -62 },
  security: { zero_trust_active: true, suricata_running: true },
};

const mockScanResults: WifiScanResponse = {
  networks: [
    { ssid: 'HotelGuest', signal_dbm: -62, band: '2.4GHz', security: 'WPA2' },
    { ssid: 'FacilityNet-5G', signal_dbm: -55, band: '5GHz', security: 'WPA2' },
    { ssid: 'CorpWifi', signal_dbm: -74, band: '2.4GHz', security: 'WPA2' },
    { ssid: 'PublicAP', signal_dbm: -80, band: '2.4GHz', security: 'Open' },
    { ssid: 'BackupNet', signal_dbm: -69, band: '5GHz', security: 'WPA2' },
  ],
};

const mockClients: WifiClientsResponse = {
  clients: [
    { mac: 'A4:C3:F0:85:7B:2E', hostname: 'PLC-Controller-03', ip: '192.168.10.2', signal_dbm: -58 },
    { mac: '78:D2:94:C1:5F:33', hostname: 'SCADA-Server-01', ip: '192.168.10.3', signal_dbm: -65 },
    { mac: 'B2:4F:C9:12:8A:56', hostname: 'Unknown-B24FC9', ip: '192.168.10.4', signal_dbm: -72 },
  ],
};

export const wifiService = {
  getWifiMode: async (): Promise<WifiModeResponse> => {
    const { data } = await fetchWithFallback(
      () => api.get<WifiModeResponse>('/v1/wifi/mode'),
      mockWifiMode,
      { silent: true }
    );
    return data;
  },

  setWifiMode: async (payload: WifiModePayload): Promise<{ success: boolean; message: string }> => {
    const { data } = await fetchWithFallback(
      () => api.post<{ success: boolean; message: string }>('/v1/wifi/mode', payload),
      { success: true, message: 'Configuration applied' },
      { silent: true }
    );
    return data;
  },

  scanNetworks: async (): Promise<WifiScanResponse> => {
    const { data } = await fetchWithFallback(
      () => api.post<WifiScanResponse>('/v1/wifi/scan'),
      mockScanResults,
      { silent: true }
    );
    return data;
  },

  getConnectedClients: async (): Promise<WifiClientsResponse> => {
    const { data } = await fetchWithFallback(
      () => api.get<WifiClientsResponse>('/v1/wifi/clients'),
      mockClients,
      { silent: true }
    );
    return data;
  },
};

export default wifiService;
