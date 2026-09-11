import api from "./api";

export type WifiMode = "off" | "hotspot_only" | "client_only" | "dual";
export type WifiModeRequest = "Off" | "HotspotOnly" | "ClientOnly" | "DualWifi";
export type WifiBand = "2.4GHz" | "5GHz";
export type WifiRuntimeState =
  | "Idle"
  | "ApplyingChange"
  | "HotspotStarting"
  | "HotspotActive"
  | "ClientConnecting"
  | "ClientConnected"
  | "DualStarting"
  | "DualActive"
  | "Error"
  | string;

export interface WifiModeResponse {
  mode: WifiMode;
  status: {
    state: WifiRuntimeState;
    metadata: {
      message: string | null;
      error_code: string | null;
    };
  };
  module1: {
    role: "ap";
    ssid: string;
    channel: number;
  };
  module2: {
    role: "client";
    saved_networks: string[];
  };
  security: {
    zero_trust_active: boolean;
    suricata_running: boolean;
  };
}

export interface WifiNetworkProfile {
  ssid: string;
  bssid: string | null;
  password: string;
}

export interface WifiModePayload {
  mode: WifiModeRequest;
  hotspot: {
    interface: "uap0";
    ssid: string;
    password: string;
    channel: number;
    band: WifiBand;
    client_isolation: boolean;
  };
  uplink: {
    interface: "wlan1";
    networks: WifiNetworkProfile[];
  };
}

export interface WifiModeApplyResponse {
  status: "applying" | "error" | string;
  estimated_downtime_seconds?: number;
  message?: string;
}

export interface ScannedNetwork {
  ssid: string;
  bssid: string;
  signal_percent: number;
  band: WifiBand | string;
  security: string;
}

export interface WifiScanResponse {
  networks: ScannedNetwork[];
}

export interface WifiClient {
  expiry: number;
  mac_address: string;
  ip_address: string;
  hostname: string;
  client_id: string;
}

export interface WifiClientsResponse {
  clients: WifiClient[];
}

export const wifiService = {
  getWifiMode: () => api.get<WifiModeResponse>("/wifi/mode"),
  setWifiMode: (payload: WifiModePayload) =>
    api.post<WifiModeApplyResponse>("/wifi/mode", payload),
  scanNetworks: () => api.get<WifiScanResponse>("/wifi/scan"),
  getConnectedClients: () => api.get<WifiClientsResponse>("/wifi/clients"),
};

export default wifiService;
