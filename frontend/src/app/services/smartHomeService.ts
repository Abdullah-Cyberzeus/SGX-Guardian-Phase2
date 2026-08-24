import api from './api';

// ── Shared pagination envelope ──────────────────────────────────────────────
export interface Paginated<T> {
  items: T[];
  total_count: number;
  page: number;
  per_page: number;
  total_pages: number;
}

// ── GET /ha/devices, /ha/devices/{id} ───────────────────────────────────────
export interface SmartDevice {
  id: string;
  ha_entity_id: string;
  vendor: string;
  device_type: string;
  room?: string | null;
  friendly_name: string;
  current_state: string;
  health_status: 'online' | 'offline' | 'error' | string;
  last_seen: string;
  /** Raw Home Assistant attributes for this entity. */
  attributes?: Record<string, unknown>;
}

export interface DeviceListFilters {
  page?: number;
  per_page?: number;
  device_type?: string;
  room?: string;
  search?: string;
}

// ── GET /ha/devices/{id}/state ──────────────────────────────────────────────
export interface DeviceStateSnapshot {
  id: string;
  ha_entity_id: string;
  current_state: string;
  health_status: string;
  last_seen: string;
  attributes?: Record<string, unknown>;
  /** Home Assistant's configured temperature unit, e.g. "°F". */
  temperature_unit?: string;
}

// ── GET /ha/devices/{id}/capabilities ───────────────────────────────────────
// Mirrors `src/device/capabilities.rs`. The control UI is rendered entirely from
// this, so an option is only ever offered when the device actually supports it.

export type ParamKind = 'number' | 'enum' | 'bool' | 'rgb' | 'text';

export interface CommandParamSpec {
  name: string;
  label: string;
  kind: ParamKind;
  required: boolean;
  min?: number;
  max?: number;
  step?: number;
  /** Unit to display alongside the input, e.g. "°F", "%", "K". */
  unit?: string;
  /** Permitted values for `enum` params — the device's real modes. */
  options?: string[];
  /** Current value on the device, used to pre-fill the control. */
  default?: unknown;
}

export interface CommandSpec {
  command: string;
  label: string;
  domain: string;
  params: CommandParamSpec[];
}

export interface Reading {
  key: string;
  label: string;
  value: unknown;
  unit?: string | null;
}

export interface ClimateCapabilities {
  hvac_modes: string[];
  preset_modes: string[];
  fan_modes: string[];
  swing_modes: string[];
  min_temp?: number | null;
  max_temp?: number | null;
  target_temp_step?: number | null;
  supports_target_temperature: boolean;
  supports_temperature_range: boolean;
  supports_target_humidity: boolean;
  current_temperature?: number | null;
  target_temperature?: number | null;
  target_temp_low?: number | null;
  target_temp_high?: number | null;
  current_humidity?: number | null;
  hvac_action?: string | null;
  preset_mode?: string | null;
  fan_mode?: string | null;
}

export interface LightCapabilities {
  supported_color_modes: string[];
  effect_list: string[];
  min_color_temp_kelvin?: number | null;
  max_color_temp_kelvin?: number | null;
  brightness?: number | null;
  supports_brightness: boolean;
  supports_color: boolean;
  supports_color_temp: boolean;
}

export interface DeviceCapabilities {
  device_id: string;
  ha_entity_id: string;
  domain: string;
  temperature_unit: string;
  supported_features: number;
  /** When false the device is read-only and no command controls should render. */
  controllable: boolean;
  supported_commands: CommandSpec[];
  readings: Reading[];
  climate?: ClimateCapabilities;
  light?: LightCapabilities;
}

// ── POST /ha/devices/{id}/command ───────────────────────────────────────────
export interface DeviceCommandRequest {
  command: string;
  domain?: string;
  params?: Record<string, unknown>;
}

export interface DeviceCommandResponse {
  status: string;
  command_id: string;
  message: string;
  entity_id?: string;
  command?: string;
  params?: Record<string, unknown> | null;
  accepted_at?: string;
}

// ── POST /ha/devices/sync ───────────────────────────────────────────────────
export interface DeviceSyncResponse {
  status: string;
  total_devices: number;
  message: string;
}

// ── GET /ha/device-health ───────────────────────────────────────────────────
export interface DeviceHealthSummary {
  total_devices: number;
  online_devices: number;
  offline_devices: number;
  error_devices: number;
  healthy_percentage: number;
}

// ── Automations ──────────────────────────────────────────────────────────────
export interface AutomationTrigger {
  type: 'state_changed' | string;
  entity_id: string;
  to_state?: string | null;
}

export interface AutomationAction {
  type: 'command' | string;
  entity_id: string;
  domain: string;
  command: string;
  service_data?: Record<string, unknown> | null;
  /** Backend enum is `FailurePolicy` (serde `rename_all = "lowercase"`). */
  on_failure?: 'continue' | 'abort' | 'log' | 'retry' | string;
}

export interface AutomationRule {
  id: string;
  name: string;
  priority: number;
  enabled: boolean;
  trigger: AutomationTrigger;
  conditions: unknown[];
  actions: AutomationAction[];
}

export interface AutomationListFilters {
  page?: number;
  per_page?: number;
}

export interface AutomationMutationResponse {
  status: string;
  rule_id: string;
  message: string;
}

// ── Telemetry ────────────────────────────────────────────────────────────────
export interface TelemetryEvent {
  entity_id: string;
  state: string;
  attributes: Record<string, unknown>;
  timestamp: string;
}

export interface TelemetryFilters {
  page?: number;
  per_page?: number;
  device_id?: string;
  from?: string;
  to?: string;
}

// ── Notifications ────────────────────────────────────────────────────────────
export interface SmartHomeNotification {
  id: string;
  title: string;
  message: string;
  severity: 'info' | 'warning' | 'critical' | string;
  read: boolean;
  created_at: string;
}

export interface NotificationFilters {
  page?: number;
  per_page?: number;
  unread?: boolean;
  severity?: string;
}

export interface MarkNotificationsReadResponse {
  status: string;
  marked_read_count: number;
  message: string;
}

// ── Vendor integrations ──────────────────────────────────────────────────────
export type IntegrationProvider = 'google_nest' | 'tp_link_kasa';

export interface IntegrationStatus {
  name: string;
  provider?: string;
  status: 'connected' | 'disconnected' | string;
  has_credentials: boolean;
  device_count: number;
  last_synced: string | null;
  error_message: string | null;
  mode?: string;
}

export interface IntegrationsOverview {
  providers: Record<string, IntegrationStatus>;
  total_integrations: number;
}

export interface ConnectOAuthProviderRequest {
  access_token: string;
  refresh_token: string;
  expires_in_secs: number;
}

export interface ConnectKasaRequest {
  mode: 'cloud' | 'local';
  username?: string;
  password?: string;
}

export type ConnectIntegrationRequest = ConnectOAuthProviderRequest | ConnectKasaRequest;

export interface ConnectIntegrationResponse {
  status: string;
  provider: string;
  message: string;
  mode?: string;
  devices_discovered?: number;
}

export interface DisconnectIntegrationResponse {
  message: string;
  provider: string;
  status: string;
}

export const smartHomeService = {
  // ── Devices ──────────────────────────────────────────────────────────────
  listDevices: (filters?: DeviceListFilters): Promise<Paginated<SmartDevice>> =>
    api.get<Paginated<SmartDevice>>('/ha/devices', filters as Record<string, string | number | boolean>),

  getDevice: (id: string): Promise<SmartDevice> =>
    api.get<SmartDevice>(`/ha/devices/${encodeURIComponent(id)}`),

  getDeviceState: (id: string): Promise<DeviceStateSnapshot> =>
    api.get<DeviceStateSnapshot>(`/ha/devices/${encodeURIComponent(id)}/state`),

  /** What this device can actually do, derived from its Home Assistant attributes. */
  getDeviceCapabilities: (id: string): Promise<DeviceCapabilities> =>
    api.get<DeviceCapabilities>(`/ha/devices/${encodeURIComponent(id)}/capabilities`),

  // The backend allows 30s for Home Assistant to complete a service call (a cloud
  // thermostat waits on the vendor round-trip), so the client must not give up first.
  sendDeviceCommand: (id: string, body: DeviceCommandRequest): Promise<DeviceCommandResponse> =>
    api.post<DeviceCommandResponse>(`/ha/devices/${encodeURIComponent(id)}/command`, body, {
      timeoutMs: 35_000,
    }),

  syncDevices: (): Promise<DeviceSyncResponse> =>
    api.post<DeviceSyncResponse>('/ha/devices/sync'),

  getDeviceHealth: (): Promise<DeviceHealthSummary> =>
    api.get<DeviceHealthSummary>('/ha/device-health'),

  // ── Automations ──────────────────────────────────────────────────────────
  listAutomations: (filters?: AutomationListFilters): Promise<Paginated<AutomationRule>> =>
    api.get<Paginated<AutomationRule>>('/ha/automations', filters as Record<string, string | number | boolean>),

  createAutomation: (rule: AutomationRule): Promise<AutomationMutationResponse> =>
    api.post<AutomationMutationResponse>('/ha/automations', rule),

  updateAutomation: (id: string, rule: AutomationRule): Promise<AutomationMutationResponse> =>
    api.put<AutomationMutationResponse>(`/ha/automations/${encodeURIComponent(id)}`, rule),

  deleteAutomation: (id: string): Promise<AutomationMutationResponse> =>
    api.delete<AutomationMutationResponse>(`/ha/automations/${encodeURIComponent(id)}`),

  enableAutomation: (id: string): Promise<AutomationMutationResponse> =>
    api.post<AutomationMutationResponse>(`/ha/automations/${encodeURIComponent(id)}/enable`),

  disableAutomation: (id: string): Promise<AutomationMutationResponse> =>
    api.post<AutomationMutationResponse>(`/ha/automations/${encodeURIComponent(id)}/disable`),

  // ── Telemetry ────────────────────────────────────────────────────────────
  getTelemetry: (filters?: TelemetryFilters): Promise<Paginated<TelemetryEvent>> =>
    api.get<Paginated<TelemetryEvent>>('/ha/telemetry', filters as Record<string, string | number | boolean>),

  getDeviceTelemetry: (
    deviceId: string,
    filters?: Omit<TelemetryFilters, 'device_id'>,
  ): Promise<Paginated<TelemetryEvent>> =>
    api.get<Paginated<TelemetryEvent>>(
      `/ha/telemetry/${encodeURIComponent(deviceId)}`,
      filters as Record<string, string | number | boolean>,
    ),

  // ── Notifications ────────────────────────────────────────────────────────
  listNotifications: (filters?: NotificationFilters): Promise<Paginated<SmartHomeNotification>> =>
    api.get<Paginated<SmartHomeNotification>>('/ha/notifications', filters as Record<string, string | number | boolean>),

  markNotificationsRead: (notificationIds: string[]): Promise<MarkNotificationsReadResponse> =>
    api.post<MarkNotificationsReadResponse>('/ha/notifications/read', { notification_ids: notificationIds }),

  // ── Vendor integrations ──────────────────────────────────────────────────
  listIntegrations: (): Promise<IntegrationsOverview> =>
    api.get<IntegrationsOverview>('/ha/integrations'),

  getIntegrationStatus: (provider: IntegrationProvider | string): Promise<IntegrationStatus> =>
    api.get<IntegrationStatus>(`/ha/integrations/${encodeURIComponent(provider)}/status`),

  getNestAuthUrl: (): Promise<{ auth_url: string; configured: boolean; redirect_uri: string }> =>
    api.get<{ auth_url: string; configured: boolean; redirect_uri: string }>('/ha/integrations/google_nest/oauth/auth_url'),

  connectIntegration: (
    provider: IntegrationProvider | string,
    body: ConnectIntegrationRequest,
  ): Promise<ConnectIntegrationResponse> =>
    api.post<ConnectIntegrationResponse>(`/ha/integrations/${encodeURIComponent(provider)}/connect`, body),

  disconnectIntegration: (provider: IntegrationProvider | string): Promise<DisconnectIntegrationResponse> =>
    api.post<DisconnectIntegrationResponse>(`/ha/integrations/${encodeURIComponent(provider)}/disconnect`),
};

// ── Real-time WebSocket feed ──────────────────────────────────────────────────
export type SmartHomeTopic = 'device_events' | 'telemetry_stream' | 'notifications' | 'rule_triggers' | 'all';

export interface SmartHomeSocketEvent {
  topic: string;
  event: string;
  data: Record<string, unknown>;
}

/**
 * Opens a persistent connection to wss://.../api/v1/ha/ws, subscribes to the
 * given topics, and reconnects with exponential backoff on drop — mirroring
 * openChatSocket's reconnect behavior since Guardian's WS has no ack/replay.
 */
export function openSmartHomeSocket(
  topics: SmartHomeTopic[],
  onEvent: (event: SmartHomeSocketEvent) => void,
  onState?: (connected: boolean) => void,
): () => void {
  let socket: WebSocket | null = null;
  let retryTimer: number | undefined;
  let pingTimer: number | undefined;
  let stopped = false;
  let retryCount = 0;

  const connect = () => {
    if (stopped) return;
    const endpoint = new URL(api.publicUrl('/ha/ws'));
    endpoint.protocol = endpoint.protocol === 'https:' ? 'wss:' : 'ws:';
    const token = api.getToken();
    if (token) endpoint.searchParams.set('access_token', token);

    socket = new WebSocket(endpoint);
    socket.onopen = () => {
      retryCount = 0;
      onState?.(true);
      topics.forEach((topic) => socket?.send(JSON.stringify({ action: 'subscribe', topic })));
      pingTimer = window.setInterval(() => {
        if (socket?.readyState === WebSocket.OPEN) socket.send(JSON.stringify({ action: 'ping' }));
      }, 25_000);
    };
    socket.onmessage = (raw) => {
      try {
        const parsed = JSON.parse(String(raw.data));
        if (parsed?.event === 'pong') return;
        onEvent(parsed as SmartHomeSocketEvent);
      } catch {
        // Ignore malformed frames rather than tearing down the socket.
      }
    };
    socket.onerror = () => socket?.close();
    socket.onclose = () => {
      onState?.(false);
      if (pingTimer) window.clearInterval(pingTimer);
      if (!stopped) {
        const delay = Math.min(15_000, 500 * 2 ** retryCount++);
        retryTimer = window.setTimeout(connect, delay);
      }
    };
  };

  connect();
  return () => {
    stopped = true;
    if (retryTimer) window.clearTimeout(retryTimer);
    if (pingTimer) window.clearInterval(pingTimer);
    socket?.close();
  };
}

export default smartHomeService;
