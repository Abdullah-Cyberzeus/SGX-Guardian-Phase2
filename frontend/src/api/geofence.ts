import { api } from "./http";

export type GeofenceSource = "auto" | "manual" | "reported" | "rf" | "gnss" | "unavailable";
export type GeofenceSelectionMode = "auto" | "forced";
export type GeofenceZoneKind = "coordinate" | "rf_signature";
export type GeofenceTransition = "entry" | "exit";
export type GeofenceSeverity = "low" | "medium" | "high" | "critical" | string;

export interface CoordinateFix {
  kind: "coordinate";
  lat: number;
  lng: number;
  accuracy_m?: number;
}

export interface StoredLocation {
  source: GeofenceSource;
  fix: CoordinateFix;
  updated_at: string;
}

export interface ZoneAutomationAction {
  action: "raise_alert" | "notify" | "run_scan" | "lock_network" | "emergency_key_rotation" | string;
  severity?: GeofenceSeverity;
}

export interface ZoneAutomation {
  on_entry: ZoneAutomationAction[];
  on_exit: ZoneAutomationAction[];
  allow_destructive: boolean;
  min_confidence: number;
}

export interface RfSignature {
  aps: { bssid: string; signal_dbm: number }[];
  threshold: number;
}

export interface GeofenceZone {
  zone_id: string;
  name: string;
  topology_node_ref?: string | null;
  kind: GeofenceZoneKind;
  center_lat: number | null;
  center_lng: number | null;
  radius_m: number | null;
  rf_signature?: RfSignature | null;
  on_entry: boolean;
  on_exit: boolean;
  severity: GeofenceSeverity;
  automation: ZoneAutomation;
  enabled: boolean;
  created_at: string;
  updated_at: string;
}

export interface EvaluatedZone {
  zone_id: string;
  zone_name: string;
  enabled: boolean;
  inside: boolean;
  distance_m?: number | null;
  rf_score?: number | null;
}

export interface GeofenceStatus {
  source: GeofenceSource;
  selection_mode: GeofenceSelectionMode;
  source_reason: string;
  location: StoredLocation | null;
  zones: EvaluatedZone[];
}

export interface GeofenceEvent {
  id: string;
  zone_id: string;
  zone_name?: string;
  transition: GeofenceTransition;
  fix_summary: string;
  at?: string;
  timestamp?: string;
  severity: GeofenceSeverity;
  zone_kind?: GeofenceZoneKind;
  detection_source?: GeofenceSource | string;
  source?: GeofenceSource | string;
  rf_score?: number | null;
}

export interface ThreatAlert extends Record<string, unknown> {
  id?: string;
  severity?: GeofenceSeverity;
  trigger?: string;
  signature?: string;
  zone_id?: string;
  dst_ip?: string;
  ref_id?: string;
  zone_name?: string;
  zone_kind?: GeofenceZoneKind;
  source?: GeofenceSource | string;
  detection_source?: GeofenceSource | string;
  at?: string;
  timestamp?: string;
  created_at?: string;
}

export type ReportLocationRequest = {
  lat: number;
  lng: number;
  accuracy_m?: number;
};

export type CreateZoneRequest = {
  name: string;
  topology_node_ref?: string | null;
  kind: GeofenceZoneKind;
  center_lat?: number | null;
  center_lng?: number | null;
  radius_m?: number | null;
  rf_signature?: RfSignature | null;
  on_entry?: boolean;
  on_exit?: boolean;
  severity?: GeofenceSeverity;
  automation?: ZoneAutomation;
  enabled?: boolean;
};

export type EditZoneRequest = Partial<CreateZoneRequest>;

export const geofenceApi = {
  status: () => api<GeofenceStatus>("/geofence/status"),
  getLocation: () => api<{ location: StoredLocation | null }>("/geofence/location"),
  reportLocation: (body: ReportLocationRequest) => api<{ location: StoredLocation }>("/geofence/location", {
    method: "POST",
    body: JSON.stringify(body),
  }),
  listZones: () => api<{ count: number; zones: GeofenceZone[] }>("/geofence/zones"),
  createZone: (body: CreateZoneRequest) => api<{ zone: GeofenceZone }>("/geofence/zones", {
    method: "POST",
    body: JSON.stringify(body),
  }),
  editZone: (zoneId: string, body: EditZoneRequest) => api<{ zone: GeofenceZone }>(`/geofence/zones/${encodeURIComponent(zoneId)}`, {
    method: "PATCH",
    body: JSON.stringify(body),
  }),
  deleteZone: (zoneId: string) => api<{ zone: GeofenceZone }>(`/geofence/zones/${encodeURIComponent(zoneId)}`, {
    method: "DELETE",
  }),
  captureRf: (zoneId: string) => api<{ zone: GeofenceZone }>(`/geofence/zones/${encodeURIComponent(zoneId)}/capture-rf`, {
    method: "POST",
  }),
  events: () => api<{ count: number; events: GeofenceEvent[] }>("/geofence/events"),
  alerts: () => api<{ count: number; alerts: ThreatAlert[] }>("/geofence/alerts"),
  getActions: (zoneId: string) => api<{ zone_id: string; automation: ZoneAutomation }>(`/geofence/zones/${encodeURIComponent(zoneId)}/actions`),
  replaceActions: (zoneId: string, body: ZoneAutomation) => api<{ zone_id: string; automation: ZoneAutomation }>(`/geofence/zones/${encodeURIComponent(zoneId)}/actions`, {
    method: "PUT",
    body: JSON.stringify(body),
  }),
  testActions: (body: { zone_id: string; transition: GeofenceTransition; confidence?: number }) => api<{ zone_id: string; automation: ZoneAutomation }>("/geofence/actions/test", {
    method: "POST",
    body: JSON.stringify(body),
  }),
};
