import type { GeofenceEvent, GeofenceZone, ThreatAlert } from "../../api/geofence";

export function zoneTypeLabel(kind: GeofenceZone["kind"] | string | undefined): string {
  if (kind === "rf_signature") return "RF Signature";
  if (kind === "coordinate") return "Coordinate";
  return "Not reported";
}

export function locationSourceLabel(source: string | undefined): string {
  if (!source) return "Unavailable";
  if (["reported", "manual", "browser"].includes(source.toLowerCase())) return "Browser / Reported";
  return source.toUpperCase();
}

export function sourceLabel(source: unknown): string {
  if (typeof source !== "string" || !source.trim()) return "Not reported";
  const normalized = source.trim().toLowerCase();
  if (normalized === "rf" || normalized === "rf_signature") return "RF";
  if (normalized === "coordinate" || normalized === "gnss") return normalized === "gnss" ? "GNSS" : "Coordinate";
  if (["reported", "manual", "browser"].includes(normalized)) return "Browser / Reported";
  return source;
}

export function configuredActions(zone: GeofenceZone): string {
  const entry = (zone.automation?.on_entry ?? []).map((action) => action.action);
  const exit = (zone.automation?.on_exit ?? []).map((action) => action.action);
  const parts = [];
  if (zone.on_entry) parts.push(`Entry: ${entry.join(", ") || "None"}`);
  if (zone.on_exit) parts.push(`Exit: ${exit.join(", ") || "None"}`);
  return parts.join(" | ") || "None";
}

export function eventDetails(event: GeofenceEvent, zones: GeofenceZone[]) {
  const zone = zones.find((item) => item.zone_id === event.zone_id);
  const explicitSource = event.detection_source ?? event.source;
  const kind = event.zone_kind
    ?? (event as GeofenceEvent & { kind?: GeofenceZone["kind"] }).kind
    ?? zone?.kind
    ?? (typeof explicitSource === "string" && /(^rf$|rf_signature)/i.test(explicitSource) ? "rf_signature" : undefined);
  return {
    kind,
    zoneName: event.zone_name?.trim() || zone?.name || "Deleted zone",
    source: sourceLabel(explicitSource ?? (kind === "rf_signature" ? "rf" : kind)),
    timestamp: event.at ?? event.timestamp,
    detectionDetails: event.fix_summary?.trim(),
  };
}

function textField(record: ThreatAlert, ...keys: string[]): string | undefined {
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim()) return value;
  }
  return undefined;
}

export function alertDetails(alert: ThreatAlert, zones: GeofenceZone[]) {
  const zoneReferences = [textField(alert, "zone_id"), textField(alert, "dst_ip"), textField(alert, "ref_id")].filter((value): value is string => !!value);
  const zone = zones.find((item) => zoneReferences.some((reference) => reference === item.zone_id || reference.includes(item.zone_id)));
  const zoneId = zoneReferences[0];
  const kind = textField(alert, "zone_kind", "kind") ?? zone?.kind;
  const detectionSource = textField(alert, "detection_source", "source") ?? (kind === "rf_signature" ? "rf" : kind) ?? "Not reported";
  return {
    id: textField(alert, "id") ?? `${textField(alert, "at", "timestamp", "created_at") ?? "alert"}-${textField(alert, "zone_name") ?? zoneId ?? "unknown"}`,
    severity: textField(alert, "severity") ?? "Not reported",
    trigger: textField(alert, "trigger", "signature", "transition", "event", "action", "title", "message") ?? "Not reported",
    zoneName: textField(alert, "zone_name") ?? zone?.name ?? (zoneId ? "Deleted zone" : "Not reported"),
    kind,
    source: sourceLabel(detectionSource),
    timestamp: textField(alert, "at", "timestamp", "created_at") ?? "Not reported",
  };
}
