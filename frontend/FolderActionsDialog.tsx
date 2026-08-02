import type { GeofenceStatus, GeofenceZone, StoredLocation } from "../../../../api/geofence";
import { GUARDIANS, VIEW_BOX, ZONES, type Guardian, type NodeHealth, type ZoneId } from "./topology";

export interface MapPoint {
  lat: number;
  lng: number;
  x: number;
  y: number;
}

export interface MapGuardian extends Guardian {
  lat: number;
  lng: number;
  locationSource: string;
  updatedAt?: string;
}

export interface MapZone {
  zone_id: string;
  name: string;
  enabled: boolean;
  inside?: boolean;
  distance_m?: number | null;
  rf_score?: number | null;
  severity?: string;
  kind: string;
  radius_m?: number | null;
  lat: number;
  lng: number;
  cx: number;
  cy: number;
  rx: number;
  ry: number;
  color: string;
  text: string;
}

const FALLBACK_COORDS: Record<string, { lat: number; lng: number }> = {
  "sgx-1": { lat: 37.7749, lng: -122.4194 },
  "sgx-2": { lat: 40.7128, lng: -74.006 },
  "sgx-3": { lat: 51.5072, lng: -0.1276 },
  "sgx-4": { lat: 35.6762, lng: 139.6503 },
};

const ZONE_COLORS = ["#14B8A6", "#3B82F6", "#F59E0B", "#EF4444", "#A855F7", "#22C55E"];

export function projectLngLat(lat: number, lng: number): MapPoint {
  const clampedLat = Math.max(-85, Math.min(85, lat));
  const wrappedLng = ((((lng + 180) % 360) + 360) % 360) - 180;
  return {
    lat: clampedLat,
    lng: wrappedLng,
    x: ((wrappedLng + 180) / 360) * VIEW_BOX.w,
    y: ((90 - clampedLat) / 180) * VIEW_BOX.h,
  };
}

export function radiusMetersToPixels(radiusM: number | null | undefined, lat: number): { rx: number; ry: number } {
  const radius = Math.max(25, Number(radiusM) || 250);
  const metersPerDegreeLat = 111_320;
  const metersPerDegreeLng = Math.max(1, metersPerDegreeLat * Math.cos((lat * Math.PI) / 180));
  const degLat = radius / metersPerDegreeLat;
  const degLng = radius / metersPerDegreeLng;
  return {
    rx: Math.max(10, (degLng / 360) * VIEW_BOX.w),
    ry: Math.max(10, (degLat / 180) * VIEW_BOX.h),
  };
}

function deriveGuardianCoord(guardian: Guardian, location: StoredLocation | null, index: number) {
  if (index === 0 && location?.fix?.kind === "coordinate") {
    return {
      lat: location.fix.lat,
      lng: location.fix.lng,
      source: location.source,
      updatedAt: location.updated_at,
    };
  }
  const fallback = FALLBACK_COORDS[guardian.id] ?? { lat: 15 + index * 12, lng: -110 + index * 70 };
  return { ...fallback, source: "configured" };
}

export function buildMapGuardians(status: GeofenceStatus | null): MapGuardian[] {
  return GUARDIANS.map((guardian, index) => {
    const coord = deriveGuardianCoord(guardian, status?.location ?? null, index);
    const point = projectLngLat(coord.lat, coord.lng);
    const evaluated = status?.zones?.[index];
    const health: NodeHealth | undefined = evaluated?.enabled === false
      ? "offline"
      : evaluated?.inside === false && evaluated.distance_m != null
        ? "degraded"
        : guardian.health;

    return {
      ...guardian,
      cx: point.x,
      cy: point.y,
      lat: coord.lat,
      lng: coord.lng,
      locationSource: coord.source,
      updatedAt: coord.updatedAt,
      health,
    };
  });
}

export function buildMapZones(zones: GeofenceZone[], status: GeofenceStatus | null): MapZone[] {
  return zones
    .filter((zone) => typeof zone.center_lat === "number" && typeof zone.center_lng === "number")
    .map((zone, index) => {
      const point = projectLngLat(zone.center_lat as number, zone.center_lng as number);
      const radius = radiusMetersToPixels(zone.radius_m, point.lat);
      const evaluated = status?.zones.find((z) => z.zone_id === zone.zone_id);
      const paletteZone = ZONES[index % ZONES.length];
      const color = paletteZone?.color ?? ZONE_COLORS[index % ZONE_COLORS.length];
      return {
        zone_id: zone.zone_id,
        name: zone.name,
        enabled: zone.enabled,
        inside: evaluated?.inside,
        distance_m: evaluated?.distance_m,
        rf_score: evaluated?.rf_score,
        severity: zone.severity,
        kind: zone.kind,
        radius_m: zone.radius_m,
        lat: point.lat,
        lng: point.lng,
        cx: point.x,
        cy: point.y,
        rx: radius.rx,
        ry: radius.ry,
        color,
        text: paletteZone?.text ?? color,
      };
    });
}

export function zoneIdForIndex(index: number): ZoneId {
  return ZONES[index % ZONES.length].id;
}
