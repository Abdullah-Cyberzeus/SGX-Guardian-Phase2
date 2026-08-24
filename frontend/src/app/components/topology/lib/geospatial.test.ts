import { describe, expect, it } from "vitest";
import type { GeofenceStatus, GeofenceZone } from "../../../../api/geofence";
import {
  buildMapGuardians,
  buildMapZones,
  projectLngLat,
  radiusMetersToPixels,
  zoneIdForIndex,
} from "./geospatial";
import { GUARDIANS, VIEW_BOX, ZONES } from "./topology";

function zone(overrides: Partial<GeofenceZone> = {}): GeofenceZone {
  return {
    zone_id: "zone-alpha",
    name: "Alpha perimeter",
    kind: "coordinate",
    center_lat: 37.7749,
    center_lng: -122.4194,
    radius_m: 500,
    on_entry: true,
    on_exit: true,
    severity: "high",
    automation: {
      on_entry: [],
      on_exit: [],
      allow_destructive: false,
      min_confidence: 0.8,
    },
    enabled: true,
    created_at: "2026-08-24T00:00:00Z",
    updated_at: "2026-08-24T01:00:00Z",
    ...overrides,
  };
}

const liveStatus: GeofenceStatus = {
  source: "gnss",
  selection_mode: "auto",
  source_reason: "best available fix",
  location: {
    source: "gnss",
    fix: { kind: "coordinate", lat: 91, lng: 181, accuracy_m: 4 },
    updated_at: "2026-08-24T02:00:00Z",
  },
  zones: [
    { zone_id: "zone-alpha", zone_name: "Alpha", enabled: false, inside: true, distance_m: 0, rf_score: 0.9 },
    { zone_id: "zone-bravo", zone_name: "Bravo", enabled: true, inside: false, distance_m: 42, rf_score: null },
    { zone_id: "zone-charlie", zone_name: "Charlie", enabled: true, inside: true, distance_m: null, rf_score: 0.7 },
    { zone_id: "zone-delta", zone_name: "Delta", enabled: true, inside: false },
  ],
};

describe("geospatial projection", () => {
  it("clamps latitude and wraps longitude into the map view box", () => {
    expect(projectLngLat(0, 0)).toEqual({ lat: 0, lng: 0, x: VIEW_BOX.w / 2, y: VIEW_BOX.h / 2 });

    const northeast = projectLngLat(120, 540);
    expect(northeast.lat).toBe(85);
    expect(northeast.lng).toBe(-180);
    expect(northeast.x).toBe(0);
    expect(northeast.y).toBeGreaterThanOrEqual(0);

    const southwest = projectLngLat(-120, -181);
    expect(southwest.lat).toBe(-85);
    expect(southwest.lng).toBe(179);
    expect(southwest.x).toBeLessThanOrEqual(VIEW_BOX.w);
    expect(southwest.y).toBeLessThanOrEqual(VIEW_BOX.h);
  });

  it("converts radii safely and expands longitude radius near the poles", () => {
    expect(radiusMetersToPixels(undefined, 0)).toEqual({ rx: 10, ry: 10 });
    expect(radiusMetersToPixels(Number.NaN, 0)).toEqual({ rx: 10, ry: 10 });
    expect(radiusMetersToPixels(-5, 0)).toEqual({ rx: 10, ry: 10 });

    const equator = radiusMetersToPixels(1_000_000, 0);
    const polar = radiusMetersToPixels(1_000_000, 89.9999);
    expect(polar.rx).toBeGreaterThan(equator.rx);
    expect(polar.ry).toBe(equator.ry);
  });
});

describe("live geofence topology mapping", () => {
  it("uses configured guardian coordinates when no live status exists", () => {
    const guardians = buildMapGuardians(null);
    expect(guardians).toHaveLength(GUARDIANS.length);
    expect(guardians.every((guardian) => guardian.locationSource === "configured")).toBe(true);
    expect(guardians.every((guardian) => guardian.zoneIds.length === 0)).toBe(true);
    expect(guardians[0]).toMatchObject({ id: "sgx-1", lat: 37.7749, lng: -122.4194 });
  });

  it("maps a live location, membership, and evaluated zone health", () => {
    const guardians = buildMapGuardians(liveStatus);
    expect(guardians[0]).toMatchObject({
      lat: 91,
      lng: 181,
      locationSource: "gnss",
      updatedAt: "2026-08-24T02:00:00Z",
      health: "offline",
    });
    expect(guardians[0].cx).toBeCloseTo((1 / 360) * VIEW_BOX.w);
    expect(guardians[1].health).toBe("degraded");
    expect(guardians[2].health).toBe(GUARDIANS[2].health);
    expect(guardians[3].health).toBe(GUARDIANS[3].health);
    expect(guardians.every((guardian) =>
      guardian.zoneIds.join(",") === "zone-alpha,zone-charlie"
    )).toBe(true);
  });

  it("filters invalid zones and combines definitions with live evaluations", () => {
    const definitions = [
      zone(),
      zone({ zone_id: "zone-bravo", name: "Bravo RF", kind: "rf_signature", center_lat: -95, center_lng: 540, radius_m: null, enabled: false }),
      zone({ zone_id: "missing-lat", center_lat: null }),
      zone({ zone_id: "missing-lng", center_lng: null }),
    ];
    const mapped = buildMapZones(definitions, liveStatus);

    expect(mapped).toHaveLength(2);
    expect(mapped[0]).toMatchObject({
      zone_id: "zone-alpha",
      inside: true,
      distance_m: 0,
      rf_score: 0.9,
      severity: "high",
      kind: "coordinate",
      color: ZONES[0].color,
      text: ZONES[0].text,
    });
    expect(mapped[1]).toMatchObject({
      zone_id: "zone-bravo",
      enabled: false,
      inside: false,
      distance_m: 42,
      lat: -85,
      lng: -180,
      color: ZONES[1].color,
    });
    expect(mapped.every((item) => item.rx >= 10 && item.ry >= 10)).toBe(true);
  });

  it("supports absent evaluations and cycles deterministic zone identifiers", () => {
    const mapped = buildMapZones([zone({ zone_id: "unseen" })], null);
    expect(mapped[0].inside).toBeUndefined();
    expect(mapped[0].distance_m).toBeUndefined();
    expect(zoneIdForIndex(0)).toBe("ALPHA");
    expect(zoneIdForIndex(ZONES.length)).toBe("ALPHA");
    expect(zoneIdForIndex(ZONES.length + 1)).toBe("BRAVO");
  });
});
