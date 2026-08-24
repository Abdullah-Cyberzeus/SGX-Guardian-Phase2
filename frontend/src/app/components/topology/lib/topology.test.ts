import { describe, expect, it } from "vitest";
import {
  CLUSTERS,
  DEVICE_LINKS,
  GUARDIANS,
  MESH,
  OVERLAPS,
  SAMPLE_EVENTS,
  SHAREDS,
  THREATS,
  VIEW_BOX,
  ZONE_DEFS,
  ZONE_DEVICES,
  ZONES,
  buildZoneDevices,
} from "./topology";

describe("static live topology model", () => {
  it("defines a complete four-zone guardian mesh", () => {
    expect(ZONES.map((zone) => zone.id)).toEqual(["ALPHA", "BRAVO", "CHARLIE", "DELTA"]);
    expect(GUARDIANS.map((guardian) => guardian.zone)).toEqual(ZONES.map((zone) => zone.id));
    expect(new Set(GUARDIANS.map((guardian) => guardian.id)).size).toBe(4);
    expect(MESH).toHaveLength(6);
    expect(MESH.filter((edge) => edge.faded)).toHaveLength(2);
    expect(MESH.every((edge) =>
      GUARDIANS.some((guardian) => guardian.id === edge.from) &&
      GUARDIANS.some((guardian) => guardian.id === edge.to)
    )).toBe(true);
    expect(VIEW_BOX).toEqual({ w: 1600, h: 720 });
  });

  it("keeps clusters linked to the guardian for their zone", () => {
    expect(DEVICE_LINKS).toHaveLength(CLUSTERS.length);
    for (const cluster of CLUSTERS) {
      const guardian = GUARDIANS.find((item) => item.zone === cluster.zone)!;
      expect(DEVICE_LINKS).toContainEqual({ deviceId: cluster.id, guardianId: guardian.id });
    }
  });

  it("contains overlap, shared-node, threat, and event data needed by the map", () => {
    expect(OVERLAPS).toHaveLength(3);
    expect(SHAREDS.every((node) => node.zone.includes("∩"))).toBe(true);
    expect(THREATS.map((threat) => threat.sev)).toEqual(["HIGH", "CRITICAL"]);
    expect(SAMPLE_EVENTS.some((event) => event.lvl === "INFO")).toBe(true);
    expect(SAMPLE_EVENTS.some((event) => event.lvl === "WARN")).toBe(true);
    expect(SAMPLE_EVENTS.some((event) => event.lvl === "ERR")).toBe(true);
  });
});

describe("zone device generation", () => {
  it("builds every configured device deterministically with unique identifiers", () => {
    const devices = buildZoneDevices();
    const expectedCount = ZONE_DEFS.reduce((total, definition) => total + definition.count, 0);
    expect(devices).toHaveLength(expectedCount);
    expect(new Set(devices.map((device) => device.id)).size).toBe(expectedCount);
    expect(devices).toEqual(ZONE_DEVICES);
    expect(buildZoneDevices()).toEqual(devices);
  });

  it("places alternating rings around each zone and marks known faults", () => {
    for (const definition of ZONE_DEFS) {
      const devices = ZONE_DEVICES.filter((device) => device.zone === definition.zone);
      expect(devices).toHaveLength(definition.count);
      expect(devices[0]).toMatchObject({
        id: `${definition.prefix}-01`,
        x: definition.cx + 90,
        y: definition.cy,
        color: definition.color,
        stroke: definition.stroke,
      });
    }

    expect(ZONE_DEVICES.filter((device) => device.status === "err").map((device) => device.id)).toEqual([
      "SRV-04",
      "RTU-08",
    ]);
    expect(ZONE_DEVICES.filter((device) => device.status === "ok")).toHaveLength(ZONE_DEVICES.length - 2);
  });
});
