import { describe, expect, it } from "vitest";
import {
  buildCircleMembershipIndex,
  getNodeCircles,
  normalizeNodeId,
} from "./circleMembership";
import type { CircleTopologyCircle } from "./types";

describe("circle topology membership", () => {
  it("normalizes names, DIDs, punctuation, whitespace, and missing identifiers", () => {
    expect(normalizeNodeId("  Node A / West  ")).toBe("node-a-west");
    expect(normalizeNodeId("did:guardian:Peer_01")).toBe("did-guardian-peer_01");
    expect(normalizeNodeId(undefined)).toBe("unknown-node");
    expect(normalizeNodeId(null)).toBe("unknown-node");
  });

  it("indexes string and object members across circles without duplicates", () => {
    const circles: CircleTopologyCircle[] = [
      {
        id: "alpha",
        name: "Alpha",
        members: [
          "Node A",
          { id: "node-b", name: "Node B", did: "did:guardian:b" },
          { id: "node-b", name: "Duplicate B" },
        ],
      },
      {
        id: "bravo",
        name: "Bravo",
        members: [
          { id: "Node A", name: "Node A" },
          { id: "", name: "", did: "did:guardian:c" },
        ],
      },
      { id: "empty", name: "Empty" },
    ];

    const index = buildCircleMembershipIndex(circles);
    expect(getNodeCircles(index, "node-a")).toEqual([
      { circleId: "alpha", circleName: "Alpha" },
      { circleId: "bravo", circleName: "Bravo" },
    ]);
    expect(getNodeCircles(index, "node-b")).toEqual([
      { circleId: "alpha", circleName: "Alpha" },
    ]);
    expect(getNodeCircles(index, "did-guardian-c")).toEqual([
      { circleId: "bravo", circleName: "Bravo" },
    ]);
    expect(getNodeCircles(index, "absent")).toEqual([]);
  });
});
