import { describe, expect, it } from "vitest";
import { circleMemberIsOnline, countOnlineCircleMembers, type CircleMember } from "./circleService";
import type { Peer } from "./peerService";

const member = (overrides: Partial<CircleMember>): CircleMember => ({
  did: "did:guardian:member",
  role: "member",
  ...overrides,
});

const peer = (overrides: Partial<Peer>): Peer => ({
  id: "peer_001",
  peerId: "node-a",
  displayName: "Node A",
  deviceName: "node-a",
  ip: "",
  port: 0,
  status: "verified",
  role: "member",
  memberType: "guardian",
  lastSeen: "",
  lastSeenAgo: "Unknown",
  attestationCount: 0,
  online: false,
  presenceStatus: "offline",
  presenceStale: false,
  callAvailable: true,
  ...overrides,
});

describe("circle online member counts", () => {
  it("counts members with direct online presence", () => {
    const members = [
      member({ did: "did:guardian:alice", presenceStatus: "online" }),
      member({ did: "did:guardian:bob", online: true }),
      member({ did: "did:guardian:carol", presenceStatus: "offline" }),
      member({ did: "did:guardian:dana", presenceStatus: "hidden", online: true }),
    ];

    expect(countOnlineCircleMembers(members)).toBe(2);
  });

  it("counts guardian members from matching trusted peer presence", () => {
    const peers = new Map<string, Peer>([
      ["did:guardian:alice", peer({ did: "did:guardian:alice", online: true, presenceStatus: "online" })],
      ["node-b", peer({ peerId: "node-b", online: true, presenceStatus: "online" })],
      ["did:guardian:carol", peer({ did: "did:guardian:carol", online: true, presenceStatus: "stale" })],
    ]);

    expect(circleMemberIsOnline(member({ did: "did:guardian:alice" }), peers)).toBe(true);
    expect(circleMemberIsOnline(member({ did: "did:guardian:bob", nodeHint: "node-b" }), peers)).toBe(true);
    expect(circleMemberIsOnline(member({ did: "did:guardian:carol" }), peers)).toBe(false);
  });
});
