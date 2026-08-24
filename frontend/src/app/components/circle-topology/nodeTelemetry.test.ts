import { describe, expect, it } from "vitest";
import { matchDidDocumentPeer } from "./nodeTelemetry";
import type { CircleTopologyNode } from "./types";
import type { DIDDocumentPeerSummary } from "../../services/didService";

const node: CircleTopologyNode = {
  id: "node-a",
  label: "Node A",
  ip: "192.168.100.2",
  presence: "online",
  attestation: "verified",
  roles: ["member"],
  lastSeen: "Just now",
  did: "did:guardian:a",
};

const peers: DIDDocumentPeerSummary[] = [
  { did: "did:guardian:a", node_name: "Different label", version: 2, status: "active", services: 1 },
  { did: "did:guardian:b", node_name: "Node A", version: 1, status: "active", services: 2 },
];

describe("DID topology telemetry matching", () => {
  it("prefers an exact DID over a matching node label", () => {
    expect(matchDidDocumentPeer(node, peers)).toBe(peers[0]);
  });

  it("falls back to node-name equality when the topology node has no matching DID", () => {
    expect(matchDidDocumentPeer({ ...node, did: undefined }, peers)).toBe(peers[1]);
    expect(matchDidDocumentPeer({ ...node, did: "did:guardian:missing" }, peers)).toBe(peers[1]);
  });

  it("returns null instead of inventing telemetry", () => {
    expect(matchDidDocumentPeer({ ...node, did: undefined, label: "Unknown" }, peers)).toBeNull();
    expect(matchDidDocumentPeer(node, [])).toBeNull();
  });
});
