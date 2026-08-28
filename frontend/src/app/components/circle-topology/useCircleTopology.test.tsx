import { act, useEffect } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { Peer } from "../../services/peerService";
import type { DIDDocumentPeerSummary } from "../../services/didService";
import {
  buildTopologyLinks,
  mergeLiveNodes,
  useCircleTopology,
} from "./useCircleTopology";
import type {
  CircleTopologyCircle,
  CircleTopologyNode,
} from "./types";

const serviceMocks = vi.hoisted(() => ({
  getPeers: vi.fn(),
  getRelays: vi.fn(),
  getLighthouses: vi.fn(),
  getMembers: vi.fn(),
  getDualRole: vi.fn(),
  getDidPeers: vi.fn(),
  getGuardianInfo: vi.fn(),
}));

vi.mock("../../services/peerService", () => ({
  peerService: { getAll: serviceMocks.getPeers },
}));
vi.mock("../../services/relayService", () => ({
  relayService: {
    getList: serviceMocks.getRelays,
    getLighthouseList: serviceMocks.getLighthouses,
    getMemberList: serviceMocks.getMembers,
    getRelayLighthouseList: serviceMocks.getDualRole,
  },
}));
vi.mock("../../services/didService", () => ({
  didService: { getDocumentPeers: serviceMocks.getDidPeers },
}));
vi.mock("../../services/guardianService", () => ({
  guardianService: { getInfo: serviceMocks.getGuardianInfo },
}));

function peer(overrides: Partial<Peer>): Peer {
  return {
    id: "peer-1",
    peerId: "member-a",
    displayName: "Member A",
    deviceName: "Member A",
    ip: "192.168.100.10",
    port: 0,
    status: "verified",
    role: "member",
    memberType: "guardian",
    lastSeen: "2026-08-24T00:00:00Z",
    lastSeenAgo: "Just now",
    attestationCount: 1,
    online: true,
    presenceStatus: "online",
    presenceStale: false,
    callAvailable: true,
    ...overrides,
  };
}

const circles: CircleTopologyCircle[] = [
  {
    id: "circle-a",
    name: "Circle A",
    members: [
      { id: "member-a", name: "Member A", did: "did:guardian:a", status: "online" },
      { id: "pending", name: "Pending Member", pending: true, status: "offline" },
      "String Member",
    ],
  },
];

describe("live topology node model", () => {
  it("merges registries, peers, metrics, roles, and offline circle members", () => {
    const nodes = mergeLiveNodes(
      circles,
      [
        peer({ peerId: "relay-a|device", ip: "192.168.100.20", did: "did:guardian:relay" }),
        peer({ peerId: "alias", ip: "192.168.100.1", online: false, lastSeen: "", lastSeenAgo: "" }),
        peer({ peerId: "unregistered", ip: "", online: false, lastSeen: "recent", lastSeenAgo: "5m ago", status: "pending" }),
        peer({ peerId: "unknown", ip: "", online: false, lastSeen: "", lastSeenAgo: "", status: "failed" }),
      ],
      [
        {
          records: [{ node: "Relay A", overlayIp: "192.168.100.20", active: true, maxPeers: 8, maxBandwidthMbps: 100, currentMbps: 12 }],
          roles: ["relay"],
        },
        {
          records: [{ node: "Lighthouse A", overlayIp: "192.168.100.1", active: true, relayEnabled: false, lighthouseEnabled: true }],
          roles: ["lighthouse"],
        },
        {
          records: [{ node: "Relay A", overlayIp: "192.168.100.20", active: false, relayEnabled: true, lighthouseEnabled: false }],
          roles: ["member"],
        },
      ],
    );

    expect(nodes[0].label).toBe("Lighthouse A");
    expect(nodes[0].primaryLighthouse).toBe(true);
    expect(nodes[0].ip).toBe("192.168.100.1");
    const relay = nodes.find((node) => node.id === "relay-a")!;
    expect(relay.roles).toEqual(["relay", "member"]);
    expect(relay.maxPeers).toBe(8);
    expect(relay.maxBandwidthMbps).toBe(100);
    expect(relay.currentMbps).toBe(12);
    expect(relay.did).toBe("did:guardian:relay");
    expect(nodes.find((node) => node.id === "unregistered")?.presence).toBe("stale");
    expect(nodes.find((node) => node.id === "unknown")?.presence).toBe("unknown");
    expect(nodes.find((node) => node.id === "pending")?.attestation).toBe("pending");
    expect(nodes.find((node) => node.id === "pending")?.presence).toBe("offline");
    expect(nodes.find((node) => node.id === "string-member")?.label).toBe("String Member");
  });

  it("uses member fallbacks and deterministic alphabetical ordering without a lighthouse", () => {
    const nodes = mergeLiveNodes(
      [{ id: "c", name: "C", members: [{ id: "", name: "", did: "did:guardian:z" }] }],
      [peer({ peerId: "Bravo", ip: "10.0.0.2" }), peer({ peerId: "Alpha", ip: "10.0.0.1" })],
      [],
    );
    expect(nodes.map((node) => node.label)).toEqual(["Alpha", "Bravo", "did:guardian:z"]);
    expect(nodes.every((node) => node.roles.includes("member"))).toBe(true);
  });

  it("builds active mesh, relay, and verified-attestation links around the primary lighthouse", () => {
    expect(buildTopologyLinks([])).toEqual([]);
    const nodes: CircleTopologyNode[] = [
      { id: "member", label: "Member", ip: "2", presence: "offline", attestation: "pending", roles: ["member"], lastSeen: "old" },
      { id: "relay", label: "Relay", ip: "3", presence: "online", attestation: "verified", roles: ["relay"], lastSeen: "now" },
      { id: "light", label: "Light", ip: "1", presence: "online", attestation: "verified", roles: ["lighthouse"], primaryLighthouse: true, lastSeen: "now" },
    ];
    const links = buildTopologyLinks(nodes);
    expect(links).toHaveLength(3);
    expect(links.find((link) => link.id === "mesh-light-member")).toMatchObject({ kind: "mesh", active: false });
    expect(links.find((link) => link.id === "mesh-light-relay")).toMatchObject({ kind: "relay", active: true, label: "Relay route" });
    expect(links.find((link) => link.id === "trust-light-relay")).toMatchObject({ kind: "attestation", verified: true });

    const noPrimary = buildTopologyLinks(nodes.map((node) => ({ ...node, primaryLighthouse: false })));
    expect(noPrimary[0].source).toBe("member");
  });
});

type HookValue = ReturnType<typeof useCircleTopology>;
let latest: HookValue | undefined;
let root: Root | undefined;
let container: HTMLDivElement | undefined;

function Probe({ value, onValue }: { value: CircleTopologyCircle[]; onValue: (result: HookValue) => void }) {
  const result = useCircleTopology(value);
  useEffect(() => onValue(result), [onValue, result]);
  return null;
}

async function mountHook(value = circles) {
  container = document.createElement("div");
  document.body.appendChild(container);
  root = createRoot(container);
  await act(async () => {
    root!.render(<Probe value={value} onValue={(result) => { latest = result; }} />);
    await Promise.resolve();
    await Promise.resolve();
  });
  return latest!;
}

function resolveDefaultServices() {
  serviceMocks.getPeers.mockResolvedValue([peer({})]);
  serviceMocks.getRelays.mockResolvedValue({ relays: [] });
  serviceMocks.getLighthouses.mockResolvedValue({ lighthouses: [] });
  serviceMocks.getMembers.mockResolvedValue({ members: [] });
  serviceMocks.getDualRole.mockResolvedValue({ relayLighthouses: [] });
  serviceMocks.getDidPeers.mockResolvedValue({ peers: [] });
  serviceMocks.getGuardianInfo.mockResolvedValue({ id: "local-node", nodeId: "local-node", deviceId: "Local Guardian" });
}

beforeEach(() => {
  latest = undefined;
  Object.values(serviceMocks).forEach((mock) => mock.mockReset());
  resolveDefaultServices();
});

afterEach(async () => {
  if (root) {
    await act(async () => root!.unmount());
  }
  container?.remove();
  root = undefined;
  container = undefined;
  vi.useRealTimers();
});

describe("useCircleTopology", () => {
  it("publishes a successful live snapshot and DID telemetry", async () => {
    const didPeer: DIDDocumentPeerSummary = {
      did: "did:guardian:a",
      node_name: "Member A",
      version: 1,
      status: "active",
      services: 1,
    };
    serviceMocks.getDidPeers.mockResolvedValue({ peers: [didPeer] });
    const value = await mountHook();
    expect(value.loading).toBe(false);
    expect(value.fatalError).toBeNull();
    expect(value.staleWarning).toBeNull();
    expect(value.snapshot.nodes).toHaveLength(3);
    expect(value.snapshot.generatedAt).not.toBe(new Date(0).toISOString());
    expect(value.didPeers).toEqual([didPeer]);
  });

  it("uses available APIs when some topology sources fail", async () => {
    serviceMocks.getRelays.mockRejectedValue(new Error("relay unavailable"));
    serviceMocks.getDidPeers.mockRejectedValue(new Error("DID unavailable"));
    const value = await mountHook();
    expect(value.loading).toBe(false);
    expect(value.fatalError).toBeNull();
    expect(value.snapshot.nodes.some((node) => node.id === "member-a")).toBe(true);
    expect(value.didPeers).toEqual([]);
  });

  it("reports a fatal initial outage and a stale warning after prior success", async () => {
    const initial = await mountHook();
    expect(initial.snapshot.nodes.length).toBeGreaterThan(0);

    Object.values(serviceMocks).forEach((mock) => mock.mockRejectedValue(new Error("topology offline")));
    await act(async () => {
      await latest!.refresh();
    });
    expect(latest!.fatalError).toBeNull();
    expect(latest!.staleWarning).toBe("topology offline");
    expect(latest!.snapshot.nodes.length).toBeGreaterThan(0);
  });

  it("uses a safe default error when all initial failures are non-Error values", async () => {
    Object.values(serviceMocks).forEach((mock) => mock.mockRejectedValue("offline"));
    const value = await mountHook([]);
    expect(value.loading).toBe(false);
    expect(value.fatalError).toBe("The live topology APIs are unreachable.");
    expect(value.snapshot.generatedAt).toBe(new Date(0).toISOString());
    expect(value.snapshot.nodes).toEqual([]);
  });

  it("polls the live registries every ten seconds", async () => {
    vi.useFakeTimers();
    await mountHook();
    expect(serviceMocks.getPeers).toHaveBeenCalledTimes(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(10_000);
    });
    expect(serviceMocks.getPeers).toHaveBeenCalledTimes(2);
    expect(latest!.fatalError).toBeNull();
  });
});
