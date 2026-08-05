import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { peerService, type Peer } from "../../services/peerService";
import { relayService, type RegistryNode, type RelayNode } from "../../services/relayService";
import type {
  CircleTopologyCircle,
  CircleTopologyLink,
  CircleTopologyNode,
  CircleTopologySnapshot,
  TopologyRole,
} from "./types";

const POLL_MS = 10_000;

type RoleRecord = RegistryNode | RelayNode;

function normalizeId(value: string | null | undefined) {
  return String(value || "unknown-node").trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
}

function fixtureSnapshot(circle: CircleTopologyCircle): CircleTopologySnapshot {
  const members = circle.members ?? [];
  const memberNodes: CircleTopologyNode[] = members.map((rawMember, index) => {
    const member =
      typeof rawMember === "string"
        ? { id: rawMember, name: rawMember, status: "unknown", lastSeen: "Not reported" }
        : rawMember;
    const roles: TopologyRole[] =
      index === 0 ? ["lighthouse", "relay"] : index === 1 ? ["lighthouse"] : index === 2 ? ["relay"] : ["member"];
    const presence =
      member.pending ? "unknown" : member.status === "online" ? "online" : member.status === "offline" ? "offline" : "unknown";
    return {
      id: normalizeId(member.id || member.did || member.name),
      label: member.name || member.did || `Circle member ${index + 1}`,
      ip: `10.${20 + Number(circle.id.replace(/\D/g, "").slice(-1) || 1)}.0.${index + 10}`,
      overlayIp: `192.168.100.${index + 1}`,
      presence,
      attestation: member.pending ? "pending" : index === members.length - 1 && presence === "offline" ? "never" : "verified",
      roles,
      primaryLighthouse: index === 0,
      lastSeen: member.lastSeen || (presence === "online" ? "Just now" : "Unknown"),
      did: member.did,
      maxPeers: roles.includes("relay") ? 12 : undefined,
      maxBandwidthMbps: roles.includes("relay") ? 25 : undefined,
      currentMbps: roles.includes("relay") ? (index === 0 ? 4.8 : 1.7) : undefined,
    };
  });

  // Frontend-only demonstration nodes. These exist exclusively in the fallback
  // snapshot shown when the live node APIs return no usable topology data.
  // They are never written to, or returned by, any backend service.
  const demoPrefix = normalizeId(circle.id || "circle");
  const demoNodes: CircleTopologyNode[] = [
    {
      id: `${demoPrefix}-demo-primary`,
      label: "Aegis Lighthouse",
      ip: "10.90.0.10",
      overlayIp: "192.168.250.10",
      presence: "online",
      attestation: "verified",
      roles: ["lighthouse", "relay"],
      primaryLighthouse: true,
      lastSeen: "Just now",
      did: `did:sgx:${demoPrefix}:aegis`,
      maxPeers: 64,
      maxBandwidthMbps: 100,
      currentMbps: 18.6,
    },
    {
      id: `${demoPrefix}-demo-lighthouse-west`,
      label: "West Trust Beacon",
      ip: "10.90.0.11",
      overlayIp: "192.168.250.11",
      presence: "online",
      attestation: "verified",
      roles: ["lighthouse"],
      lastSeen: "4 seconds ago",
      did: `did:sgx:${demoPrefix}:west`,
    },
    {
      id: `${demoPrefix}-demo-lighthouse-dr`,
      label: "DR Lighthouse",
      ip: "10.90.0.12",
      overlayIp: "192.168.250.12",
      presence: "stale",
      attestation: "pending",
      roles: ["lighthouse"],
      lastSeen: "2 minutes ago",
      did: `did:sgx:${demoPrefix}:recovery`,
    },
    {
      id: `${demoPrefix}-demo-relay-core`,
      label: "Core Relay 01",
      ip: "10.90.1.20",
      overlayIp: "192.168.251.20",
      presence: "online",
      attestation: "verified",
      roles: ["relay"],
      lastSeen: "Health check passed",
      maxPeers: 32,
      maxBandwidthMbps: 50,
      currentMbps: 12.4,
    },
    {
      id: `${demoPrefix}-demo-relay-edge`,
      label: "Edge Relay 02",
      ip: "10.90.1.21",
      overlayIp: "192.168.251.21",
      presence: "offline",
      attestation: "failed",
      roles: ["relay"],
      lastSeen: "18 minutes ago",
      maxPeers: 16,
      maxBandwidthMbps: 25,
      currentMbps: 0,
    },
    {
      id: `${demoPrefix}-demo-member-plc`,
      label: "PLC Gateway 07",
      ip: "10.90.2.31",
      overlayIp: "192.168.252.31",
      presence: "online",
      attestation: "verified",
      roles: ["member"],
      lastSeen: "Just now",
      did: `did:sgx:${demoPrefix}:plc-07`,
    },
    {
      id: `${demoPrefix}-demo-member-camera`,
      label: "Camera Node 14",
      ip: "10.90.2.32",
      overlayIp: "192.168.252.32",
      presence: "unknown",
      attestation: "never",
      roles: ["member"],
      lastSeen: "Not reported",
    },
  ];

  // Preserve real Circle members in fixture mode, while using the demonstration
  // primary as the stable visual anchor. Remove accidental ID collisions.
  const demoIds = new Set(demoNodes.map((node) => node.id));
  const nodes = [
    ...demoNodes,
    ...memberNodes
      .filter((node) => !demoIds.has(node.id))
      .map((node) => ({ ...node, primaryLighthouse: false })),
  ];

  const primary = nodes.find((node) => node.primaryLighthouse) ?? nodes[0];
  const relay = nodes.find((node) => node.roles.includes("relay"));
  const links: CircleTopologyLink[] = [];
  if (primary) {
    for (const node of nodes) {
      if (node.id === primary.id) continue;
      links.push({
        id: `mesh-${primary.id}-${node.id}`,
        source: primary.id,
        target: node.id,
        kind: relay && node.presence === "offline" ? "relay" : "mesh",
        active: node.presence === "online",
        label: node.presence === "online" ? "Nebula mesh" : "Last known route",
      });
      if (node.attestation === "verified") {
        links.push({
          id: `trust-${primary.id}-${node.id}`,
          source: primary.id,
          target: node.id,
          kind: "attestation",
          active: true,
          verified: true,
          label: "Mutual attestation",
        });
      }
    }
  }

  return {
    circleId: circle.id,
    generatedAt: new Date().toISOString(),
    source: "fixture",
    nodes,
    links,
  };
}

function mergeLiveSnapshot(
  circle: CircleTopologyCircle,
  peers: Peer[],
  roleGroups: Array<{ records: RoleRecord[]; roles: TopologyRole[] }>,
): CircleTopologySnapshot | null {
  const map = new Map<string, CircleTopologyNode>();

  for (const group of roleGroups) {
    for (const record of group.records) {
      const id = normalizeId(record.node);
      const previous = map.get(id);
      const roles = Array.from(new Set([...(previous?.roles ?? []), ...group.roles]));
      map.set(id, {
        id,
        label: record.node,
        ip: previous?.ip || record.overlayIp || "Not reported",
        overlayIp: record.overlayIp,
        presence: record.active ? "online" : "offline",
        attestation: previous?.attestation ?? "never",
        roles,
        primaryLighthouse: previous?.primaryLighthouse ?? false,
        lastSeen: record.active ? "Health check passed" : "Health check failed",
        maxPeers: "maxPeers" in record ? record.maxPeers : previous?.maxPeers,
        maxBandwidthMbps: "maxBandwidthMbps" in record ? record.maxBandwidthMbps : previous?.maxBandwidthMbps,
        currentMbps: "currentMbps" in record ? record.currentMbps : previous?.currentMbps,
      });
    }
  }

  for (const peer of peers) {
    const probableId = normalizeId(peer.peerId.split("|")[0] || peer.peerId);
    const match =
      map.get(probableId) ??
      Array.from(map.values()).find((node) => node.ip === peer.ip || node.overlayIp === peer.ip);
    const id = match?.id ?? probableId;
    map.set(id, {
      id,
      label: match?.label ?? peer.peerId,
      ip: peer.ip || match?.ip || "Not reported",
      overlayIp: match?.overlayIp,
      presence: peer.online ? "online" : match?.presence ?? (peer.lastSeen ? "stale" : "unknown"),
      attestation: peer.status,
      roles: match?.roles ?? ["member"],
      primaryLighthouse: match?.primaryLighthouse,
      lastSeen: peer.lastSeenAgo || match?.lastSeen || "Unknown",
      maxPeers: match?.maxPeers,
      maxBandwidthMbps: match?.maxBandwidthMbps,
      currentMbps: match?.currentMbps,
    });
  }

  // The live peer/relay registries are global. Add the selected Circle's
  // membership records so its members remain visible even when a member has
  // not yet appeared in the live peer registry.
  for (const [index, rawMember] of (circle.members ?? []).entries()) {
    const member = typeof rawMember === "string"
      ? { id: rawMember, name: rawMember, did: rawMember }
      : rawMember;
    const id = normalizeId(member.id || member.did || member.name);
    if (map.has(id)) continue;
    map.set(id, {
      id,
      label: member.name || member.did || `Circle member ${index + 1}`,
      ip: "Not reported",
      presence: member.status === "online" ? "online" : member.status === "offline" ? "offline" : "unknown",
      attestation: member.pending ? "pending" : "verified",
      roles: ["member"],
      lastSeen: member.lastSeen || "Not reported",
      did: member.did,
    });
  }

  if (map.size === 0) return null;
  const nodes = Array.from(map.values()).sort((a, b) => {
    const rank = (node: CircleTopologyNode) =>
      node.primaryLighthouse ? 0 : node.roles.includes("lighthouse") ? 1 : node.roles.includes("relay") ? 2 : 3;
    return rank(a) - rank(b) || a.label.localeCompare(b.label);
  });

  const firstLighthouse = nodes.find((node) => node.roles.includes("lighthouse"));
  if (firstLighthouse) firstLighthouse.primaryLighthouse = true;
  const anchor = firstLighthouse ?? nodes[0];
  const links: CircleTopologyLink[] = [];
  for (const node of nodes) {
    if (node.id === anchor.id) continue;
    links.push({
      id: `mesh-${anchor.id}-${node.id}`,
      source: anchor.id,
      target: node.id,
      kind: node.roles.includes("relay") ? "relay" : "mesh",
      active: node.presence === "online",
      label: node.roles.includes("relay") ? "Relay route" : "Nebula mesh",
    });
    if (node.attestation === "verified") {
      links.push({
        id: `trust-${anchor.id}-${node.id}`,
        source: anchor.id,
        target: node.id,
        kind: "attestation",
        active: true,
        verified: true,
        label: "Verified trust",
      });
    }
  }

  return { circleId: circle.id, generatedAt: new Date().toISOString(), source: "live", nodes, links };
}

export function useCircleTopology(circle: CircleTopologyCircle) {
  const fallback = useMemo(() => fixtureSnapshot(circle), [circle]);
  const [snapshot, setSnapshot] = useState<CircleTopologySnapshot>(fallback);
  const [loading, setLoading] = useState(true);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const refresh = useCallback(async () => {
    const results = await Promise.allSettled([
      peerService.getAll(),
      relayService.getList(),
      relayService.getLighthouseList(),
      relayService.getMemberList(),
      relayService.getRelayLighthouseList(),
    ]);
    if (!mounted.current) return;

    const peers = results[0].status === "fulfilled" ? results[0].value : [];
    const relays = results[1].status === "fulfilled" ? results[1].value.relays : [];
    const lighthouses = results[2].status === "fulfilled" ? results[2].value.lighthouses : [];
    const members = results[3].status === "fulfilled" ? results[3].value.members : [];
    const dual = results[4].status === "fulfilled" ? results[4].value.relayLighthouses : [];
    const live = mergeLiveSnapshot(circle, peers, [
      { records: relays, roles: ["relay"] },
      { records: lighthouses, roles: ["lighthouse"] },
      { records: members, roles: ["member"] },
      { records: dual, roles: ["lighthouse", "relay"] },
    ]);

    if (live) {
      setSnapshot(live);
      setConnected(true);
      setError(null);
    } else {
      setSnapshot(fallback);
      setConnected(false);
      setError("Live node APIs are unavailable. Showing the circle test snapshot.");
    }
    setLoading(false);
  }, [circle, fallback]);

  useEffect(() => {
    setSnapshot(fallback);
    setLoading(true);
    void refresh();
    const timer = window.setInterval(() => void refresh(), POLL_MS);
    return () => window.clearInterval(timer);
  }, [fallback, refresh]);

  return { snapshot, loading, connected, error, refresh };
}
