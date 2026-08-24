import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { peerService, type Peer } from "../../services/peerService";
import { relayService, type RegistryNode, type RelayNode } from "../../services/relayService";
import { didService, type DIDDocumentPeerSummary } from "../../services/didService";
import { normalizeNodeId } from "./circleMembership";
import type {
  CircleTopologyCircle,
  CircleTopologyLink,
  CircleTopologyNode,
  CircleTopologySnapshot,
  TopologyRole,
} from "./types";

const POLL_MS = 10_000;

type RoleRecord = RegistryNode | RelayNode;

export function mergeLiveNodes(
  circles: CircleTopologyCircle[],
  peers: Peer[],
  roleGroups: Array<{ records: RoleRecord[]; roles: TopologyRole[] }>,
): CircleTopologyNode[] {
  const map = new Map<string, CircleTopologyNode>();

  for (const group of roleGroups) {
    for (const record of group.records) {
      const id = normalizeNodeId(record.node);
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
        did: previous?.did,
        maxPeers: "maxPeers" in record ? record.maxPeers : previous?.maxPeers,
        maxBandwidthMbps: "maxBandwidthMbps" in record ? record.maxBandwidthMbps : previous?.maxBandwidthMbps,
        currentMbps: "currentMbps" in record ? record.currentMbps : previous?.currentMbps,
      });
    }
  }

  for (const peer of peers) {
    const probableId = normalizeNodeId(peer.peerId.split("|")[0] || peer.peerId);
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
      did: peer.did || match?.did,
      maxPeers: match?.maxPeers,
      maxBandwidthMbps: match?.maxBandwidthMbps,
      currentMbps: match?.currentMbps,
    });
  }

  // The live peer/relay registries are global. Add every circle's membership
  // records so members remain visible even when they haven't yet appeared in
  // the live peer registry.
  for (const circle of circles) {
    for (const [index, rawMember] of (circle.members ?? []).entries()) {
      const member = typeof rawMember === "string"
        ? { id: rawMember, name: rawMember, did: rawMember }
        : rawMember;
      const id = normalizeNodeId(member.id || member.did || member.name);
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
  }

  const nodes = Array.from(map.values()).sort((a, b) => {
    const rank = (node: CircleTopologyNode) =>
      node.primaryLighthouse ? 0 : node.roles.includes("lighthouse") ? 1 : node.roles.includes("relay") ? 2 : 3;
    return rank(a) - rank(b) || a.label.localeCompare(b.label);
  });
  const firstLighthouse = nodes.find((node) => node.roles.includes("lighthouse"));
  if (firstLighthouse) firstLighthouse.primaryLighthouse = true;
  return nodes;
}

/** Builds mesh/relay/attestation links relative to whichever node subset is
 * currently visible (global roster or one circle's scoped members) — link
 * building must stay a pure function over the visible set, never baked once
 * into a snapshot, or circle-scoping leaves links pointing at an anchor
 * that isn't even in the filtered view. */
export function buildTopologyLinks(nodes: CircleTopologyNode[]): CircleTopologyLink[] {
  if (nodes.length === 0) return [];
  const anchor = nodes.find((node) => node.primaryLighthouse) ?? nodes[0];
  const links: CircleTopologyLink[] = [];
  for (const node of nodes) {
    if (node.id === anchor.id) continue;
    links.push({
      id: `mesh-${anchor.id}-${node.id}`,
      source: anchor.id,
      target: node.id,
      kind: node.roles.includes("relay") ? "relay" : "mesh",
      active: node.presence === "online",
      label: node.roles.includes("relay") ? "Relay route" : "Guardian Mesh",
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
  return links;
}

export function useCircleTopology(circles: CircleTopologyCircle[]) {
  const [nodes, setNodes] = useState<CircleTopologyNode[] | null>(null);
  const [didPeers, setDidPeers] = useState<DIDDocumentPeerSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [fatalError, setFatalError] = useState<string | null>(null);
  const [staleWarning, setStaleWarning] = useState<string | null>(null);
  const [lastSuccessAt, setLastSuccessAt] = useState<string | null>(null);
  const mounted = useRef(true);
  const circlesRef = useRef(circles);
  circlesRef.current = circles;

  useEffect(() => {
    mounted.current = true;
    return () => { mounted.current = false; };
  }, []);

  // refresh() checks `nodes` via this ref (rather than closing over the state
  // value directly) so the callback identity stays stable across polls
  // instead of recreating the interval below on every successful refresh.
  const nodesRef = useRef<CircleTopologyNode[] | null>(null);
  nodesRef.current = nodes;

  const refresh = useCallback(async () => {
    const results = await Promise.allSettled([
      peerService.getAll(),
      relayService.getList(),
      relayService.getLighthouseList(),
      relayService.getMemberList(),
      relayService.getRelayLighthouseList(),
      didService.getDocumentPeers(),
    ]);
    if (!mounted.current) return;

    const failures = results.filter((result) => result.status === "rejected");
    if (failures.length === results.length) {
      const reason = failures[0].status === "rejected" ? failures[0].reason : undefined;
      const message = reason instanceof Error ? reason.message : "The live topology APIs are unreachable.";
      if (nodesRef.current === null) {
        setFatalError(message);
      } else {
        setStaleWarning(message);
      }
      setLoading(false);
      return;
    }

    const peers = results[0].status === "fulfilled" ? results[0].value : [];
    const relays = results[1].status === "fulfilled" ? results[1].value.relays : [];
    const lighthouses = results[2].status === "fulfilled" ? results[2].value.lighthouses : [];
    const members = results[3].status === "fulfilled" ? results[3].value.members : [];
    const dual = results[4].status === "fulfilled" ? results[4].value.relayLighthouses : [];
    const didPeersResult = results[5].status === "fulfilled" ? results[5].value.peers : [];

    const merged = mergeLiveNodes(circlesRef.current, peers, [
      { records: relays, roles: ["relay"] },
      { records: lighthouses, roles: ["lighthouse"] },
      { records: members, roles: ["member"] },
      { records: dual, roles: ["lighthouse", "relay"] },
    ]);

    setNodes(merged);
    setDidPeers(didPeersResult);
    setLastSuccessAt(new Date().toISOString());
    setFatalError(null);
    setStaleWarning(null);
    setLoading(false);
  }, []);

  useEffect(() => {
    void refresh();
    const timer = window.setInterval(() => void refresh(), POLL_MS);
    return () => window.clearInterval(timer);
  }, [refresh]);

  const snapshot = useMemo<CircleTopologySnapshot>(() => ({
    generatedAt: lastSuccessAt ?? new Date(0).toISOString(),
    nodes: nodes ?? [],
  }), [nodes, lastSuccessAt]);

  return { snapshot, didPeers, loading, fatalError, staleWarning, lastSuccessAt, refresh };
}
