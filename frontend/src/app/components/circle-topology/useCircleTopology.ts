import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { peerService, type Peer } from "../../services/peerService";
import { relayService, type RegistryNode, type RelayNode } from "../../services/relayService";
import { didService, type DIDDocumentPeerSummary } from "../../services/didService";
import { guardianService } from "../../services/guardianService";
import { displayLocalGuardianNode, type LocalGuardianIdentity } from "../../utils/localGuardianName";
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

function firstText(...values: unknown[]): string | undefined {
  for (const value of values) {
    const text = String(value || "").trim();
    if (text) return text;
  }
  return undefined;
}

function memberAliases(member: Record<string, unknown>): string[] {
  return [
    member.id,
    member.nodeHint,
    member.node_hint,
    member.deviceId,
    member.device_id,
    member.peerId,
    member.peer_id,
    member.did,
    member.name,
    member.overlayIp,
    member.overlay_ip,
    member.physicalIp,
    member.physical_ip,
    member.ip,
  ]
    .map((value) => normalizeNodeId(firstText(value)))
    .filter((value) => value && value !== "unknown-node");
}

function physicalIpFromPeer(peer: Peer): string | undefined {
  return firstText(peer.physicalIp, peer.ip);
}

function overlayIpFromPeer(peer: Peer): string | undefined {
  return firstText(peer.overlayIp);
}

function physicalIpFromMember(member: Record<string, unknown>): string | undefined {
  return firstText(member.physicalIp, member.physical_ip, member.ip, member.endpointIp, member.endpoint_ip);
}

function overlayIpFromMember(member: Record<string, unknown>): string | undefined {
  return firstText(member.overlayIp, member.overlay_ip, member.nebulaIp, member.nebula_ip, member.overlay);
}

function lastSignalFromMember(member: Record<string, unknown>): string | undefined {
  return firstText(member.lastSeen, member.last_seen, member.lastSignal, member.last_signal, member.updatedAt, member.updated_at);
}

export function mergeLiveNodes(
  circles: CircleTopologyCircle[],
  peers: Peer[],
  roleGroups: Array<{ records: RoleRecord[]; roles: TopologyRole[] }>,
  guardianInfo?: LocalGuardianIdentity | null,
): CircleTopologyNode[] {
  const map = new Map<string, CircleTopologyNode>();

  const rolesFromPeer = (peer: Peer): TopologyRole[] => {
    const raw = String(peer.role || "").trim().toLowerCase();
    if (!raw) return [];
    const roles = new Set<TopologyRole>();
    if (raw.includes("relay")) roles.add("relay");
    if (raw.includes("lighthouse") || raw === "lh_relay" || raw === "relay_lh") roles.add("lighthouse");
    if (raw === "member") roles.add("member");
    return Array.from(roles);
  };

  for (const group of roleGroups) {
    for (const record of group.records) {
      const id = normalizeNodeId(record.node);
      const previous = map.get(id);
      const roles = Array.from(new Set([...(previous?.roles ?? []), ...group.roles]));
      const label = displayLocalGuardianNode(record.node, guardianInfo);
      map.set(id, {
        id,
        label,
        ip: previous?.ip && previous.ip !== "Not reported" ? previous.ip : record.physicalIp || "Not reported",
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
      Array.from(map.values()).find((node) => (
        Boolean(peer.did && node.did === peer.did) ||
        Boolean(peer.ip && (node.ip === peer.ip || node.overlayIp === peer.ip)) ||
        Boolean(peer.overlayIp && node.overlayIp === peer.overlayIp)
      ));
    const id = match?.id ?? probableId;
    const peerRoles = rolesFromPeer(peer);
    const mergedRoles = Array.from(new Set([...(match?.roles ?? []), ...peerRoles]));
    const physicalIp = physicalIpFromPeer(peer) || match?.ip || "Not reported";
    map.set(id, {
      id,
      label: match?.label ?? displayLocalGuardianNode(peer.peerId, guardianInfo),
      ip: physicalIp,
      overlayIp: match?.overlayIp || overlayIpFromPeer(peer),
      presence: peer.online ? "online" : match?.presence ?? (peer.lastSeen ? "stale" : "unknown"),
      attestation: peer.status,
      roles: mergedRoles.length > 0 ? mergedRoles : ["member"],
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
      const record = member as Record<string, unknown>;
      const aliases = memberAliases(record);
      const matched = aliases.map((alias) => map.get(alias)).find(Boolean);
      const id = matched?.id ?? aliases[0] ?? normalizeNodeId(member.id || member.did || member.name);
      const physicalIp = physicalIpFromMember(record);
      const overlayIp = overlayIpFromMember(record);
      const lastSignal = lastSignalFromMember(record);
      if (matched) {
        map.set(id, {
          ...matched,
          label: matched.label || member.name || member.did || `Circle member ${index + 1}`,
          ip: physicalIp || (matched.ip !== "Not reported" ? matched.ip : "Not reported"),
          overlayIp: matched.overlayIp || overlayIp,
          lastSeen: lastSignal || matched.lastSeen || "Not reported",
          did: matched.did || member.did,
        });
        continue;
      }
      map.set(id, {
        id,
        label: member.name || member.did || `Circle member ${index + 1}`,
        ip: physicalIp || "Not reported",
        overlayIp,
        presence: member.status === "online" ? "online" : member.status === "offline" ? "offline" : "unknown",
        attestation: member.pending ? "pending" : "verified",
        roles: ["member"],
        lastSeen: lastSignal || "Not reported",
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
      guardianService.getInfo(),
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
    const guardianInfo = results[6].status === "fulfilled" ? results[6].value : null;

    const merged = mergeLiveNodes(circlesRef.current, peers, [
      { records: relays, roles: ["relay"] },
      { records: lighthouses, roles: ["lighthouse"] },
      { records: members, roles: ["member"] },
      { records: dual, roles: ["lighthouse", "relay"] },
    ], guardianInfo);

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
    window.addEventListener("sgx:guardian-display-updated", refresh);
    return () => {
      window.clearInterval(timer);
      window.removeEventListener("sgx:guardian-display-updated", refresh);
    };
  }, [refresh]);

  const snapshot = useMemo<CircleTopologySnapshot>(() => ({
    generatedAt: lastSuccessAt ?? new Date(0).toISOString(),
    nodes: nodes ?? [],
  }), [nodes, lastSuccessAt]);

  return { snapshot, didPeers, loading, fatalError, staleWarning, lastSuccessAt, refresh };
}
