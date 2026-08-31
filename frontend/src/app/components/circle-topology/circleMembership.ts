import type { CircleTopologyCircle } from "./types";

export const ALL_CIRCLES_ID = "__all__";

export interface CircleMembershipEntry {
  circleId: string;
  circleName: string;
}

export function normalizeNodeId(value: string | null | undefined): string {
  return String(value || "unknown-node").trim().toLowerCase().replace(/[^a-z0-9_-]+/g, "-");
}

function memberNodeKeys(member: Record<string, unknown>): string[] {
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
    .map((value) => normalizeNodeId(String(value || "")))
    .filter((value) => value && value !== "unknown-node");
}

export function buildCircleMembershipIndex(circles: CircleTopologyCircle[]): Map<string, CircleMembershipEntry[]> {
  const index = new Map<string, CircleMembershipEntry[]>();
  for (const circle of circles) {
    for (const rawMember of circle.members ?? []) {
      const member = typeof rawMember === "string" ? { id: rawMember, name: rawMember } : rawMember;
      for (const nodeId of memberNodeKeys(member)) {
        const entries = index.get(nodeId) ?? [];
        if (!entries.some((entry) => entry.circleId === circle.id)) {
          entries.push({ circleId: circle.id, circleName: circle.name });
        }
        index.set(nodeId, entries);
      }
    }
  }
  return index;
}

export function getNodeCircles(index: Map<string, CircleMembershipEntry[]>, nodeId: string): CircleMembershipEntry[] {
  return index.get(normalizeNodeId(nodeId)) ?? [];
}
