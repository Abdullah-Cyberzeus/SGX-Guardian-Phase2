export type PresenceStatus = "online" | "stale" | "offline" | "unknown";
export type AttestationStatus = "verified" | "pending" | "failed" | "never";
export type TopologyRole = "member" | "lighthouse" | "relay";
export type TopologyLinkKind = "mesh" | "attestation" | "relay";

export interface CircleTopologyNode {
  id: string;
  label: string;
  ip: string;
  overlayIp?: string;
  presence: PresenceStatus;
  attestation: AttestationStatus;
  roles: TopologyRole[];
  primaryLighthouse?: boolean;
  lastSeen: string;
  did?: string;
  maxPeers?: number;
  maxBandwidthMbps?: number;
  currentMbps?: number;
}

export interface CircleTopologyLink {
  id: string;
  source: string;
  target: string;
  kind: TopologyLinkKind;
  active: boolean;
  verified?: boolean;
  label?: string;
}

export interface CircleTopologySnapshot {
  generatedAt: string;
  nodes: CircleTopologyNode[];
}

export interface CircleTopologyCircle {
  id: string;
  name: string;
  members?: Array<
    | string
    | {
        id: string;
        name: string;
        status?: string;
        lastSeen?: string;
        did?: string;
        role?: string;
        pending?: boolean;
      }
  >;
}
