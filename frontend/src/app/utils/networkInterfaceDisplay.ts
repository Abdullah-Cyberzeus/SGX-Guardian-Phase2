import { guardianDisplayText } from "./displayText";

export type InterfaceCategory = "Wireless" | "Network" | "Infrastructure";
export type InterfaceGroup = "WIRELESS CONNECTIONS" | "GUARDIAN NETWORK" | "INFRASTRUCTURE";

export interface InterfaceDisplayMeta {
  displayName: string;
  category: InterfaceCategory;
  group: InterfaceGroup;
  description: string;
}

const KNOWN_INTERFACES: Record<string, InterfaceDisplayMeta> = {
  docker0: {
    displayName: "Container Platform",
    category: "Infrastructure",
    group: "INFRASTRUCTURE",
    description: "Guardian software virtualization layer",
  },
  nebula0: {
    displayName: "Peer Network (P2P)",
    category: "Network",
    group: "GUARDIAN NETWORK",
    description: "Connection to other Guardian devices",
  },
  "guardian mesh interface": {
    displayName: "Peer Network (P2P)",
    category: "Network",
    group: "GUARDIAN NETWORK",
    description: "Connection to other Guardian devices",
  },
  uap0: {
    displayName: "Primary Access Point",
    category: "Wireless",
    group: "WIRELESS CONNECTIONS",
    description: "Main wireless network connection",
  },
  uap1: {
    displayName: "Secondary Access Point",
    category: "Wireless",
    group: "WIRELESS CONNECTIONS",
    description: "Backup wireless network connection",
  },
  vfd0: {
    displayName: "Virtual Network Link",
    category: "Infrastructure",
    group: "INFRASTRUCTURE",
    description: "Internal virtual network interface",
  },
  wfq1: {
    displayName: "Main Data Channel",
    category: "Wireless",
    group: "WIRELESS CONNECTIONS",
    description: "Primary encrypted data transmission",
  },
  wfqn0: {
    displayName: "Standby Channel",
    category: "Wireless",
    group: "WIRELESS CONNECTIONS",
    description: "Backup data transmission channel",
  },
  wfar1: {
    displayName: "Threat Response Link",
    category: "Wireless",
    group: "WIRELESS CONNECTIONS",
    description: "Autonomous response signal channel",
  },
  wewan0: {
    displayName: "Remote Connection",
    category: "Wireless",
    group: "WIRELESS CONNECTIONS",
    description: "External wide-area network connection",
  },
};

export function networkInterfaceDisplay(rawName: string): InterfaceDisplayMeta {
  const normalized = rawName.trim().toLowerCase();
  if (KNOWN_INTERFACES[normalized]) return KNOWN_INTERFACES[normalized];

  if (normalized.startsWith("br-")) {
    return {
      displayName: "Internal Network Bridge",
      category: "Infrastructure",
      group: "INFRASTRUCTURE",
      description: "System network bridge for internal communications",
    };
  }

  if (normalized.includes("cloud") || normalized.includes("sync")) {
    return {
      displayName: "Cloud Sync Channel",
      category: "Wireless",
      group: "GUARDIAN NETWORK",
      description: "Connection to Guardian cloud services",
    };
  }

  return {
    displayName: guardianDisplayText(rawName) || rawName,
    category: normalized.startsWith("wl") || normalized.startsWith("wf") ? "Wireless" : "Network",
    group: normalized.startsWith("wl") || normalized.startsWith("wf") ? "WIRELESS CONNECTIONS" : "GUARDIAN NETWORK",
    description: "Network interface",
  };
}
