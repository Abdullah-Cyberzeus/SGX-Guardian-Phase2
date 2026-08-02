export type ZoneId = "ALPHA" | "BRAVO" | "CHARLIE" | "DELTA";
export type NodeHealth = "healthy" | "degraded" | "critical" | "offline";

export interface Zone {
  id: ZoneId;
  cx: number; cy: number; rx: number; ry: number;
  color: string;
  text: string;
  textHex: string;
  bgFill: string;
  haloId: string;
  title: string;
  subtitle: string;
  labelX: number; labelY: number;
  textAnchor?: "start" | "end" | "middle";
}

export const ZONES: Zone[] = [
  {
    id: "ALPHA", cx: 320, cy: 280, rx: 290, ry: 210,
    color: "#14B8A6", text: "#5eead4", textHex: "#14B8A6",
    bgFill: "rgba(20,184,166,0.04)", haloId: "haloAlpha",
    title: "CIRCLE OF TRUST · ALPHA",
    subtitle: "INDUSTRIAL · WEST · 47 DEVICES",
    labelX: 60, labelY: 56,
  },
  {
    id: "BRAVO", cx: 820, cy: 240, rx: 270, ry: 200,
    color: "#9333EA", text: "#d8b4fe", textHex: "#9333EA",
    bgFill: "rgba(147,51,234,0.04)", haloId: "haloBravo",
    title: "CIRCLE OF TRUST · BRAVO",
    subtitle: "IT CORE · 31 DEVICES",
    labelX: 640, labelY: 44,
  },
  {
    id: "CHARLIE", cx: 700, cy: 540, rx: 330, ry: 190,
    color: "#F59E0B", text: "#fcd34d", textHex: "#F59E0B",
    bgFill: "rgba(245,158,11,0.04)", haloId: "haloCharlie",
    title: "CIRCLE OF TRUST · CHARLIE",
    subtitle: "OT / SCADA · SOUTH · 62 DEVICES",
    labelX: 380, labelY: 700,
  },
  {
    id: "DELTA", cx: 1230, cy: 360, rx: 240, ry: 200,
    color: "#3B82F6", text: "#bfdbfe", textHex: "#3B82F6",
    bgFill: "rgba(59,130,246,0.04)", haloId: "haloDelta",
    title: "CIRCLE OF TRUST · DELTA",
    subtitle: "REMOTE SITE · EAST · 19 DEVICES",
    labelX: 1430, labelY: 160, textAnchor: "end",
  },
];

export interface Overlap { cx: number; cy: number; tag: string; gradId: string; tx: number; ty: number; w: number; tcolor: string; }
export const OVERLAPS: Overlap[] = [
  { cx: 580, cy: 260, tag: "ALPHA ∩ BRAVO", gradId: "overlapAB", tx: 540, ty: 200, w: 106, tcolor: "#e0f2fe" },
  { cx: 760, cy: 400, tag: "BRAVO ∩ CHARLIE", gradId: "overlapBC", tx: 706, ty: 468, w: 120, tcolor: "#fef3c7" },
  { cx: 1030, cy: 460, tag: "CHARLIE ∩ DELTA", gradId: "overlapCD", tx: 978, ty: 528, w: 124, tcolor: "#dbeafe" },
];

export interface Cluster {
  id: string;
  zone: ZoneId;
  cx: number; cy: number;
  label: string;
  sub?: string;
  subAbove?: boolean;
  name: string;
  health?: NodeHealth;
}

export const CLUSTERS: Cluster[] = [
  { id: "plc", zone: "ALPHA", cx: 140, cy: 200, label: "PLC×12", sub: "PROGRAMMABLE", name: "PLC Bank · ALPHA" },
  { id: "sen", zone: "ALPHA", cx: 140, cy: 380, label: "SEN×18", sub: "SENSOR ARRAY", name: "Sensor Mesh · ALPHA" },
  { id: "hmi", zone: "ALPHA", cx: 320, cy: 100, label: "HMI×9", sub: "OPERATOR PANELS", subAbove: true, name: "HMI Stations · ALPHA" },
  { id: "cam", zone: "ALPHA", cx: 240, cy: 460, label: "CAM×8", sub: "SURVEILLANCE", name: "Cameras · ALPHA" },
  { id: "srv", zone: "BRAVO", cx: 700, cy: 110, label: "SRV×8", sub: "APP SERVERS", subAbove: true, name: "App Servers · BRAVO" },
  { id: "sw",  zone: "BRAVO", cx: 900, cy: 110, label: "SW×6", sub: "SWITCHES", subAbove: true, name: "Core Switches · BRAVO" },
  { id: "wks", zone: "BRAVO", cx: 1010, cy: 200, label: "WKS×11", sub: "WORKSTATIONS", subAbove: true, name: "Workstations · BRAVO" },
  { id: "hst", zone: "BRAVO", cx: 970, cy: 320, label: "HST×6", sub: "HISTORIAN", name: "Historian · BRAVO", health: "degraded" },
  { id: "rtu", zone: "CHARLIE", cx: 450, cy: 620, label: "RTU×15", sub: "REMOTE TERMINAL", name: "RTU Cabinets · CHARLIE" },
  { id: "ana", zone: "CHARLIE", cx: 560, cy: 660, label: "ANA×12", name: "Analyzers · CHARLIE" },
  { id: "act", zone: "CHARLIE", cx: 820, cy: 650, label: "ACT×22", sub: "ACTUATORS", name: "Actuators · CHARLIE" },
  { id: "mtr", zone: "CHARLIE", cx: 940, cy: 620, label: "MTR×13", sub: "SMART METERS", name: "Smart Meters · CHARLIE" },
  { id: "pmp", zone: "CHARLIE", cx: 540, cy: 450, label: "PMP×7", name: "Pumps · CHARLIE" },
  { id: "gw",  zone: "DELTA", cx: 1380, cy: 240, label: "GW×4", sub: "GATEWAYS", subAbove: true, name: "Edge Gateways · DELTA" },
  { id: "rtr", zone: "DELTA", cx: 1420, cy: 380, label: "RTR×5", name: "Routers · DELTA", health: "critical" },
  { id: "sen2",zone: "DELTA", cx: 1380, cy: 500, label: "SEN×10", sub: "FIELD SENSORS", name: "Field Sensors · DELTA" },
];

export interface SharedNode {
  id: string;
  name: string;
  role: string;
  zone: string;
  ip: string;
  proto: string;
  cx: number; cy: number;
  ringA: string; ringB: string;
  sub: string;
  subAbove?: boolean;
  health?: NodeHealth;
}

export const SHAREDS: SharedNode[] = [
  { id: "core-switch-01", name: "Core-Switch-01", role: "Shared L2/L3 switch · ALPHA ∩ BRAVO", zone: "ALPHA ∩ BRAVO", ip: "10.10.0.21", proto: "LACP / 802.1Q", cx: 580, cy: 260, ringA: "#14B8A6", ringB: "#9333EA", sub: "SHARED · L2 / L3" },
  { id: "identity-bridge-a", name: "Identity-Bridge-A", role: "DID bridge · ALPHA ∩ BRAVO", zone: "ALPHA ∩ BRAVO", ip: "10.10.0.4", proto: "DID-Comm v2", cx: 620, cy: 180, ringA: "#14B8A6", ringB: "#9333EA", sub: "SHARED · DID-COMM" },
  { id: "scada-master", name: "SCADA-Master", role: "SCADA master · BRAVO ∩ CHARLIE", zone: "BRAVO ∩ CHARLIE", ip: "10.20.4.10", proto: "DNP3 / OPC-UA", cx: 740, cy: 400, ringA: "#9333EA", ringB: "#F59E0B", sub: "SHARED · DNP3" },
  { id: "telemetry-relay-3", name: "Telemetry-Relay-3", role: "Telemetry relay · BRAVO ∩ CHARLIE", zone: "BRAVO ∩ CHARLIE", ip: "10.20.4.33", proto: "MQTT-SN / TLS", cx: 800, cy: 360, ringA: "#9333EA", ringB: "#F59E0B", sub: "SHARED · MQTT-SN", subAbove: true, health: "degraded" },
  { id: "edge-router-09", name: "Edge-Router-09", role: "Edge router · CHARLIE ∩ DELTA", zone: "CHARLIE ∩ DELTA", ip: "10.30.7.9", proto: "BGP / IPSec", cx: 1030, cy: 460, ringA: "#F59E0B", ringB: "#3B82F6", sub: "SHARED · BGP / IPSEC" },
];

export interface Guardian {
  id: string;
  zone: ZoneId;
  cx: number; cy: number;
  label: string; sub: string;
  text: string;
  haloId: string;
  ring: string;
  bodyFill: string;
  peers: number;
  threats?: number;
  ip: string;
  fw: string;
  ato: string;
  impact: string;
  fips: string;
  stig: string;
  name: string;
  role: string;
  deviceId: string;
  virtualId?: string;
  threatsToday: number;
  threatsWeek: number;
  peersConnected: number;
  peersTotal: number;
  policyVersion: string;
  threatDetection: boolean;
  autoQuarantine: boolean;
  health?: NodeHealth;
}

export const GUARDIANS: Guardian[] = [
  { id: "sgx-1", zone: "ALPHA", cx: 320, cy: 280, label: "SGX-1", sub: "ALPHA",
    text: "#5eead4", haloId: "haloAlpha", ring: "#14B8A6", bodyFill: "#04141a",
    peers: 47, ip: "10.10.0.1", fw: "v4.2.1", ato: "AUTHORIZED · ATO #DOD-2024-0481",
    impact: "IL5", fips: "FIPS 140-3 L2", stig: "98.4%",
    name: "SGX-1 · ALPHA", role: "Guardian · Industrial West",
    deviceId: "SGX-01-A1Z200", threatsToday: 8, threatsWeek: 33,
    peersConnected: 47, peersTotal: 47,
    policyVersion: "v1.0", threatDetection: true, autoQuarantine: true },
  { id: "sgx-2", zone: "BRAVO", cx: 820, cy: 240, label: "SGX-2", sub: "BRAVO",
    text: "#d8b4fe", haloId: "haloBravo", ring: "#9333EA", bodyFill: "#100819",
    peers: 31, threats: 2, ip: "10.20.0.1", fw: "v4.2.1", ato: "AUTHORIZED · ATO #DOD-2024-0481",
    impact: "IL5", fips: "FIPS 140-3 L2", stig: "99.1%",
    name: "SGX-2 · BRAVO", role: "Guardian · IT Core",
    deviceId: "SGX-02-B2Y300", threatsToday: 14, threatsWeek: 51,
    peersConnected: 31, peersTotal: 31,
    policyVersion: "v1.0", threatDetection: true, autoQuarantine: true, health: "degraded" },
  { id: "sgx-3", zone: "CHARLIE", cx: 700, cy: 540, label: "SGX-3", sub: "CHARLIE",
    text: "#fcd34d", haloId: "haloCharlie", ring: "#F59E0B", bodyFill: "#1a1208",
    peers: 62, threats: 1, ip: "10.30.0.1", fw: "v4.2.0", ato: "AUTHORIZED · ATO #DOD-2024-0481",
    impact: "IL6", fips: "FIPS 140-3 L2", stig: "96.7%",
    name: "SGX-3 · CHARLIE", role: "Guardian · OT-SCADA South",
    deviceId: "SGX-03-C3X400", threatsToday: 6, threatsWeek: 28,
    peersConnected: 62, peersTotal: 62,
    policyVersion: "v1.0", threatDetection: true, autoQuarantine: true, health: "offline" },
  { id: "sgx-4", zone: "DELTA", cx: 1230, cy: 360, label: "SGX-4", sub: "DELTA",
    text: "#bfdbfe", haloId: "haloDelta", ring: "#3B82F6", bodyFill: "#08101e",
    peers: 19, ip: "10.40.0.1", fw: "v4.2.1", ato: "AUTHORIZED · ATO #DOD-2024-0481",
    impact: "IL5", fips: "FIPS 140-3 L2", stig: "97.9%",
    name: "SGX-4 · DELTA", role: "Guardian · Remote Site East",
    deviceId: "SGX-04-X2W100", threatsToday: 12, threatsWeek: 47,
    peersConnected: 0, peersTotal: 0,
    policyVersion: "v1.0", threatDetection: true, autoQuarantine: true },
];

export type GuardianId = "sgx-1" | "sgx-2" | "sgx-3" | "sgx-4";

export interface MeshEdge { from: GuardianId; to: GuardianId; faded?: boolean; }
export const MESH: MeshEdge[] = [
  { from: "sgx-1", to: "sgx-2" },
  { from: "sgx-2", to: "sgx-4" },
  { from: "sgx-4", to: "sgx-3" },
  { from: "sgx-3", to: "sgx-1" },
  { from: "sgx-1", to: "sgx-4", faded: true },
  { from: "sgx-2", to: "sgx-3", faded: true },
];

export interface DeviceLink { deviceId: string; guardianId: GuardianId; }

const ZONE_TO_GUARDIAN: Record<ZoneId, GuardianId> = {
  ALPHA: "sgx-1",
  BRAVO: "sgx-2",
  CHARLIE: "sgx-3",
  DELTA: "sgx-4",
};
export const DEVICE_LINKS: readonly DeviceLink[] = CLUSTERS.map((c) => ({
  deviceId: c.id,
  guardianId: ZONE_TO_GUARDIAN[c.zone],
}));

export interface Threat {
  id: string;
  name: string; role: string; zone: string;
  ip: string; proto: string; sev: "HIGH" | "CRITICAL";
  mitre: string; cvss: string; actor: string; cisa: string; nist: string;
  cx: number; cy: number;
  beam: { x1: number; y1: number; x2: number; y2: number };
  labelY: number;
  badgeX: number; badgeY: number; badgeW: number; badgeText: string;
  nameY: number; subY: number;
}

export const THREATS: Threat[] = [
  {
    id: "unknown-b24fc9",
    name: "Unknown-B24FC9", role: "Unattested device · NOT IN ANY CIRCLE",
    zone: "UNKNOWN", ip: "172.16.99.41", proto: "No attestation", sev: "HIGH",
    mitre: "T1190 · Exploit Public-Facing Application", cvss: "8.6 · HIGH",
    actor: "TEMP.Periscope (suspected)", cisa: "AA24-038A", nist: "SC-7, AC-4, SI-4",
    cx: 80, cy: 540, beam: { x1: 80, y1: 540, x2: 320, y2: 280 },
    labelY: 0,
    badgeX: 34, badgeY: 572, badgeW: 92, badgeText: "⚠ HIGH",
    nameY: 608, subY: 622,
  },
  {
    id: "rogue-ap-0034",
    name: "Rogue-AP-0034", role: "Unauthorised access point",
    zone: "UNKNOWN", ip: "0.0.0.0", proto: "802.11 / WPA2-Open", sev: "CRITICAL",
    mitre: "T1557.004 · Adversary-in-the-Middle (Wi-Fi)", cvss: "9.4 · CRITICAL",
    actor: "Volt Typhoon-adjacent (signatures)", cisa: "AA24-131A", nist: "AC-18, IA-3, SI-4",
    cx: 1530, cy: 210, beam: { x1: 1530, y1: 210, x2: 1230, y2: 360 },
    labelY: 0,
    badgeX: 1472, badgeY: 238, badgeW: 116, badgeText: "⚠ CRITICAL",
    nameY: 274, subY: 288,
  },
];

export const VIEW_BOX = { w: 1600, h: 720 };

export interface ZoneDef {
  zone: ZoneId;
  cx: number; cy: number;
  prefix: string;
  count: number;
  color: string;
  stroke: string;
}

export const ZONE_DEFS: ZoneDef[] = [
  { zone: "ALPHA",   cx: 320,  cy: 280, prefix: "PLC", count: 12, color: "#5eead4", stroke: "#14B8A6" },
  { zone: "BRAVO",   cx: 820,  cy: 240, prefix: "SRV", count: 11, color: "#d8b4fe", stroke: "#9333EA" },
  { zone: "CHARLIE", cx: 700,  cy: 540, prefix: "RTU", count: 14, color: "#fcd34d", stroke: "#F59E0B" },
  { zone: "DELTA",   cx: 1230, cy: 360, prefix: "GW",  count: 10, color: "#bfdbfe", stroke: "#3B82F6" },
];

export interface ZoneDevice {
  id: string;
  zone: ZoneId;
  x: number; y: number;
  status: "ok" | "err";
  color: string;
  stroke: string;
}

export function buildZoneDevices(): ZoneDevice[] {
  const out: ZoneDevice[] = [];
  const ring1 = 90, ring2 = 130;
  for (const d of ZONE_DEFS) {
    for (let i = 0; i < d.count; i++) {
      const ringR = i % 2 === 0 ? ring1 : ring2;
      const t = (i / d.count) * Math.PI * 2 + (i % 2 ? 0.18 : 0);
      const x = Math.round((d.cx + Math.cos(t) * ringR) * 100) / 100;
      const y = Math.round((d.cy + Math.sin(t) * ringR * 0.78) * 100) / 100;
      const id = `${d.prefix}-${String(i + 1).padStart(2, "0")}`;
      const isErr = (d.zone === "BRAVO" && i === 3) || (d.zone === "CHARLIE" && i === 7);
      out.push({ id, zone: d.zone, x, y, status: isErr ? "err" : "ok", color: d.color, stroke: d.stroke });
    }
  }
  return out;
}

export const ZONE_DEVICES = buildZoneDevices();

export type CoTTag =
  | "ALPHA" | "BRAVO" | "CHARLIE" | "DELTA"
  | "ALPHA ∩ BRAVO" | "BRAVO ∩ CHARLIE" | "CHARLIE ∩ DELTA"
  | "MESH" | "POLICY";

export interface SampleEvent {
  lvl: "INFO" | "WARN" | "ERR";
  cot: CoTTag;
  device: string;
  msg: string;
  src: string;
}

export const SAMPLE_EVENTS: SampleEvent[] = [
  { lvl: "INFO", cot: "MESH",            device: "SGX-2",            msg: "SGX-2 → SGX-3 mesh attestation OK · digest <em>a1f3…c92e</em>",                  src: "sgx.mesh" },
  { lvl: "INFO", cot: "ALPHA ∩ BRAVO",   device: "Identity-Bridge-A",msg: "Identity-Bridge-A revalidated <em>ALPHA ∩ BRAVO</em> overlap · 5 peers",         src: "circles" },
  { lvl: "WARN", cot: "ALPHA",           device: "PLC-Controller-03",msg: "Repeated auth failure on <em>PLC-Controller-03</em> from <em>10.10.0.21</em>",   src: "SGX-1" },
  { lvl: "INFO", cot: "BRAVO ∩ CHARLIE", device: "Telemetry-Relay-3",msg: "Telemetry-Relay-3 synced 1,284 points · <em>BRAVO ∩ CHARLIE</em>",                src: "SGX-2" },
  { lvl: "ERR",  cot: "DELTA",           device: "Rogue-AP-0034",    msg: "<em>Rogue-AP-0034</em> emitted deauth burst — autoblock applied",                 src: "SGX-2" },
  { lvl: "INFO", cot: "CHARLIE ∩ DELTA", device: "Edge-Router-09",   msg: "Edge-Router-09 BGP session up · <em>CHARLIE ∩ DELTA</em>",                        src: "SGX-4" },
  { lvl: "WARN", cot: "CHARLIE",         device: "Wyze-Cam-04",      msg: "Anomalous outbound flow <em>Wyze-Cam-04 → 185.220.…</em>",                        src: "SGX-3" },
  { lvl: "INFO", cot: "POLICY",          device: "sgx.policy",       msg: "Policy digest <em>a1f3…c92e</em> propagated to 4/4 Guardians",                    src: "sgx.policy" },
  { lvl: "ERR",  cot: "CHARLIE",         device: "Unknown-B24FC9",   msg: "Unattested device <em>Unknown-B24FC9</em> probed <em>10.30.0.0/24</em>",          src: "SGX-3" },
  { lvl: "INFO", cot: "POLICY",          device: "sgx.policy",       msg: "Quorum reached for <em>policy v3.4.0</em> · 4 / 4 sign-offs",                     src: "sgx.policy" },
];
