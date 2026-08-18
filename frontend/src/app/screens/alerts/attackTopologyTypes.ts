import type { ThreatAlert, ThreatSeverity } from "../../services/threatService";

export type TopologyNodeKind =
  | "internet"
  | "attacker"
  | "firewall"
  | "guardian"
  | "plc"
  | "rtu"
  | "gateway"
  | "coil"
  | "coil-array"
  | "holding-register"
  | "input-register"
  | "firmware"
  | "logic"
  | "ethernet"
  | "modbus"
  | "safety"
  | "sensor";

export type TopologyStatus = "healthy" | "warm" | "hot" | "critical" | "compromised";
export type TopologyMode = "production" | "demo";

export interface TopologyNode {
  id: string;
  name: string;
  kind: TopologyNodeKind;
  x: number;
  y: number;
  ip: string;
  mac: string;
  protocol: string;
  health: number;
  packetsPerSec: number;
  cpu?: number;
  connections: number;
  lastSeen: string;
  site: string;
  description: string;
}

export interface TopologyLink {
  id: string;
  source: string;
  target: string;
  protocol: string;
  bandwidth: string;
  activity: number;
  criticality: "normal" | "protected" | "industrial";
}

export interface NodeTelemetry {
  threatScore: number;
  heat: number;
  attacks: number;
  lastAttack?: string;
  lastAlert?: string;
}

export interface AttackEvent {
  id: string;
  timestamp: number;
  sourceId: string;
  targetId: string;
  pathNodeIds: string[];
  severity: ThreatSeverity;
  signature: string;
  srcIp: string;
  dstIp: string;
  protocol: string;
  blocked: boolean;
  alert?: ThreatAlert;
  impact: string;
}

export interface SignatureTargetMapping {
  key: string;
  label: string;
  matcher: RegExp;
  targetId: string;
  impact: string;
  mitre: string;
}

export const SEVERITY_COLORS: Record<ThreatSeverity | "healthy" | "compromised", string> = {
  healthy: "#38bdf8",
  info: "#22d3ee",
  low: "#22c55e",
  medium: "#eab308",
  high: "#f97316",
  critical: "#ef4444",
  compromised: "#a855f7",
};

export const SIGNATURE_TARGETS: SignatureTargetMapping[] = [
  { key: "FC5", label: "Write Single Coil", matcher: /\bFC\s*5\b|\bFC5\b|write single coil/i, targetId: "coil", impact: "Coil state manipulation", mitre: "T0831 Manipulation of Control" },
  { key: "FC15", label: "Write Multiple Coils", matcher: /\bFC\s*15\b|\bFC15\b|write multiple coils/i, targetId: "coil-array", impact: "Coil array overwrite", mitre: "T0831 Manipulation of Control" },
  { key: "FC6", label: "Write Single Register", matcher: /\bFC\s*6\b|\bFC6\b|write single register/i, targetId: "holding-register", impact: "Holding register tamper", mitre: "T0831 Manipulation of Control" },
  { key: "FC16", label: "Write Multiple Registers", matcher: /\bFC\s*16\b|\bFC16\b|write multiple registers/i, targetId: "holding-register", impact: "Register block overwrite", mitre: "T0831 Manipulation of Control" },
  { key: "FC65", label: "Logic Upload", matcher: /\bFC\s*65\b|\bFC65\b|logic/i, targetId: "logic", impact: "PLC logic access", mitre: "T0843 Program Upload" },
  { key: "FC66", label: "Logic Download", matcher: /\bFC\s*66\b|\bFC66\b|program download/i, targetId: "logic", impact: "PLC logic modification", mitre: "T0843 Program Upload" },
  { key: "FC67", label: "Firmware Access", matcher: /\bFC\s*67\b|\bFC67\b|firmware/i, targetId: "firmware", impact: "Firmware module access", mitre: "T0857 System Firmware" },
  { key: "FC68", label: "Firmware Write", matcher: /\bFC\s*68\b|\bFC68\b|firmware write/i, targetId: "firmware", impact: "Firmware write attempt", mitre: "T0857 System Firmware" },
  { key: "FC129", label: "Exception Flood", matcher: /\bFC\s*129\b|\bFC129\b|exception flood|exception response/i, targetId: "modbus", impact: "Exception flood against Modbus service", mitre: "T0868 Detect Operating Mode" },
  { key: "Exception Response", label: "Modbus Exception", matcher: /exception response|modbus exception/i, targetId: "modbus", impact: "Protocol exception storm", mitre: "T0868 Detect Operating Mode" },
  { key: "Time Audit", label: "Time Audit", matcher: /time audit|clock|time/i, targetId: "coil", impact: "Timing audit anomaly", mitre: "T0856 Spoof Reporting Message" },
];

export interface ModbusSensor {
  id: "temperature" | "pressure" | "flow" | "vibration";
  name: string;
  type: string;
  registerRange: string;
  registerAddress: string;
  slaveId: number;
  normalRead: string;
  attackVector: string;
  color: string;
  icon: string;
}

export interface ModbusScenario {
  id: "S1" | "S2" | "S3" | "S4";
  name: string;
  fcCode: "FC6" | "FC15" | "FC65" | "FC129";
  fcLabel: string;
  targetSensorId: ModbusSensor["id"];
  registerAddress: string;
  attackVector: string;
  suricataAlert: string;
  matcher: RegExp;
}

export interface ModbusAlertContext {
  scenario: ModbusScenario | null;
  sensor: ModbusSensor | null;
  fcCode: string;
  scenarioLabel: string;
  sensorType: string;
  registerAddress: string;
}

export const MODBUS_SENSORS: ModbusSensor[] = [
  {
    id: "temperature",
    name: "Temperature Sensor",
    type: "Temperature",
    registerRange: "Reg 0-9",
    registerAddress: "Reg 0-9 - Slave ID 1",
    slaveId: 1,
    normalRead: "FC3 read -> C values (20-80)",
    attackVector: "FC6 write Reg 0 -> spoof 9999 (overheat)",
    color: "#ef4444",
    icon: "Thermometer",
  },
  {
    id: "pressure",
    name: "Pressure Sensor",
    type: "Pressure",
    registerRange: "Reg 10-19",
    registerAddress: "Reg 10-19 - Slave ID 2",
    slaveId: 2,
    normalRead: "FC3 read -> bar values (0.5-10)",
    attackVector: "FC15 bulk write -> mass register overwrite",
    color: "#06b6d4",
    icon: "Gauge",
  },
  {
    id: "flow",
    name: "Flow Meter",
    type: "Flow Meter",
    registerRange: "Reg 20-29",
    registerAddress: "Reg 20-29 - Slave ID 3",
    slaveId: 3,
    normalRead: "FC3 read -> L/min (0-100)",
    attackVector: "FC65 payload -> firmware upload attempt",
    color: "#0ea5e9",
    icon: "Droplet",
  },
  {
    id: "vibration",
    name: "Vibration Sensor",
    type: "Vibration",
    registerRange: "Reg 30-39",
    registerAddress: "Reg 30-39 - Slave ID 4",
    slaveId: 4,
    normalRead: "FC3 read -> Hz values (0-500)",
    attackVector: "FC129 x 100/min -> exception flood",
    color: "#8b5cf6",
    icon: "Activity",
  },
];

export const MODBUS_SCENARIOS: ModbusScenario[] = [
  {
    id: "S1",
    name: "Temperature Spoof",
    fcCode: "FC6",
    fcLabel: "FC6 Write",
    targetSensorId: "temperature",
    registerAddress: "Reg 0",
    attackVector: "Unauthorized write spoofs the temperature value.",
    suricataAlert: "SGX-OT: MODBUS UNAUTHORIZED WRITE",
    matcher: /\bFC\s*6\b|\bFC6\b|unauthorized write|write single register|temperature/i,
  },
  {
    id: "S2",
    name: "Pressure Takeover",
    fcCode: "FC15",
    fcLabel: "FC15 Bulk",
    targetSensorId: "pressure",
    registerAddress: "Reg 10-19",
    attackVector: "Bulk coil/register write overwrites the pressure range.",
    suricataAlert: "SGX-OT: MODBUS COIL WRITE BULK",
    matcher: /\bFC\s*15\b|\bFC15\b|bulk|write multiple coils|coil write|pressure/i,
  },
  {
    id: "S3",
    name: "Firmware Upload",
    fcCode: "FC65",
    fcLabel: "FC65 Upload",
    targetSensorId: "flow",
    registerAddress: "Slave ID 3",
    attackVector: "Firmware upload attempt targets the flow meter path.",
    suricataAlert: "SGX-OT: MODBUS FIRMWARE UPLOAD",
    matcher: /\bFC\s*65\b|\bFC65\b|firmware|upload|flow meter|flow/i,
  },
  {
    id: "S4",
    name: "Exception Flood",
    fcCode: "FC129",
    fcLabel: "FC129 Flood",
    targetSensorId: "vibration",
    registerAddress: "Reg 30-39",
    attackVector: "Exception responses flood the vibration sensor path.",
    suricataAlert: "SGX-OT: MODBUS EXCEPTION FLOOD",
    matcher: /\bFC\s*129\b|\bFC129\b|exception flood|exception response|100\/min|vibration/i,
  },
];
export const TOPOLOGY_NODES: TopologyNode[] = [
  { id: "internet", name: "Internet", kind: "internet", x: 560, y: 42, ip: "0.0.0.0/0", mac: "external", protocol: "TCP/IP", health: 100, packetsPerSec: 418, connections: 128, lastSeen: "live", site: "WAN Edge", description: "External ingress and egress observation point." },
  { id: "attacker-a", name: "Hacker A", kind: "attacker", x: 365, y: 118, ip: "185.231.72.42", mac: "unknown", protocol: "TCP", health: 0, packetsPerSec: 22, connections: 8, lastSeen: "seconds ago", site: "External", description: "Untrusted source cluster inferred from Guardian alerts." },
  { id: "attacker-b", name: "Hacker B", kind: "attacker", x: 755, y: 118, ip: "91.214.124.8", mac: "unknown", protocol: "UDP/TCP", health: 0, packetsPerSec: 18, connections: 6, lastSeen: "seconds ago", site: "External", description: "Secondary untrusted source cluster." },
  { id: "firewall", name: "Firewall Gateway", kind: "firewall", x: 560, y: 205, ip: "10.0.0.1", mac: "00:16:3e:aa:10:01", protocol: "L3/L4", health: 96, packetsPerSec: 690, connections: 214, lastSeen: "live", site: "Plant DMZ", description: "Ingress gateway protecting the Guardian segment." },
  { id: "guardian", name: "Guardian Node", kind: "guardian", x: 560, y: 330, ip: "10.0.10.10", mac: "00:16:3e:aa:42:10", protocol: "SGX Mesh", health: 98, cpu: 34, packetsPerSec: 1240, connections: 42, lastSeen: "live", site: "Cell 01", description: "Guardian enforcement point and trusted identity anchor." },
  { id: "plc", name: "PLC", kind: "plc", x: 330, y: 460, ip: "10.0.20.11", mac: "00:1b:1c:20:11:01", protocol: "Modbus TCP", health: 93, cpu: 41, packetsPerSec: 280, connections: 9, lastSeen: "live", site: "Cell 01", description: "Primary programmable logic controller." },
  { id: "gateway", name: "Cell Gateway", kind: "gateway", x: 560, y: 460, ip: "10.0.20.1", mac: "00:1b:1c:20:01:01", protocol: "OPC UA", health: 95, cpu: 28, packetsPerSec: 360, connections: 14, lastSeen: "live", site: "Cell 01", description: "Industrial protocol gateway." },
  { id: "rtu", name: "RTU", kind: "rtu", x: 790, y: 460, ip: "10.0.20.21", mac: "00:1b:1c:20:21:01", protocol: "DNP3", health: 91, cpu: 37, packetsPerSec: 145, connections: 6, lastSeen: "live", site: "Remote Skid", description: "Remote terminal unit for field I/O." },
  { id: "coil", name: "Coil", kind: "coil", x: 170, y: 600, ip: "10.0.20.11:0005", mac: "virtual", protocol: "Modbus FC5", health: 97, packetsPerSec: 40, connections: 3, lastSeen: "live", site: "PLC Memory", description: "Single writable coil output." },
  { id: "coil-array", name: "Coil Array", kind: "coil-array", x: 285, y: 630, ip: "10.0.20.11:0015", mac: "virtual", protocol: "Modbus FC15", health: 97, packetsPerSec: 46, connections: 3, lastSeen: "live", site: "PLC Memory", description: "Writable coil block." },
  { id: "holding-register", name: "Holding Register", kind: "holding-register", x: 430, y: 630, ip: "10.0.20.11:40001", mac: "virtual", protocol: "Modbus FC6/16", health: 94, packetsPerSec: 52, connections: 4, lastSeen: "live", site: "PLC Memory", description: "Writable process register." },
  { id: "input-register", name: "Input Register", kind: "input-register", x: 555, y: 615, ip: "10.0.20.11:30001", mac: "virtual", protocol: "Modbus FC4", health: 99, packetsPerSec: 38, connections: 2, lastSeen: "live", site: "PLC Memory", description: "Read-only process input register." },
  { id: "logic", name: "Logic Module", kind: "logic", x: 670, y: 620, ip: "10.0.20.11:logic", mac: "virtual", protocol: "Vendor Logic", health: 95, packetsPerSec: 26, connections: 2, lastSeen: "live", site: "PLC Runtime", description: "Control strategy and ladder logic module." },
  { id: "firmware", name: "Firmware", kind: "firmware", x: 795, y: 620, ip: "10.0.20.11:fw", mac: "virtual", protocol: "Vendor Maint", health: 96, packetsPerSec: 12, connections: 1, lastSeen: "live", site: "PLC Runtime", description: "Firmware management interface." },
  { id: "ethernet", name: "Ethernet Interface", kind: "ethernet", x: 920, y: 605, ip: "10.0.20.11:eth0", mac: "00:1b:1c:20:11:aa", protocol: "Ethernet", health: 98, packetsPerSec: 480, connections: 18, lastSeen: "live", site: "Cell 01", description: "Industrial Ethernet interface." },
  { id: "modbus", name: "Modbus TCP", kind: "modbus", x: 1000, y: 500, ip: "10.0.20.11:502", mac: "virtual", protocol: "Modbus TCP", health: 92, packetsPerSec: 172, connections: 11, lastSeen: "live", site: "PLC Service", description: "Modbus TCP service boundary." },
  { id: "safety", name: "Safety Controller", kind: "safety", x: 705, y: 720, ip: "10.0.20.31", mac: "00:1b:1c:20:31:01", protocol: "SafetyNet", health: 99, packetsPerSec: 33, connections: 2, lastSeen: "live", site: "Safety Zone", description: "Safety controller with protected interlock logic." },
  { id: "temperature", name: "Temperature Sensor", kind: "sensor", x: 395, y: 735, ip: "10.0.30.11", mac: "00:1b:1c:30:11:01", protocol: "Modbus TCP", health: 99, packetsPerSec: 21, connections: 1, lastSeen: "live", site: "Field I/O", description: "Temperature process sensor." },
  { id: "pressure", name: "Pressure Sensor", kind: "sensor", x: 535, y: 760, ip: "10.0.30.12", mac: "00:1b:1c:30:12:01", protocol: "Modbus TCP", health: 98, packetsPerSec: 24, connections: 1, lastSeen: "live", site: "Field I/O", description: "Pressure process sensor." },
];

export const TOPOLOGY_LINKS: TopologyLink[] = [
  { id: "internet-a", source: "internet", target: "attacker-a", protocol: "TCP", bandwidth: "18 Mbps", activity: 0.34, criticality: "normal" },
  { id: "internet-b", source: "internet", target: "attacker-b", protocol: "TCP", bandwidth: "12 Mbps", activity: 0.3, criticality: "normal" },
  { id: "a-firewall", source: "attacker-a", target: "firewall", protocol: "TCP/502", bandwidth: "2.8 Mbps", activity: 0.68, criticality: "normal" },
  { id: "b-firewall", source: "attacker-b", target: "firewall", protocol: "TCP/502", bandwidth: "1.9 Mbps", activity: 0.56, criticality: "normal" },
  { id: "firewall-guardian", source: "firewall", target: "guardian", protocol: "SGX Inspect", bandwidth: "44 Mbps", activity: 0.9, criticality: "protected" },
  { id: "guardian-plc", source: "guardian", target: "plc", protocol: "Modbus TCP", bandwidth: "8 Mbps", activity: 0.8, criticality: "industrial" },
  { id: "guardian-gateway", source: "guardian", target: "gateway", protocol: "OPC UA", bandwidth: "6 Mbps", activity: 0.72, criticality: "industrial" },
  { id: "guardian-rtu", source: "guardian", target: "rtu", protocol: "DNP3", bandwidth: "3 Mbps", activity: 0.58, criticality: "industrial" },
  { id: "plc-coil", source: "plc", target: "coil", protocol: "FC5", bandwidth: "120 Kbps", activity: 0.42, criticality: "industrial" },
  { id: "plc-coil-array", source: "plc", target: "coil-array", protocol: "FC15", bandwidth: "160 Kbps", activity: 0.38, criticality: "industrial" },
  { id: "plc-holding", source: "plc", target: "holding-register", protocol: "FC6/16", bandwidth: "210 Kbps", activity: 0.45, criticality: "industrial" },
  { id: "plc-input", source: "plc", target: "input-register", protocol: "FC4", bandwidth: "118 Kbps", activity: 0.32, criticality: "industrial" },
  { id: "plc-logic", source: "plc", target: "logic", protocol: "Logic", bandwidth: "80 Kbps", activity: 0.22, criticality: "industrial" },
  { id: "plc-firmware", source: "plc", target: "firmware", protocol: "Maint", bandwidth: "22 Kbps", activity: 0.18, criticality: "industrial" },
  { id: "plc-ethernet", source: "plc", target: "ethernet", protocol: "Ethernet", bandwidth: "20 Mbps", activity: 0.65, criticality: "industrial" },
  { id: "rtu-modbus", source: "rtu", target: "modbus", protocol: "Modbus TCP", bandwidth: "480 Kbps", activity: 0.44, criticality: "industrial" },
  { id: "holding-temp", source: "holding-register", target: "temperature", protocol: "Telemetry", bandwidth: "24 Kbps", activity: 0.34, criticality: "industrial" },
  { id: "input-pressure", source: "input-register", target: "pressure", protocol: "Telemetry", bandwidth: "28 Kbps", activity: 0.36, criticality: "industrial" },
  { id: "logic-safety", source: "logic", target: "safety", protocol: "Safety", bandwidth: "15 Kbps", activity: 0.28, criticality: "industrial" },
];

function textForModbusMatch(alert: Pick<ThreatAlert, "signature" | "signature_id" | "category" | "protocol" | "dst_port">) {
  return [alert.signature, alert.signature_id, alert.category, alert.protocol, alert.dst_port].filter(Boolean).join(" ");
}

export function extractModbusFcCode(text: string) {
  const explicit = text.match(/\bFC\s*0*(\d{1,3})\b/i) ?? text.match(/function\s*code\s*0*(\d{1,3})\b/i);
  if (explicit?.[1]) return `FC${explicit[1]}`;
  if (/exception flood|exception response/i.test(text)) return "FC129";
  if (/unauthorized write|write single register/i.test(text)) return "FC6";
  if (/bulk|write multiple coils|coil write/i.test(text)) return "FC15";
  if (/firmware|upload/i.test(text)) return "FC65";
  return "FC?";
}

export function getModbusAlertContext(alert: Pick<ThreatAlert, "signature" | "signature_id" | "category" | "protocol" | "dst_port">): ModbusAlertContext {
  const text = textForModbusMatch(alert);
  const fcCode = extractModbusFcCode(text);
  const scenario = MODBUS_SCENARIOS.find((item) => item.matcher.test(text) || item.fcCode === fcCode) ?? null;
  const sensor = scenario ? MODBUS_SENSORS.find((item) => item.id === scenario.targetSensorId) ?? null : null;

  return {
    scenario,
    sensor,
    fcCode: scenario?.fcCode ?? fcCode,
    scenarioLabel: scenario ? `${scenario.id} - ${scenario.name}` : "Unmapped Modbus Alert",
    sensorType: sensor?.type ?? "Modbus TCP",
    registerAddress: scenario?.registerAddress ?? sensor?.registerAddress ?? "Port 502",
  };
}

export function isModbusSensorAlert(alert: Pick<ThreatAlert, "signature" | "signature_id" | "category" | "protocol" | "dst_port">) {
  const text = textForModbusMatch(alert);
  return alert.dst_port === 502 || /modbus|\bFC\s*\d+\b|exception flood|unauthorized write|coil write|firmware upload/i.test(text);
}
export function getNode(nodes: TopologyNode[], id: string) {
  return nodes.find((node) => node.id === id);
}

export function severityDelta(severity: ThreatSeverity) {
  if (severity === "critical") return 24;
  if (severity === "high") return 18;
  if (severity === "medium") return 12;
  if (severity === "low") return 7;
  return 4;
}

export function severityRank(severity: ThreatSeverity) {
  if (severity === "critical") return 5;
  if (severity === "high") return 4;
  if (severity === "medium") return 3;
  if (severity === "low") return 2;
  return 1;
}

export function statusFromThreatScore(score: number): TopologyStatus {
  if (score >= 88) return "compromised";
  if (score >= 68) return "critical";
  if (score >= 42) return "hot";
  if (score >= 18) return "warm";
  return "healthy";
}

export function colorForThreatScore(score: number) {
  const status = statusFromThreatScore(score);
  if (status === "compromised") return SEVERITY_COLORS.compromised;
  if (status === "critical") return SEVERITY_COLORS.critical;
  if (status === "hot") return SEVERITY_COLORS.high;
  if (status === "warm") return SEVERITY_COLORS.medium;
  return SEVERITY_COLORS.healthy;
}

export function mapAlertToTarget(alert: Pick<ThreatAlert, "signature" | "dst_port">) {
  const match = SIGNATURE_TARGETS.find((mapping) => mapping.matcher.test(alert.signature));
  if (match) return match;
  if (alert.dst_port === 502) return SIGNATURE_TARGETS.find((mapping) => mapping.targetId === "modbus") ?? SIGNATURE_TARGETS[0];
  return SIGNATURE_TARGETS[0];
}

export function sourceNodeForIp(ip: string) {
  const lastOctet = Number(ip.split(".").pop() ?? "0");
  return Number.isFinite(lastOctet) && lastOctet % 2 === 0 ? "attacker-a" : "attacker-b";
}

export function formatClock(timestamp: number | string) {
  const date = typeof timestamp === "number" ? new Date(timestamp) : new Date(timestamp);
  if (Number.isNaN(date.getTime())) return "live";
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" });
}
