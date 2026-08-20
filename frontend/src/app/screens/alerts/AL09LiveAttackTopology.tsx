import { useCallback, useEffect, useMemo, useRef, useState, type MouseEvent } from "react";
import { select } from "d3-selection";
import { zoom, zoomIdentity, type ZoomBehavior } from "d3-zoom";
import "d3-transition";
import { Maximize2, Pause, Play, RefreshCw, RotateCcw, ShieldAlert, ZoomIn, ZoomOut, Thermometer, Gauge, Droplet, Activity } from "lucide-react";
import { useThreatAlerts, useThreatStatus } from "../../hooks/useApiData";
import type { ThreatAlert, ThreatSeverity } from "../../services/threatService";
import "../../components/topology/topology.css";
import "./AL09LiveAttackTopology.css";
import {
  MODBUS_SCENARIOS,
  MODBUS_SENSORS,
  SEVERITY_COLORS,
  formatClock,
  getModbusAlertContext,
  isModbusSensorAlert,
  type ModbusAlertContext,
  type ModbusScenario,
  type ModbusSensor,
} from "./attackTopologyTypes";

const VIEW_BOX = { w: 1160, h: 720 };
const ACTIVE_WINDOW_MS = 12_000;

const NODE_A = { id: "node-a", label: "Node A", role: "SERVER + IDS", ip: "192.168.50.115", sub: "Guardian + Modbus TCP :502", x: 570, y: 360, r: 48, color: "#38bdf8" };
const NODE_B = { id: "node-b", label: "Node B", role: "ATTACKER", ip: "192.168.50.248", sub: "Modbus TCP client", x: 175, y: 360, r: 42, color: "#f97316" };

type SceneNodeKind = "attacker" | "server" | "sensor";

interface SceneNode {
  id: string;
  kind: SceneNodeKind;
  label: string;
  role: string;
  ip: string;
  sub: string;
  x: number;
  y: number;
  r: number;
  color: string;
  sensor?: ModbusSensor;
  scenario?: ModbusScenario;
}

interface MeshLink {
  id: string;
  source: string;
  target: string;
  label: string;
  type: "attack" | "sensor" | "sensor-mesh";
}

interface SimAttack {
  id: string;
  seenAt: number;
  alert: ThreatAlert;
  context: ModbusAlertContext;
  targetNodeId: string;
  isDemo: boolean;
}

const SENSOR_POSITIONS: Record<ModbusSensor["id"], { x: number; y: number }> = {
  temperature: { x: 905, y: 145 },
  pressure: { x: 1010, y: 290 },
  flow: { x: 1010, y: 430 },
  vibration: { x: 905, y: 575 },
};

function sensorNodeId(id: ModbusSensor["id"]) {
  return `sensor-${id}`;
}

const SCENE_NODES: SceneNode[] = [
  { ...NODE_B, kind: "attacker" },
  { ...NODE_A, kind: "server" },
  ...MODBUS_SENSORS.map((sensor) => {
    const scenario = MODBUS_SCENARIOS.find((item) => item.targetSensorId === sensor.id);
    const pos = SENSOR_POSITIONS[sensor.id];
    return {
      id: sensorNodeId(sensor.id),
      kind: "sensor" as const,
      label: sensor.name,
      role: scenario ? `${scenario.id} ${scenario.fcLabel}` : "SENSOR",
      ip: sensor.registerAddress,
      sub: sensor.attackVector,
      x: pos.x,
      y: pos.y,
      r: 34,
      color: sensor.color,
      sensor,
      scenario,
    };
  }),
];

const MESH_LINKS: MeshLink[] = [
  { id: "node-b-node-a", source: "node-b", target: "node-a", label: "MODBUS TCP / 502", type: "attack" },
  ...MODBUS_SENSORS.map((sensor) => {
    const scenario = MODBUS_SCENARIOS.find((item) => item.targetSensorId === sensor.id);
    return {
      id: `node-a-${sensor.id}`,
      source: "node-a",
      target: sensorNodeId(sensor.id),
      label: scenario ? `${scenario.id} ${scenario.fcCode}` : sensor.registerRange,
      type: "sensor" as const,
    };
  }),
  { id: "temperature-pressure", source: sensorNodeId("temperature"), target: sensorNodeId("pressure"), label: "SENSOR MESH", type: "sensor-mesh" },
  { id: "pressure-flow", source: sensorNodeId("pressure"), target: sensorNodeId("flow"), label: "SENSOR MESH", type: "sensor-mesh" },
  { id: "flow-vibration", source: sensorNodeId("flow"), target: sensorNodeId("vibration"), label: "SENSOR MESH", type: "sensor-mesh" },
  { id: "vibration-temperature", source: sensorNodeId("vibration"), target: sensorNodeId("temperature"), label: "SENSOR MESH", type: "sensor-mesh" },
];

function findNode(id: string) {
  return SCENE_NODES.find((node) => node.id === id) ?? SCENE_NODES[1];
}

function linkId(source: string, target: string) {
  const direct = MESH_LINKS.find((link) => link.source === source && link.target === target);
  if (direct) return direct.id;
  const reverse = MESH_LINKS.find((link) => link.source === target && link.target === source);
  return reverse?.id ?? `${source}-${target}`;
}

function makeDemoAlert(scenario: ModbusScenario, index: number): ThreatAlert {
  return {
    alert_id: `demo-modbus-${scenario.id}-${Date.now()}-${index}`,
    timestamp: new Date().toISOString(),
    src_ip: NODE_B.ip,
    src_port: 48_000 + index,
    dst_ip: NODE_A.ip,
    dst_port: 502,
    protocol: "TCP",
    signature_id: 920_100 + index,
    signature: `${scenario.guardianAlert} ${scenario.fcLabel}`,
    category: "exploit",
    severity: scenario.id === "S4" ? "critical" : scenario.id === "S3" ? "high" : "medium",
    rev: 1,
    gid: 1,
    event_type: "alert",
    blocked: scenario.id !== "S1",
  };
}

function timestampMs(alert: ThreatAlert) {
  const value = Date.parse(alert.timestamp);
  return Number.isNaN(value) ? Date.now() : value;
}

function severityColor(severity: ThreatSeverity) {
  return SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.medium;
}

function attackToNodeId(context: ModbusAlertContext) {
  return context.sensor ? sensorNodeId(context.sensor.id) : "node-a";
}

function safeDomId(value: string) {
  return value.replace(/[^a-zA-Z0-9_-]/g, "-");
}

function attackPath(targetNodeId: string) {
  const source = findNode("node-b");
  const server = findNode("node-a");
  const target = findNode(targetNodeId);
  if (target.id === server.id) {
    const midX = (source.x + server.x) / 2;
    return `M ${source.x} ${source.y} C ${midX} ${source.y - 90}, ${midX} ${server.y + 90}, ${server.x} ${server.y}`;
  }
  const midA = (source.x + server.x) / 2;
  const midB = (server.x + target.x) / 2;
  return `M ${source.x} ${source.y} C ${midA} ${source.y - 95}, ${midA} ${server.y + 95}, ${server.x} ${server.y} C ${midB} ${server.y}, ${midB} ${target.y}, ${target.x} ${target.y}`;
}
function getNodeAttackCount(node: SceneNode, activeAttacks: SimAttack[]) {
  if (node.id === "node-b" || node.id === "node-a") return activeAttacks.length;
  return activeAttacks.filter((attack) => attack.targetNodeId === node.id).length;
}

function TopologyNode({ node, attackCount, latestAttack, selected, onSelect, onHover, onLeave }: {
  node: SceneNode;
  attackCount: number;
  latestAttack?: SimAttack;
  selected: boolean;
  onSelect: (node: SceneNode) => void;
  onHover: (node: SceneNode, event: MouseEvent<SVGGElement>) => void;
  onLeave: () => void;
}) {
  const attacked = attackCount > 0;
  const color = attacked ? "#ef4444" : node.color;
  const detail = node.kind === "sensor" && node.sensor ? node.sensor.registerAddress : node.ip;

  return (
    <g
      className={`modbus-scene-node node ${selected ? "focus-node" : ""} ${attacked ? "is-attacked" : ""}`}
      transform={`translate(${node.x},${node.y})`}
      onClick={(event) => { event.stopPropagation(); onSelect(node); }}
      onMouseEnter={(event) => onHover(node, event)}
      onMouseMove={(event) => onHover(node, event)}
      onMouseLeave={onLeave}
    >
      <title>{`${node.label}\n${node.role}\n${detail}\n${attacked ? "UNDER ATTACK" : "READY"}`}</title>
      <circle className="hit" r={node.r + 22} fill="transparent" />
      {attacked && <circle className="modbus-threat-pulse" r={node.r + 8} />}
      <circle r={node.r + 18} fill={color} opacity={attacked ? 0.14 : 0.08} className={node.kind === "server" ? "modbus-server-halo" : ""} />
      <circle r={node.r + 7} fill="none" stroke={color} strokeOpacity={attacked ? 0.95 : 0.42} strokeWidth={attacked ? 2.4 : 1.2} strokeDasharray={node.kind === "server" ? "8 7" : "5 6"} className={attacked ? "modbus-ring-spin" : ""} />
      <circle r={node.r} fill={node.kind === "attacker" ? "#180909" : node.kind === "server" ? "#07131d" : "#071018"} stroke={selected ? "#f8fafc" : color} strokeWidth={selected ? 2.6 : attacked ? 2.2 : 1.6} />

      {node.kind === "server" ? (
        <>
          <path d="M0 -24 C15 -17 25 -17 30 -17 C29 8 18 26 0 34 C-18 26 -29 8 -30 -17 C-25 -17 -15 -17 0 -24 Z" fill="rgba(255,255,255,0.05)" stroke={color} strokeWidth="2" />
          <path d="M-12 2 L-3 12 L15 -11" fill="none" stroke="#e0f2fe" strokeWidth="3.4" strokeLinecap="round" strokeLinejoin="round" />
        </>
      ) : node.kind === "attacker" ? (
        <>
          <path d="M0 -26 C15 -24 27 -10 27 5 C27 24 10 33 0 33 C-10 33 -27 24 -27 5 C-27 -10 -15 -24 0 -26 Z" fill="rgba(248,113,113,0.12)" stroke={color} strokeWidth="2" />
          <path d="M-18 2 C-11 -10 11 -10 18 2 L13 22 H-13 Z" fill="rgba(248,113,113,0.18)" stroke={color} strokeWidth="1.8" strokeLinejoin="round" />
          <path d="M-13 -2 H-5 M5 -2 H13" stroke="#fecaca" strokeWidth="3" strokeLinecap="round" />
          <path d="M-10 12 H10" stroke={color} strokeWidth="2" strokeLinecap="round" />
          <path d="M-19 24 H19" stroke="#fecaca" strokeWidth="2.4" strokeLinecap="round" />
          <path d="M-18 16 L-23 20 L-18 24 M18 16 L23 20 L18 24" fill="none" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
          <circle cx="20" cy="-20" r="5" fill={color} className={attacked ? "modbus-red-blink" : ""} />
        </>
      ) : (
        <>
          <circle r="22" fill="rgba(255,255,255,0.04)" stroke={color} strokeOpacity="0.65" />
          <circle r="6" fill={attacked ? "#ef4444" : "#22c55e"} className="modbus-status-dot" cx="12" cy="12" />
          {node.sensor?.icon === "Thermometer" && <Thermometer size={24} x="-12" y="-12" color={color} strokeWidth={1.5} />}
          {node.sensor?.icon === "Gauge" && <Gauge size={24} x="-12" y="-12" color={color} strokeWidth={1.5} />}
          {node.sensor?.icon === "Droplet" && <Droplet size={24} x="-12" y="-12" color={color} strokeWidth={1.5} />}
          {node.sensor?.icon === "Activity" && <Activity size={24} x="-12" y="-12" color={color} strokeWidth={1.5} />}
          <text y="-25" textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize="10" fontWeight="800" fill={color}>{node.scenario?.id ?? "S?"}</text>
        </>
      )}

      <text y={node.kind === "sensor" ? 50 : 58} textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize={node.kind === "sensor" ? 10 : 12} fontWeight="800" fill="#f8fafc" letterSpacing="1.2">
        {node.label}
      </text>
      <text y={node.kind === "sensor" ? 65 : 74} textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize="9" fill={attacked ? "#fecaca" : "#94a3b8"} letterSpacing="1.4">
        {node.kind === "sensor" ? node.sensor?.registerRange : node.ip}
      </text>

      {node.kind === "sensor" && node.scenario && (
        <g transform="translate(-38,-54)">
          <rect width="76" height="20" rx="4" fill={attacked ? "rgba(239,68,68,0.20)" : "rgba(8,12,18,0.88)"} stroke={attacked ? "rgba(239,68,68,0.72)" : "rgba(148,163,184,0.30)"} />
          <text x="38" y="14" textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize="9" fontWeight="900" fill={attacked ? "#fecaca" : node.color} letterSpacing="1.2">{node.scenario.fcCode}</text>
        </g>
      )}

      {attacked && (
        <g transform={`translate(${node.r - 4},${-node.r + 2})`}>
          <rect width="74" height="20" rx="9" fill="rgba(239,68,68,0.22)" stroke="rgba(239,68,68,0.72)" />
          <circle cx="11" cy="10" r="3" fill="#ef4444" className="modbus-red-blink" />
          <text x="43" y="14" textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize="8" fontWeight="900" fill="#fecaca">LIVE</text>
        </g>
      )}

      {latestAttack && node.kind === "sensor" && (
        <text y="84" textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize="8" fill="#fca5a5" letterSpacing="1.2">
          {latestAttack.context.scenario?.name ?? "Modbus alert"}
        </text>
      )}
    </g>
  );
}

function AttackBeam({ attack }: { attack: SimAttack }) {
  const target = findNode(attack.targetNodeId);
  const server = findNode("node-a");
  const source = findNode("node-b");
  const d = attackPath(attack.targetNodeId);
  const id = `beam-${safeDomId(attack.id)}`;
  const color = severityColor(attack.alert.severity);
  const labelX = target.id === server.id ? (source.x + server.x) / 2 : (server.x + target.x) / 2;
  const labelY = target.id === server.id ? server.y - 72 : target.y - 28;
  const scenario = attack.context.scenario;

  return (
    <g className="modbus-attack-beam-wrap" pointerEvents="none">
      <path id={id} d={d} fill="none" stroke={color} strokeWidth="8" strokeOpacity="0.12" />
      <path d={d} fill="none" stroke={color} strokeWidth="2.4" strokeLinecap="round" strokeDasharray="10 8" className="modbus-attack-beam" />
      <circle r="5" fill={color} filter="url(#modbusGlow)">
        <animateMotion dur="1.45s" repeatCount="indefinite">
          <mpath href={`#${id}`} />
        </animateMotion>
      </circle>
      <g transform={`translate(${labelX},${labelY})`}>
        <rect x="-45" y="-13" width="90" height="24" rx="5" fill="rgba(10,14,20,0.92)" stroke={color} strokeOpacity="0.72" />
        <text y="4" textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize="10" fontWeight="900" fill="#fff" letterSpacing="1.3">
          {scenario ? `${scenario.id} ${scenario.fcCode}` : attack.context.fcCode}
        </text>
      </g>
      <circle cx={target.x} cy={target.y} r={target.r + 10} fill="none" stroke={color} strokeWidth="2" className="modbus-impact-ring" />
    </g>
  );
}
function HoverTooltip({ hover }: { hover: { node: SceneNode; x: number; y: number } | null }) {
  if (!hover) return null;
  const { node } = hover;
  return (
    <div className="topo-tooltip show" style={{ left: hover.x + 14, top: hover.y + 14 }}>
      <div className="tt-name">{node.label}</div>
      <div className="tt-sub">{node.role}</div>
      <div className="tt-hint">{node.kind === "sensor" ? node.sensor?.registerAddress : node.ip}</div>
    </div>
  );
}

function NodeDetailPanel({ node, history, onClose }: { node: SceneNode; history: SimAttack[]; onClose: () => void }) {
  const related = history.filter((attack) => node.id === "node-b" || node.id === "node-a" || attack.targetNodeId === node.id).slice(0, 6);
  const latest = related[0];

  return (
    <div className="topo-rpanel" onClick={(event) => event.stopPropagation()}>
      <div className="topo-rpanel-h">
        <div className="topo-eyebrow">{node.kind === "sensor" ? "VIRTUAL SENSOR" : node.role}</div>
        <button className="topo-rpanel-close" aria-label="Close" onClick={onClose}>x</button>
      </div>
      <div className="topo-rpanel-body">
        <h3>{node.label}</h3>
        <div className="topo-role">{node.sub}</div>
        <div className="topo-kv">
          <div className="k">IP / Reg</div><div className="v">{node.kind === "sensor" ? node.sensor?.registerAddress : node.ip}</div>
          <div className="k">Scenario</div><div className="v">{node.scenario ? `${node.scenario.id} ${node.scenario.name}` : node.role}</div>
          <div className="k">FC Code</div><div className="v">{node.scenario?.fcCode ?? "TCP/502"}</div>
          <div className="k">Status</div><div className="v">{related.length > 0 ? "ATTACKED" : "READY"}</div>
          {latest && <><div className="k">Source</div><div className="v">{latest.alert.src_ip}:{latest.alert.src_port}</div></>}
          {latest && <><div className="k">Last Alert</div><div className="v">{latest.alert.signature}</div></>}
        </div>
      </div>
    </div>
  );
}

function AttackLog({ history, activeCount }: { history: SimAttack[]; activeCount: number }) {
  return (
    <div className="modbus-attack-log" onClick={(event) => event.stopPropagation()}>
      <div className="modbus-log-head">
        <span>LIVE ATTACK STREAM</span>
        <strong>{activeCount} active</strong>
      </div>
      <div className="modbus-log-items">
        {history.slice(0, 8).map((attack) => {
          const scenario = attack.context.scenario;
          const sensor = attack.context.sensor;
          return (
            <div key={attack.id} className="modbus-log-row">
              <span className="modbus-log-time">{formatClock(attack.alert.timestamp)}</span>
              <span className="modbus-log-tag">{scenario ? scenario.id : "S?"}</span>
              <span className="modbus-log-fc">{attack.context.fcCode}</span>
              <span className="modbus-log-main">{attack.alert.src_ip} -&gt; {sensor?.name ?? "Node A"}</span>
              <span className="modbus-log-reg">{attack.context.registerAddress}</span>
            </div>
          );
        })}
        {history.length === 0 && <div className="modbus-log-empty">Waiting for /threat/alerts. Start SIM to preview the full attack flow.</div>}
      </div>
    </div>
  );
}

export function AL09LiveAttackTopology() {
  const svgRef = useRef<SVGSVGElement | null>(null);
  const groupRef = useRef<SVGGElement | null>(null);
  const meshRef = useRef<SVGGElement | null>(null);
  const zoomRef = useRef<ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const processedAlertIds = useRef<Set<string>>(new Set());
  const demoIndex = useRef(0);

  const [mode, setMode] = useState<"live" | "demo">("live");
  const [playing, setPlaying] = useState(true);
  const [fullscreen, setFullscreen] = useState(false);
  const [activeAttacks, setActiveAttacks] = useState<SimAttack[]>([]);
  const [history, setHistory] = useState<SimAttack[]>([]);
  const [selectedNode, setSelectedNode] = useState<SceneNode | null>(null);
  const [hover, setHover] = useState<{ node: SceneNode; x: number; y: number } | null>(null);

  const alertsQuery = useThreatAlerts({ limit: 1000 });
  const statusQuery = useThreatStatus();
  const liveAlerts = alertsQuery.data ?? [];
  const guardianActive = statusQuery.data?.suricata?.toLowerCase() === "active";

  const addAttack = useCallback((alert: ThreatAlert, isDemo = false) => {
    const context = getModbusAlertContext(alert);
    const targetNodeId = attackToNodeId(context);
    const id = `${isDemo ? "demo" : "live"}-${alert.alert_id || alert.signature_id}-${Date.now()}-${Math.random().toString(36).slice(2, 7)}`;
    const attack: SimAttack = { id, seenAt: Date.now(), alert, context, targetNodeId, isDemo };
    setActiveAttacks((current) => [attack, ...current].slice(0, 16));
    setHistory((current) => [attack, ...current].slice(0, 80));
  }, []);

  useEffect(() => {
    if (!svgRef.current) return;
    const behavior = zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.55, 2.8])
      .filter((event: any) => {
        if (event.type === "wheel") return true;
        if (event.button === 2) return false;
        return !event.ctrlKey;
      })
      .on("zoom", (event) => groupRef.current?.setAttribute("transform", event.transform.toString()));

    zoomRef.current = behavior;
    const svg = select(svgRef.current);
    svg.call(behavior as any);
    svg.on("dblclick.zoom", null);
    svg.call(behavior.transform as any, zoomIdentity.translate(0, 0).scale(1));
    return () => { svg.on(".zoom", null); };
  }, []);

  const activeLinkIds = useMemo(() => {
    const ids = new Set<string>();
    for (const attack of activeAttacks) {
      ids.add(linkId("node-b", "node-a"));
      if (attack.targetNodeId !== "node-a") ids.add(linkId("node-a", attack.targetNodeId));
    }
    return ids;
  }, [activeAttacks]);

  const activeLinkKey = useMemo(() => Array.from(activeLinkIds).sort().join("|"), [activeLinkIds]);

  useEffect(() => {
    if (!meshRef.current) return;
    const layer = select(meshRef.current);
    const edges = layer.selectAll<SVGGElement, MeshLink>("g.modbus-mesh-edge").data(MESH_LINKS, (item: any) => item.id);
    const entered = edges.enter().append("g").attr("class", "modbus-mesh-edge mesh-edge");
    entered.append("line").attr("class", "mesh-line modbus-mesh-line");
    entered.append("line").attr("class", "mesh-hit");
    const labels = entered.append("g").attr("class", "mesh-label-wrap modbus-mesh-label-wrap");
    labels.append("rect").attr("class", "mesh-label-bg").attr("x", -54).attr("y", -8).attr("width", 108).attr("height", 16).attr("rx", 4);
    labels.append("text").attr("class", "mesh-label").attr("text-anchor", "middle").attr("y", 3);

    const merged = entered.merge(edges);
    merged.classed("is-active", (link) => activeLinkIds.has(link.id)).classed("is-sensor-mesh", (link) => link.type === "sensor-mesh");
    merged.select<SVGLineElement>("line.modbus-mesh-line")
      .attr("x1", (link) => findNode(link.source).x).attr("y1", (link) => findNode(link.source).y)
      .attr("x2", (link) => findNode(link.target).x).attr("y2", (link) => findNode(link.target).y);
    merged.select<SVGLineElement>("line.mesh-hit")
      .attr("x1", (link) => findNode(link.source).x).attr("y1", (link) => findNode(link.source).y)
      .attr("x2", (link) => findNode(link.target).x).attr("y2", (link) => findNode(link.target).y);
    merged.select<SVGGElement>("g.modbus-mesh-label-wrap")
      .attr("transform", (link) => {
        const source = findNode(link.source);
        const target = findNode(link.target);
        return `translate(${(source.x + target.x) / 2},${(source.y + target.y) / 2})`;
      })
      .style("opacity", (link) => link.type === "sensor-mesh" && !activeLinkIds.has(link.id) ? 0.45 : 1);
    merged.select<SVGTextElement>("text.mesh-label").text((link) => link.label);
    edges.exit().remove();
  }, [activeLinkIds, activeLinkKey]);
  useEffect(() => {
    if (mode !== "live" || !playing) return;
    const modbusAlerts = liveAlerts.filter(isModbusSensorAlert).sort((a, b) => timestampMs(a) - timestampMs(b));
    if (modbusAlerts.length === 0) return;

    const firstPass = processedAlertIds.current.size === 0;
    const fresh = firstPass ? modbusAlerts.slice(-4) : modbusAlerts.filter((alert) => !processedAlertIds.current.has(alert.alert_id)).slice(-12);
    for (const alert of modbusAlerts) processedAlertIds.current.add(alert.alert_id);
    fresh.forEach((alert, index) => window.setTimeout(() => addAttack(alert, false), index * 520));
  }, [addAttack, liveAlerts, mode, playing]);

  useEffect(() => {
    if (mode !== "demo" || !playing) return;
    const run = () => {
      const scenario = MODBUS_SCENARIOS[demoIndex.current % MODBUS_SCENARIOS.length];
      demoIndex.current += 1;
      addAttack(makeDemoAlert(scenario, demoIndex.current), true);
    };
    run();
    const interval = window.setInterval(run, 2400);
    return () => window.clearInterval(interval);
  }, [addAttack, mode, playing]);

  useEffect(() => {
    const interval = window.setInterval(() => {
      const now = Date.now();
      setActiveAttacks((current) => current.filter((attack) => now - attack.seenAt < ACTIVE_WINDOW_MS));
    }, 600);
    return () => window.clearInterval(interval);
  }, []);

  useEffect(() => {
    if (!fullscreen) return;
    const onKey = (event: KeyboardEvent) => { if (event.key === "Escape") setFullscreen(false); };
    window.addEventListener("keydown", onKey);
    const previousOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = previousOverflow;
    };
  }, [fullscreen]);

  const latestByNode = useMemo(() => {
    const result = new Map<string, SimAttack>();
    for (const attack of history) {
      if (!result.has(attack.targetNodeId)) result.set(attack.targetNodeId, attack);
    }
    return result;
  }, [history]);

  const activeSensorCount = useMemo(() => {
    return MODBUS_SENSORS.filter((sensor) => activeAttacks.some((attack) => attack.targetNodeId === sensorNodeId(sensor.id))).length;
  }, [activeAttacks]);

  const zoomBy = (factor: number) => {
    if (!svgRef.current || !zoomRef.current) return;
    select(svgRef.current).transition().duration(220).call(zoomRef.current.scaleBy as any, factor);
  };

  const resetZoom = () => {
    if (!svgRef.current || !zoomRef.current) return;
    select(svgRef.current).transition().duration(360).call(zoomRef.current.transform as any, zoomIdentity);
  };

  const refreshApis = () => {
    void alertsQuery.refetch();
    void statusQuery.refetch();
  };

  const latestSourceIp = history[0]?.alert.src_ip ?? NODE_B.ip;
  const stageClass = `topo-stage alerts-modbus-stage${fullscreen ? " is-alert-fullscreen" : ""}`;

  const stage = (
    <div className={stageClass} onClick={() => setSelectedNode(null)}>
      <div className="topo-grid-bg" />
      <div className="topo-vignette" />

      <div className="modbus-hud" onClick={(event) => event.stopPropagation()}>
        <div className="modbus-hud-title-wrap">
          <ShieldAlert size={16} />
          <div>
            <div className="modbus-hud-eyebrow">MODBUS TCP SENSOR DETECTION</div>
            <div className="modbus-hud-title">Node B attacking Node A and virtual sensors</div>
          </div>
        </div>
        <div className="modbus-hud-stats">
          <span className={guardianActive || mode === "demo" ? "is-good" : "is-warn"}>{mode === "demo" ? "DEMO STREAM" : guardianActive ? "GUARDIAN LIVE" : "GUARDIAN WAITING"}</span>
          <span>{activeAttacks.length} active attacks</span>
          <span>{activeSensorCount}/4 sensors hit</span>
          <span>source {latestSourceIp}</span>
        </div>
      </div>

      <div className="topo-toolbar modbus-toolbar" onClick={(event) => event.stopPropagation()}>
        <button title={playing ? "Pause attacks" : "Play attacks"} onClick={() => setPlaying((value) => !value)} aria-label={playing ? "Pause attacks" : "Play attacks"}>{playing ? <Pause size={14} /> : <Play size={14} />}</button>
        <button title="Live API mode" className={mode === "live" ? "is-active" : ""} onClick={() => setMode("live")} aria-label="Live API mode">API</button>
        <button title="Demo attack stream" className={mode === "demo" ? "is-active" : ""} onClick={() => setMode("demo")} aria-label="Demo attack stream">SIM</button>
        <button title="Refresh APIs" onClick={refreshApis} aria-label="Refresh APIs"><RefreshCw size={14} /></button>
        <button title="Zoom in" onClick={() => zoomBy(1.18)} aria-label="Zoom in"><ZoomIn size={14} /></button>
        <button title="Zoom out" onClick={() => zoomBy(1 / 1.18)} aria-label="Zoom out"><ZoomOut size={14} /></button>
        <button title="Reset view" onClick={resetZoom} aria-label="Reset view"><RotateCcw size={14} /></button>
        <button title={fullscreen ? "Exit full view" : "Full view"} onClick={() => setFullscreen((value) => !value)} aria-label={fullscreen ? "Exit full view" : "Full view"}><Maximize2 size={14} /></button>
      </div>

      <svg ref={svgRef} className="topo" viewBox={`0 0 ${VIEW_BOX.w} ${VIEW_BOX.h}`} preserveAspectRatio="xMidYMid meet" role="img" aria-label="Live Modbus attack topology">
        <defs>
          <filter id="modbusGlow" x="-80%" y="-80%" width="260%" height="260%">
            <feGaussianBlur stdDeviation="4" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
          <radialGradient id="modbusCoreGlow" cx="50%" cy="48%" r="62%">
            <stop offset="0%" stopColor="rgba(14,165,233,0.18)" />
            <stop offset="62%" stopColor="rgba(14,165,233,0.03)" />
            <stop offset="100%" stopColor="rgba(14,165,233,0)" />
          </radialGradient>
        </defs>
        <g ref={groupRef}>
          <rect x="0" y="0" width={VIEW_BOX.w} height={VIEW_BOX.h} fill="url(#modbusCoreGlow)" opacity="0.88" />
          <g className="modbus-zone-labels">
            <text x="170" y="96">ATTACKER ZONE</text>
            <text x="555" y="96">SERVER + IDS</text>
            <text x="906" y="96">VIRTUAL SENSOR MESH</text>
          </g>
          <g ref={meshRef} className="gxmesh modbus-d3-mesh" />
          <g className="modbus-attack-layer">{activeAttacks.map((attack) => <AttackBeam key={attack.id} attack={attack} />)}</g>
          <g className="modbus-node-layer">
            {SCENE_NODES.map((node) => (
              <TopologyNode
                key={node.id}
                node={node}
                attackCount={getNodeAttackCount(node, activeAttacks)}
                latestAttack={latestByNode.get(node.id)}
                selected={selectedNode?.id === node.id}
                onSelect={setSelectedNode}
                onHover={(hoveredNode, event) => setHover({ node: hoveredNode, x: event.clientX, y: event.clientY })}
                onLeave={() => setHover(null)}
              />
            ))}
          </g>
        </g>
      </svg>

      <HoverTooltip hover={hover} />
      {selectedNode && <NodeDetailPanel node={selectedNode} history={history} onClose={() => setSelectedNode(null)} />}
      <AttackLog history={history} activeCount={activeAttacks.length} />
    </div>
  );

  if (!fullscreen) return <div className="h-full min-h-0 bg-background p-3 md:p-4">{stage}</div>;
  return stage;
}
