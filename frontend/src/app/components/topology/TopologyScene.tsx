import { useEffect, useRef, useState, type RefObject } from "react";
import {
  ZONES, OVERLAPS, CLUSTERS, SHAREDS, GUARDIANS, MESH, DEVICE_LINKS, THREATS, VIEW_BOX,
  ZONE_DEVICES,
  type Cluster, type Guardian, type SharedNode, type Threat, type ZoneDevice,
  type NodeHealth,
} from "./lib/topology";
import type { PanZoomSubscribe } from "./hooks/usePanZoom";
import { useIsMobile } from "./hooks/useIsMobile";
import { Defs } from "./Defs";
import { WorldMap } from "./WorldMap";
import type { MapGuardian, MapZone } from "./lib/geospatial";

export type SelectedNode =
  | { kind: "guardian"; data: Guardian }
  | { kind: "shared"; data: SharedNode }
  | { kind: "cluster"; data: Cluster }
  | { kind: "zoneDevice"; data: ZoneDevice }
  | { kind: "threat"; data: Threat };

export interface HoverInfo {
  name: string; sub: string; x: number; y: number;
  hint?: string;
}

const smooth = (a: number, b: number, x: number) => {
  const t = Math.max(0, Math.min(1, (x - a) / (b - a)));
  return t * t * (3 - 2 * t);
};

const HEALTH: Record<NodeHealth, { color: string; label: string }> = {
  healthy: { color: "#28f0a5", label: "HEALTHY" },
  degraded: { color: "#ffb020", label: "DEGRADED" },
  critical: { color: "#ff4567", label: "CRITICAL" },
  offline: { color: "#64748b", label: "OFFLINE" },
};

function NodeGlyph({ type, x, y, size = 16 }: { type: string; x: number; y: number; size?: number }) {
  const s = size / 24;
  const common = { fill: "none", stroke: "currentColor", strokeWidth: 1.8, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  let glyph: React.ReactNode;
  if (type === "guardian") {
    glyph = <><path {...common} d="M12 2.8 20 6v5.5c0 5-3.3 8.2-8 9.7-4.7-1.5-8-4.7-8-9.7V6l8-3.2Z" /><path {...common} d="m8.5 12 2.1 2.1 4.9-5M12 3v3M4.5 8l3 1M19.5 8l-3 1" opacity=".8" /></>;
  } else if (type === "relay") {
    glyph = <><circle {...common} cx="12" cy="12" r="2.2" /><path {...common} d="M7.8 16.2a6 6 0 0 1 0-8.4M16.2 7.8a6 6 0 0 1 0 8.4M4.5 19.5a10.6 10.6 0 0 1 0-15M19.5 4.5a10.6 10.6 0 0 1 0 15" /></>;
  } else if (type === "camera") {
    glyph = <><rect {...common} x="3" y="7" width="14" height="10" rx="2" /><path {...common} d="m17 10 4-2v8l-4-2M8 17v3M5 20h6" /><circle {...common} cx="10" cy="12" r="2.5" /></>;
  } else if (type === "sensor") {
    glyph = <><circle {...common} cx="12" cy="12" r="2" /><path {...common} d="M8.5 8.5a5 5 0 0 0 0 7M15.5 8.5a5 5 0 0 1 0 7M5.5 5.5a9.2 9.2 0 0 0 0 13M18.5 5.5a9.2 9.2 0 0 1 0 13" /></>;
  } else if (type === "network") {
    glyph = <><rect {...common} x="3" y="8" width="18" height="9" rx="2" /><path {...common} d="M7 12h.01M10 12h.01M13 12h5M7 17v3M17 17v3M5 20h14" /></>;
  } else if (type === "server") {
    glyph = <><rect {...common} x="4" y="3" width="16" height="7" rx="2" /><rect {...common} x="4" y="14" width="16" height="7" rx="2" /><path {...common} d="M8 6.5h.01M8 17.5h.01M12 6.5h5M12 17.5h5" /></>;
  } else if (type === "industrial") {
    glyph = <><path {...common} d="M4 20V9l5 3V8l5 3V4h4l2 16H4Z" /><path {...common} d="M8 16h2M13 16h2M17 16h2" /></>;
  } else {
    glyph = <><rect {...common} x="5" y="6" width="14" height="10" rx="2" /><path {...common} d="M9 20h6M12 16v4M8 10h.01M11 10h5M8 13h8" /></>;
  }
  return <g className="node-glyph" transform={`translate(${x - size / 2},${y - size / 2}) scale(${s})`}>{glyph}</g>;
}

function clusterGlyph(id: string) {
  if (id === "cam") return "camera";
  if (id.startsWith("sen") || id === "mtr" || id === "ana") return "sensor";
  if (["sw", "rtr", "gw"].includes(id)) return "network";
  if (["srv", "hst"].includes(id)) return "server";
  if (["plc", "rtu", "act", "pmp"].includes(id)) return "industrial";
  return "member";
}

export function TopologyScene({
  svgRef,
  groupRef,
  subscribe,
  selectedId,
  onSelect,
  onHover,
  onGuardianDoubleClick,
  mapGuardians,
  mapZones,
}: {
  svgRef: RefObject<SVGSVGElement | null>;
  groupRef: RefObject<SVGGElement | null>;
  subscribe: PanZoomSubscribe;
  selectedId: string | null;
  onSelect: (n: SelectedNode | null) => void;
  onHover: (info: HoverInfo | null) => void;
  onGuardianDoubleClick?: (g: Guardian) => void;
  mapGuardians?: MapGuardian[];
  mapZones?: MapZone[];
}) {
  const lvl1ConnRef = useRef<SVGGElement | null>(null);
  const lvl1ClustersRef = useRef<SVGGElement | null>(null);
  const lvl2DotsRef = useRef<SVGGElement | null>(null);
  const guardianHaloRefs = useRef<Map<string, SVGCircleElement>>(new Map());
  const guardianRingRefs = useRef<Map<string, SVGCircleElement>>(new Map());

  useEffect(() => {
    return subscribe(({ k }) => {
      const t = smooth(1.20, 1.45, k);
      const u = smooth(2.20, 2.80, k);
      const lvl1Op = String(1 - t);
      const lvl2Op = 1 - (1 - t);
      const haloOp = String(1 - u * 0.85);
      const ringOp = String(1 - u * 0.7);

      if (lvl1ConnRef.current) lvl1ConnRef.current.style.opacity = lvl1Op;
      if (lvl1ClustersRef.current) lvl1ClustersRef.current.style.opacity = lvl1Op;
      if (lvl2DotsRef.current) {
        lvl2DotsRef.current.style.opacity = String(lvl2Op);
        lvl2DotsRef.current.style.pointerEvents = lvl2Op > 0.3 ? "auto" : "none";
      }
      guardianHaloRefs.current.forEach((el) => { el.style.opacity = haloOp; });
      guardianRingRefs.current.forEach((el) => { el.style.opacity = ringOp; });
    });
  }, [subscribe]);

  const isMobile = useIsMobile();

  const [booted, setBooted] = useState(false);
  useEffect(() => {
    const t = setTimeout(() => setBooted(true), 1200);
    return () => clearTimeout(t);
  }, []);
  const bootStyle = (i: number): React.CSSProperties =>
    booted ? {} : { animation: `topoNodeIn .55s cubic-bezier(.32,.72,0,1) both`, animationDelay: `${i * 35}ms`, transformOrigin: "center", transformBox: "fill-box" };

  const handleEnter = (info: { name: string; sub: string; hint?: string }) => (e: React.MouseEvent) => {
    if (isMobile) return;
    onHover({ name: info.name, sub: info.sub, hint: info.hint, x: e.clientX, y: e.clientY });
  };
  const handleMove = (info: { name: string; sub: string; hint?: string }) => (e: React.MouseEvent) => {
    if (isMobile) return;
    onHover({ name: info.name, sub: info.sub, hint: info.hint, x: e.clientX, y: e.clientY });
  };
  const handleLeave = () => { if (!isMobile) onHover(null); };

  const lastGuardianTap = useRef<{ id: string; t: number } | null>(null);
  const handleGuardianTap = (g: Guardian) => (e: React.MouseEvent | React.TouchEvent) => {
    e.stopPropagation();
    const now = Date.now();
    const last = lastGuardianTap.current;
    if (last && last.id === g.id && now - last.t < 320) {
      lastGuardianTap.current = null;
      onGuardianDoubleClick?.(g);
      return;
    }
    lastGuardianTap.current = { id: g.id, t: now };
    onSelect({ kind: "guardian", data: g });
  };
  const guardians = mapGuardians && mapGuardians.length > 0 ? mapGuardians : GUARDIANS;
  const geofenceZones = mapZones ?? [];

  return (
    <svg
      ref={svgRef}
      className="topo"
      viewBox={`0 0 ${VIEW_BOX.w} ${VIEW_BOX.h}`}
      preserveAspectRatio={isMobile ? "xMidYMid slice" : "xMidYMid meet"}
    >
      <Defs />
      <g ref={groupRef}>
        <WorldMap />

        {geofenceZones.length > 0 && (
          <g className="geo-zones">
            {geofenceZones.map((zone) => (
              <g
                key={zone.zone_id}
                className={`geo-zone${zone.enabled ? "" : " disabled"}${zone.inside ? " inside" : ""}`}
              >
                <ellipse
                  className="geo-zone-fill"
                  cx={zone.cx}
                  cy={zone.cy}
                  rx={zone.rx}
                  ry={zone.ry}
                  style={{ "--geo-zone-color": zone.color } as React.CSSProperties}
                />
                <ellipse
                  className="geo-zone-ring"
                  cx={zone.cx}
                  cy={zone.cy}
                  rx={zone.rx}
                  ry={zone.ry}
                  style={{ "--geo-zone-color": zone.color } as React.CSSProperties}
                />
                <text className="geo-zone-label" x={zone.cx} y={zone.cy - zone.ry - 8} textAnchor="middle" fill={zone.text}>
                  {zone.name.toUpperCase()}
                </text>
                <text className="geo-zone-sub" x={zone.cx} y={zone.cy - zone.ry + 6} textAnchor="middle" fill={zone.text}>
                  {zone.inside === true ? "INSIDE" : zone.inside === false ? "OUTSIDE" : zone.kind.toUpperCase()}
                </text>
              </g>
            ))}
          </g>
        )}

        <g className="cot">
          {ZONES.map((z) => (
            <g key={z.id} className="cot-zone" data-zone={z.id}>
              <ellipse className="halo" cx={z.cx} cy={z.cy} rx={z.rx} ry={z.ry} fill={`url(#${z.haloId})`} />
              <ellipse cx={z.cx} cy={z.cy} rx={z.rx} ry={z.ry} fill={z.bgFill} stroke={z.color} strokeOpacity=".55" strokeWidth="1.2" />
              <text className="label" x={z.labelX} y={z.labelY} fill={z.text} fontSize="11" letterSpacing="3" textAnchor={z.textAnchor || "start"}>{z.title}</text>
              <text className="label" x={z.labelX} y={z.labelY + 16} fill={z.color} fontSize="9" letterSpacing="2.5" opacity=".75" textAnchor={z.textAnchor || "start"}>{z.subtitle}</text>
            </g>
          ))}
        </g>

        <g className="overlaps">
          {OVERLAPS.map((o, i) => (
            <g key={i}>
              <circle className="overlap-fill" cx={o.cx} cy={o.cy} r={60} fill={`url(#${o.gradId})`} />
              <g transform={`translate(${o.tx},${o.ty})`}>
                <rect className="overlap-tag" x={0} y={0} width={o.w} height={18} rx={9} />
                <text x={o.w / 2} y={12} textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize={9} fill={o.tcolor} letterSpacing="2">{o.tag}</text>
              </g>
            </g>
          ))}
        </g>

        <g className="gxmesh">
          {MESH.map((m, i) => {
            const a = guardians.find((g) => g.id === m.from)!;
            const b = guardians.find((g) => g.id === m.to)!;
            const mx = (a.cx + b.cx) / 2;
            const my = (a.cy + b.cy) / 2;
            const dx = b.cx - a.cx;
            const dy = b.cy - a.cy;
            const bend = m.faded ? 18 : 34;
            const len = Math.max(1, Math.hypot(dx, dy));
            const qx = mx - (dy / len) * bend;
            const qy = my + (dx / len) * bend;
            const pathD = `M ${a.cx} ${a.cy} Q ${qx} ${qy} ${b.cx} ${b.cy}`;
            const meshHover = {
              name: "Federated Peering",
              sub: "mutual attestation between Guardian nodes",
              hint: "",
            };
            return (
              <g
                key={i}
                className={`mesh-edge${m.faded ? " faded" : ""}`}
                onMouseEnter={handleEnter(meshHover)}
                onMouseMove={handleMove(meshHover)}
                onMouseLeave={handleLeave}
              >
                <path className="mesh-line" d={pathD} />
                {!m.faded && (
                  <circle className="mesh-packet" r="2.6">
                    <animateMotion path={pathD} dur={`${2.4 + i * .18}s`} repeatCount="indefinite" keyPoints="0;0.15;0.78;1" keyTimes="0;0.28;0.72;1" calcMode="spline" keySplines=".4 0 .8 1;.2 0 .2 1;.2 0 .6 1" />
                  </circle>
                )}
                <path className="mesh-hit" d={pathD} />
                <g transform={`translate(${qx},${qy})`} className="mesh-label-wrap">
                  <rect className="mesh-label-bg" x={-58} y={-7} width={116} height={14} rx={3} />
                  <text className="mesh-label" textAnchor="middle" y={3}>FEDERATED PEERING</text>
                </g>
                {!m.faded && (
                  <g className="mesh-trust-proof" transform={`translate(${qx + 62},${qy - 11})`}>
                    <path d="M0-6 6-3v4c0 4-2.5 6-6 7-3.5-1-6-3-6-7v-4Z" />
                    <path d="m-2 0 1.5 1.5L3-2" />
                    <text x="10" y="3">mTLS · ATTESTED</text>
                  </g>
                )}
              </g>
            );
          })}
        </g>

        {!mapGuardians && <g ref={lvl1ConnRef} className="conn lvl1" strokeWidth={1} fill="none">
          {DEVICE_LINKS.map((link, i) => {
            const device = CLUSTERS.find((c) => c.id === link.deviceId)!;
            const guardian = GUARDIANS.find((g) => g.id === link.guardianId)!;
            const mx = (guardian.cx + device.cx) / 2;
            const my = (guardian.cy + device.cy) / 2;
            const pathD = `M ${guardian.cx} ${guardian.cy} Q ${mx + 9} ${my - 12} ${device.cx} ${device.cy}`;
            return (
              <g key={i} className="member-link">
              <path
                key={i}
                d={pathD}
                stroke={ZONES.find((z) => z.id === device.zone)!.color}
                strokeOpacity=".4"
              />
              {i % 3 === 0 && <g className="link-lock" transform={`translate(${mx - 4},${my - 5})`}><rect x="1" y="4" width="7" height="6" rx="1" /><path d="M2.5 4V2.7a2 2 0 0 1 4 0V4" /></g>}
              </g>
            );
          })}
        </g>}

        {!mapGuardians && <g ref={lvl1ClustersRef} className="lvl1 clusters">
          {CLUSTERS.map((c, i) => {
            const zoneColor = ZONES.find((z) => z.id === c.zone)!;
            const stroke = zoneColor.color;
            const fill = c.zone === "ALPHA" ? "#0a141a" : c.zone === "BRAVO" ? "#10081a" : c.zone === "CHARLIE" ? "#1a1208" : "#08101e";
            const isSelected = selectedId === `cluster:${c.id}`;
            const health = HEALTH[c.health || "healthy"];
            const hover = { name: c.name, sub: `${health.label} · ${c.sub || "MEMBER NODES"}` };
            return (
              <g
                key={c.id}
                className={`cluster node${isSelected ? " focus-node" : ""}`}
                data-zone={c.zone}
                onClick={(e) => { e.stopPropagation(); onSelect({ kind: "cluster", data: c }); }}
                onMouseEnter={handleEnter(hover)}
                onMouseMove={handleMove(hover)}
                onMouseLeave={handleLeave}
                style={{ ...bootStyle(8 + i), color: health.color, "--node-health": health.color } as React.CSSProperties}
              >
                <circle className="hit" cx={c.cx} cy={c.cy} r={31} fill="transparent" />
                <circle className="node-aura" cx={c.cx} cy={c.cy} r={28} />
                <path className="member-hex" d={`M${c.cx - 23},${c.cy - 13} L${c.cx},${c.cy - 27} L${c.cx + 23},${c.cy - 13} L${c.cx + 23},${c.cy + 13} L${c.cx},${c.cy + 27} L${c.cx - 23},${c.cy + 13} Z`} fill={fill} />
                <NodeGlyph type={clusterGlyph(c.id)} x={c.cx} y={c.cy - 3} size={17} />
                <circle className="health-orbit-dot" cx={c.cx + 24} cy={c.cy - 12} r={3.2} />
                <text className="node-count" x={c.cx} y={c.cy + 18} textAnchor="middle">{c.label}</text>
                {c.sub && (
                  <text
                    x={c.cx}
                    y={c.subAbove ? c.cy - 24 : c.cy + 38}
                    textAnchor="middle"
                    fontFamily="JetBrains Mono, monospace"
                    fontSize={9}
                    fill={zoneColor.text}
                    letterSpacing="2"
                  >
                    {c.sub}
                  </text>
                )}
              </g>
            );
          })}
        </g>}

        {!mapGuardians && <g ref={lvl2DotsRef} className="lvl2 zone-dots-wrap" style={{ opacity: 0, pointerEvents: "none" }}>
          {ZONE_DEVICES.map((d) => {
            const status = d.status === "err" ? "#EF4444" : "#22c55e";
            const hover = { name: d.id, sub: `Device · ${d.zone}` };
            const isSelected = selectedId === `zoneDevice:${d.id}`;
            return (
              <g
                key={d.id}
                className={`device-dot node${isSelected ? " focus-node" : ""}`}
                data-zone={d.zone}
                onClick={(e) => { e.stopPropagation(); onSelect({ kind: "zoneDevice", data: d }); }}
                onMouseEnter={handleEnter(hover)}
                onMouseMove={handleMove(hover)}
                onMouseLeave={handleLeave}
              >
                <circle className="hit" cx={d.x} cy={d.y} r={22} fill="transparent" />
                <circle cx={d.x} cy={d.y} r={6} fill="#0a121c" stroke={d.stroke} strokeOpacity=".75" />
                <circle cx={d.x + 5} cy={d.y - 5} r={2} fill={status} style={{ animation: "topoStatusBlink 2.4s infinite" }} />
                <text x={d.x} y={d.y + 18} textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize={8} fill={d.color}>{d.id}</text>
              </g>
            );
          })}
        </g>}

        {!mapGuardians && <g className="shareds">
          {SHAREDS.map((s, i) => {
            const isSelected = selectedId === `shared:${s.id}`;
            const health = HEALTH[s.health || "healthy"];
            const hover = { name: s.name, sub: `${health.label} · ${s.role}` };
            return (
              <g
                key={s.id}
                className={`shared node${isSelected ? " focus-node" : ""}`}
                onClick={(e) => { e.stopPropagation(); onSelect({ kind: "shared", data: s }); }}
                onMouseEnter={handleEnter(hover)}
                onMouseMove={handleMove(hover)}
                onMouseLeave={handleLeave}
                style={{ ...bootStyle(4 + i), color: health.color, "--node-health": health.color } as React.CSSProperties}
              >
                <circle className="hit" cx={s.cx} cy={s.cy} r={32} fill="transparent" />
                <g transform={`translate(${s.cx},${s.cy})`}>
                  <circle className="node-aura" r={31} />
                  <circle className="relay-orbit relay-orbit-a" r={25} stroke={s.ringA} />
                  <circle className="relay-orbit relay-orbit-b" r={19} stroke={s.ringB} />
                  <circle className="node-core" r={15} />
                  <NodeGlyph type="relay" x={0} y={0} size={18} />
                  <circle className="health-orbit-dot" cx={22} cy={-18} r={3.2} />
                </g>
                <text className="label" x={s.cx} y={s.subAbove ? s.cy - 26 : s.cy + 45} textAnchor="middle" fontSize={10} fontWeight={600} fill="#e2e8f0">{s.name}</text>
                <text className="label" x={s.cx} y={s.subAbove ? s.cy - 13 : s.cy + 58} textAnchor="middle" fontSize={8} fill="#94a3b8" letterSpacing="2">{s.sub}</text>
              </g>
            );
          })}
        </g>}

        <g className="guardians">
          {guardians.map((g, i) => {
            const isSelected = selectedId === `guardian:${g.id}`;
            const health = HEALTH[g.health || "healthy"];
            const mapMeta = "lat" in g ? ` · ${(g as MapGuardian).lat.toFixed(3)}, ${(g as MapGuardian).lng.toFixed(3)}` : "";
            const hover = { name: g.name, sub: `${health.label} · ${g.role}${mapMeta}` };
            return (
              <g
                key={g.id}
                className={`gx node${isSelected ? " focus-node" : ""}`}
                data-zone={g.zone}
                onClick={handleGuardianTap(g)}
                onDoubleClick={(e) => { e.stopPropagation(); onGuardianDoubleClick?.(g); }}
                onMouseEnter={handleEnter(hover)}
                onMouseMove={handleMove(hover)}
                onMouseLeave={handleLeave}
                style={{ ...bootStyle(i), color: health.color, "--node-health": health.color } as React.CSSProperties}
              >
                <circle className="hit" cx={g.cx} cy={g.cy} r={48} fill="transparent" />
                <circle
                  ref={(el) => {
                    if (el) guardianHaloRefs.current.set(g.id, el);
                    else guardianHaloRefs.current.delete(g.id);
                  }}
                  cx={g.cx} cy={g.cy} r={58} fill={`url(#${g.haloId})`}
                  style={{ transition: "opacity .2s linear" }}
                />
                <circle
                  ref={(el) => {
                    if (el) guardianRingRefs.current.set(g.id, el);
                    else guardianRingRefs.current.delete(g.id);
                  }}
                  cx={g.cx} cy={g.cy} r={40} fill="none" stroke={g.ring} strokeOpacity=".35" strokeWidth="1"
                  style={{ transition: "opacity .2s linear" }}
                />
                <circle className="guardian-scan" cx={g.cx} cy={g.cy} r={34} />
                <circle className="guardian-orbit guardian-orbit-a" cx={g.cx} cy={g.cy} r={42} />
                <circle className="guardian-orbit guardian-orbit-b" cx={g.cx} cy={g.cy} r={48} />
                <circle className="node-core guardian-core" cx={g.cx} cy={g.cy} r={27} />
                <NodeGlyph type="guardian" x={g.cx} y={g.cy - 3} size={25} />
                <g className="attestation-badge" transform={`translate(${g.cx - 41},${g.cy - 31})`}>
                  <rect width="24" height="13" rx="6.5" />
                  <path d="m6 6.5 2 2 4-4" />
                  <text x="17" y="9">A</text>
                </g>
                <circle className="health-orbit-dot" cx={g.cx + 25} cy={g.cy - 20} r={4} />
                <text className="guardian-label" x={g.cx} y={g.cy + 42} textAnchor="middle">{g.label} · {g.sub}</text>
                <text className="health-label" x={g.cx} y={g.cy + 54} textAnchor="middle">{health.label}</text>
                <g transform={`translate(${g.cx + 32},${g.cy - 24})`}>
                  <rect rx={8} ry={8} width={46} height={18} fill={g.bodyFill} stroke={g.ring} strokeOpacity=".55" />
                  <text x={23} y={13} textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize={10} fontWeight={600} fill={g.text}>{g.peers}</text>
                </g>
                {g.threats !== undefined && (
                  <g transform={`translate(${g.cx + 32},${g.cy - 2})`}>
                    <rect rx={8} ry={8} width={46} height={18} fill="rgba(239,68,68,0.18)" stroke="rgba(239,68,68,0.6)" />
                    <circle cx={9} cy={9} r={3} fill="#EF4444" />
                    <text x={32} y={13} textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize={10} fontWeight={600} fill="#fecaca">{g.threats}</text>
                  </g>
                )}
              </g>
            );
          })}
        </g>

        <g className="threats-wrap">
          {THREATS.map((t, i) => {
            const isSelected = selectedId === `threat:${t.id}`;
            const hover = { name: t.name, sub: `${t.sev} · ${t.role}` };
            return (
              <g
                key={t.id}
                className={`threat node${isSelected ? " focus-node" : ""}`}
                style={bootStyle(20 + i)}
                onClick={(e) => { e.stopPropagation(); onSelect({ kind: "threat", data: t }); }}
                onMouseEnter={handleEnter(hover)}
                onMouseMove={handleMove(hover)}
                onMouseLeave={handleLeave}
              >
                <line className="threat-beam" x1={t.beam.x1} y1={t.beam.y1} x2={t.beam.x2} y2={t.beam.y2} />
                <circle className="hit" cx={t.cx} cy={t.cy} r={28} fill="transparent" />
                <circle className="threat-pulse" cx={t.cx} cy={t.cy} r={22} />
                <circle className="threat-radar" cx={t.cx} cy={t.cy} r={25} />
                <circle cx={t.cx} cy={t.cy} r={18} fill="#1a0608" stroke="#EF4444" strokeWidth="2" />
                <text x={t.cx} y={t.cy + 6} textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize={14} fontWeight={800} fill="#fecaca">!</text>
                <g className="containment-mark" transform={`translate(${t.cx + 18},${t.cy - 22})`}>
                  <path d="M0-5 5-3v4c0 3-2 5-5 6-3-1-5-3-5-6v-4Z" />
                  <path d="m-2 0 1.5 1.5L3-2" />
                </g>
                <g transform={`translate(${t.badgeX},${t.badgeY})`}>
                  <rect rx={3} ry={3} width={t.badgeW} height={18} fill="rgba(239,68,68,0.22)" stroke="rgba(239,68,68,0.7)" />
                  <text x={t.badgeW / 2} y={13} textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize={10} fontWeight={800} fill="#fecaca" letterSpacing="2.5">{t.badgeText}</text>
                </g>
                <text x={t.cx} y={t.nameY} textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize={11} fontWeight={600} fill="#fecaca">{t.name}</text>
                <text x={t.cx} y={t.subY} textAnchor="middle" fontFamily="JetBrains Mono, monospace" fontSize={9} fill="#fca5a5" letterSpacing="2.5">{t.sev === "CRITICAL" ? "DEAUTH · BLOCKED" : "UNATTESTED · BLOCKED"}</text>
              </g>
            );
          })}
        </g>
      </g>
    </svg>
  );
}
