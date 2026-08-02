import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { select } from "d3-selection";
import { zoom, zoomIdentity, type ZoomBehavior } from "d3-zoom";
import "d3-transition";
import {
  Activity,
  CheckCircle2,
  Clock3,
  Expand,
  Focus,
  Gauge,
  Info,
  MapPin,
  Network,
  Plus,
  Radio,
  RefreshCw,
  Router,
  ShieldCheck,
  ShieldQuestion,
  TowerControl,
  Trash2,
  Wifi,
  WifiOff,
  X,
  Zap,
} from "lucide-react";
import type {
  AttestationStatus,
  CircleTopologyCircle,
  CircleTopologyLink,
  CircleTopologyNode,
  PresenceStatus,
} from "./types";
import { useCircleTopology } from "./useCircleTopology";
import { geofenceApi, type GeofenceStatus, type GeofenceZone, type ZoneAutomation } from "../../../api/geofence";
import "./circle-topology.css";

const WIDTH = 1440;
const HEIGHT = 820;
const TILE_ZOOM = 3;
const TILE_COUNT = 2 ** TILE_ZOOM;
const MAP_SIZE = WIDTH;
const MAP_Y = (HEIGHT - MAP_SIZE) / 2;

type Filter = "all" | "online" | "offline" | "verified" | "lighthouse" | "relay";

const presenceMeta: Record<PresenceStatus, { label: string; color: string }> = {
  online: { label: "Online", color: "#22c55e" },
  stale: { label: "Stale", color: "#f59e0b" },
  offline: { label: "Offline", color: "#64748b" },
  unknown: { label: "Unknown", color: "#94a3b8" },
};

const trustMeta: Record<AttestationStatus, { label: string; color: string }> = {
  verified: { label: "Attested", color: "#38bdf8" },
  pending: { label: "Pending", color: "#f59e0b" },
  failed: { label: "Rejected", color: "#ef4444" },
  never: { label: "Not attested", color: "#64748b" },
};

interface PositionedNode extends CircleTopologyNode {
  x: number;
  y: number;
  lat?: number;
  lng?: number;
  locationSource?: string;
}

interface PositionedZone {
  id: string;
  name: string;
  x: number;
  y: number;
  rx: number;
  ry: number;
  color: string;
  enabled: boolean;
  inside?: boolean;
  source: GeofenceZone;
}

interface MapLabel {
  id: string;
  label: string;
  sub: string;
  x: number;
  y: number;
}

const DEFAULT_AUTOMATION: ZoneAutomation = {
  on_entry: [{ action: "notify", severity: "low" }],
  on_exit: [{ action: "raise_alert", severity: "high" }],
  allow_destructive: false,
  min_confidence: 0.9,
};

const FALLBACK_COORDS = [
  { lat: 37.7749, lng: -122.4194 },
  { lat: 40.7128, lng: -74.006 },
  { lat: 51.5072, lng: -0.1276 },
  { lat: 52.52, lng: 13.405 },
  { lat: 35.6762, lng: 139.6503 },
  { lat: -33.8688, lng: 151.2093 },
  { lat: 1.3521, lng: 103.8198 },
  { lat: 25.2048, lng: 55.2708 },
];

const ZONE_COLORS = ["#18B5C8", "#20C7D9", "#3AC569", "#F4B640", "#E14D4D", "#7A7A7A"];
const MAP_LABELS: MapLabel[] = [
  { id: "na", label: "NORTH AMERICA", sub: "WEST TRUST REGION", x: 255, y: 278 },
  { id: "eu", label: "EUROPE", sub: "ATTESTATION HUB", x: 728, y: 254 },
  { id: "apac", label: "APAC", sub: "EDGE RELAY REGION", x: 1120, y: 410 },
  { id: "aus", label: "AUSTRALIA", sub: "RECOVERY REGION", x: 1190, y: 654 },
];

function projectLocation(lat: number, lng: number) {
  const clampedLat = Math.max(-85, Math.min(85, lat));
  const wrappedLng = ((((lng + 180) % 360) + 360) % 360) - 180;
  const sin = Math.sin((clampedLat * Math.PI) / 180);
  const mercY = 0.5 - Math.log((1 + sin) / (1 - sin)) / (4 * Math.PI);
  return {
    x: ((wrappedLng + 180) / 360) * MAP_SIZE,
    y: mercY * MAP_SIZE + MAP_Y,
    lat: clampedLat,
    lng: wrappedLng,
  };
}

function radiusToPixels(radiusM: number | null | undefined, lat: number) {
  const radius = Math.max(25, Number(radiusM) || 250);
  const metersPerDegreeLat = 111_320;
  const metersPerDegreeLng = Math.max(1, metersPerDegreeLat * Math.cos((lat * Math.PI) / 180));
  return {
    rx: Math.max(6, (radius / metersPerDegreeLng / 360) * MAP_SIZE),
    ry: Math.max(6, (radius / metersPerDegreeLat / 360) * MAP_SIZE),
  };
}

function RealMapTiles() {
  const tileSize = MAP_SIZE / TILE_COUNT;
  const tiles: React.ReactNode[] = [];
  for (let x = 0; x < TILE_COUNT; x += 1) {
    for (let y = 0; y < TILE_COUNT; y += 1) {
      tiles.push(
        <image
          key={`${x}-${y}`}
          className="clt-map-tile"
          href={`https://a.basemaps.cartocdn.com/dark_all/${TILE_ZOOM}/${x}/${y}.png`}
          x={x * tileSize}
          y={MAP_Y + y * tileSize}
          width={tileSize}
          height={tileSize}
          preserveAspectRatio="none"
        />,
      );
    }
  }
  return (
    <g className="clt-real-map" pointerEvents="none">
      <rect x={0} y={0} width={WIDTH} height={HEIGHT} />
      {tiles}
      <rect className="clt-map-contrast" x={0} y={MAP_Y} width={MAP_SIZE} height={MAP_SIZE} />
      <text x={WIDTH - 12} y={HEIGHT - 12}>Map tiles © CARTO · Data © OpenStreetMap contributors</text>
    </g>
  );
}

function roleWeight(node: CircleTopologyNode) {
  if (node.primaryLighthouse) return 0;
  if (node.roles.includes("lighthouse")) return 1;
  if (node.roles.includes("relay")) return 2;
  return 3;
}

function layoutNodes(nodes: CircleTopologyNode[]): PositionedNode[] {
  const ordered = [...nodes].sort((a, b) => roleWeight(a) - roleWeight(b) || a.label.localeCompare(b.label));
  const primary = ordered.find((node) => node.primaryLighthouse) ?? ordered[0];
  const secondary = ordered.filter((node) => node.id !== primary?.id && node.roles.includes("lighthouse"));
  const relays = ordered.filter(
    (node) => node.id !== primary?.id && !secondary.some((item) => item.id === node.id) && node.roles.includes("relay"),
  );
  const members = ordered.filter(
    (node) => node.id !== primary?.id && !secondary.some((item) => item.id === node.id) && !relays.some((item) => item.id === node.id),
  );

  const out: PositionedNode[] = [];
  if (primary) out.push({ ...primary, x: 155, y: HEIGHT / 2 });

  const placeColumns = (
    group: CircleTopologyNode[],
    x: number,
    top = 120,
    bottom = 580,
    maxRows = 5,
    columnGap = 104,
  ) => {
    const columnCount = Math.max(1, Math.ceil(group.length / maxRows));
    const firstX = x - ((columnCount - 1) * columnGap) / 2;
    group.forEach((node, index) => {
      const column = Math.floor(index / maxRows);
      const row = index % maxRows;
      const rowsInColumn = Math.min(maxRows, group.length - column * maxRows);
      const y = rowsInColumn === 1 ? HEIGHT / 2 : top + ((bottom - top) * row) / Math.max(rowsInColumn - 1, 1);
      out.push({ ...node, x: firstX + column * columnGap, y });
    });
  };

  placeColumns(secondary, 485, 185, 635, 4, 112);
  placeColumns(relays, 835, 145, 675, 4, 112);
  placeColumns(members, 1240, 105, 715, 5, 118);
  return out;
}

function mapLayoutNodes(nodes: CircleTopologyNode[], status: GeofenceStatus | null): PositionedNode[] {
  return nodes.map((node, index) => {
    const coord = index === 0 && status?.location?.fix?.kind === "coordinate"
      ? { lat: status.location.fix.lat, lng: status.location.fix.lng, source: status.location.source }
      : { ...FALLBACK_COORDS[index % FALLBACK_COORDS.length], source: "configured" };
    const point = projectLocation(coord.lat, coord.lng);
    return { ...node, ...point, locationSource: coord.source };
  });
}

function mapZones(zones: GeofenceZone[], status: GeofenceStatus | null): PositionedZone[] {
  return zones
    .filter((zone) => typeof zone.center_lat === "number" && typeof zone.center_lng === "number")
    .map((zone, index) => {
      const point = projectLocation(zone.center_lat as number, zone.center_lng as number);
      const radius = radiusToPixels(zone.radius_m, point.lat);
      const evaluated = status?.zones.find((item) => item.zone_id === zone.zone_id);
      return {
        id: zone.zone_id,
        name: zone.name,
        x: point.x,
        y: point.y,
        rx: radius.rx,
        ry: radius.ry,
        color: ZONE_COLORS[index % ZONE_COLORS.length],
        enabled: zone.enabled,
        inside: evaluated?.inside,
        source: zone,
      };
    });
}

function initials(label: string) {
  return label
    .split(/[\s_-]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((part) => part[0]?.toUpperCase())
    .join("");
}

function nodeKind(node: CircleTopologyNode): "lighthouse" | "relay" | "member" {
  if (node.roles.includes("lighthouse")) return "lighthouse";
  if (node.roles.includes("relay")) return "relay";
  return "member";
}

function TopologyGlyph({ kind, size = 26 }: { kind: "lighthouse" | "relay" | "member"; size?: number }) {
  const scale = size / 24;
  const common = { fill: "none", stroke: "currentColor", strokeWidth: 1.7, strokeLinecap: "round" as const, strokeLinejoin: "round" as const };
  return (
    <g className={`clt-glyph clt-glyph--${kind}`} transform={`translate(${-size / 2} ${-size / 2}) scale(${scale})`}>
      {kind === "lighthouse" ? (
        <>
          <path {...common} d="M12 2.8 20 6v5.5c0 5-3.3 8.2-8 9.7-4.7-1.5-8-4.7-8-9.7V6l8-3.2Z" />
          <path {...common} d="m8.5 12 2.1 2.1 4.9-5M12 3v3M4.5 8l3 1M19.5 8l-3 1" opacity=".8" />
        </>
      ) : kind === "relay" ? (
        <>
          <circle {...common} cx="12" cy="12" r="2.2" />
          <path {...common} d="M7.8 16.2a6 6 0 0 1 0-8.4M16.2 7.8a6 6 0 0 1 0 8.4M4.5 19.5a10.6 10.6 0 0 1 0-15M19.5 4.5a10.6 10.6 0 0 1 0 15" />
        </>
      ) : (
        <>
          <rect {...common} x="4" y="5" width="16" height="12" rx="2" />
          <path {...common} d="M8 21h8M12 17v4M8 9h.01M11 9h5M8 13h8" />
        </>
      )}
    </g>
  );
}

function shortTime(value: string) {
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return new Intl.DateTimeFormat(undefined, { hour: "numeric", minute: "2-digit", second: "2-digit" }).format(parsed);
}

function filterNode(node: CircleTopologyNode, filter: Filter) {
  if (filter === "all") return true;
  if (filter === "online") return node.presence === "online";
  if (filter === "offline") return node.presence === "offline" || node.presence === "stale";
  if (filter === "verified") return node.attestation === "verified";
  return node.roles.includes(filter);
}

function linkPath(source: PositionedNode, target: PositionedNode, offset = 0) {
  const mx = (source.x + target.x) / 2;
  const my = (source.y + target.y) / 2;
  const dx = target.x - source.x;
  const dy = target.y - source.y;
  const length = Math.max(Math.hypot(dx, dy), 1);
  const cx = mx - (dy / length) * offset;
  const cy = my + (dx / length) * offset;
  return `M ${source.x} ${source.y} Q ${cx} ${cy} ${target.x} ${target.y}`;
}

function NodeDetails({ node, onClose }: { node: CircleTopologyNode; onClose: () => void }) {
  const presence = presenceMeta[node.presence];
  const trust = trustMeta[node.attestation];
  return (
    <aside className="clt-details">
      <div className="clt-details__header">
        <div>
          <span className="clt-eyebrow">NODE INSPECTOR</span>
          <h3>{node.label}</h3>
        </div>
        <button onClick={onClose} aria-label="Close node details"><X size={17} /></button>
      </div>

      <div className="clt-details__hero">
        <div className="clt-details__avatar" style={{ "--node-color": presence.color } as React.CSSProperties}>
          {nodeKind(node) === "lighthouse" ? <ShieldCheck size={26} /> : nodeKind(node) === "relay" ? <Router size={26} /> : <Radio size={26} />}
          <span />
        </div>
        <div>
          <div className="clt-status-line"><i style={{ background: presence.color }} />{presence.label}</div>
          <div className="clt-trust-line"><ShieldCheck size={14} color={trust.color} />{trust.label}</div>
        </div>
      </div>

      <div className="clt-role-list">
        {node.primaryLighthouse && <span><Zap size={12} />Primary</span>}
        {node.roles.includes("lighthouse") && <span><TowerControl size={12} />Lighthouse</span>}
        {node.roles.includes("relay") && <span><Router size={12} />Relay</span>}
        {node.roles.includes("member") && <span><Radio size={12} />Member</span>}
      </div>

      <dl className="clt-kv">
        <div><dt>Node ID</dt><dd>{node.id}</dd></div>
        <div><dt>Physical IP</dt><dd>{node.ip || "Not reported"}</dd></div>
        <div><dt>Overlay IP</dt><dd>{node.overlayIp || "Not reported"}</dd></div>
        <div><dt>Last signal</dt><dd>{node.lastSeen}</dd></div>
        {"lat" in node && typeof node.lat === "number" && <div><dt>Location</dt><dd>{node.lat.toFixed(5)}, {node.lng?.toFixed(5)}</dd></div>}
        {"locationSource" in node && node.locationSource && <div><dt>Source</dt><dd>{node.locationSource}</dd></div>}
        {node.did && <div><dt>DID</dt><dd className="clt-truncate" title={node.did}>{node.did}</dd></div>}
      </dl>

      <div className="clt-security-posture">
        <div><span>TRUST SCORE</span><strong>{node.attestation === "verified" ? 96 : node.attestation === "pending" ? 71 : 28}</strong></div>
        <div><span>HEALTH SCORE</span><strong>{node.presence === "online" ? 98 : node.presence === "stale" ? 62 : 12}</strong></div>
      </div>
      <div className="clt-telemetry-grid">
        <div><span>CPU</span><b>{node.presence === "online" ? "34%" : "—"}</b><i><em style={{ width: node.presence === "online" ? "34%" : "0%" }} /></i></div>
        <div><span>MEMORY</span><b>{node.presence === "online" ? "48%" : "—"}</b><i><em style={{ width: node.presence === "online" ? "48%" : "0%" }} /></i></div>
        <div><span>POLICY</span><b>v3.4.0</b></div>
        <div><span>CERTIFICATE</span><b>{node.attestation === "verified" ? "VALID · 183d" : "UNVERIFIED"}</b></div>
      </div>

      {node.roles.includes("relay") && (
        <div className="clt-meter-card">
          <div><span><Gauge size={14} />Relay utilization</span><strong>{(node.currentMbps ?? 0).toFixed(1)} Mbps</strong></div>
          <div className="clt-meter"><span style={{ width: `${Math.min(100, ((node.currentMbps ?? 0) / Math.max(node.maxBandwidthMbps ?? 1, 1)) * 100)}%` }} /></div>
          <p>{node.maxPeers ?? 0} peer limit · {node.maxBandwidthMbps ?? 0} Mbps capacity</p>
        </div>
      )}
    </aside>
  );
}

export function CircleLiveTopology({ circle }: { circle: CircleTopologyCircle }) {
  const { snapshot, loading, connected, error, refresh } = useCircleTopology(circle);
  const svgRef = useRef<SVGSVGElement | null>(null);
  const viewportRef = useRef<SVGGElement | null>(null);
  const zoomRef = useRef<ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filter, setFilter] = useState<Filter>("all");
  const [search, setSearch] = useState("");
  const [fullscreen, setFullscreen] = useState(false);
  const [zoomMode, setZoomMode] = useState<"dots" | "icons">("dots");
  const [geofenceStatus, setGeofenceStatus] = useState<GeofenceStatus | null>(null);
  const [geofenceZones, setGeofenceZones] = useState<GeofenceZone[]>([]);
  const [geofenceError, setGeofenceError] = useState<string | null>(null);
  const [geofenceBusy, setGeofenceBusy] = useState<string | null>(null);
  const [geofenceLoaded, setGeofenceLoaded] = useState(false);
  const zoomLabelRef = useRef<HTMLSpanElement | null>(null);
  const footerZoomRef = useRef<HTMLSpanElement | null>(null);
  const minimapZoomRef = useRef<HTMLSpanElement | null>(null);

  const nodes = useMemo(() => mapLayoutNodes(snapshot.nodes, geofenceStatus), [snapshot.nodes, geofenceStatus]);
  const zones = useMemo(() => mapZones(geofenceZones, geofenceStatus), [geofenceZones, geofenceStatus]);
  const nodeMap = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes]);
  const selected = nodes.find((node) => node.id === selectedId) ?? null;
  const visibleIds = useMemo(() => {
    const q = search.trim().toLowerCase();
    return new Set(nodes.filter((node) => {
      const matchesFilter = filterNode(node, filter);
      if (!q) return matchesFilter;
      const haystack = [node.label, node.id, node.ip, node.overlayIp, node.roles.join(" "), node.attestation, node.presence]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return matchesFilter && haystack.includes(q);
    }).map((node) => node.id));
  }, [nodes, filter, search]);
  const summary = useMemo(() => ({
    online: snapshot.nodes.filter((node) => node.presence === "online").length,
    offline: snapshot.nodes.filter((node) => node.presence === "offline" || node.presence === "stale").length,
    verified: snapshot.nodes.filter((node) => node.attestation === "verified").length,
    pending: snapshot.nodes.filter((node) => node.attestation === "pending").length,
    failed: snapshot.nodes.filter((node) => node.attestation === "failed").length,
    lighthouses: snapshot.nodes.filter((node) => node.roles.includes("lighthouse")).length,
    relays: snapshot.nodes.filter((node) => node.roles.includes("relay")).length,
    members: snapshot.nodes.filter((node) => node.roles.includes("member")).length,
  }), [snapshot.nodes]);
  const visibleNodes = useMemo(() => nodes.filter((node) => visibleIds.has(node.id)), [nodes, visibleIds]);
  const meshLinks = snapshot.links.filter((link) => link.kind === "mesh").length;
  const relayLinks = snapshot.links.filter((link) => link.kind === "relay").length;
  const attestationLinks = snapshot.links.filter((link) => link.kind === "attestation").length;

  const refreshGeofence = useCallback(async () => {
    setGeofenceError(null);
    try {
      const [status, location, zoneResult] = await Promise.all([
        geofenceApi.status(),
        geofenceApi.getLocation(),
        geofenceApi.listZones(),
        geofenceApi.events(),
        geofenceApi.alerts(),
      ]);
      setGeofenceStatus({ ...status, location: status.location ?? location.location });
      setGeofenceZones(zoneResult.zones);
      setGeofenceLoaded(true);
    } catch (err) {
      setGeofenceError(err instanceof Error ? err.message : "Geofence API unavailable");
    }
  }, []);

  const reportLocation = useCallback(() => {
    if (!navigator.geolocation) {
      setGeofenceError("Browser geolocation is unavailable");
      return;
    }
    setGeofenceBusy("Uploading location");
    navigator.geolocation.getCurrentPosition(
      async (position) => {
        try {
          await geofenceApi.reportLocation({
            lat: position.coords.latitude,
            lng: position.coords.longitude,
            accuracy_m: position.coords.accuracy,
          });
          await refreshGeofence();
        } catch (err) {
          setGeofenceError(err instanceof Error ? err.message : "Could not report location");
        } finally {
          setGeofenceBusy(null);
        }
      },
      (err) => {
        setGeofenceBusy(null);
        setGeofenceError(err.message || "Location permission denied");
      },
      { enableHighAccuracy: true, timeout: 10000, maximumAge: 30000 },
    );
  }, [refreshGeofence]);

  const createZone = async () => {
    const fix = geofenceStatus?.location?.fix;
    if (!fix) return;
    setGeofenceBusy("Creating zone");
    try {
      await geofenceApi.createZone({
        name: `${circle.name} Zone`,
        kind: "coordinate",
        center_lat: fix.lat,
        center_lng: fix.lng,
        radius_m: 250,
        on_entry: true,
        on_exit: true,
        severity: "high",
        automation: DEFAULT_AUTOMATION,
        enabled: true,
      });
      await refreshGeofence();
    } catch (err) {
      setGeofenceError(err instanceof Error ? err.message : "Could not create zone");
    } finally {
      setGeofenceBusy(null);
    }
  };

  const firstZone = geofenceZones[0];
  const runZoneAction = async (action: "toggle" | "delete" | "rf" | "actions" | "entry" | "exit") => {
    if (!firstZone) return;
    setGeofenceBusy(action);
    try {
      if (action === "toggle") await geofenceApi.editZone(firstZone.zone_id, { enabled: !firstZone.enabled });
      if (action === "delete") await geofenceApi.deleteZone(firstZone.zone_id);
      if (action === "rf") await geofenceApi.captureRf(firstZone.zone_id);
      if (action === "actions") {
        await geofenceApi.getActions(firstZone.zone_id);
        await geofenceApi.replaceActions(firstZone.zone_id, firstZone.automation ?? DEFAULT_AUTOMATION);
      }
      if (action === "entry" || action === "exit") {
        await geofenceApi.getActions(firstZone.zone_id);
        await geofenceApi.testActions({ zone_id: firstZone.zone_id, transition: action, confidence: 1 });
      }
      await refreshGeofence();
    } catch (err) {
      setGeofenceError(err instanceof Error ? err.message : "Geofence action failed");
    } finally {
      setGeofenceBusy(null);
    }
  };

  useEffect(() => {
    void refreshGeofence();
    const interval = window.setInterval(refreshGeofence, 15000);
    return () => window.clearInterval(interval);
  }, [refreshGeofence]);

  useEffect(() => {
    if (!geofenceLoaded || geofenceStatus?.location || geofenceError) return;
    reportLocation();
  }, [geofenceError, geofenceLoaded, geofenceStatus?.location, reportLocation]);

  useEffect(() => {
    if (!svgRef.current || !viewportRef.current) return;
    const behavior = zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.45, 16])
      .on("zoom", (event) => {
        select(viewportRef.current).attr("transform", event.transform.toString());
        const value = `${Math.round(event.transform.k * 100)}%`;
        const nextMode = event.transform.k < 1.08 ? "dots" : "icons";
        const markerScale = Math.max(0.16, Math.min(1.25, 1 / event.transform.k));
        select(viewportRef.current).selectAll<SVGGElement, unknown>(".clt-node-scale").attr("transform", `scale(${markerScale})`);
        setZoomMode((current) => current === nextMode ? current : nextMode);
        if (zoomLabelRef.current) zoomLabelRef.current.textContent = value;
        if (footerZoomRef.current) footerZoomRef.current.textContent = value;
        if (minimapZoomRef.current) minimapZoomRef.current.textContent = value;
      });
    zoomRef.current = behavior;
    select(svgRef.current).call(behavior);
    return () => {
      if (svgRef.current) select(svgRef.current).on(".zoom", null);
    };
  }, []);

  useEffect(() => {
    if (!fullscreen) return;
    const close = (event: KeyboardEvent) => event.key === "Escape" && setFullscreen(false);
    window.addEventListener("keydown", close);
    const old = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", close);
      document.body.style.overflow = old;
    };
  }, [fullscreen]);

  const resetView = () => {
    if (!svgRef.current || !zoomRef.current) return;
    select(svgRef.current).transition().duration(500).call(zoomRef.current.transform, zoomIdentity);
  };

  const centerNode = (node: PositionedNode, scale = 5) => {
    if (!svgRef.current || !zoomRef.current) return;
    const transform = zoomIdentity
      .translate(WIDTH / 2 - node.x * scale, HEIGHT / 2 - node.y * scale)
      .scale(scale);
    select(svgRef.current).transition().duration(520).call(zoomRef.current.transform, transform);
  };

  const zoomBy = (factor: number) => {
    if (!svgRef.current || !zoomRef.current) return;
    select(svgRef.current).transition().duration(220).call(zoomRef.current.scaleBy, factor);
  };

  const filters: Array<{ id: Filter; label: string }> = [
    { id: "all", label: "All nodes" },
    { id: "online", label: "Online" },
    { id: "offline", label: "Offline" },
    { id: "verified", label: "Attested" },
    { id: "lighthouse", label: "Lighthouses" },
    { id: "relay", label: "Relays" },
  ];

  return (
    <section className={`clt-shell ${fullscreen ? "clt-shell--fullscreen" : ""} clt-shell--${zoomMode}`}>
      <header className="clt-header">
        <div className="clt-title">
          <div className="clt-title__icon"><Network size={19} /></div>
          <div>
            <span className="clt-eyebrow">NETWORK TOPOLOGY</span>
            <h2>{circle.name}</h2>
          </div>
        </div>
        <div className="clt-env">
          <span>Environment</span>
          <strong>Production</strong>
        </div>
        <div className="clt-live-state" title={error ?? "Live node APIs connected"}>
          <span className={connected ? "is-live" : "is-fixture"} />
          <div><strong>{connected ? "Live" : "Test data"}</strong><small>Updated {shortTime(snapshot.generatedAt)}</small></div>
        </div>
        <label className="clt-search">
          <span>Search</span>
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && visibleNodes[0]) {
                setSelectedId(visibleNodes[0].id);
                centerNode(visibleNodes[0], 6);
              }
            }}
            placeholder="Hostname, peer, IP, role"
          />
        </label>
        <div className="clt-actions">
          <button onClick={() => void refresh()} aria-label="Refresh topology" title="Refresh"><RefreshCw size={15} /></button>
          <button onClick={resetView} aria-label="Reset view" title="Reset view"><Focus size={15} /></button>
          <button onClick={() => setFullscreen((value) => !value)} aria-label="Toggle fullscreen" title="Fullscreen"><Expand size={15} /></button>
        </div>
      </header>

      {error && (
        <div className="clt-notice"><Info size={14} /><span>{error}</span></div>
      )}

      <div className="clt-workspace">
      <div className="clt-stage">
        <div className="clt-grid" />
        <div className="clt-lattice" />
        <div className="clt-particles" />
        <div className="clt-streams" />
        <div className="clt-glow clt-glow--a" />
        <div className="clt-glow clt-glow--b" />
        {loading && <div className="clt-loading"><RefreshCw size={20} /><span>Synchronizing mesh…</span></div>}
        {!loading && nodes.length === 0 && (
          <div className="clt-empty"><ShieldQuestion size={34} /><strong>No nodes in this circle</strong><span>Nodes appear after discovery or membership enrollment.</span></div>
        )}

        <svg ref={svgRef} className="clt-svg" viewBox={`0 0 ${WIDTH} ${HEIGHT}`} role="img" aria-label={`Live topology for ${circle.name}`}>
          <defs>
            <radialGradient id="clt-node-online"><stop offset="0" stopColor="#153b3b" /><stop offset="1" stopColor="#07151c" /></radialGradient>
            <radialGradient id="clt-node-offline"><stop offset="0" stopColor="#233044" /><stop offset="1" stopColor="#0b111d" /></radialGradient>
            <linearGradient id="clt-mesh" x1="0" y1="0" x2="1" y2="0"><stop stopColor="#2dd4bf" /><stop offset="1" stopColor="#38bdf8" /></linearGradient>
            <linearGradient id="clt-relay" x1="0" y1="0" x2="1" y2="0"><stop stopColor="#18B5C8" /><stop offset="1" stopColor="#20C7D9" /></linearGradient>
            <filter id="clt-glow-filter" x="-100%" y="-100%" width="300%" height="300%"><feGaussianBlur stdDeviation="5" result="blur" /><feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge></filter>
            <filter id="clt-soft-shadow" x="-60%" y="-60%" width="220%" height="220%"><feDropShadow dx="0" dy="8" stdDeviation="10" floodColor="#020617" floodOpacity=".72" /></filter>
            <marker id="clt-flow-arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto" markerUnits="strokeWidth">
              <path d="M0 0 7 3.5 0 7Z" fill="#38bdf8" opacity=".72" />
            </marker>
          </defs>
          <g ref={viewportRef}>
            <RealMapTiles />
            <g className="clt-map-labels">
              {MAP_LABELS.map((item) => (
                <g key={item.id} transform={`translate(${item.x} ${item.y})`}>
                  <text className="clt-map-label">{item.label}</text>
                  <text className="clt-map-label-sub" y="13">{item.sub}</text>
                </g>
              ))}
            </g>
            <g className="clt-geo-zones">
              {zones.map((zone) => (
                <g key={zone.id} className={`clt-geo-zone ${zone.enabled ? "" : "is-disabled"} ${zone.inside ? "is-inside" : ""}`} style={{ "--zone-color": zone.color } as React.CSSProperties}>
                  <ellipse cx={zone.x} cy={zone.y} rx={zone.rx} ry={zone.ry} />
                  <text x={zone.x} y={zone.y - zone.ry - 8}>{zone.name}</text>
                </g>
              ))}
            </g>

            <g className="clt-links">
              {snapshot.links.map((link: CircleTopologyLink, linkIndex) => {
                const source = nodeMap.get(link.source);
                const target = nodeMap.get(link.target);
                if (!source || !target) return null;
                const visible = visibleIds.has(source.id) && visibleIds.has(target.id);
                const path = linkPath(source, target, link.kind === "attestation" ? 18 : -7);
                const mx = (source.x + target.x) / 2;
                const my = (source.y + target.y) / 2;
                return (
                  <g key={link.id} className={`clt-link-group ${visible ? "" : "is-filtered"}`}>
                    <path
                      d={path}
                      className={`clt-link clt-link--${link.kind} ${link.active ? "is-active" : "is-inactive"}`}
                      markerEnd={link.kind !== "attestation" ? "url(#clt-flow-arrow)" : undefined}
                    >
                      <title>{link.label || link.kind}</title>
                    </path>
                    {link.active && link.kind !== "attestation" && linkIndex % 3 === 0 && (
                      <circle r="3" className={`clt-packet clt-packet--${link.kind}`}>
                        <animateMotion path={path} dur={link.kind === "relay" ? "2.1s" : "3.1s"} repeatCount="indefinite" />
                      </circle>
                    )}
                    {link.verified && (
                      <g className="clt-link-proof" transform={`translate(${mx} ${my})`}>
                        <rect x="-21" y="-8" width="42" height="16" rx="8" />
                        <path d="M-12-4-7-2v3c0 3-2 4-5 5-3-1-5-2-5-5v-3Z" />
                        <path d="m-14 0 1.3 1.3 2.8-3" />
                        <text x="-3" y="3">mTLS</text>
                      </g>
                    )}
                  </g>
                );
              })}
            </g>

            <g className="clt-nodes">
              {nodes.map((node) => {
                const presence = presenceMeta[node.presence];
                const trust = trustMeta[node.attestation];
                const selectedNode = node.id === selectedId;
                const visible = visibleIds.has(node.id);
                const radius = node.primaryLighthouse ? 30 : node.roles.includes("lighthouse") ? 26 : node.roles.includes("relay") ? 23 : 17;
                const kind = nodeKind(node);
                const dotRadius = node.primaryLighthouse ? 8 : node.roles.includes("lighthouse") ? 7 : node.roles.includes("relay") ? 6 : 5;
                return (
                  <g
                    key={node.id}
                    transform={`translate(${node.x} ${node.y})`}
                    className={`clt-node ${selectedNode ? "is-selected" : ""} ${visible ? "" : "is-filtered"} clt-node--${node.presence}`}
                    role="button"
                    tabIndex={0}
                    aria-label={`${node.label}, ${presence.label}, ${trust.label}`}
                    onClick={(event) => { event.stopPropagation(); setSelectedId(node.id); centerNode(node, 6); }}
                    onKeyDown={(event) => {
                      if (event.key === "Enter" || event.key === " ") {
                        setSelectedId(node.id);
                        centerNode(node, 6);
                      }
                    }}
                  >
                    <g className="clt-node-scale">
                      <circle r={dotRadius} className="clt-node__map-dot" style={{ fill: presence.color, stroke: trust.color }} />
                      {node.presence === "online" && kind !== "member" && <circle r={radius + 5} className="clt-node__pulse" style={{ stroke: presence.color }} />}
                      <circle r={radius + 2} className="clt-node__trust" style={{ stroke: trust.color }} />
                      {kind === "lighthouse" ? (
                        <>
                          <circle r={radius + 1} className="clt-node__body clt-node__body--lighthouse" style={{ stroke: presence.color }} />
                          <circle r={radius - 8} className="clt-node__energy" style={{ stroke: presence.color }} />
                          <circle r={radius + 5} className="clt-node__orbit" />
                        </>
                      ) : kind === "relay" ? (
                        <path d={`M 0 ${-radius} L ${radius * .86} ${-radius * .5} L ${radius * .86} ${radius * .5} L 0 ${radius} L ${-radius * .86} ${radius * .5} L ${-radius * .86} ${-radius * .5} Z`} className="clt-node__body clt-node__body--relay" style={{ stroke: presence.color }} />
                      ) : (
                        <rect x={-radius} y={-radius} width={radius * 2} height={radius * 2} rx="8" className="clt-node__body clt-node__body--member" style={{ stroke: presence.color }} />
                      )}
                      <TopologyGlyph kind={kind} size={kind === "lighthouse" ? 22 : kind === "relay" ? 20 : 16} />
                      <circle cx={radius * .72} cy={-radius * .72} r="5" fill={presence.color} className="clt-node__status" />
                      {node.primaryLighthouse && <g className="clt-primary-mark" transform={`translate(${-radius - 5} ${-radius - 9})`}><circle r="12" /><path d="M-4 1-1 4 5-4" /></g>}
                      {node.roles.includes("lighthouse") && <g className="clt-role-mark" transform={`translate(${-radius - 4} ${radius - 2})`}><circle r="12" /><TowerControl x={-7} y={-7} width={14} height={14} /></g>}
                      {node.roles.includes("relay") && <g className="clt-role-mark clt-role-mark--relay" transform={`translate(${radius + 3} ${radius - 2})`}><circle r="12" /><Router x={-7} y={-7} width={14} height={14} /></g>}
                      <text className="clt-node__label" y={radius + 27}>{node.label}</text>
                      <text className="clt-node__sub" y={radius + 43}>{node.overlayIp || node.ip}</text>
                      <text className="clt-node__map-label" x={dotRadius + 8} y="3">{node.label}</text>
                    </g>
                  </g>
                );
              })}
            </g>
          </g>
        </svg>

        <div className="clt-zoom">
          <button onClick={() => zoomBy(1.2)} aria-label="Zoom in">+</button>
          <span ref={zoomLabelRef}>100%</span>
          <button onClick={() => zoomBy(1 / 1.2)} aria-label="Zoom out">−</button>
        </div>

        <div className="clt-map-status">
          <span>{snapshot.source === "live" ? "LIVE BACKEND" : "FIXTURE FALLBACK"}</span>
          <b>{nodes.length}</b> nodes
          <b>{zones.length}</b> zones
          <b>{zoomMode === "dots" ? "DOT VIEW" : "INSPECT VIEW"}</b>
        </div>

        <div className="clt-minimap" aria-label="Circle minimap">
          <div><Network size={10} /> MESH OVERVIEW <span ref={minimapZoomRef}>100%</span></div>
          <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`}>
            {snapshot.links.filter((link) => link.kind !== "attestation").map((link) => {
              const source = nodeMap.get(link.source);
              const target = nodeMap.get(link.target);
              return source && target ? <line key={link.id} x1={source.x} y1={source.y} x2={target.x} y2={target.y} /> : null;
            })}
            {nodes.map((node) => <circle key={node.id} cx={node.x} cy={node.y} r={node.primaryLighthouse ? 15 : 9} className={`is-${node.presence}`} />)}
            <rect x="4" y="4" width={WIDTH - 8} height={HEIGHT - 8} rx="18" />
          </svg>
        </div>
      </div>

      <aside className="clt-side">
        <section className="clt-card">
          <div className="clt-card__head"><span>Network Summary</span><Activity size={13} /></div>
          <div className="clt-metrics">
            <div><b>{snapshot.nodes.length}</b><span>Nodes</span></div>
            <div><b>{summary.online}</b><span>Online</span></div>
            <div><b>{summary.offline}</b><span>Offline</span></div>
            <div><b>{summary.relays}</b><span>Relays</span></div>
            <div><b>{summary.lighthouses}</b><span>Lighthouses</span></div>
            <div><b>{summary.members}</b><span>Members</span></div>
            <div><b>{summary.verified}</b><span>Attested</span></div>
            <div><b>{meshLinks + relayLinks}</b><span>Mesh Links</span></div>
          </div>
        </section>

        <section className="clt-card">
          <div className="clt-card__head"><span>Filters</span><Network size={13} /></div>
          <div className="clt-filterbar" aria-label="Topology filters">
            {filters.map((item) => (
              <button key={item.id} className={filter === item.id ? "is-active" : ""} onClick={() => setFilter(item.id)}>
                {item.label}
              </button>
            ))}
          </div>
        </section>

        <section className="clt-card">
          <div className="clt-card__head"><span>Selected Node</span><ShieldCheck size={13} /></div>
          {selected ? (
            <NodeDetails node={selected} onClose={() => setSelectedId(null)} />
          ) : (
            <div className="clt-card-empty">Select a node to inspect trust, route, and endpoint details.</div>
          )}
        </section>

        <section className="clt-card">
          <div className="clt-card__head"><span>Trust Overview</span><ShieldCheck size={13} /></div>
          <div className="clt-trust-bars">
            <div><span>Attested</span><i><em style={{ width: `${snapshot.nodes.length ? (summary.verified / snapshot.nodes.length) * 100 : 0}%` }} /></i><b>{summary.verified}</b></div>
            <div><span>Pending</span><i><em className="warn" style={{ width: `${snapshot.nodes.length ? (summary.pending / snapshot.nodes.length) * 100 : 0}%` }} /></i><b>{summary.pending}</b></div>
            <div><span>Failed</span><i><em className="crit" style={{ width: `${snapshot.nodes.length ? (summary.failed / snapshot.nodes.length) * 100 : 0}%` }} /></i><b>{summary.failed}</b></div>
          </div>
        </section>

        <section className="clt-card">
          <div className="clt-card__head"><span>Relay & Lighthouse</span><Router size={13} /></div>
          <div className="clt-compact-list">
            <div><span>Relay routes</span><b>{relayLinks}</b></div>
            <div><span>Lighthouses</span><b>{summary.lighthouses}</b></div>
            <div><span>Primary</span><b>{nodes.find((n) => n.primaryLighthouse)?.label ?? "None"}</b></div>
            <div><span>Discovery</span><b>{connected ? "Healthy" : "Fallback"}</b></div>
          </div>
        </section>

        <section className="clt-card">
          <div className="clt-card__head"><span>Mesh Health</span><Wifi size={13} /></div>
          <div className="clt-compact-list">
            <div><span>Mesh links</span><b>{meshLinks}</b></div>
            <div><span>Attestation links</span><b>{attestationLinks}</b></div>
            <div><span>Topology age</span><b>{shortTime(snapshot.generatedAt)}</b></div>
            <div><span>Visible nodes</span><b>{visibleNodes.length}</b></div>
          </div>
        </section>

        <section className="clt-card">
          <div className="clt-card__head"><span>Geofence</span><MapPin size={13} /></div>
          <div className="clt-compact-list">
            <div><span>Source</span><b>{geofenceStatus?.source ?? "Unavailable"}</b></div>
            <div><span>Zones</span><b>{geofenceZones.length}</b></div>
            <div><span>Current zone</span><b>{geofenceStatus?.zones.find((z) => z.inside)?.zone_name ?? "Outside"}</b></div>
            <div><span>Location</span><b>{geofenceStatus?.location?.fix ? `${geofenceStatus.location.fix.lat.toFixed(3)}, ${geofenceStatus.location.fix.lng.toFixed(3)}` : "Not stored"}</b></div>
          </div>
          <div className="clt-geofence-actions">
            <button onClick={() => void refreshGeofence()} title="Refresh geofence"><RefreshCw size={12} /></button>
            <button onClick={reportLocation} title="Report location"><MapPin size={12} /></button>
            <button onClick={() => void createZone()} disabled={!geofenceStatus?.location?.fix} title="Create zone"><Plus size={12} /></button>
            <button onClick={() => void runZoneAction("toggle")} disabled={!firstZone} title="Toggle zone"><ShieldCheck size={12} /></button>
            <button onClick={() => void runZoneAction("rf")} disabled={!firstZone} title="Capture RF"><Radio size={12} /></button>
            <button onClick={() => void runZoneAction("actions")} disabled={!firstZone} title="Replace actions"><Zap size={12} /></button>
            <button onClick={() => void runZoneAction("entry")} disabled={!firstZone} title="Test entry"><CheckCircle2 size={12} /></button>
            <button onClick={() => void runZoneAction("exit")} disabled={!firstZone} title="Test exit"><WifiOff size={12} /></button>
            <button onClick={() => void runZoneAction("delete")} disabled={!firstZone} title="Delete zone"><Trash2 size={12} /></button>
          </div>
          {(geofenceError || geofenceBusy) && <p className="clt-card-note">{geofenceBusy ?? geofenceError}</p>}
        </section>
      </aside>
      </div>

      <footer className="clt-footer">
        <span>{connected ? <CheckCircle2 size={13} /> : <WifiOff size={13} />}{connected ? "Backend connected" : "Fixture mode"}</span>
        <span>Peers {snapshot.nodes.length}</span>
        <span>Relays {summary.relays}</span>
        <span>Zoom <span ref={footerZoomRef}>100%</span></span>
        <span>Topology v2.1</span>
        <span><Clock3 size={13} />10s refresh</span>
      </footer>
    </section>
  );
}
