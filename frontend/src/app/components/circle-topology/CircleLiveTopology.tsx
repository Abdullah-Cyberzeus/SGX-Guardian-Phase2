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
  Layers,
  Map as MapIcon,
  MapPin,
  Network,
  Plus,
  Pencil,
  Radio,
  RefreshCw,
  Router,
  ShieldCheck,
  ShieldQuestion,
  TowerControl,
  Trash2,
  Waypoints,
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
import { buildTopologyLinks, useCircleTopology } from "./useCircleTopology";
import { ALL_CIRCLES_ID, buildCircleMembershipIndex, getNodeCircles } from "./circleMembership";
import { matchDidDocumentPeer } from "./nodeTelemetry";
import { PRESENCE_COLORS, TRUST_COLORS, paletteCssVars } from "./palette";
import { geofenceApi, type CreateZoneRequest, type GeofenceEvent, type GeofenceStatus, type GeofenceZone, type StoredLocation, type ThreatAlert, type ZoneAutomation } from "../../../api/geofence";
import { alertDetails, configuredActions, eventDetails, locationSourceLabel, sourceLabel, zoneTypeLabel } from "../geofenceDisplay";
import attestationService, { type PeerAttestationRecord } from "../../services/attestationService";
import type { DIDDocumentPeerSummary } from "../../services/didService";
import { useContactNames } from "../../contexts/ContactNameContext";
import "./circle-topology.css";

const WIDTH = 1440;
const HEIGHT = 820;
const TILE_ZOOM = 3;
const TILE_COUNT = 2 ** TILE_ZOOM;
const MAP_SIZE = WIDTH;
const MAP_Y = (HEIGHT - MAP_SIZE) / 2;
const POLL_MS = 10_000;

type Filter = "all" | "online" | "offline" | "verified" | "lighthouse" | "relay";
type ViewMode = "mesh" | "map";
type BrowserLocationAttempt = { options: PositionOptions };

const browserLocationAttempts: BrowserLocationAttempt[] = [
  { options: { enableHighAccuracy: false, timeout: 2000, maximumAge: 300000 } },
  { options: { enableHighAccuracy: false, timeout: 12000, maximumAge: 60000 } },
];

function getBrowserPosition(options: PositionOptions): Promise<GeolocationPosition> {
  return new Promise((resolve, reject) => {
    navigator.geolocation.getCurrentPosition(resolve, reject, options);
  });
}

function getBrowserPositionFromWatch(options: PositionOptions, timeoutMs: number): Promise<GeolocationPosition> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let timeoutId = 0;
    let watchId = 0;
    const finish = (callback: () => void) => {
      if (settled) return;
      settled = true;
      window.clearTimeout(timeoutId);
      navigator.geolocation.clearWatch(watchId);
      callback();
    };
    timeoutId = window.setTimeout(() => {
      finish(() => reject(new Error("Browser location timed out")));
    }, timeoutMs);
    watchId = navigator.geolocation.watchPosition(
      (position) => finish(() => resolve(position)),
      (error) => {
        if (error.code === error.PERMISSION_DENIED) {
          finish(() => reject(error));
        }
      },
      options,
    );
  });
}

async function getBrowserPositionWithFallback(): Promise<GeolocationPosition> {
  let lastError: unknown = null;
  for (const attempt of browserLocationAttempts) {
    try {
      return await getBrowserPosition(attempt.options);
    } catch (err) {
      lastError = err;
      if (isPermissionDenied(err)) {
        throw lastError;
      }
    }
  }
  try {
    return await getBrowserPositionFromWatch({ enableHighAccuracy: false, maximumAge: 300000 }, 25000);
  } catch (err) {
    lastError = err;
    if (isPermissionDenied(err)) {
      throw lastError;
    }
  }
  throw lastError ?? new Error("Location unavailable");
}

function getLocationErrorCode(err: unknown): number | undefined {
  return typeof err === "object" && err !== null && "code" in err && typeof (err as { code?: unknown }).code === "number"
    ? (err as { code: number }).code
    : undefined;
}

function isPermissionDenied(err: unknown) {
  return getLocationErrorCode(err) === 1;
}

const presenceMeta: Record<PresenceStatus, { label: string; color: string }> = {
  online: { label: "Online", color: PRESENCE_COLORS.online },
  stale: { label: "Stale", color: PRESENCE_COLORS.stale },
  offline: { label: "Offline", color: PRESENCE_COLORS.offline },
  unknown: { label: "Unknown", color: PRESENCE_COLORS.unknown },
};

const trustMeta: Record<AttestationStatus, { label: string; color: string }> = {
  verified: { label: "Attested", color: TRUST_COLORS.verified },
  pending: { label: "Pending", color: TRUST_COLORS.pending },
  failed: { label: "Rejected", color: TRUST_COLORS.failed },
  never: { label: "Not attested", color: TRUST_COLORS.never },
};

interface PositionedNode extends CircleTopologyNode {
  x: number;
  y: number;
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

const DEFAULT_AUTOMATION: ZoneAutomation = {
  on_entry: [{ action: "notify", severity: "low" }],
  on_exit: [{ action: "raise_alert", severity: "high" }],
  allow_destructive: false,
  min_confidence: 0.9,
};

function ZoneDialog({ zone, node, fix, busy, onClose, onSave }: { zone?: GeofenceZone; node: CircleTopologyNode | null; fix: { lat: number; lng: number } | null; busy: boolean; onClose: () => void; onSave: (body: CreateZoneRequest) => void }) {
  const [name, setName] = useState(zone?.name ?? "");
  const [lat, setLat] = useState(String(zone?.center_lat ?? fix?.lat ?? ""));
  const [lng, setLng] = useState(String(zone?.center_lng ?? fix?.lng ?? ""));
  const [radius, setRadius] = useState(String(zone?.radius_m ?? 250));
  const [severity, setSeverity] = useState(zone?.severity ?? "high");
  const valid = name.trim() && Number.isFinite(Number(lat)) && Number.isFinite(Number(lng)) && Number(radius) > 0;
  return <div className="clt-zone-modal" role="dialog" aria-modal="true" aria-label={zone ? "Edit zone" : "Create zone"} onClick={onClose}>
    <form className="clt-zone-dialog" onClick={(event) => event.stopPropagation()} onSubmit={(event) => { event.preventDefault(); if (valid) onSave({ name: name.trim(), topology_node_ref: zone?.topology_node_ref ?? node?.did ?? node?.id ?? null, kind: "coordinate", center_lat: Number(lat), center_lng: Number(lng), radius_m: Number(radius), severity, enabled: zone?.enabled ?? true, on_entry: zone?.on_entry ?? true, on_exit: zone?.on_exit ?? true, automation: zone?.automation ?? DEFAULT_AUTOMATION }); }}>
      <header><div><span>{zone ? "EDIT GEOFENCE" : "NEW GEOFENCE"}</span><h3>{zone ? "Edit zone" : "Name your zone"}</h3></div><button type="button" onClick={onClose}><X size={16} /></button></header>
      <div className="clt-zone-dialog__anchor"><Network size={14} /><span>Topology node</span><b>{node?.label ?? zone?.topology_node_ref ?? "Not assigned"}</b></div>
      <label>Zone name<input autoFocus value={name} placeholder="Office" onChange={(event) => setName(event.target.value)} /></label>
      <div><label>Latitude<input type="number" step="any" value={lat} onChange={(event) => setLat(event.target.value)} /></label><label>Longitude<input type="number" step="any" value={lng} onChange={(event) => setLng(event.target.value)} /></label></div>
      <div><label>Radius (m)<input type="number" min="1" value={radius} onChange={(event) => setRadius(event.target.value)} /></label><label>Severity<select value={severity} onChange={(event) => setSeverity(event.target.value)}><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label></div>
      <footer><button type="button" onClick={onClose}>Cancel</button><button type="submit" disabled={!valid || busy}>{busy ? "Saving…" : zone ? "Save changes" : "Create zone"}</button></footer>
    </form>
  </div>;
}

const ZONE_COLORS = ["#18B5C8", "#20C7D9", "#3AC569", "#F4B640", "#E14D4D", "#7A7A7A"];

function zoneMatchesNode(zone: GeofenceZone, node: CircleTopologyNode) {
  const reference = zone.topology_node_ref;
  return !!reference && (reference === node.id || reference === node.did);
}

function topologyZoneRadius(zone: GeofenceZone, index: number) {
  const meters = Math.max(1, zone.radius_m ?? 250);
  return 48 + Math.min(22, Math.log10(meters + 1) * 8) + index * 15;
}

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
  // Tracks reachability of the public CARTO tile CDN specifically — distinct
  // from Guardian-LAN reachability (`staleWarning`/`fatalError` above). One
  // failed tile is enough to assume the whole CDN is unreachable and stop
  // requesting the rest, rather than let every tile fail individually.
  const [tilesUnavailable, setTilesUnavailable] = useState(false);
  const tileSize = MAP_SIZE / TILE_COUNT;

  if (tilesUnavailable) {
    return (
      <g className="clt-real-map clt-map-unavailable" pointerEvents="none">
        <rect x={0} y={0} width={WIDTH} height={HEIGHT} />
        <rect className="clt-map-contrast" x={0} y={MAP_Y} width={MAP_SIZE} height={MAP_SIZE} />
        <text className="clt-map-unavailable-label" x={WIDTH / 2} y={HEIGHT / 2}>
          Map tiles unavailable — requires Internet access
        </text>
      </g>
    );
  }

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
          onError={() => setTilesUnavailable(true)}
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

/** Re-derives which node is "primary" within whatever subset is currently in
 * view (global roster or one circle's members) — the globally-designated
 * primary lighthouse may not even be a member of the selected circle. */
function assignPrimaryLighthouse(list: CircleTopologyNode[]): CircleTopologyNode[] {
  if (list.length === 0) return list;
  const ordered = [...list].sort((a, b) => roleWeight(a) - roleWeight(b) || a.label.localeCompare(b.label));
  const primaryId = ordered[0].id;
  return list.map((node) => ({ ...node, primaryLighthouse: node.id === primaryId }));
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

function GlyphSwatch({ kind }: { kind: "lighthouse" | "relay" | "member" }) {
  return (
    <svg width={18} height={18} viewBox="-12 -12 24 24" className={`clt-legend-swatch clt-legend-swatch--${kind}`} aria-hidden="true">
      <TopologyGlyph kind={kind} size={16} />
    </svg>
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

function NodeDetails({ node, nodeCircles, didPeers, onClose }: {
  node: CircleTopologyNode;
  nodeCircles: string[];
  didPeers: DIDDocumentPeerSummary[];
  onClose: () => void;
}) {
  const { displayForDid } = useContactNames();
  const presence = presenceMeta[node.presence];
  const trust = trustMeta[node.attestation];
  const attestationCacheRef = useRef<Map<string, PeerAttestationRecord | null>>(new Map());
  const [attestation, setAttestation] = useState<PeerAttestationRecord | null | undefined>(undefined);

  useEffect(() => {
    if (!node.did) { setAttestation(null); return; }
    const cached = attestationCacheRef.current.get(node.did);
    if (cached !== undefined) { setAttestation(cached); return undefined; }
    let cancelled = false;
    setAttestation(undefined);
    void attestationService.getForPeer(node.did).then((result) => {
      attestationCacheRef.current.set(node.did!, result);
      if (!cancelled) setAttestation(result);
    });
    return () => { cancelled = true; };
  }, [node.did]);

  const identity = useMemo(() => matchDidDocumentPeer(node, didPeers), [node, didPeers]);
  const attestationPassed = attestation ? attestation.result === "pass" || attestation.result === "success" : false;
  const nodeDisplayName = displayForDid(node.did, node.label);

  return (
    <aside className="clt-details">
      <div className="clt-details__header">
        <div>
          <span className="clt-eyebrow">NODE INSPECTOR</span>
          <h3 title={node.did || node.label}>{nodeDisplayName}</h3>
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

      {nodeCircles.length > 0 && (
        <div className="clt-circle-chips">
          <span className="clt-card-label">Circles</span>
          <div>{nodeCircles.map((name) => <span key={name} className="clt-circle-chip"><Layers size={10} />{name}</span>)}</div>
        </div>
      )}

      <dl className="clt-kv">
        <div><dt>Node ID</dt><dd title={node.did || node.id}>{node.did || node.id}</dd></div>
        <div><dt>Physical IP</dt><dd>{node.ip || "Not reported"}</dd></div>
        <div><dt>Overlay IP</dt><dd>{node.overlayIp || "Not reported"}</dd></div>
        <div><dt>Last signal</dt><dd>{node.lastSeen}</dd></div>
        {node.did && <div><dt>DID</dt><dd className="clt-truncate" title={node.did}>{node.did}</dd></div>}
      </dl>

      <div className="clt-attestation-card">
        <span className="clt-card-label">Attestation</span>
        {!node.did ? (
          <p>No DID on record for this node yet.</p>
        ) : attestation === undefined ? (
          <p>Checking…</p>
        ) : attestation ? (
          <>
            <strong className={attestationPassed ? "is-good" : "is-bad"}>{attestationPassed ? "Passed" : "Failed"}</strong>
            <p>Checked {shortTime(attestation.timestamp)}</p>
            <p className="clt-truncate" title={attestation.policyDigest}>Policy {attestation.policyDigest ? `${attestation.policyDigest.slice(0, 12)}…` : "Not reported"}</p>
          </>
        ) : (
          <p>No attestation record available for this node yet.</p>
        )}
      </div>

      <div className="clt-identity-card">
        <span className="clt-card-label">Identity</span>
        {identity ? (
          <>
            <p>DID Document v{identity.version} · {identity.status}</p>
            <p>{identity.services} published service{identity.services === 1 ? "" : "s"}</p>
          </>
        ) : (
          <p>No published DID Document found for this node.</p>
        )}
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

function LegendPanel({ onClose }: { onClose: () => void }) {
  return (
    <div className="clt-legend-panel" role="dialog" aria-label="Topology legend">
      <header><strong>How to read this screen</strong><button type="button" onClick={onClose} aria-label="Close legend"><X size={14} /></button></header>

      <section>
        <h4>Status</h4>
        {(Object.keys(presenceMeta) as PresenceStatus[]).map((key) => (
          <div key={key} className="clt-legend-row"><i style={{ background: presenceMeta[key].color }} />{presenceMeta[key].label}</div>
        ))}
      </section>

      <section>
        <h4>Trust</h4>
        {(Object.keys(trustMeta) as AttestationStatus[]).map((key) => (
          <div key={key} className="clt-legend-row"><i className="clt-legend-ring" style={{ borderColor: trustMeta[key].color }} />{trustMeta[key].label}</div>
        ))}
      </section>

      <section>
        <h4>Node types</h4>
        <div className="clt-legend-row"><GlyphSwatch kind="lighthouse" />Lighthouse — coordinates the circle</div>
        <div className="clt-legend-row"><GlyphSwatch kind="relay" />Relay — forwards traffic for others</div>
        <div className="clt-legend-row"><GlyphSwatch kind="member" />Member device</div>
        <div className="clt-legend-row"><Zap size={14} />★ badge = primary lighthouse for this view</div>
      </section>

      <section>
        <h4>Connections</h4>
        <div className="clt-legend-row"><span className="clt-legend-line clt-legend-line--mesh" />Mesh route</div>
        <div className="clt-legend-row"><span className="clt-legend-line clt-legend-line--relay" />Relay route</div>
        <div className="clt-legend-row"><span className="clt-legend-line clt-legend-line--trust" />Verified trust link (mTLS)</div>
      </section>

      <section>
        <h4>Multiple circles</h4>
        <div className="clt-legend-row"><Layers size={14} />Member of more than one circle — hover the badge for the list</div>
      </section>

      <p className="clt-legend-note">Zones shown on the map apply to this device only — not scoped to the selected circle.</p>
    </div>
  );
}

export function CircleLiveTopology({ circle, circles }: { circle: CircleTopologyCircle; circles: CircleTopologyCircle[] }) {
  const { snapshot, didPeers, loading: dataLoading, fatalError, staleWarning, lastSuccessAt, refresh } = useCircleTopology(circles);
  const { displayForDid } = useContactNames();
  const svgRef = useRef<SVGSVGElement | null>(null);
  const viewportRef = useRef<SVGGElement | null>(null);
  const zoomRef = useRef<ZoomBehavior<SVGSVGElement, unknown> | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [selectedCircleId, setSelectedCircleId] = useState<string>(circle.id);
  const [viewMode, setViewMode] = useState<ViewMode>("mesh");
  const [legendOpen, setLegendOpen] = useState(false);
  const [filter, setFilter] = useState<Filter>("all");
  const [search, setSearch] = useState("");
  const [fullscreen, setFullscreen] = useState(false);
  const [zoomMode, setZoomMode] = useState<"dots" | "icons">("dots");
  const [geofenceStatus, setGeofenceStatus] = useState<GeofenceStatus | null>(null);
  const [geofenceZones, setGeofenceZones] = useState<GeofenceZone[]>([]);
  const [geofenceEvents, setGeofenceEvents] = useState<GeofenceEvent[]>([]);
  const [geofenceAlerts, setGeofenceAlerts] = useState<ThreatAlert[]>([]);
  const [geofenceError, setGeofenceError] = useState<string | null>(null);
  const [geofenceBusy, setGeofenceBusy] = useState<string | null>(null);
  const [geofenceToast, setGeofenceToast] = useState<{ message: string; tone: "success" | "error" } | null>(null);
  const [showAllGeofenceEvents, setShowAllGeofenceEvents] = useState(false);
  const [showAllGeofenceAlerts, setShowAllGeofenceAlerts] = useState(false);
  const [selectedZoneId, setSelectedZoneId] = useState<string | null>(null);
  const [editingZone, setEditingZone] = useState<GeofenceZone | null | undefined>(undefined);
  const zoomLabelRef = useRef<HTMLSpanElement | null>(null);
  const footerZoomRef = useRef<HTMLSpanElement | null>(null);
  const minimapZoomRef = useRef<HTMLSpanElement | null>(null);
  const locationRequestInFlightRef = useRef(false);
  const zoneActionInFlightRef = useRef(false);

  const membershipIndex = useMemo(() => buildCircleMembershipIndex(circles), [circles]);
  const selectedCircleLabel = selectedCircleId === ALL_CIRCLES_ID
    ? "All my circles"
    : (circles.find((item) => item.id === selectedCircleId)?.name ?? circle.name);
  const nodeCircleEntries = useCallback((node: CircleTopologyNode) => {
    const keys = [node.id, node.did, node.label, node.ip, node.overlayIp].filter(Boolean) as string[];
    const merged = keys.flatMap((key) => getNodeCircles(membershipIndex, key));
    return Array.from(new Map(merged.map((entry) => [entry.circleId, entry])).values());
  }, [membershipIndex]);

  const scopedNodes = useMemo(() => {
    const filtered = selectedCircleId === ALL_CIRCLES_ID
      ? snapshot.nodes
      : snapshot.nodes.filter((node) => nodeCircleEntries(node).some((entry) => entry.circleId === selectedCircleId));
    return assignPrimaryLighthouse(filtered);
  }, [snapshot.nodes, selectedCircleId, nodeCircleEntries]);

  const links = useMemo(() => buildTopologyLinks(scopedNodes), [scopedNodes]);
  const nodes = useMemo(() => layoutNodes(scopedNodes), [scopedNodes]);
  const zones = useMemo(() => mapZones(geofenceZones, geofenceStatus), [geofenceZones, geofenceStatus]);
  const nodeMap = useMemo(() => new Map(nodes.map((node) => [node.id, node])), [nodes]);
  const selected = nodes.find((node) => node.id === selectedId) ?? null;
  const selectedNodeCircles = useMemo(
    () => (selected ? nodeCircleEntries(selected).map((entry) => entry.circleName) : []),
    [selected, nodeCircleEntries],
  );
  const selectedZone = geofenceZones.find((zone) => zone.zone_id === selectedZoneId) ?? null;
  const editingZoneNode = useMemo(() => {
    if (!editingZone) return selected;
    if (!editingZone.topology_node_ref) return null;
    return nodes.find((node) => zoneMatchesNode(editingZone, node)) ?? null;
  }, [editingZone, nodes, selected]);
  const deviceFix = geofenceStatus?.location?.fix?.kind === "coordinate" ? geofenceStatus.location.fix : null;
  const devicePoint = useMemo(() => (deviceFix ? projectLocation(deviceFix.lat, deviceFix.lng) : null), [deviceFix]);
  const orderedGeofenceEvents = useMemo(() => [...geofenceEvents].sort((a, b) => {
    const right = Date.parse(b.at ?? b.timestamp ?? "") || 0;
    const left = Date.parse(a.at ?? a.timestamp ?? "") || 0;
    return right - left;
  }), [geofenceEvents]);
  const orderedGeofenceAlerts = useMemo(() => [...geofenceAlerts].sort((a, b) => {
    const right = Date.parse(String(b.at ?? b.timestamp ?? b.created_at ?? "")) || 0;
    const left = Date.parse(String(a.at ?? a.timestamp ?? a.created_at ?? "")) || 0;
    return right - left;
  }), [geofenceAlerts]);
  const visibleIds = useMemo(() => {
    const q = search.trim().toLowerCase();
    return new Set(nodes.filter((node) => {
      const matchesFilter = filterNode(node, filter);
      if (!q) return matchesFilter;
      const haystack = [displayForDid(node.did, node.label), node.label, node.id, node.ip, node.overlayIp, node.roles.join(" "), node.attestation, node.presence]
        .filter(Boolean)
        .join(" ")
        .toLowerCase();
      return matchesFilter && haystack.includes(q);
    }).map((node) => node.id));
  }, [nodes, filter, search, displayForDid]);
  const summary = useMemo(() => ({
    online: scopedNodes.filter((node) => node.presence === "online").length,
    offline: scopedNodes.filter((node) => node.presence === "offline" || node.presence === "stale").length,
    verified: scopedNodes.filter((node) => node.attestation === "verified").length,
    pending: scopedNodes.filter((node) => node.attestation === "pending").length,
    failed: scopedNodes.filter((node) => node.attestation === "failed").length,
    lighthouses: scopedNodes.filter((node) => node.roles.includes("lighthouse")).length,
    relays: scopedNodes.filter((node) => node.roles.includes("relay")).length,
    members: scopedNodes.filter((node) => node.roles.includes("member")).length,
  }), [scopedNodes]);
  const visibleNodes = useMemo(() => nodes.filter((node) => visibleIds.has(node.id)), [nodes, visibleIds]);
  const meshLinks = links.filter((link) => link.kind === "mesh").length;
  // A relay route is backed by an enabled relay node. Counting generated mesh
  // edges under-reports when the relay is also the lighthouse/anchor, because
  // the layout intentionally omits an anchor-to-itself edge.
  const relayLinks = summary.relays;
  const attestationLinks = links.filter((link) => link.kind === "attestation").length;
  const locationBusy = geofenceBusy === "Getting location...";

  const refreshGeofence = useCallback(async () => {
    setGeofenceError(null);
    try {
      const [status, location, zoneResult, eventResult, alertResult] = await Promise.all([
        geofenceApi.status().catch((error) => { throw new Error(`Geofence status request failed: ${error instanceof Error ? error.message : "Unknown error"}`); }),
        geofenceApi.getLocation().catch((error) => { throw new Error(`Geofence location request failed: ${error instanceof Error ? error.message : "Unknown error"}`); }),
        geofenceApi.listZones().catch((error) => { throw new Error(`Geofence zones request failed: ${error instanceof Error ? error.message : "Unknown error"}`); }),
        geofenceApi.events().catch((error) => { throw new Error(`Geofence events request failed: ${error instanceof Error ? error.message : "Unknown error"}`); }),
        geofenceApi.alerts().catch((error) => { throw new Error(`Geofence alerts request failed: ${error instanceof Error ? error.message : "Unknown error"}`); }),
      ]);
      const mergedStatus: GeofenceStatus = {
        ...status,
        location: status.location ?? location.location ?? geofenceStatus?.location ?? null,
      };
      setGeofenceStatus(mergedStatus);
      setGeofenceZones(zoneResult.zones);
      setGeofenceEvents(eventResult.events);
      setGeofenceAlerts(alertResult.alerts);
      return mergedStatus;
    } catch (err) {
      setGeofenceError(err instanceof Error ? err.message : "Geofence refresh failed: Unknown error");
      return null;
    }
  }, [geofenceStatus?.location]);

  const refreshSimulationResults = useCallback(async () => {
    const [status, eventResult, alertResult] = await Promise.all([
      geofenceApi.status().catch((error) => { throw new Error(`Geofence status request failed: ${error instanceof Error ? error.message : "Unknown error"}`); }),
      geofenceApi.events().catch((error) => { throw new Error(`Geofence events request failed: ${error instanceof Error ? error.message : "Unknown error"}`); }),
      geofenceApi.alerts().catch((error) => { throw new Error(`Geofence alerts request failed: ${error instanceof Error ? error.message : "Unknown error"}`); }),
    ]);
    setGeofenceStatus((current) => ({ ...status, location: status.location ?? current?.location ?? null }));
    setGeofenceEvents(eventResult.events);
    setGeofenceAlerts(alertResult.alerts);
  }, []);

  const refreshAll = useCallback(() => { void refresh(); void refreshGeofence(); }, [refresh, refreshGeofence]);

  const applyBrowserLocation = useCallback((location: StoredLocation) => {
    setGeofenceStatus((current) => ({
      source: current?.source ?? "reported",
      selection_mode: current?.selection_mode ?? "forced",
      source_reason: current?.source_reason ?? "Browser location reported from this device",
      zones: current?.zones ?? [],
      ...current,
      location,
    }));
    setViewMode("map");
  }, []);

  const reportLocation = useCallback(() => {
    if (locationRequestInFlightRef.current) return;
    setGeofenceToast(null);
    if (!navigator.geolocation) {
      setGeofenceError("Location unavailable");
      return;
    }
    locationRequestInFlightRef.current = true;
    setGeofenceBusy("Getting location...");
    setGeofenceError(null);
    void (async () => {
      try {
        const position = await getBrowserPositionWithFallback();
        const browserLocation: StoredLocation = {
          source: "reported",
          fix: {
            kind: "coordinate",
            lat: position.coords.latitude,
            lng: position.coords.longitude,
            accuracy_m: position.coords.accuracy,
          },
          updated_at: new Date().toISOString(),
        };
        applyBrowserLocation(browserLocation);
        try {
          const result = await geofenceApi.reportLocation({
            lat: position.coords.latitude,
            lng: position.coords.longitude,
            accuracy_m: position.coords.accuracy,
          });
          applyBrowserLocation(result.location);
          await refreshGeofence();
          setGeofenceToast({ message: "Location updated successfully", tone: "success" });
        } catch (err) {
          setGeofenceError(`Location update failed: ${err instanceof Error ? err.message : "Unknown error"}`);
        } finally {
          locationRequestInFlightRef.current = false;
          setGeofenceBusy(null);
        }
      } catch (err) {
        const code = getLocationErrorCode(err);
        locationRequestInFlightRef.current = false;
        setGeofenceBusy(null);
        const refreshedStatus = await refreshGeofence();
        const fallbackLocation = refreshedStatus?.location ?? geofenceStatus?.location;
        if (fallbackLocation) {
          setViewMode("map");
          setGeofenceToast({ message: "Showing last stored location. Browser did not return a fresh location fix.", tone: "error" });
          setGeofenceError(null);
          return;
        }
        setGeofenceError(code === 1
          ? "Permission denied"
          : code === 2
            ? "Browser location unavailable. Make sure location services are enabled for this device."
            : code === 3
              ? "Browser location timed out. Make sure location services are enabled for this device."
              : "Browser location unavailable. Make sure location services are enabled for this device.");
      }
    })();
  }, [applyBrowserLocation, geofenceStatus?.location, refreshGeofence]);

  const saveZone = async (body: CreateZoneRequest) => {
    setGeofenceBusy("Creating zone");
    try {
      const result = editingZone
        ? await geofenceApi.editZone(editingZone.zone_id, body)
        : await geofenceApi.createZone(body);
      setGeofenceZones((current) => editingZone
        ? current.map((zone) => zone.zone_id === result.zone.zone_id ? result.zone : zone)
        : [...current, result.zone]);
      setSelectedZoneId(result.zone.zone_id);
      setEditingZone(undefined);
      await refreshGeofence();
    } catch (err) {
      setGeofenceError(`Zone save request failed: ${err instanceof Error ? err.message : "Unknown error"}`);
    } finally {
      setGeofenceBusy(null);
    }
  };

  const runZoneAction = async (zone: GeofenceZone, action: "toggle" | "delete" | "rf" | "actions" | "entry" | "exit") => {
    if (geofenceBusy || zoneActionInFlightRef.current) return;
    zoneActionInFlightRef.current = true;
    setGeofenceToast(null);
    setGeofenceError(null);
    setGeofenceBusy(action);
    if (action === "toggle") {
      setGeofenceZones((current) => current.map((item) => item.zone_id === zone.zone_id ? { ...item, enabled: !zone.enabled } : item));
    }
    try {
      if (action === "toggle") {
        const result = await geofenceApi.editZone(zone.zone_id, { enabled: !zone.enabled });
        setGeofenceZones((current) => current.map((item) => item.zone_id === zone.zone_id ? result.zone : item));
      }
      if (action === "delete") await geofenceApi.deleteZone(zone.zone_id);
      if (action === "rf") {
        setGeofenceBusy("Capturing current RF environment...");
        await geofenceApi.captureRf(zone.zone_id);
      }
      if (action === "actions") {
        await geofenceApi.getActions(zone.zone_id);
        await geofenceApi.replaceActions(zone.zone_id, zone.automation ?? DEFAULT_AUTOMATION);
      }
      if (action === "entry" || action === "exit") {
        await geofenceApi.testActions({ zone_id: zone.zone_id, transition: action, confidence: 1 });
        await refreshSimulationResults();
        setGeofenceToast({ message: `Zone ${action.toUpperCase()} simulation completed`, tone: "success" });
      } else {
        await refreshGeofence();
      }
    } catch (err) {
      if (action === "toggle") {
        setGeofenceZones((current) => current.map((item) => item.zone_id === zone.zone_id ? zone : item));
      }
      const requestName = action === "toggle" ? "Zone enable/disable" : action === "delete" ? "Zone delete" : action === "rf" ? "RF capture" : action === "actions" ? "Zone actions update" : `Zone ${action} action test`;
      const message = `${requestName} request failed: ${err instanceof Error ? err.message : "Unknown error"}`;
      setGeofenceError(message);
      if (action === "entry" || action === "exit") setGeofenceToast({ message, tone: "error" });
    } finally {
      zoneActionInFlightRef.current = false;
      setGeofenceBusy(null);
    }
  };

  useEffect(() => {
    void refreshGeofence();
    const timer = window.setInterval(() => void refreshGeofence(), POLL_MS);
    return () => window.clearInterval(timer);
  }, [refreshGeofence]);

  useEffect(() => {
    if (selectedZoneId && !geofenceZones.some((zone) => zone.zone_id === selectedZoneId)) setSelectedZoneId(null);
  }, [geofenceZones, selectedZoneId]);

  useEffect(() => {
    if (geofenceToast?.tone !== "success") return;
    const timeout = window.setTimeout(() => setGeofenceToast(null), 4200);
    return () => window.clearTimeout(timeout);
  }, [geofenceToast]);

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

  const selectNode = (node: PositionedNode) => {
    setSelectedId(node.id);
    if (viewMode === "mesh") centerNode(node, 6);
  };

  // Switching circle/scope changes the node set and mesh layout entirely, so
  // preserving the old pan/zoom framing would just show empty space — reset
  // to fit-all instead, which is the predictable behavior for this audience.
  useEffect(() => {
    setSelectedId(null);
    const raf = requestAnimationFrame(() => resetView());
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectedCircleId]);

  const filters: Array<{ id: Filter; label: string }> = [
    { id: "all", label: "All nodes" },
    { id: "online", label: "Online" },
    { id: "offline", label: "Offline" },
    { id: "verified", label: "Attested" },
    { id: "lighthouse", label: "Lighthouses" },
    { id: "relay", label: "Relays" },
  ];

  const liveState: "live" | "stale" | "error" = fatalError ? "error" : staleWarning ? "stale" : "live";

  return (
    <section className={`clt-shell ${fullscreen ? "clt-shell--fullscreen" : ""} clt-shell--${zoomMode}`} style={paletteCssVars() as React.CSSProperties}>
      <header className="clt-header">
        <div className="clt-title">
          <div className="clt-title__icon"><Network size={19} /></div>
          <div>
            <span className="clt-eyebrow">NETWORK TOPOLOGY</span>
            <h2>{selectedCircleLabel}</h2>
          </div>
        </div>
        <div className="clt-env">
          <span>Environment</span>
          <strong>Production</strong>
        </div>
        <div className="clt-live-state" title={fatalError ?? staleWarning ?? "Live node APIs connected"}>
          <span className={`is-${liveState}`} />
          <div><strong>{liveState === "error" ? "Offline" : liveState === "stale" ? "Reconnecting…" : "Live"}</strong><small>{lastSuccessAt ? `Updated ${shortTime(lastSuccessAt)}` : "Not yet synced"}</small></div>
        </div>
        <label className="clt-search">
          <span>Search</span>
          <input
            value={search}
            onChange={(event) => setSearch(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter" && visibleNodes[0]) selectNode(visibleNodes[0]);
            }}
            placeholder="Hostname, peer, IP, role"
          />
        </label>
        <div className="clt-actions">
          <button onClick={() => zoomBy(1.2)} aria-label="Zoom in" title="Zoom in"><Plus size={15} /></button>
          <button onClick={() => zoomBy(1 / 1.2)} aria-label="Zoom out" title="Zoom out"><span className="clt-minus-icon">−</span></button>
          <button onClick={refreshAll} aria-label="Refresh topology" title="Refresh"><RefreshCw size={15} /></button>
          <button onClick={resetView} aria-label="Reset view" title="Reset view"><Focus size={15} /></button>
          <button onClick={() => setFullscreen((value) => !value)} aria-label="Toggle fullscreen" title="Fullscreen"><Expand size={15} /></button>
        </div>
      </header>

      <div className="clt-toolbar">
        <div className="clt-toolbar__group" role="group" aria-label="Layout view">
          <button type="button" className={viewMode === "mesh" ? "is-active" : ""} onClick={() => setViewMode("mesh")}><Waypoints size={13} />Mesh</button>
          <button type="button" className={viewMode === "map" ? "is-active" : ""} onClick={() => setViewMode("map")}><MapIcon size={13} />Map</button>
        </div>
        <label className="clt-toolbar__circle">
          <span>Circle</span>
          <select value={selectedCircleId} onChange={(event) => setSelectedCircleId(event.target.value)}>
            <option value={ALL_CIRCLES_ID}>All my circles</option>
            {circles.map((item) => <option key={item.id} value={item.id}>{item.name} · {item.members?.length ?? 0} members</option>)}
          </select>
        </label>
        <p className="clt-toolbar__hint">Click a node for details · Drag to pan · Scroll to zoom · Use Mesh/Map to change the layout</p>
        <div className="clt-toolbar__legend-wrap">
          <button type="button" className="clt-toolbar__legend" onClick={() => setLegendOpen((value) => !value)} aria-expanded={legendOpen} aria-label="Show legend"><Info size={13} />Legend</button>
          {legendOpen && <LegendPanel onClose={() => setLegendOpen(false)} />}
        </div>
      </div>

      {staleWarning && (
        <div className="clt-notice"><Info size={14} /><span>Showing the last synced data — {staleWarning}</span><button type="button" onClick={refreshAll}>Retry</button></div>
      )}

      <div className="clt-workspace">
      <div className="clt-stage">
        <div className="clt-grid" />
        <div className="clt-lattice" />
        <div className="clt-particles" />
        <div className="clt-streams" />
        <div className="clt-glow clt-glow--a" />
        <div className="clt-glow clt-glow--b" />
        {dataLoading && scopedNodes.length === 0 && !fatalError && (
          <div className="clt-loading"><RefreshCw size={20} /><span>Synchronizing mesh…</span></div>
        )}
        {!dataLoading && fatalError && scopedNodes.length === 0 && (
          <div className="clt-fatal-error">
            <WifiOff size={34} />
            <strong>Unable to load live topology data</strong>
            <span>{fatalError}</span>
            <button type="button" onClick={refreshAll}><RefreshCw size={14} />Retry</button>
          </div>
        )}
        {!dataLoading && !fatalError && scopedNodes.length === 0 && (
          <div className="clt-empty">
            <ShieldQuestion size={34} />
            <strong>{selectedCircleId === ALL_CIRCLES_ID ? "No nodes found yet" : `No members found in "${selectedCircleLabel}"`}</strong>
            <span>Nodes appear after discovery or membership enrollment.</span>
          </div>
        )}
        {viewMode === "map" && !deviceFix && scopedNodes.length > 0 && (
          <div className="clt-empty">
            <MapPin size={30} />
            <strong>No device location yet</strong>
            <span>Use "Update browser location" in the Geofence card to report this device's position.</span>
          </div>
        )}

        <svg ref={svgRef} className="clt-svg" viewBox={`0 0 ${WIDTH} ${HEIGHT}`} role="img" aria-label={`${viewMode === "mesh" ? "Mesh" : "Map"} topology for ${selectedCircleLabel}`}>
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
            {viewMode === "map" && <RealMapTiles />}
            {viewMode === "map" && (
              <g className="clt-geo-zones">
                {zones.map((zone) => (
                  <g key={zone.id} className={`clt-geo-zone ${zone.enabled ? "" : "is-disabled"} ${zone.inside ? "is-inside" : ""}`} style={{ "--zone-color": zone.color } as React.CSSProperties}>
                    <ellipse cx={zone.x} cy={zone.y} rx={zone.rx} ry={zone.ry} />
                    <text x={zone.x} y={zone.y - zone.ry - 8}>{zone.name}</text>
                  </g>
                ))}
              </g>
            )}
            {viewMode === "map" && devicePoint && (
              <g className="clt-device-marker" transform={`translate(${devicePoint.x} ${devicePoint.y})`}>
                <circle r="16" className="clt-device-marker__halo" />
                <circle r="7" className="clt-device-marker__dot" />
                <MapPin x={-9} y={-32} width={18} height={18} className="clt-device-marker__pin" />
                <text className="clt-device-marker__label" y="26">This device</text>
              </g>
            )}

            {viewMode === "mesh" && (
              <>
                <g className="clt-links">
                  {links.map((link: CircleTopologyLink, linkIndex) => {
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
                    const nodeDisplayName = displayForDid(node.did, node.label);
                    const selectedNode = node.id === selectedId;
                    const visible = visibleIds.has(node.id);
                    const radius = node.primaryLighthouse ? 30 : node.roles.includes("lighthouse") ? 26 : node.roles.includes("relay") ? 23 : 17;
                    const kind = nodeKind(node);
                    const dotRadius = node.primaryLighthouse ? 8 : node.roles.includes("lighthouse") ? 7 : node.roles.includes("relay") ? 6 : 5;
                    const nodeCircleEntriesForNode = nodeCircleEntries(node);
                    const nodeZones = geofenceZones.filter((zone) => zoneMatchesNode(zone, node));
                    return (
                      <g
                        key={node.id}
                        transform={`translate(${node.x} ${node.y})`}
                        className={`clt-node ${selectedNode ? "is-selected" : ""} ${visible ? "" : "is-filtered"} clt-node--${node.presence}`}
                        role="button"
                        tabIndex={0}
                        aria-label={`${nodeDisplayName}, ${presence.label}, ${trust.label}`}
                        onClick={(event) => { event.stopPropagation(); selectNode(node); }}
                        onKeyDown={(event) => {
                          if (event.key === "Enter" || event.key === " ") selectNode(node);
                        }}
                      >
                        <g className="clt-node-zones" aria-label={`${nodeZones.length} zones on ${nodeDisplayName}`}>
                          {nodeZones.map((zone, zoneIndex) => {
                            const zoneRadius = topologyZoneRadius(zone, zoneIndex);
                            const evaluation = geofenceStatus?.zones.find((item) => item.zone_id === zone.zone_id);
                            const zoneColor = ZONE_COLORS[geofenceZones.findIndex((item) => item.zone_id === zone.zone_id) % ZONE_COLORS.length];
                            return <g key={zone.zone_id} className={`clt-node-zone ${zone.enabled ? "is-enabled" : "is-disabled"} ${evaluation?.inside ? "is-inside" : ""} ${selectedZoneId === zone.zone_id ? "is-selected" : ""}`} style={{ "--zone-color": zoneColor } as React.CSSProperties}>
                              <circle r={zoneRadius} className="clt-node-zone__fill" />
                              {zone.enabled && <circle r={zoneRadius} className="clt-node-zone__pulse" />}
                              <circle r={zoneRadius} className="clt-node-zone__boundary" />
                              <text y={-zoneRadius - 7}>{zone.name}{zone.enabled ? "" : " · OFF"}</text>
                              <title>{`${zone.name}: ${zone.enabled ? "enabled" : "disabled"}, radius ${Math.round(zone.radius_m ?? 0)} m`}</title>
                            </g>;
                          })}
                        </g>
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
                          {nodeCircleEntriesForNode.length > 1 && (
                            <g className="clt-role-mark clt-role-mark--multi" transform={`translate(${radius + 4} ${-radius - 9})`}>
                              <circle r="12" />
                              <Layers x={-7} y={-7} width={14} height={14} />
                              <title>{`Member of ${nodeCircleEntriesForNode.length} circles: ${nodeCircleEntriesForNode.map((entry) => entry.circleName).join(", ")}`}</title>
                            </g>
                          )}
                          <text className="clt-node__label" y={radius + 27}>{nodeDisplayName}</text>
                          <text className="clt-node__sub" y={radius + 43}>{node.overlayIp || node.ip}</text>
                          <text className="clt-node__map-label" x={dotRadius + 8} y="3">{nodeDisplayName}</text>
                        </g>
                      </g>
                    );
                  })}
                </g>
              </>
            )}
          </g>
        </svg>

        <div className="clt-zoom">
          <button onClick={() => zoomBy(1.2)} aria-label="Zoom in">+</button>
          <span ref={zoomLabelRef}>100%</span>
          <button onClick={() => zoomBy(1 / 1.2)} aria-label="Zoom out">−</button>
        </div>

        <div className="clt-map-status">
          <span>{liveState === "error" ? "OFFLINE" : liveState === "stale" ? "RECONNECTING" : "LIVE"}</span>
          {viewMode === "mesh" ? (
            <>
              <b>{nodes.length}</b> nodes
              <b>{zones.length}</b> zones
              <b>{zoomMode === "dots" ? "DOT VIEW" : "INSPECT VIEW"}</b>
            </>
          ) : (
            <>
              <b>{zones.length}</b> zones
              <b>{devicePoint ? "DEVICE LOCATED" : "NO DEVICE FIX"}</b>
            </>
          )}
        </div>

        {viewMode === "mesh" && (
          <div className="clt-minimap" aria-label="Circle minimap">
            <div><Network size={10} /> MESH OVERVIEW <span ref={minimapZoomRef}>100%</span></div>
            <svg viewBox={`0 0 ${WIDTH} ${HEIGHT}`}>
              {links.filter((link) => link.kind !== "attestation").map((link) => {
                const source = nodeMap.get(link.source);
                const target = nodeMap.get(link.target);
                return source && target ? <line key={link.id} x1={source.x} y1={source.y} x2={target.x} y2={target.y} /> : null;
              })}
              {nodes.map((node) => <circle key={node.id} cx={node.x} cy={node.y} r={node.primaryLighthouse ? 15 : 9} className={`is-${node.presence}`} />)}
              <rect x="4" y="4" width={WIDTH - 8} height={HEIGHT - 8} rx="18" />
            </svg>
          </div>
        )}
      </div>

      <aside className="clt-side">
        <section className="clt-card">
          <div className="clt-card__head"><span>Network Summary</span><Activity size={13} /></div>
          <div className="clt-metrics">
            <div><b>{scopedNodes.length}</b><span>Nodes</span></div>
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
          {viewMode === "mesh" ? (
            <div className="clt-filterbar" aria-label="Topology filters">
              {filters.map((item) => (
                <button key={item.id} className={filter === item.id ? "is-active" : ""} onClick={() => setFilter(item.id)}>
                  {item.label}
                </button>
              ))}
            </div>
          ) : (
            <div className="clt-card-empty">Switch to Mesh view to filter and browse individual nodes.</div>
          )}
        </section>

        <section className="clt-card">
          <div className="clt-card__head"><span>Selected Node</span><ShieldCheck size={13} /></div>
          {selected ? (
            <NodeDetails node={selected} nodeCircles={selectedNodeCircles} didPeers={didPeers} onClose={() => setSelectedId(null)} />
          ) : (
            <div className="clt-card-empty">Select a node to inspect trust, route, and endpoint details.</div>
          )}
        </section>

        <section className="clt-card">
          <div className="clt-card__head"><span>Trust Overview</span><ShieldCheck size={13} /></div>
          <div className="clt-trust-bars">
            <div><span>Attested</span><i><em style={{ width: `${scopedNodes.length ? (summary.verified / scopedNodes.length) * 100 : 0}%` }} /></i><b>{summary.verified}</b></div>
            <div><span>Pending</span><i><em className="warn" style={{ width: `${scopedNodes.length ? (summary.pending / scopedNodes.length) * 100 : 0}%` }} /></i><b>{summary.pending}</b></div>
            <div><span>Failed</span><i><em className="crit" style={{ width: `${scopedNodes.length ? (summary.failed / scopedNodes.length) * 100 : 0}%` }} /></i><b>{summary.failed}</b></div>
          </div>
        </section>

        <section className="clt-card">
          <div className="clt-card__head"><span>Relay & Lighthouse</span><Router size={13} /></div>
          <div className="clt-compact-list">
            <div><span>Relay routes</span><b>{relayLinks}</b></div>
            <div><span>Lighthouses</span><b>{summary.lighthouses}</b></div>
            <div><span>Primary</span><b>{scopedNodes.find((n) => n.primaryLighthouse)?.label ?? "None"}</b></div>
            <div><span>Discovery</span><b>{fatalError ? "Offline" : "Healthy"}</b></div>
          </div>
        </section>

        <section className="clt-card">
          <div className="clt-card__head"><span>Mesh Health</span><Wifi size={13} /></div>
          <div className="clt-compact-list">
            <div><span>Mesh links</span><b>{meshLinks}</b></div>
            <div><span>Attestation links</span><b>{attestationLinks}</b></div>
            <div><span>Topology age</span><b>{lastSuccessAt ? shortTime(lastSuccessAt) : "—"}</b></div>
            <div><span>Visible nodes</span><b>{visibleNodes.length}</b></div>
          </div>
        </section>

        <section className="clt-card">
          <div className="clt-card__head">
            <div className="clt-card__head-text">
              <span>Geofence</span>
              <small className="clt-card__subtitle" title="This device's zones apply network-wide, not scoped to the selected circle.">This device's zones — not scoped to "{selectedCircleLabel}"</small>
            </div>
            <MapPin size={13} />
          </div>
          <div className="clt-compact-list">
            <div><span>Active Provider</span><b>{sourceLabel(geofenceStatus?.source)}</b></div>
            <div><span>Location Source</span><b>{locationSourceLabel(geofenceStatus?.location?.source)}</b></div>
            <div><span>Location Type</span><b>{zoneTypeLabel(geofenceStatus?.location?.fix?.kind)}</b></div>
            <div><span>Zones Count</span><b>{geofenceZones.length}</b></div>
            <div><span>Current Zone</span><b>{geofenceStatus?.zones.find((z) => z.inside)?.zone_name ?? "Outside"}</b></div>
            <div><span>Current Coordinates</span><b>{geofenceStatus?.location?.fix ? `${geofenceStatus.location.fix.lat.toFixed(5)}, ${geofenceStatus.location.fix.lng.toFixed(5)}` : "Not stored"}</b></div>
            <div><span>Accuracy</span><b>{geofenceStatus?.location?.fix?.accuracy_m != null ? `${Math.round(geofenceStatus.location.fix.accuracy_m)} m` : "Unavailable"}</b></div>
            <div><span>Last Updated</span><b>{geofenceStatus?.location?.updated_at ? new Date(geofenceStatus.location.updated_at).toLocaleString() : "Never"}</b></div>
          </div>
          <div className="clt-geofence-actions">
            <button onClick={() => void refreshGeofence()} disabled={!!geofenceBusy} title="Refresh geofence" aria-label="Refresh geofence"><RefreshCw size={12} /></button>
            <button onClick={reportLocation} disabled={locationBusy} title="Update browser location" aria-label="Update browser location"><MapPin size={12} /></button>
            <button onClick={() => setEditingZone(null)} disabled={!!geofenceBusy || !selected} title={selected ? `Create zone on ${displayForDid(selected.did, selected.label)}` : "Select a topology node first"} aria-label="Create zone on selected node"><Plus size={12} /></button>
            <button onClick={() => setEditingZone(selectedZone)} disabled={!!geofenceBusy || !selectedZone} title="Edit selected zone" aria-label="Edit selected zone"><Pencil size={12} /></button>
            <button onClick={() => selectedZone && void runZoneAction(selectedZone, "toggle")} disabled={!!geofenceBusy || !selectedZone} title={selectedZone?.enabled ? "Disable zone" : "Enable zone"} aria-label={selectedZone?.enabled ? "Disable zone" : "Enable zone"}><ShieldCheck size={12} /></button>
            <button onClick={() => selectedZone && void runZoneAction(selectedZone, "rf")} disabled={!!geofenceBusy || !selectedZone} title={selectedZone?.kind === "rf_signature" ? "Re-capture RF baseline" : "Capture RF for selected zone"} aria-label={selectedZone?.kind === "rf_signature" ? "Re-capture RF baseline" : "Capture RF for selected zone"}><Radio size={12} /></button>
            <button onClick={() => selectedZone && void runZoneAction(selectedZone, "entry")} disabled={!!geofenceBusy || !selectedZone} title="Test zone action" aria-label="Test zone action"><Zap size={12} /></button>
            <button onClick={() => selectedZone && void runZoneAction(selectedZone, "entry")} disabled={!!geofenceBusy || !selectedZone} title="Simulate zone entry" aria-label="Simulate zone entry"><CheckCircle2 size={12} /></button>
            <button onClick={() => selectedZone && void runZoneAction(selectedZone, "exit")} disabled={!!geofenceBusy || !selectedZone} title="Simulate zone exit" aria-label="Simulate zone exit"><WifiOff size={12} /></button>
            <button onClick={() => selectedZone && void runZoneAction(selectedZone, "delete")} disabled={!!geofenceBusy || !selectedZone} title="Delete zone" aria-label="Delete zone"><Trash2 size={12} /></button>
          </div>
          <div className="clt-zone-cards">{geofenceZones.map((zone) => { const evaluation = geofenceStatus?.zones.find((item) => item.zone_id === zone.zone_id); const membership = evaluation?.inside === true ? "Inside" : evaluation?.inside === false ? "Outside" : "Pending"; const selectZone = () => setSelectedZoneId(zone.zone_id); return <div className={`clt-geofence-detail${selectedZoneId === zone.zone_id ? " is-selected" : ""}`} key={zone.zone_id} role="button" tabIndex={0} aria-pressed={selectedZoneId === zone.zone_id} onClick={selectZone} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); selectZone(); } }}>
            <b>{zone.name}</b><span>Topology node: {nodes.find((node) => zoneMatchesNode(zone, node))?.label ?? "Not assigned"}</span><span>Zone Type: {zoneTypeLabel(zone.kind)}</span><span>{zone.enabled ? "Enabled" : "Disabled"} | {membership}</span>
            {zone.kind === "coordinate" ? <><span>Radius: {zone.radius_m != null ? `${Math.round(zone.radius_m)} m` : "Not set"}</span><span>Current distance: {evaluation?.distance_m != null ? `${Math.round(evaluation.distance_m)} m` : "Unavailable"}</span></> : <><span>Captured AP count: {zone.rf_signature?.aps?.length ?? 0}</span><span>Current RF score: {evaluation?.rf_score != null ? evaluation.rf_score.toFixed(2) : "Unavailable"}</span><span>Match threshold: {zone.rf_signature?.threshold ?? "Unavailable"}</span></>}
            <span>Configured actions: {configuredActions(zone)}</span>
          </div>; })}</div>
          <div className="clt-geofence-feed">
            <b>Events ({orderedGeofenceEvents.length})</b>
            {(showAllGeofenceEvents ? orderedGeofenceEvents : orderedGeofenceEvents.slice(0, 3)).map((event) => { const details = eventDetails(event, geofenceZones); const detection = details.source !== "Not reported" ? details.source : sourceLabel(details.detectionDetails); const timestamp = details.timestamp && !Number.isNaN(new Date(details.timestamp).getTime()) ? new Date(details.timestamp).toLocaleString() : "Not reported"; const showDetectionDetails = details.detectionDetails && details.detectionDetails.toLowerCase() !== detection.toLowerCase(); return <article className="clt-feed-card" key={event.id}><div className="clt-feed-card__head"><b className={`clt-feed-badge is-${event.transition}`}>{event.transition.toUpperCase()}</b></div><dl><div><dt>Zone</dt><dd>{details.zoneName}</dd></div><div><dt>Zone type</dt><dd>{zoneTypeLabel(details.kind)}</dd></div><div><dt>Source</dt><dd>{detection}</dd></div><div><dt>Time</dt><dd>{timestamp}</dd></div>{showDetectionDetails && <div className="is-wide"><dt>Details</dt><dd>{details.detectionDetails}</dd></div>}{event.rf_score != null && <div className="is-wide"><dt>RF score</dt><dd>{event.rf_score.toFixed(2)}</dd></div>}</dl></article>; })}
            {!orderedGeofenceEvents.length && <span>No geofence events</span>}
            {orderedGeofenceEvents.length > 3 && <button className="clt-feed-toggle" onClick={() => setShowAllGeofenceEvents((value) => !value)}>{showAllGeofenceEvents ? "Show less" : "View all"}</button>}
            <b>Alerts ({orderedGeofenceAlerts.length})</b>
            {(showAllGeofenceAlerts ? orderedGeofenceAlerts : orderedGeofenceAlerts.slice(0, 3)).map((alert, index) => { const details = alertDetails(alert, geofenceZones); const timestamp = details.timestamp !== "Not reported" && !Number.isNaN(new Date(details.timestamp).getTime()) ? new Date(details.timestamp).toLocaleString() : details.timestamp; const rfScore = typeof alert.rf_score === "number" ? alert.rf_score : null; const rfDetails = typeof alert.fix_summary === "string" && alert.fix_summary.trim() ? alert.fix_summary.trim() : null; return <article className="clt-feed-card" key={`${details.id}-${index}`}><div className="clt-feed-card__head"><b className={`clt-feed-badge is-${details.severity.toLowerCase()}`}>{details.severity.toUpperCase()}</b>{details.trigger !== "Not reported" && <span>{details.trigger}</span>}</div><dl><div><dt>Zone</dt><dd>{details.zoneName}</dd></div><div><dt>Zone type</dt><dd>{zoneTypeLabel(details.kind)}</dd></div><div><dt>Source</dt><dd>{details.source}</dd></div><div><dt>Time</dt><dd>{timestamp}</dd></div>{rfDetails && <div className="is-wide"><dt>RF details</dt><dd>{rfDetails}</dd></div>}{rfScore != null && <div className="is-wide"><dt>RF score</dt><dd>{rfScore.toFixed(2)}</dd></div>}</dl></article>; })}
            {!orderedGeofenceAlerts.length && <span>No geofence alerts</span>}
            {orderedGeofenceAlerts.length > 3 && <button className="clt-feed-toggle" onClick={() => setShowAllGeofenceAlerts((value) => !value)}>{showAllGeofenceAlerts ? "Show less" : "View all"}</button>}
          </div>
          {geofenceToast && <div className={`clt-geofence-toast is-${geofenceToast.tone}`} role="status" aria-live="polite">{geofenceToast.message}</div>}
          {(geofenceError || geofenceBusy) && <p className="clt-card-note">{geofenceBusy ?? geofenceError}</p>}
        </section>
      </aside>
      {editingZone !== undefined && <ZoneDialog zone={editingZone ?? undefined} node={editingZoneNode} fix={geofenceStatus?.location?.fix ?? null} busy={!!geofenceBusy} onClose={() => setEditingZone(undefined)} onSave={(body) => void saveZone(body)} />}
      </div>

      <footer className="clt-footer">
        <span>{fatalError ? <WifiOff size={13} /> : <CheckCircle2 size={13} />}{fatalError ? "Backend unreachable" : "Backend connected"}</span>
        <span>Peers {scopedNodes.length}</span>
        <span>Relays {summary.relays}</span>
        <span>Zoom <span ref={footerZoomRef}>100%</span></span>
        <span>Topology v2.2</span>
        <span><Clock3 size={13} />Auto-refreshing every 10s</span>
      </footer>
    </section>
  );
}
