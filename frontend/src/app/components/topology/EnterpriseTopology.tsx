import { useCallback, useEffect, useRef, useState } from "react";
import { ZoomIn, ZoomOut, RotateCcw, X, Maximize2, MapPin, Radio, RefreshCw, Trash2, TestTube2, Plus, ShieldCheck } from "lucide-react";
import { TopologyScene, type SelectedNode, type HoverInfo } from "./TopologyScene";
import { MiniMap } from "./MiniMap";
import { TopologyTopBar, type FilterMode } from "./TopologyTopBar";
import { TopologyLogBar } from "./TopologyLogBar";
import { CornerTL, CornerBL, CornerBR, ZoneFocusLabel } from "./CornerLabels";
import { usePanZoom } from "./hooks/usePanZoom";
import { useZoomPercent } from "./hooks/useZoomPercent";
import { useFocusedZone } from "./hooks/useFocusedZone";
import { GUARDIANS, SHAREDS, CLUSTERS, THREATS, ZONES, VIEW_BOX, type Guardian } from "./lib/topology";
import { geofenceApi, type CreateZoneRequest, type GeofenceEvent, type GeofenceStatus, type GeofenceZone, type ThreatAlert, type ZoneAutomation } from "../../../api/geofence";
import { alertDetails, configuredActions, eventDetails, locationSourceLabel, sourceLabel, zoneTypeLabel } from "../geofenceDisplay";
import { buildMapGuardians, buildMapZones, type MapGuardian, type MapZone } from "./lib/geospatial";
import "./topology.css";

function selectedKey(sel: SelectedNode | null): string | null {
  if (!sel) return null;
  return `${sel.kind}:${sel.data.id}`;
}

function findNodeByName(name: string): SelectedNode | null {
  const n = name.trim();
  const g = GUARDIANS.find((x) => x.name === n || x.id === n.toLowerCase());
  if (g) return { kind: "guardian", data: g };
  const s = SHAREDS.find((x) => x.name === n);
  if (s) return { kind: "shared", data: s };
  const t = THREATS.find((x) => x.name === n);
  if (t) return { kind: "threat", data: t };
  const lower = n.toLowerCase();
  if (lower.startsWith("plc")) return { kind: "cluster", data: CLUSTERS.find((c) => c.id === "plc")! };
  if (lower.startsWith("wyze") || lower.startsWith("cam")) return { kind: "cluster", data: CLUSTERS.find((c) => c.id === "cam")! };
  return null;
}

function TelemetrySection({ health = "healthy", seed = 1 }: { health?: string; seed?: number }) {
  const cpu = health === "offline" ? 0 : 24 + (seed * 13) % 51;
  const memory = health === "offline" ? 0 : 38 + (seed * 11) % 43;
  const trust = health === "critical" ? 42 : health === "degraded" ? 78 : health === "offline" ? 0 : 96;
  return (
    <>
      <div className="topo-score-row">
        <div className="topo-score"><span>TRUST SCORE</span><strong>{trust}</strong><i style={{ "--score": `${trust}%` } as React.CSSProperties} /></div>
        <div className="topo-score"><span>THREAT SCORE</span><strong>{health === "critical" ? 86 : health === "degraded" ? 34 : 8}</strong><i style={{ "--score": `${health === "critical" ? 86 : health === "degraded" ? 34 : 8}%` } as React.CSSProperties} /></div>
      </div>
      <div className="topo-telemetry">
        <div><span>CPU</span><b>{cpu}%</b><i><em style={{ width: `${cpu}%` }} /></i></div>
        <div><span>MEMORY</span><b>{memory}%</b><i><em style={{ width: `${memory}%` }} /></i></div>
        <div><span>NETWORK</span><b>{health === "offline" ? "0" : `${12 + seed * 3}.4`} Mb/s</b><i><em style={{ width: health === "offline" ? "0%" : "64%" }} /></i></div>
      </div>
      <div className="topo-security-strip">
        <span><i className="ok" />ATTESTED</span>
        <span><i className="ok" />POLICY VALID</span>
        <span><i className={health === "offline" ? "off" : "ok"} />mTLS</span>
      </div>
      <div className="topo-panel-actions">
        <button>Inspect telemetry</button>
        <button>Open investigation</button>
      </div>
    </>
  );
}

type PlaceLabel = { city: string; region: string; country: string };
type Toast = { message: string; tone: "success" | "error" | "info" };

function NodeDetail({ sel, zones = [], place, onViewZones }: { sel: SelectedNode; zones?: GeofenceZone[]; place?: PlaceLabel | null; onViewZones?: () => void }) {
  if (sel.kind === "guardian") {
    const g = sel.data;
    const geo = "lat" in g ? g as MapGuardian : null;
    return (
      <>
        <h3>{g.name}</h3>
        <div className="topo-role">{g.role}</div>
        <div className="topo-kv">
          <div className="k">IP</div><div className="v">{g.ip}</div>
          <div className="k">Firmware</div><div className="v">{g.fw}</div>
          <div className="k">Impact</div><div className="v">{g.impact}</div>
          <div className="k">FIPS</div><div className="v">{g.fips}</div>
          <div className="k">STIG</div><div className="v">{g.stig}</div>
          <div className="k">Peers</div><div className="v">{g.peersConnected} / {g.peersTotal}</div>
          <div className="k">Threats wk</div><div className="v">{g.threatsWeek}</div>
          <div className="k">Policy</div><div className="v">{g.policyVersion}</div>
          <div className="k">Health</div><div className={`v topo-health-value is-${g.health || "healthy"}`}>{(g.health || "healthy").toUpperCase()}</div>
          <div className="k">Attestation</div><div className="v is-healthy">VERIFIED · 18s ago</div>
          <div className="k">Certificate</div><div className="v">SGX-ICA-04 · 183d</div>
          <div className="k">Last seen</div><div className="v">{g.health === "offline" ? "14m 22s ago" : "Now"}</div>
          {geo && <><div className="k">Latitude / longitude</div><div className="v">{geo.lat.toFixed(5)}, {geo.lng.toFixed(5)}</div></>}
          {geo && <><div className="k">City / town</div><div className="v">{place?.city || "Resolving…"}</div></>}
          {geo && <><div className="k">Region</div><div className="v">{place?.region || "—"}</div></>}
          {geo && <><div className="k">Country</div><div className="v">{place?.country || "—"}</div></>}
          {geo && <><div className="k">Source</div><div className="v">{geo.locationSource.toUpperCase()}</div></>}
        </div>
        {geo && <button className="topo-zone-detail-btn" onClick={onViewZones}><MapPin size={14} /> View zones ({zones.length})</button>}
        <TelemetrySection health={g.health} seed={Number(g.id.at(-1)) || 1} />
      </>
    );
  }
  if (sel.kind === "shared") {
    const s = sel.data;
    return (
      <>
        <h3>{s.name}</h3>
        <div className="topo-role">{s.role}</div>
        <div className="topo-kv">
          <div className="k">Zone</div><div className="v">{s.zone}</div>
          <div className="k">IP</div><div className="v">{s.ip}</div>
          <div className="k">Protocol</div><div className="v">{s.proto}</div>
          <div className="k">Health</div><div className={`v topo-health-value is-${s.health || "healthy"}`}>{(s.health || "healthy").toUpperCase()}</div>
        </div>
        <TelemetrySection health={s.health} seed={s.id.length % 6} />
      </>
    );
  }
  if (sel.kind === "cluster") {
    const c = sel.data;
    return (
      <>
        <h3>{c.name}</h3>
        <div className="topo-role">{c.sub || c.label}</div>
        <div className="topo-kv">
          <div className="k">Zone</div><div className="v">{c.zone}</div>
          <div className="k">Devices</div><div className="v">{c.label}</div>
          <div className="k">Health</div><div className={`v topo-health-value is-${c.health || "healthy"}`}>{(c.health || "healthy").toUpperCase()}</div>
        </div>
        <TelemetrySection health={c.health} seed={c.id.length} />
      </>
    );
  }
  if (sel.kind === "zoneDevice") {
    const d = sel.data;
    return (
      <>
        <h3>{d.id}</h3>
        <div className="topo-role">Device · {d.zone}</div>
        <div className="topo-kv">
          <div className="k">Status</div><div className="v">{d.status === "err" ? "ERROR" : "OK"}</div>
        </div>
      </>
    );
  }
  if (sel.kind === "threat") {
    const t = sel.data;
    return (
      <>
        <h3 style={{ color: "#fecaca" }}>{t.name}</h3>
        <div className="topo-role">{t.role}</div>
        <div className="topo-kv">
          <div className="k">Severity</div><div className="v">{t.sev}</div>
          <div className="k">IP</div><div className="v">{t.ip}</div>
          <div className="k">Protocol</div><div className="v">{t.proto}</div>
          <div className="k">CVSS</div><div className="v">{t.cvss}</div>
          <div className="k">MITRE</div><div className="v">{t.mitre}</div>
          <div className="k">Actor</div><div className="v">{t.actor}</div>
          <div className="k">CISA</div><div className="v">{t.cisa}</div>
          <div className="k">NIST</div><div className="v">{t.nist}</div>
        </div>
      </>
    );
  }
  return null;
}

const DEFAULT_AUTOMATION: ZoneAutomation = {
  on_entry: [{ action: "notify", severity: "low" }],
  on_exit: [{ action: "raise_alert", severity: "high" }],
  allow_destructive: false,
  min_confidence: 0.9,
};

function ZoneForm({ fix, count, busy, onCancel, onSubmit }: { fix: { lat: number; lng: number } | null; count: number; busy: boolean; onCancel: () => void; onSubmit: (zone: CreateZoneRequest) => void }) {
  const [name, setName] = useState(`Topology Zone ${count + 1}`);
  const [kind, setKind] = useState<"coordinate" | "rf_signature">("coordinate");
  const [lat, setLat] = useState(String(fix?.lat ?? ""));
  const [lng, setLng] = useState(String(fix?.lng ?? ""));
  const [radius, setRadius] = useState("250");
  const [severity, setSeverity] = useState("high");
  const [onEntry, setOnEntry] = useState(true);
  const [onExit, setOnExit] = useState(true);
  const valid = !!name.trim() && (kind === "rf_signature" || (!!lat.trim() && !!lng.trim() && Number.isFinite(Number(lat)) && Number.isFinite(Number(lng)))) && Number(radius) > 0;
  return <div className="topo-modal-backdrop" onClick={onCancel}><form className="topo-api-form" onClick={(e) => e.stopPropagation()} onSubmit={(e) => { e.preventDefault(); if (!valid) return; onSubmit({ name: name.trim(), kind, center_lat: kind === "coordinate" ? Number(lat) : null, center_lng: kind === "coordinate" ? Number(lng) : null, radius_m: Number(radius), on_entry: onEntry, on_exit: onExit, severity, automation: DEFAULT_AUTOMATION, enabled: true }); }}>
    <div className="topo-api-form-head"><div><span>NEW GEOFENCE</span><h3>Create zone</h3></div><button type="button" onClick={onCancel}><X size={16} /></button></div>
    <label>Zone name<input autoFocus value={name} onChange={(e) => setName(e.target.value)} placeholder="Office" /></label>
    <label>Detection kind<select value={kind} onChange={(e) => setKind(e.target.value as typeof kind)}><option value="coordinate">Coordinate</option><option value="rf_signature">RF signature</option></select></label>
    <div className="topo-form-row"><label>Latitude<input type="number" step="any" disabled={kind !== "coordinate"} value={lat} onChange={(e) => setLat(e.target.value)} /></label><label>Longitude<input type="number" step="any" disabled={kind !== "coordinate"} value={lng} onChange={(e) => setLng(e.target.value)} /></label></div>
    <div className="topo-form-row"><label>Radius (metres)<input type="number" min="1" value={radius} onChange={(e) => setRadius(e.target.value)} /></label><label>Severity<select value={severity} onChange={(e) => setSeverity(e.target.value)}><option>low</option><option>medium</option><option>high</option><option>critical</option></select></label></div>
    <div className="topo-form-checks"><label><input type="checkbox" checked={onEntry} onChange={(e) => setOnEntry(e.target.checked)} /> On entry</label><label><input type="checkbox" checked={onExit} onChange={(e) => setOnExit(e.target.checked)} /> On exit</label></div>
    <p className="topo-form-note">The zone API supports name, kind, coordinates/RF signature, radius, triggers, severity, automation and enabled state. It does not define a description field.</p>
    <div className="topo-form-actions"><button type="button" onClick={onCancel}>Cancel</button><button type="submit" disabled={!valid || busy}>{busy ? "Creating…" : "Create zone"}</button></div>
  </form></div>;
}

function GeofencePanel({
  status,
  zones,
  events,
  alerts,
  loading,
  error,
  busy,
  onRefresh,
  onReportLocation,
  onCreateZone,
  onToggleZone,
  onDeleteZone,
  onCaptureRf,
  onTestActions,
  onReplaceActions,
}: {
  status: GeofenceStatus | null;
  zones: GeofenceZone[];
  events: GeofenceEvent[];
  alerts: ThreatAlert[];
  loading: boolean;
  error: string | null;
  busy: string | null;
  onRefresh: () => void;
  onReportLocation: () => void;
  onCreateZone: () => void;
  onToggleZone: (zone: GeofenceZone) => void;
  onDeleteZone: (zone: GeofenceZone) => void;
  onCaptureRf: (zone: GeofenceZone) => void;
  onTestActions: (zone: GeofenceZone, transition: "entry" | "exit") => void;
  onReplaceActions: (zone: GeofenceZone) => void;
}) {
  const fix = status?.location?.fix;
  const activeZone = status?.zones.find((item) => item.inside);
  const [showAllEvents, setShowAllEvents] = useState(false);
  const [showAllAlerts, setShowAllAlerts] = useState(false);
  const orderedEvents = [...events].sort((a, b) => (Date.parse(b.at ?? b.timestamp ?? "") || 0) - (Date.parse(a.at ?? a.timestamp ?? "") || 0));
  const orderedAlerts = [...alerts].sort((a, b) => {
    const right = Date.parse(String(b.at ?? b.timestamp ?? b.created_at ?? "")) || 0;
    const left = Date.parse(String(a.at ?? a.timestamp ?? a.created_at ?? "")) || 0;
    return right - left;
  });
  return (
    <div className="topo-geofence-panel" onClick={(e) => e.stopPropagation()}>
      <div className="topo-geofence-head">
        <span><MapPin size={13} /> Geofence</span>
        <button title="Refresh geofence data" aria-label="Refresh geofence data" onClick={onRefresh}>
          <RefreshCw size={13} className={loading ? "spin" : undefined} />
        </button>
      </div>
      <div className="topo-geofence-grid">
        <div><span>Active Provider</span><b>{sourceLabel(status?.source)}</b></div>
        <div><span>Location Source</span><b>{locationSourceLabel(status?.location?.source)}</b></div>
        <div><span>Location Type</span><b>{zoneTypeLabel(status?.location?.fix?.kind)}</b></div>
        <div><span>Zones Count</span><b>{zones.length}</b></div>
        <div><span>Current Zone</span><b>{activeZone?.zone_name ?? "Outside"}</b></div>
        <div><span>Current Coordinates</span><b>{fix ? `${fix.lat.toFixed(5)}, ${fix.lng.toFixed(5)}` : "Not stored"}</b></div>
        <div><span>Accuracy</span><b>{fix?.accuracy_m != null ? `${Math.round(fix.accuracy_m)} m` : "Unavailable"}</b></div>
        <div><span>Last Updated</span><b>{status?.location?.updated_at ? new Date(status.location.updated_at).toLocaleString() : "Never"}</b></div>
      </div>
      {error && <div className="topo-geofence-error">{error}</div>}
      <div className="topo-geofence-actions">
        <button onClick={onReportLocation} disabled={!!busy} title="Update browser location">
          <MapPin size={13} /> Report
        </button>
        <button onClick={onCreateZone} disabled={!!busy || !fix} title="Create zone">
          <Plus size={13} /> Zone
        </button>
      </div>
      {zones.length > 0 && <div className="topo-zone-status-list" aria-label="Zone membership status">
        {zones.map((item) => {
          const evaluation = status?.zones.find((entry) => entry.zone_id === item.zone_id);
          const membership = !item.enabled ? "DISABLED" : evaluation?.inside === true ? "INSIDE" : evaluation?.inside === false ? "OUTSIDE" : "PENDING";
          return <div key={item.zone_id}><strong>{item.name}</strong><span className={`is-${membership.toLowerCase()}`}>{membership}</span>{evaluation?.distance_m != null && <small>{Math.round(evaluation.distance_m)}m away</small>}</div>;
        })}
      </div>}
      <div className="topo-zone-cards">
      {zones.map((zone) => {
        const evaluation = status?.zones.find((entry) => entry.zone_id === zone.zone_id);
        const membership = evaluation?.inside === true ? "Inside" : evaluation?.inside === false ? "Outside" : "Pending";
        return (
        <div className="topo-zone-card" key={zone.zone_id}>
          <div className="topo-zone-card-title">
            <strong>{zone.name}</strong>
            <span>{zone.enabled ? "enabled" : "disabled"}</span>
          </div>
          <dl className="topo-zone-fields">
            <div><dt>Zone Type</dt><dd>{zoneTypeLabel(zone.kind)}</dd></div>
            <div><dt>Membership</dt><dd>{membership}</dd></div>
            {zone.kind === "coordinate" ? <>
              <div><dt>Radius</dt><dd>{zone.radius_m != null ? `${Math.round(zone.radius_m)} m` : "Not set"}</dd></div>
              <div><dt>Current Distance</dt><dd>{evaluation?.distance_m != null ? `${Math.round(evaluation.distance_m)} m` : "Unavailable"}</dd></div>
            </> : <>
              <div><dt>Captured AP Count</dt><dd>{zone.rf_signature?.aps?.length ?? 0}</dd></div>
              <div><dt>Current RF Score</dt><dd>{evaluation?.rf_score != null ? evaluation.rf_score.toFixed(2) : "Unavailable"}</dd></div>
              <div><dt>Match Threshold</dt><dd>{zone.rf_signature?.threshold ?? "Unavailable"}</dd></div>
            </>}
            <div className="is-wide"><dt>Configured Actions</dt><dd>{configuredActions(zone)}</dd></div>
          </dl>
          <div className="topo-geofence-actions">
            <button onClick={() => onToggleZone(zone)} disabled={!!busy} title="Patch zone enabled state">
              <ShieldCheck size={13} /> {zone.enabled ? "Disable" : "Enable"}
            </button>
            <button onClick={() => onCaptureRf(zone)} disabled={!!busy} title={zone.kind === "rf_signature" ? "Re-capture RF baseline" : "Capture RF for selected zone"}>
              <Radio size={13} /> RF
            </button>
            <button onClick={() => onReplaceActions(zone)} disabled={!!busy} title="Replace automation actions for this zone">
              <ShieldCheck size={13} /> Actions
            </button>
            <button onClick={() => onTestActions(zone, "entry")} disabled={!!busy} title="Test entry automation">
              <TestTube2 size={13} /> Entry
            </button>
            <button onClick={() => onTestActions(zone, "exit")} disabled={!!busy} title="Test exit automation">
              <TestTube2 size={13} /> Exit
            </button>
            <button onClick={() => onDeleteZone(zone)} disabled={!!busy} title="Delete this zone">
              <Trash2 size={13} /> Delete
            </button>
          </div>
        </div>
      );})}
      </div>
      <div className="topo-geofence-feed">
        <strong>Events ({orderedEvents.length})</strong>
        {(showAllEvents ? orderedEvents : orderedEvents.slice(0, 3)).map((event) => { const details = eventDetails(event, zones); const detection = details.source !== "Not reported" ? details.source : sourceLabel(details.detectionDetails); const timestamp = details.timestamp && !Number.isNaN(new Date(details.timestamp).getTime()) ? new Date(details.timestamp).toLocaleString() : "Not reported"; const showDetectionDetails = details.detectionDetails && details.detectionDetails.toLowerCase() !== detection.toLowerCase(); return <article className="topo-feed-card" key={event.id}>
          <div className="topo-feed-card-head"><b className={`topo-feed-badge is-${event.transition}`}>{event.transition.toUpperCase()}</b></div>
          <dl><div><dt>Zone</dt><dd>{details.zoneName}</dd></div><div><dt>Zone type</dt><dd>{zoneTypeLabel(details.kind)}</dd></div><div><dt>Source</dt><dd>{detection}</dd></div><div><dt>Time</dt><dd>{timestamp}</dd></div>{showDetectionDetails && <div className="is-wide"><dt>Details</dt><dd>{details.detectionDetails}</dd></div>}{event.rf_score != null && <div className="is-wide"><dt>RF score</dt><dd>{event.rf_score.toFixed(2)}</dd></div>}</dl>
        </article>; })}
        {!orderedEvents.length && <span>No geofence events</span>}
        {orderedEvents.length > 3 && <button className="topo-feed-toggle" onClick={() => setShowAllEvents((value) => !value)}>{showAllEvents ? "Show less" : "View all"}</button>}
        <strong>Alerts ({orderedAlerts.length})</strong>
        {(showAllAlerts ? orderedAlerts : orderedAlerts.slice(0, 3)).map((alert, index) => { const details = alertDetails(alert, zones); const timestamp = details.timestamp !== "Not reported" && !Number.isNaN(new Date(details.timestamp).getTime()) ? new Date(details.timestamp).toLocaleString() : details.timestamp; const rfScore = typeof alert.rf_score === "number" ? alert.rf_score : null; const rfDetails = typeof alert.fix_summary === "string" && alert.fix_summary.trim() ? alert.fix_summary.trim() : null; return <article className="topo-feed-card" key={`${details.id}-${index}`}>
          <div className="topo-feed-card-head"><b className={`topo-feed-badge is-${details.severity.toLowerCase()}`}>{details.severity.toUpperCase()}</b>{details.trigger !== "Not reported" && <span>{details.trigger}</span>}</div>
          <dl><div><dt>Zone</dt><dd>{details.zoneName}</dd></div><div><dt>Zone type</dt><dd>{zoneTypeLabel(details.kind)}</dd></div><div><dt>Source</dt><dd>{details.source}</dd></div><div><dt>Time</dt><dd>{timestamp}</dd></div>{rfDetails && <div className="is-wide"><dt>RF details</dt><dd>{rfDetails}</dd></div>}{rfScore != null && <div className="is-wide"><dt>RF score</dt><dd>{rfScore.toFixed(2)}</dd></div>}</dl>
        </article>; })}
        {!orderedAlerts.length && <span>No geofence alerts</span>}
        {orderedAlerts.length > 3 && <button className="topo-feed-toggle" onClick={() => setShowAllAlerts((value) => !value)}>{showAllAlerts ? "Show less" : "View all"}</button>}
      </div>
      {busy && <div className="topo-geofence-busy">{busy}</div>}
    </div>
  );
}

function eyebrowFor(sel: SelectedNode): string {
  switch (sel.kind) {
    case "guardian": return "GUARDIAN";
    case "shared": return "SHARED NODE";
    case "cluster": return "DEVICE CLUSTER";
    case "zoneDevice": return "DEVICE";
    case "threat": return "THREAT";
  }
}

export interface EnterpriseTopologyProps {
  /** "embed" trims the toolbar and shrinks the minimap for tight spaces. */
  variant?: "default" | "embed";
}

export function EnterpriseTopology({ variant = "default" }: EnterpriseTopologyProps) {
  const { svgRef, groupRef, subscribe, zoomBy, reset, zoomToBox } = usePanZoom({ minScale: 0.3, maxScale: 12 });
  const zoomPct = useZoomPercent(subscribe);
  const focusedZone = useFocusedZone(subscribe);
  const [selected, setSelected] = useState<SelectedNode | null>(null);
  const [hover, setHover] = useState<HoverInfo | null>(null);
  const [fullscreen, setFullscreen] = useState(false);
  const [filter, setFilter] = useState<FilterMode>("all");
  const [geofenceStatus, setGeofenceStatus] = useState<GeofenceStatus | null>(null);
  const [geofenceZones, setGeofenceZones] = useState<GeofenceZone[]>([]);
  const [geofenceEvents, setGeofenceEvents] = useState<GeofenceEvent[]>([]);
  const [geofenceAlerts, setGeofenceAlerts] = useState<ThreatAlert[]>([]);
  const [geofenceLoading, setGeofenceLoading] = useState(false);
  const [geofenceError, setGeofenceError] = useState<string | null>(null);
  const [geofenceBusy, setGeofenceBusy] = useState<string | null>(null);
  const [showZoneForm, setShowZoneForm] = useState(false);
  const [detailScreen, setDetailScreen] = useState<"node" | "zones">("node");
  const [place, setPlace] = useState<PlaceLabel | null>(null);
  const [toast, setToast] = useState<Toast | null>(null);
  const locationRequestInFlightRef = useRef(false);
  const simulationInFlightRef = useRef(false);

  const mapGuardians = buildMapGuardians(geofenceStatus);
  const mapZones = buildMapZones(geofenceZones, geofenceStatus);

  const notify = useCallback((message: string, tone: Toast["tone"] = "success") => setToast({ message, tone }), []);

  useEffect(() => {
    if (!toast) return;
    const timeout = window.setTimeout(() => setToast(null), 4200);
    return () => window.clearTimeout(timeout);
  }, [toast]);

  useEffect(() => {
    const geo = selected?.kind === "guardian" && "lat" in selected.data ? selected.data as MapGuardian : null;
    if (!geo) { setPlace(null); return; }
    const controller = new AbortController();
    const params = new URLSearchParams({ format: "jsonv2", lat: String(geo.lat), lon: String(geo.lng), zoom: "14", addressdetails: "1" });
    fetch(`https://nominatim.openstreetmap.org/reverse?${params}`, { signal: controller.signal, headers: { Accept: "application/json" } })
      .then((response) => response.ok ? response.json() : Promise.reject())
      .then((data) => { const a = data.address ?? {}; setPlace({ city: a.city || a.town || a.village || a.municipality || a.county || "Unknown locality", region: a.state || a.region || a.county || "", country: a.country || "Unknown country" }); })
      .catch(() => { if (!controller.signal.aborted) setPlace({ city: "Location unavailable", region: "", country: "" }); });
    return () => controller.abort();
  }, [selected]);

  const refreshGeofence = useCallback(async () => {
    setGeofenceLoading(true);
    setGeofenceError(null);
    try {
      const [status, location, zoneResult, eventResult, alertResult] = await Promise.all([
        geofenceApi.status().catch((error) => { throw new Error(`Geofence status request failed: ${error instanceof Error ? error.message : "Unknown error"}`); }),
        geofenceApi.getLocation().catch((error) => { throw new Error(`Geofence location request failed: ${error instanceof Error ? error.message : "Unknown error"}`); }),
        geofenceApi.listZones().catch((error) => { throw new Error(`Geofence zones request failed: ${error instanceof Error ? error.message : "Unknown error"}`); }),
        geofenceApi.events().catch((error) => { throw new Error(`Geofence events request failed: ${error instanceof Error ? error.message : "Unknown error"}`); }),
        geofenceApi.alerts().catch((error) => { throw new Error(`Geofence alerts request failed: ${error instanceof Error ? error.message : "Unknown error"}`); }),
      ]);
      setGeofenceStatus({ ...status, location: status.location ?? location.location });
      setGeofenceZones(zoneResult.zones);
      setGeofenceEvents(eventResult.events);
      setGeofenceAlerts(alertResult.alerts);
    } catch (err) {
      setGeofenceError(err instanceof Error ? err.message : "Geofence refresh failed: Unknown error");
      notify("Could not refresh geofence data", "error");
    } finally {
      setGeofenceLoading(false);
    }
  }, [notify]);

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

  const reportBrowserLocation = useCallback(async () => {
    if (locationRequestInFlightRef.current || geofenceBusy) return;
    if (!navigator.geolocation) {
      setGeofenceError("Location unavailable");
      return;
    }
    locationRequestInFlightRef.current = true;
    setGeofenceBusy("Getting location...");
    setGeofenceError(null);
    navigator.geolocation.getCurrentPosition(
      async (position) => {
        try {
          await geofenceApi.reportLocation({
            lat: position.coords.latitude,
            lng: position.coords.longitude,
            accuracy_m: position.coords.accuracy,
          });
          await refreshGeofence();
          notify("Location updated successfully");
        } catch (err) {
          setGeofenceError(`Location update failed: ${err instanceof Error ? err.message : "Unknown error"}`);
        } finally {
          locationRequestInFlightRef.current = false;
          setGeofenceBusy(null);
        }
      },
      (err) => {
        locationRequestInFlightRef.current = false;
        setGeofenceBusy(null);
        const message = err.code === err.PERMISSION_DENIED
          ? "Permission denied"
          : err.code === err.POSITION_UNAVAILABLE
            ? "Location unavailable"
            : err.code === err.TIMEOUT
              ? "Request timed out"
              : "Location unavailable";
        setGeofenceError(message);
        notify(message, "error");
      },
      { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 },
    );
  }, [geofenceBusy, notify, refreshGeofence]);

  useEffect(() => {
    void refreshGeofence();
  }, [refreshGeofence]);

  const createZone = useCallback(async (request: CreateZoneRequest) => {
    setGeofenceBusy("Creating zone");
    try {
      const result = await geofenceApi.createZone(request);
      setShowZoneForm(false);
      await refreshGeofence();
      notify(`Zone “${result.zone.name}” created and shown on the map`);
    } catch (err) {
      setGeofenceError(`Zone create request failed: ${err instanceof Error ? err.message : "Unknown error"}`);
      notify("Zone could not be created", "error");
    } finally {
      setGeofenceBusy(null);
    }
  }, [notify, refreshGeofence]);

  const toggleZone = useCallback(async (zone: GeofenceZone) => {
    setGeofenceBusy("Patching zone");
    try {
      await geofenceApi.editZone(zone.zone_id, { enabled: !zone.enabled });
      await refreshGeofence();
      notify(`Zone “${zone.name}” ${zone.enabled ? "disabled" : "enabled"}`);
    } catch (err) {
      setGeofenceError(`Zone enable/disable request failed: ${err instanceof Error ? err.message : "Unknown error"}`);
      notify(`Zone “${zone.name}” could not be updated`, "error");
    } finally {
      setGeofenceBusy(null);
    }
  }, [notify, refreshGeofence]);

  const deleteZone = useCallback(async (zone: GeofenceZone) => {
    setGeofenceBusy("Deleting zone");
    try {
      await geofenceApi.deleteZone(zone.zone_id);
      await refreshGeofence();
      notify(`Zone “${zone.name}” deleted from the map`);
    } catch (err) {
      setGeofenceError(`Zone delete request failed: ${err instanceof Error ? err.message : "Unknown error"}`);
      notify(`Zone “${zone.name}” could not be deleted`, "error");
    } finally {
      setGeofenceBusy(null);
    }
  }, [notify, refreshGeofence]);

  const captureRf = useCallback(async (zone: GeofenceZone) => {
    setGeofenceBusy("Capturing current RF environment...");
    try {
      await geofenceApi.captureRf(zone.zone_id);
      await refreshGeofence();
      notify(`RF signature captured for “${zone.name}”`);
    } catch (err) {
      setGeofenceError(`RF capture request failed: ${err instanceof Error ? err.message : "Unknown error"}`);
      notify(`RF capture failed for “${zone.name}”`, "error");
    } finally {
      setGeofenceBusy(null);
    }
  }, [notify, refreshGeofence]);

  const testActions = useCallback(async (zone: GeofenceZone, transition: "entry" | "exit") => {
    if (simulationInFlightRef.current || geofenceBusy) return;
    simulationInFlightRef.current = true;
    setGeofenceBusy(`Testing ${transition}`);
    setGeofenceError(null);
    try {
      await geofenceApi.testActions({ zone_id: zone.zone_id, transition, confidence: 1 });
      await refreshSimulationResults();
      notify(`Zone ${transition.toUpperCase()} simulation completed for “${zone.name}”`);
    } catch (err) {
      setGeofenceError(`Zone action test request failed: ${err instanceof Error ? err.message : "Unknown error"}`);
      notify(`Automation test failed for “${zone.name}”`, "error");
    } finally {
      simulationInFlightRef.current = false;
      setGeofenceBusy(null);
    }
  }, [geofenceBusy, notify, refreshSimulationResults]);

  const replaceActions = useCallback(async (zone: GeofenceZone) => {
    setGeofenceBusy("Replacing actions");
    try {
      await geofenceApi.replaceActions(zone.zone_id, zone.automation ?? DEFAULT_AUTOMATION);
      await refreshGeofence();
      notify(`Automation actions saved for “${zone.name}”`);
    } catch (err) {
      setGeofenceError(`Zone actions update request failed: ${err instanceof Error ? err.message : "Unknown error"}`);
      notify(`Automation actions could not be saved for “${zone.name}”`, "error");
    } finally {
      setGeofenceBusy(null);
    }
  }, [notify, refreshGeofence]);

  const onGuardianDoubleClick = useCallback((g: Guardian) => {
    const mapZone = mapZones.find((zone) => zone.name.toUpperCase().includes(g.sub) || zone.inside);
    if (mapZone) {
      zoomToBox({ x: mapZone.cx - mapZone.rx * 1.4, y: mapZone.cy - mapZone.ry * 1.4, w: mapZone.rx * 2.8, h: mapZone.ry * 2.8 }, VIEW_BOX.w, VIEW_BOX.h, 40);
      return;
    }
    const z = ZONES.find((zz) => zz.id === g.zone);
    if (!z) return;
    zoomToBox({ x: z.cx - z.rx, y: z.cy - z.ry, w: z.rx * 2, h: z.ry * 2 }, VIEW_BOX.w, VIEW_BOX.h, 40);
  }, [mapZones, zoomToBox]);

  // Esc to exit fullscreen + lock body scroll while expanded.
  useEffect(() => {
    if (!fullscreen) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setFullscreen(false); };
    window.addEventListener("keydown", onKey);
    const prevOverflow = document.body.style.overflow;
    document.body.style.overflow = "hidden";
    return () => {
      window.removeEventListener("keydown", onKey);
      document.body.style.overflow = prevOverflow;
    };
  }, [fullscreen]);

  const onLogDevice = useCallback((name: string) => {
    const found = findNodeByName(name);
    if (found) setSelected(found);
  }, []);

  const stageClass = [
    "topo-stage",
    !fullscreen && variant === "embed" ? "is-embed" : "",
    filter !== "all" ? `filter-${filter}` : "",
  ].filter(Boolean).join(" ");

  const stage = (
    <div className={stageClass} onClick={() => setSelected(null)}>
      <div className="topo-grid-bg" />
      <div className="topo-atmosphere" />
      <div className="topo-particle-field" />
      <div className="topo-data-streams" />
      <div className="topo-vignette" />
      <div className="topo-stage-status">
        <span className="topo-stage-live" /> LIVE FABRIC
        <b>{mapGuardians.length}</b> NODES
        <b>{mapZones.length}</b> GEOFENCES
        <b>99.97%</b> AVAILABILITY
      </div>
      <div className="topo-health-legend" aria-label="Node health legend">
        <span><i className="is-healthy" />Healthy</span>
        <span><i className="is-degraded" />Degraded</span>
        <span><i className="is-critical" />Critical</span>
        <span><i className="is-offline" />Offline</span>
      </div>

      {fullscreen && <CornerTL />}
      {fullscreen && <CornerBL />}
      {fullscreen && <ZoneFocusLabel focus={focusedZone} />}
      {fullscreen && <CornerBR />}

      <TopologyScene
        svgRef={svgRef}
        groupRef={groupRef}
        subscribe={subscribe}
        selectedId={selectedKey(selected)}
        onSelect={setSelected}
        onHover={setHover}
        onGuardianDoubleClick={onGuardianDoubleClick}
        mapGuardians={mapGuardians}
        mapZones={mapZones}
      />

      <GeofencePanel
        status={geofenceStatus}
        zones={geofenceZones}
        events={geofenceEvents}
        alerts={geofenceAlerts}
        loading={geofenceLoading}
        error={geofenceError}
        busy={geofenceBusy}
        onRefresh={() => void refreshGeofence()}
        onReportLocation={() => void reportBrowserLocation()}
        onCreateZone={() => { setShowZoneForm(true); notify("Name the new zone and set its boundary", "info"); }}
        onToggleZone={(zone) => void toggleZone(zone)}
        onDeleteZone={(zone) => void deleteZone(zone)}
        onCaptureRf={(zone) => void captureRf(zone)}
        onTestActions={(zone, transition) => void testActions(zone, transition)}
        onReplaceActions={(zone) => void replaceActions(zone)}
      />
      {toast && <div className={`topo-toast is-${toast.tone}`} role="status" aria-live="polite">{toast.message}</div>}

      {/* Tooltip */}
      {hover && (
        <div
          className="topo-tooltip show"
          style={{ left: hover.x + 14, top: hover.y + 14 }}
        >
          <div className="tt-name">{hover.name}</div>
          <div className="tt-sub">{hover.sub}</div>
          {hover.hint !== "" && <div className="tt-hint">{hover.hint || "Click for details"}</div>}
        </div>
      )}

      {/* Embedded toolbar — only shown when not fullscreen, since the
          fullscreen TopBar already provides zoom & fullscreen controls. */}
      {!fullscreen && (
        <div className="topo-toolbar" onClick={(e) => e.stopPropagation()}>
          <button title="Zoom in" onClick={() => zoomBy(1.18)} aria-label="Zoom in">
            <ZoomIn size={14} />
          </button>
          <button title="Zoom out" onClick={() => zoomBy(1 / 1.18)} aria-label="Zoom out">
            <ZoomOut size={14} />
          </button>
          <button title="Reset view" onClick={() => { reset(); setSelected(null); }} aria-label="Reset view">
            <RotateCcw size={14} />
          </button>
          <button title="Full view" onClick={() => setFullscreen(true)} aria-label="Full view">
            <Maximize2 size={14} />
          </button>
          <span className="topo-zoom-pct">{zoomPct}%</span>
        </div>
      )}

      <MiniMap subscribe={subscribe} />

      {/* Selection detail panel */}
      {selected && (
        <div className="topo-rpanel" onClick={(e) => e.stopPropagation()}>
          <div className="topo-rpanel-h">
            <div className="topo-eyebrow">{eyebrowFor(selected)}</div>
            <button
              className="topo-rpanel-close"
              aria-label="Close"
              onClick={() => setSelected(null)}
            >
              <X size={14} />
            </button>
          </div>
          <div className="topo-rpanel-tabs">
            <button className={detailScreen === "node" ? "active" : ""} onClick={() => setDetailScreen("node")}>Node</button>
            {selected.kind === "guardian" && <button className={detailScreen === "zones" ? "active" : ""} onClick={() => setDetailScreen("zones")}>Zones</button>}
          </div>
          <div className="topo-rpanel-body">
            {detailScreen === "node" || selected.kind !== "guardian" ? <NodeDetail sel={selected} zones={geofenceZones} place={place} onViewZones={() => setDetailScreen("zones")} /> : <div className="topo-node-zones"><h3>Node zones</h3><div className="topo-role">{geofenceZones.length} configured geofences</div>{geofenceZones.length ? geofenceZones.map((zone, index) => { const evaluation = geofenceStatus?.zones.find((entry) => entry.zone_id === zone.zone_id); const membership = !zone.enabled ? "DISABLED" : evaluation?.inside === true ? "INSIDE" : evaluation?.inside === false ? "OUTSIDE" : "PENDING"; return <article key={zone.zone_id} style={{ "--zone-color": mapZones[index]?.color ?? "#14b8a6" } as React.CSSProperties}><div><i /><strong>{zone.name}</strong><span>{membership}</span></div><dl><dt>Kind</dt><dd>{zone.kind}</dd><dt>Membership</dt><dd>{membership}{evaluation?.distance_m != null ? ` · ${Math.round(evaluation.distance_m)} m away` : ""}</dd><dt>Severity</dt><dd>{zone.severity}</dd><dt>Radius</dt><dd>{zone.radius_m ?? 0} m</dd><dt>Triggers</dt><dd>{zone.on_entry ? "Entry " : ""}{zone.on_exit ? "Exit" : ""}</dd><dt>Coordinates</dt><dd>{zone.center_lat?.toFixed(5) ?? "—"}, {zone.center_lng?.toFixed(5) ?? "—"}</dd><dt>Confidence</dt><dd>{Math.round((zone.automation?.min_confidence ?? 0) * 100)}%</dd></dl></article>; }) : <p className="topo-empty-zones">No zones configured for this node.</p>}</div>}
          </div>
        </div>
      )}
      {showZoneForm && <ZoneForm fix={geofenceStatus?.location?.fix ?? null} count={geofenceZones.length} busy={!!geofenceBusy} onCancel={() => setShowZoneForm(false)} onSubmit={(zone) => void createZone(zone)} />}
    </div>
  );

  if (!fullscreen) return stage;

  return (
    <div className="topo-fullscreen">
      <TopologyTopBar
        filter={filter}
        onFilter={setFilter}
        zoomPct={zoomPct}
        onZoomIn={() => zoomBy(1.18)}
        onZoomOut={() => zoomBy(1 / 1.18)}
        onReset={() => { reset(); setSelected(null); }}
        fullscreen={fullscreen}
        onToggleFullscreen={() => setFullscreen(false)}
      />
      {stage}
      <TopologyLogBar onDeviceClick={onLogDevice} />
    </div>
  );
}
