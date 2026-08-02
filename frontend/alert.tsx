import { useCallback, useEffect, useState } from "react";
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
import { geofenceApi, type GeofenceEvent, type GeofenceStatus, type GeofenceZone, type ZoneAutomation } from "../../../api/geofence";
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

function NodeDetail({ sel }: { sel: SelectedNode }) {
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
          {geo && <><div className="k">Location</div><div className="v">{geo.lat.toFixed(5)}, {geo.lng.toFixed(5)}</div></>}
          {geo && <><div className="k">Source</div><div className="v">{geo.locationSource.toUpperCase()}</div></>}
        </div>
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

function selectedZone(status: GeofenceStatus | null, zones: GeofenceZone[]): GeofenceZone | null {
  const active = status?.zones.find((zone) => zone.inside);
  if (active) return zones.find((zone) => zone.zone_id === active.zone_id) ?? null;
  return zones[0] ?? null;
}

function GeofencePanel({
  status,
  zones,
  events,
  alertCount,
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
  alertCount: number;
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
  const zone = selectedZone(status, zones);
  const fix = status?.location?.fix;
  return (
    <div className="topo-geofence-panel" onClick={(e) => e.stopPropagation()}>
      <div className="topo-geofence-head">
        <span><MapPin size={13} /> Geofence</span>
        <button title="Refresh geofence data" aria-label="Refresh geofence data" onClick={onRefresh}>
          <RefreshCw size={13} className={loading ? "spin" : undefined} />
        </button>
      </div>
      <div className="topo-geofence-grid">
        <div><span>Source</span><b>{status?.source ?? "unavailable"}</b></div>
        <div><span>Zones</span><b>{zones.length}</b></div>
        <div><span>Events</span><b>{events.length}</b></div>
        <div><span>Alerts</span><b>{alertCount}</b></div>
      </div>
      <div className="topo-geofence-fix">
        {fix ? `${fix.lat.toFixed(5)}, ${fix.lng.toFixed(5)} · +/-${Math.round(fix.accuracy_m ?? 0)}m` : "No saved location fix"}
      </div>
      {error && <div className="topo-geofence-error">{error}</div>}
      <div className="topo-geofence-actions">
        <button onClick={onReportLocation} disabled={!!busy} title="Upload this browser's current location">
          <MapPin size={13} /> Report
        </button>
        <button onClick={onCreateZone} disabled={!!busy || !fix} title="Create a zone at the current stored location">
          <Plus size={13} /> Zone
        </button>
      </div>
      {zone && (
        <div className="topo-zone-card">
          <div className="topo-zone-card-title">
            <strong>{zone.name}</strong>
            <span>{zone.enabled ? "enabled" : "disabled"}</span>
          </div>
          <div className="topo-zone-card-meta">
            {zone.kind} · {Math.round(zone.radius_m ?? 0)}m · {zone.severity}
          </div>
          <div className="topo-geofence-actions">
            <button onClick={() => onToggleZone(zone)} disabled={!!busy} title="Patch zone enabled state">
              <ShieldCheck size={13} /> {zone.enabled ? "Disable" : "Enable"}
            </button>
            <button onClick={() => onCaptureRf(zone)} disabled={!!busy} title="Capture RF signature for this zone">
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
      )}
      {events[0] && (
        <div className="topo-last-event">
          <span>{events[0].transition}</span>
          <b>{events[0].zone_name}</b>
        </div>
      )}
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
  const { svgRef, groupRef, subscribe, zoomBy, reset, zoomToBox } = usePanZoom();
  const zoomPct = useZoomPercent(subscribe);
  const focusedZone = useFocusedZone(subscribe);
  const [selected, setSelected] = useState<SelectedNode | null>(null);
  const [hover, setHover] = useState<HoverInfo | null>(null);
  const [fullscreen, setFullscreen] = useState(false);
  const [filter, setFilter] = useState<FilterMode>("all");
  const [geofenceStatus, setGeofenceStatus] = useState<GeofenceStatus | null>(null);
  const [geofenceZones, setGeofenceZones] = useState<GeofenceZone[]>([]);
  const [geofenceEvents, setGeofenceEvents] = useState<GeofenceEvent[]>([]);
  const [geofenceAlertCount, setGeofenceAlertCount] = useState(0);
  const [geofenceLoading, setGeofenceLoading] = useState(false);
  const [geofenceLoaded, setGeofenceLoaded] = useState(false);
  const [geofenceError, setGeofenceError] = useState<string | null>(null);
  const [geofenceBusy, setGeofenceBusy] = useState<string | null>(null);

  const mapGuardians = buildMapGuardians(geofenceStatus);
  const mapZones = buildMapZones(geofenceZones, geofenceStatus);

  const refreshGeofence = useCallback(async () => {
    setGeofenceLoading(true);
    setGeofenceError(null);
    try {
      const [status, location, zoneResult, eventResult, alertResult] = await Promise.all([
        geofenceApi.status(),
        geofenceApi.getLocation(),
        geofenceApi.listZones(),
        geofenceApi.events(),
        geofenceApi.alerts(),
      ]);
      setGeofenceStatus({ ...status, location: status.location ?? location.location });
      setGeofenceZones(zoneResult.zones);
      setGeofenceEvents(eventResult.events);
      setGeofenceAlertCount(alertResult.count);
      setGeofenceLoaded(true);
    } catch (err) {
      setGeofenceError(err instanceof Error ? err.message : "Geofence API unavailable");
    } finally {
      setGeofenceLoading(false);
    }
  }, []);

  const reportBrowserLocation = useCallback(async () => {
    if (!navigator.geolocation) {
      setGeofenceError("Browser geolocation is unavailable");
      return;
    }
    setGeofenceBusy("Uploading location");
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

  useEffect(() => {
    void refreshGeofence();
    const interval = window.setInterval(refreshGeofence, 15000);
    return () => window.clearInterval(interval);
  }, [refreshGeofence]);

  useEffect(() => {
    if (!geofenceLoaded || geofenceLoading || geofenceStatus?.location || geofenceError) return;
    void reportBrowserLocation();
  }, [geofenceError, geofenceLoaded, geofenceLoading, geofenceStatus?.location, reportBrowserLocation]);

  const createZoneAtFix = useCallback(async () => {
    const fix = geofenceStatus?.location?.fix;
    if (!fix) return;
    setGeofenceBusy("Creating zone");
    try {
      await geofenceApi.createZone({
        name: `Topology Zone ${geofenceZones.length + 1}`,
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
  }, [geofenceStatus?.location?.fix, geofenceZones.length, refreshGeofence]);

  const toggleZone = useCallback(async (zone: GeofenceZone) => {
    setGeofenceBusy("Patching zone");
    try {
      await geofenceApi.editZone(zone.zone_id, { enabled: !zone.enabled });
      await refreshGeofence();
    } catch (err) {
      setGeofenceError(err instanceof Error ? err.message : "Could not update zone");
    } finally {
      setGeofenceBusy(null);
    }
  }, [refreshGeofence]);

  const deleteZone = useCallback(async (zone: GeofenceZone) => {
    setGeofenceBusy("Deleting zone");
    try {
      await geofenceApi.deleteZone(zone.zone_id);
      await refreshGeofence();
    } catch (err) {
      setGeofenceError(err instanceof Error ? err.message : "Could not delete zone");
    } finally {
      setGeofenceBusy(null);
    }
  }, [refreshGeofence]);

  const captureRf = useCallback(async (zone: GeofenceZone) => {
    setGeofenceBusy("Capturing RF");
    try {
      await geofenceApi.captureRf(zone.zone_id);
      await refreshGeofence();
    } catch (err) {
      setGeofenceError(err instanceof Error ? err.message : "Could not capture RF");
    } finally {
      setGeofenceBusy(null);
    }
  }, [refreshGeofence]);

  const testActions = useCallback(async (zone: GeofenceZone, transition: "entry" | "exit") => {
    setGeofenceBusy(`Testing ${transition}`);
    try {
      await geofenceApi.getActions(zone.zone_id);
      await geofenceApi.testActions({ zone_id: zone.zone_id, transition, confidence: 1 });
      await refreshGeofence();
    } catch (err) {
      setGeofenceError(err instanceof Error ? err.message : "Could not test actions");
    } finally {
      setGeofenceBusy(null);
    }
  }, [refreshGeofence]);

  const replaceActions = useCallback(async (zone: GeofenceZone) => {
    setGeofenceBusy("Replacing actions");
    try {
      await geofenceApi.replaceActions(zone.zone_id, zone.automation ?? DEFAULT_AUTOMATION);
      await refreshGeofence();
    } catch (err) {
      setGeofenceError(err instanceof Error ? err.message : "Could not replace actions");
    } finally {
      setGeofenceBusy(null);
    }
  }, [refreshGeofence]);

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
        alertCount={geofenceAlertCount}
        loading={geofenceLoading}
        error={geofenceError}
        busy={geofenceBusy}
        onRefresh={() => void refreshGeofence()}
        onReportLocation={reportBrowserLocation}
        onCreateZone={() => void createZoneAtFix()}
        onToggleZone={(zone) => void toggleZone(zone)}
        onDeleteZone={(zone) => void deleteZone(zone)}
        onCaptureRf={(zone) => void captureRf(zone)}
        onTestActions={(zone, transition) => void testActions(zone, transition)}
        onReplaceActions={(zone) => void replaceActions(zone)}
      />

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
          <div className="topo-rpanel-body">
            <NodeDetail sel={selected} />
          </div>
        </div>
      )}
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
