import React, { useCallback, useEffect, useMemo, useRef, useState } from "react";
import type { CSSProperties } from "react";
import * as Dialog from "@radix-ui/react-dialog";
import * as Switch from "@radix-ui/react-switch";
import { toast } from "sonner";
import {
  Cloud, Home, Shield, Thermometer, Plus, Zap, Check, Loader2, ExternalLink,
  RefreshCw, Search, Trash2, Pencil, X, Power, ChevronLeft, ChevronRight,
  Bell, Activity, AlertTriangle, Send, Cpu,
} from "lucide-react";
import { PageHeader } from "../../components/PageHeader";
import { StatusBadge } from "../../components/SeverityBadge";
import {
  useSmartHomeDevices,
  useSmartHomeDeviceHealth,
  useSmartHomeIntegrations,
  useSmartHomeAutomations,
  useSmartHomeNotifications,
} from "../../hooks/useApiData";
import { smartHomeService, openSmartHomeSocket } from "../../services/smartHomeService";
import type {
  SmartDevice,
  DeviceStateSnapshot,
  DeviceHealthSummary,
  IntegrationsOverview,
  IntegrationProvider,
  AutomationRule,
  AutomationAction,
  TelemetryEvent,
  SmartHomeNotification,
  Paginated,
} from "../../services/smartHomeService";

type Tab = "devices" | "integrations" | "automations" | "telemetry" | "notifications";
type CyleniumFlow = null | "what-syncs" | "connecting" | "done";

const syncFeatures = [
  { label: "Security Alerts", desc: "Real-time threat notifications sent to Cylenium dashboard" },
  { label: "Device Telemetry", desc: "Guardian health, battery, and connectivity data" },
  { label: "Audit Logs", desc: "All events and actions logged to Cylenium Cloud" },
];

const inputClass =
  "h-10 w-full rounded-md border border-border bg-input-background px-3 text-sm outline-none transition focus:border-primary focus:ring-2 focus:ring-primary/15";
const labelClass = "mb-1.5 block text-[11px] font-medium uppercase tracking-wide text-muted-foreground";

const PROVIDER_META: Record<string, { label: string; icon: any; desc: string }> = {
  google_nest: { label: "Google Nest", icon: Home, desc: "Thermostats and cameras" },
  tp_link_kasa: { label: "TP-Link Kasa", icon: Zap, desc: "Smart plugs and switches" },
};

const COMMANDS_BY_DOMAIN: Record<string, { value: string; label: string }[]> = {
  light: [
    { value: "turn_on", label: "Turn On" },
    { value: "turn_off", label: "Turn Off" },
  ],
  switch: [
    { value: "turn_on", label: "Turn On" },
    { value: "turn_off", label: "Turn Off" },
  ],
  input_boolean: [
    { value: "turn_on", label: "Turn On" },
    { value: "turn_off", label: "Turn Off" },
  ],
  lock: [
    { value: "lock", label: "Lock" },
    { value: "unlock", label: "Unlock" },
  ],
  climate: [
    { value: "set_temperature", label: "Set Temperature" },
    { value: "set_hvac_mode", label: "Set HVAC Mode" },
    { value: "turn_on", label: "Turn On" },
    { value: "turn_off", label: "Turn Off" },
  ],
};

function commandsForDomain(domain: string): { value: string; label: string }[] {
  return COMMANDS_BY_DOMAIN[domain] ?? [
    { value: "turn_on", label: "Turn On" },
    { value: "turn_off", label: "Turn Off" },
  ];
}

function domainOf(entityId: string): string {
  return entityId.split(".")[0] || "";
}

function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return "Never";
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString();
}

function healthVariant(status: string): "success" | "warning" | "danger" | "muted" {
  switch (status) {
    case "online": return "success";
    case "error": return "danger";
    case "offline": return "muted";
    default: return "muted";
  }
}

function severityVariant(sev: string): "info" | "warning" | "danger" | "muted" {
  switch (sev) {
    case "critical": return "danger";
    case "warning": return "warning";
    case "info": return "info";
    default: return "muted";
  }
}

function errorMessage(err: unknown): string | undefined {
  return err instanceof Error ? err.message : undefined;
}

// ── Shared style helpers (kept as functions so TS narrows literal unions) ───
function primaryButtonStyle(opts?: { disabled?: boolean; fullWidth?: boolean }): CSSProperties {
  return {
    height: "44px",
    display: "flex", alignItems: "center", justifyContent: "center", gap: "8px",
    width: opts?.fullWidth ? "100%" : undefined,
    backgroundColor: "var(--primary)", color: "var(--primary-foreground)",
    border: "none", borderRadius: "var(--radius)",
    cursor: opts?.disabled ? "default" : "pointer", opacity: opts?.disabled ? 0.6 : 1,
    fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)",
  };
}
function secondaryButtonStyle(opts?: { disabled?: boolean }): CSSProperties {
  return {
    height: "40px", display: "flex", alignItems: "center", justifyContent: "center", gap: "6px",
    backgroundColor: "var(--secondary)", color: "var(--secondary-foreground)",
    border: "1px solid var(--border)", borderRadius: "var(--radius)",
    cursor: opts?.disabled ? "default" : "pointer", opacity: opts?.disabled ? 0.6 : 1,
    fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)",
    padding: "0 14px",
  };
}
function smallButtonStyle(kind: "primary" | "secondary" | "destructive", disabled?: boolean): CSSProperties {
  const palette =
    kind === "primary"
      ? { bg: "var(--primary)", fg: "var(--primary-foreground)", border: "none" }
      : kind === "destructive"
        ? { bg: "color-mix(in srgb, var(--destructive) 12%, transparent)", fg: "var(--destructive)", border: "1px solid color-mix(in srgb, var(--destructive) 30%, transparent)" }
        : { bg: "var(--secondary)", fg: "var(--secondary-foreground)", border: "1px solid var(--border)" };
  return {
    height: "28px", display: "flex", alignItems: "center", justifyContent: "center", gap: "5px",
    padding: "0 10px", backgroundColor: palette.bg, color: palette.fg, border: palette.border,
    borderRadius: "var(--radius-sm)", cursor: disabled ? "default" : "pointer", opacity: disabled ? 0.6 : 1,
    fontFamily: "Inter, sans-serif", fontSize: "10px", fontWeight: "var(--font-weight-medium)",
  };
}
function overlayStyle(): CSSProperties {
  return { position: "fixed", inset: 0, backgroundColor: "rgba(0,0,0,0.5)", zIndex: 50 };
}
function dialogPanelStyle(maxWidth: string): CSSProperties {
  return {
    position: "fixed", top: "50%", left: "50%", transform: "translate(-50%, -50%)",
    width: "calc(100vw - 32px)", maxWidth, maxHeight: "calc(100vh - 64px)", overflowY: "auto",
    backgroundColor: "var(--card)", border: "1px solid var(--border)", borderRadius: "12px",
    padding: "20px", zIndex: 51,
  };
}

// ── Small shared UI pieces ───────────────────────────────────────────────────
function CenteredSpinner() {
  return (
    <div className="flex items-center justify-center py-16">
      <Loader2 size={24} className="animate-spin" style={{ color: "var(--primary)" }} />
    </div>
  );
}

function ErrorBanner({ error, onRetry }: { error: Error; onRetry: () => void }) {
  return (
    <div
      className="rounded-lg border p-3 flex items-center justify-between gap-3"
      style={{ backgroundColor: "color-mix(in srgb, var(--destructive) 8%, transparent)", borderColor: "color-mix(in srgb, var(--destructive) 25%, transparent)" }}
    >
      <div className="flex items-center gap-2 min-w-0">
        <AlertTriangle size={14} style={{ color: "var(--destructive)", flexShrink: 0 }} />
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--destructive)" }}>{error.message}</span>
      </div>
      <button
        onClick={onRetry}
        style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--destructive)", background: "none", border: "none", textDecoration: "underline", cursor: "pointer", flexShrink: 0 }}
      >
        Retry
      </button>
    </div>
  );
}

function EmptyState({ icon: Icon, title, desc }: { icon: any; title: string; desc: string }) {
  return (
    <div className="flex flex-col items-center py-12 gap-3 text-center">
      <Icon size={32} style={{ color: "var(--muted-foreground)" }} />
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{title}</p>
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", maxWidth: "240px", lineHeight: 1.5 }}>{desc}</p>
    </div>
  );
}

function InfoLine({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>{label}</span>
      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)", textAlign: "right" }}>{value}</span>
    </div>
  );
}

function InfoRow({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "2px" }}>{label}</p>
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)", fontWeight: "var(--font-weight-medium)" }}>{value}</p>
    </div>
  );
}

function Pager({ page, totalPages, onChange }: { page: number; totalPages: number; onChange: (p: number) => void }) {
  if (totalPages <= 1) return null;
  const navBtn = (disabled: boolean): CSSProperties => ({
    opacity: disabled ? 0.4 : 1, background: "none", border: "1px solid var(--border)",
    borderRadius: "var(--radius-sm)", width: "28px", height: "28px", cursor: disabled ? "default" : "pointer",
    display: "flex", alignItems: "center", justifyContent: "center", color: "var(--foreground)",
  });
  return (
    <div className="flex items-center justify-center gap-3 mt-1">
      <button onClick={() => onChange(Math.max(1, page - 1))} disabled={page <= 1} style={navBtn(page <= 1)}>
        <ChevronLeft size={14} />
      </button>
      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
        Page {page} of {totalPages}
      </span>
      <button onClick={() => onChange(Math.min(totalPages, page + 1))} disabled={page >= totalPages} style={navBtn(page >= totalPages)}>
        <ChevronRight size={14} />
      </button>
    </div>
  );
}

function LiveIndicator({ connected }: { connected: boolean }) {
  return (
    <div className="flex items-center gap-1.5" title={connected ? "Live WebSocket feed connected" : "Live feed disconnected — reconnecting"}>
      <span
        style={{
          width: "7px", height: "7px", borderRadius: "50%",
          backgroundColor: connected ? "var(--chart-2)" : "var(--muted-foreground)",
          boxShadow: connected ? "0 0 6px var(--chart-2)" : undefined,
        }}
      />
      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>
        {connected ? "Live" : "Offline"}
      </span>
    </div>
  );
}

function HealthStat({ label, value, loading, color }: { label: string; value: string | number | undefined; loading: boolean; color?: string }) {
  return (
    <div className="flex flex-col items-center gap-0.5 flex-1" style={{ minWidth: "54px" }}>
      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-bold)", color: color || "var(--foreground)" }}>
        {loading ? "…" : value ?? "—"}
      </span>
      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "9px", color: "var(--muted-foreground)", letterSpacing: "0.06em", textTransform: "uppercase" }}>
        {label}
      </span>
    </div>
  );
}

function HealthStrip({ health, loading }: { health: DeviceHealthSummary | null; loading: boolean }) {
  return (
    <div className="flex border-b border-border" style={{ backgroundColor: "var(--background)" }}>
      <div className="flex gap-4 px-4 md:px-6 py-2.5 mx-auto w-full max-w-2xl">
        <HealthStat label="Total" value={health?.total_devices} loading={loading} />
        <HealthStat label="Online" value={health?.online_devices} loading={loading} color="var(--chart-2)" />
        <HealthStat label="Offline" value={health?.offline_devices} loading={loading} color="var(--muted-foreground)" />
        <HealthStat label="Error" value={health?.error_devices} loading={loading} color="var(--destructive)" />
        <HealthStat label="Healthy" value={health ? `${health.healthy_percentage.toFixed(0)}%` : undefined} loading={loading} color="var(--primary)" />
      </div>
    </div>
  );
}

// ── Devices tab ───────────────────────────────────────────────────────────────
function DeviceDetailDialog({ device, onClose, onChanged }: { device: SmartDevice; onClose: () => void; onChanged: () => void }) {
  const [state, setState] = useState<DeviceStateSnapshot | null>(null);
  const [loadingState, setLoadingState] = useState(true);
  const domain = domainOf(device.ha_entity_id);
  const commands = commandsForDomain(domain);
  const [command, setCommand] = useState(commands[0]?.value ?? "turn_on");
  const [brightness, setBrightness] = useState("");
  const [colorTemp, setColorTemp] = useState("");
  const [rgb, setRgb] = useState("");
  const [temperature, setTemperature] = useState("");
  const [hvacMode, setHvacMode] = useState("");
  const [sending, setSending] = useState(false);

  useEffect(() => {
    let active = true;
    setLoadingState(true);
    smartHomeService
      .getDeviceState(device.id)
      .then((s) => { if (active) setState(s); })
      .catch(() => { /* fall back to the list record — non-fatal */ })
      .finally(() => { if (active) setLoadingState(false); });
    return () => { active = false; };
  }, [device.id]);

  const handleSend = async () => {
    setSending(true);
    try {
      const params: Record<string, unknown> = {};
      if (domain === "light" && command === "turn_on") {
        if (brightness.trim()) params.brightness = Number(brightness);
        if (rgb.trim()) {
          const parts = rgb.split(",").map((s) => Number(s.trim())).filter((n) => !Number.isNaN(n));
          if (parts.length === 3) params.rgb_color = parts;
        } else if (colorTemp.trim()) {
          params.color_temp_kelvin = Number(colorTemp);
        }
      }
      if (domain === "climate" && command === "set_temperature" && temperature.trim()) {
        params.temperature = Number(temperature);
      }
      if (domain === "climate" && command === "set_hvac_mode" && hvacMode.trim()) {
        params.hvac_mode = hvacMode.trim();
      }
      const res = await smartHomeService.sendDeviceCommand(device.id, {
        command, domain, params: Object.keys(params).length ? params : undefined,
      });
      toast.success(res.message || "Command dispatched", { description: `command_id: ${res.command_id}` });
      const fresh = await smartHomeService.getDeviceState(device.id).catch(() => null);
      if (fresh) setState(fresh);
      onChanged();
    } catch (err) {
      toast.error("Command failed", { description: errorMessage(err) });
    } finally {
      setSending(false);
    }
  };

  return (
    <Dialog.Root open onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay style={overlayStyle()} />
        <Dialog.Content style={dialogPanelStyle("520px")}>
          <div className="flex items-start justify-between gap-3 mb-4">
            <div className="min-w-0">
              <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                {device.friendly_name || device.ha_entity_id}
              </Dialog.Title>
              <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--muted-foreground)", marginTop: "2px" }}>{device.ha_entity_id}</p>
            </div>
            <button
              onClick={onClose}
              className="flex items-center justify-center rounded-md flex-shrink-0"
              style={{ width: "28px", height: "28px", backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)", cursor: "pointer" }}
            >
              <X size={13} />
            </button>
          </div>

          <div className="grid grid-cols-2 gap-x-4 gap-y-3 mb-4">
            <InfoRow label="Vendor" value={device.vendor || "—"} />
            <InfoRow label="Type" value={device.device_type || "—"} />
            <InfoRow label="Room" value={device.room || "—"} />
            <InfoRow label="Current state" value={loadingState ? "…" : state?.current_state ?? device.current_state} />
            <InfoRow label="Health" value={loadingState ? "…" : state?.health_status ?? device.health_status} />
            <InfoRow label="Last seen" value={formatTimestamp(state?.last_seen ?? device.last_seen)} />
          </div>

          <div className="border-t border-border pt-4">
            <p className={labelClass}>Send command</p>
            <select className={inputClass} value={command} onChange={(e) => setCommand(e.target.value)}>
              {commands.map((c) => (
                <option key={c.value} value={c.value}>{c.label}</option>
              ))}
            </select>

            {domain === "light" && command === "turn_on" && (
              <div className="grid grid-cols-3 gap-2 mt-2">
                <div>
                  <label className={labelClass}>Brightness</label>
                  <input className={inputClass} value={brightness} onChange={(e) => setBrightness(e.target.value)} placeholder="0-255" />
                </div>
                <div>
                  <label className={labelClass}>Color temp (K)</label>
                  <input
                    className={inputClass}
                    value={colorTemp}
                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => setColorTemp(e.target.value)}
                    disabled={Boolean(rgb.trim())}
                    placeholder="2700-6500"
                  />
                </div>
                <div>
                  <label className={labelClass}>RGB</label>
                  <input
                    className={inputClass}
                    value={rgb}
                    onChange={(e: React.ChangeEvent<HTMLInputElement>) => setRgb(e.target.value)}
                    disabled={Boolean(colorTemp.trim())}
                    placeholder="255,255,255"
                  />
                </div>
              </div>
            )}
            {domain === "climate" && command === "set_temperature" && (
              <div className="mt-2">
                <label className={labelClass}>Temperature (°C)</label>
                <input className={inputClass} value={temperature} onChange={(e) => setTemperature(e.target.value)} placeholder="22.5" />
              </div>
            )}
            {domain === "climate" && command === "set_hvac_mode" && (
              <div className="mt-2">
                <label className={labelClass}>HVAC mode</label>
                <input className={inputClass} value={hvacMode} onChange={(e) => setHvacMode(e.target.value)} placeholder="heat / cool / off" />
              </div>
            )}

            <button onClick={handleSend} disabled={sending} className="mt-3" style={primaryButtonStyle({ disabled: sending, fullWidth: true })}>
              {sending ? <Loader2 size={15} className="animate-spin" /> : <Send size={15} />} Send Command
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function DevicesTab({
  data, loading, error, onRefetch,
}: { data: Paginated<SmartDevice> | null; loading: boolean; error: Error | null; onRefetch: () => void }) {
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("all");
  const [roomFilter, setRoomFilter] = useState("all");
  const [page, setPage] = useState(1);
  const [syncing, setSyncing] = useState(false);
  const [selected, setSelected] = useState<SmartDevice | null>(null);
  const pageSize = 10;

  const items = data?.items ?? [];
  const types = useMemo(() => Array.from(new Set(items.map((d) => d.device_type))).sort(), [items]);
  const rooms = useMemo(() => Array.from(new Set(items.map((d) => d.room).filter((r): r is string => !!r))).sort(), [items]);

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items.filter((d) => {
      if (typeFilter !== "all" && d.device_type !== typeFilter) return false;
      if (roomFilter !== "all" && d.room !== roomFilter) return false;
      if (q && !d.friendly_name.toLowerCase().includes(q) && !d.ha_entity_id.toLowerCase().includes(q)) return false;
      return true;
    });
  }, [items, typeFilter, roomFilter, search]);

  useEffect(() => setPage(1), [search, typeFilter, roomFilter]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const paged = filtered.slice((page - 1) * pageSize, page * pageSize);

  const handleSync = async () => {
    setSyncing(true);
    try {
      const res = await smartHomeService.syncDevices();
      toast.success(res.message || "Devices synced", { description: `${res.total_devices} device(s) reconciled` });
      onRefetch();
    } catch (err) {
      toast.error("Sync failed", { description: errorMessage(err) });
    } finally {
      setSyncing(false);
    }
  };

  if (loading) return <CenteredSpinner />;

  return (
    <div className="flex flex-col gap-4">
      {error && <ErrorBanner error={error} onRetry={onRefetch} />}

      <div className="flex gap-2 flex-wrap">
        <button onClick={handleSync} disabled={syncing} style={secondaryButtonStyle({ disabled: syncing })}>
          {syncing ? <Loader2 size={15} className="animate-spin" /> : <RefreshCw size={15} />} Sync Devices
        </button>
        <div className="relative flex-1" style={{ minWidth: "160px" }}>
          <Search size={14} style={{ position: "absolute", left: "12px", top: "50%", transform: "translateY(-50%)", color: "var(--muted-foreground)" }} />
          <input className={`${inputClass} pl-9`} placeholder="Search devices" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
      </div>

      <div className="flex gap-2">
        <select className={inputClass} value={typeFilter} onChange={(e) => setTypeFilter(e.target.value)}>
          <option value="all">All types</option>
          {types.map((t) => <option key={t} value={t}>{t}</option>)}
        </select>
        <select className={inputClass} value={roomFilter} onChange={(e) => setRoomFilter(e.target.value)}>
          <option value="all">All rooms</option>
          {rooms.map((r) => <option key={r} value={r}>{r}</option>)}
        </select>
      </div>

      {paged.length === 0 ? (
        <EmptyState icon={Cpu} title="No devices found" desc="Sync with Home Assistant or adjust your filters." />
      ) : (
        <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
          {paged.map((d, i) => (
            <button
              key={d.id}
              onClick={() => setSelected(d)}
              className="w-full text-left flex items-center gap-3 px-4 py-3.5"
              style={{ borderBottom: i < paged.length - 1 ? "1px solid var(--border)" : undefined, background: "none", border: "none", cursor: "pointer" }}
            >
              <div className="flex-1 min-w-0">
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
                  {d.friendly_name || d.ha_entity_id}
                </p>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                  {d.ha_entity_id} · {d.vendor}{d.room ? ` · ${d.room}` : ""}
                </p>
              </div>
              <StatusBadge status={d.current_state} variant={d.current_state === "on" ? "success" : "muted"} />
              <StatusBadge status={d.health_status} variant={healthVariant(d.health_status)} />
            </button>
          ))}
        </div>
      )}
      <Pager page={page} totalPages={totalPages} onChange={setPage} />
      {selected && <DeviceDetailDialog device={selected} onClose={() => setSelected(null)} onChanged={onRefetch} />}
    </div>
  );
}

// ── Integrations tab ─────────────────────────────────────────────────────────
function ConnectIntegrationDialog({
  provider, onClose, onConnected,
}: { provider: string; onClose: () => void; onConnected: () => void }) {
  const meta = PROVIDER_META[provider] ?? { label: provider, icon: Cloud, desc: "" };
  const isKasa = provider === "tp_link_kasa";
  const isNest = provider === "google_nest";
  const [mode, setMode] = useState<"cloud" | "local">("cloud");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [refreshToken, setRefreshToken] = useState("");
  const [expiresIn, setExpiresIn] = useState("3600");
  const [submitting, setSubmitting] = useState(false);
  const [nestAuthUrl, setNestAuthUrl] = useState<string | null>(null);
  const [nestConfigured, setNestConfigured] = useState(false);
  const [showManualNest, setShowManualNest] = useState(false);

  useEffect(() => {
    if (isNest) {
      smartHomeService
        .getNestAuthUrl()
        .then((res) => {
          setNestAuthUrl(res.auth_url);
          setNestConfigured(res.configured);
        })
        .catch(() => { /* non-fatal fallback */ });
    }
  }, [isNest]);

  const handleNestRedirect = () => {
    if (nestAuthUrl) {
      window.open(nestAuthUrl, "_blank", "width=600,height=700");
      toast.info("Google OAuth consent window opened. Complete authorization to connect.");
    } else {
      toast.error("Google OAuth URL not available");
    }
  };

  const fillMockCredentials = () => {
    const suffix = Math.random().toString(36).slice(2, 10);
    setAccessToken(`${provider}_access_token_demo_${suffix}`);
    setRefreshToken(`${provider}_refresh_token_demo_${suffix}`);
    setExpiresIn("3600");
  };

  const handleSubmit = async () => {
    if (isKasa && mode === "cloud" && (!username.trim() || !password.trim())) {
      toast.error("Username and password are required for cloud mode");
      return;
    }
    if (!isKasa && (!accessToken.trim() || !refreshToken.trim())) {
      toast.error("Access token and refresh token are required");
      return;
    }
    setSubmitting(true);
    try {
      const res = isKasa
        ? await smartHomeService.connectIntegration(
            provider,
            mode === "cloud" ? { mode, username: username.trim(), password } : { mode },
          )
        : await smartHomeService.connectIntegration(provider, {
            access_token: accessToken.trim(),
            refresh_token: refreshToken.trim(),
            expires_in_secs: Number(expiresIn) || 3600,
          });
      toast.success(res.message || "Integration connected", {
        description: res.devices_discovered != null ? `${res.devices_discovered} device(s) discovered` : undefined,
      });
      onConnected();
    } catch (err) {
      toast.error("Connect failed", { description: errorMessage(err) });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog.Root open onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay style={overlayStyle()} />
        <Dialog.Content style={dialogPanelStyle("440px")}>
          <div className="flex items-start justify-between mb-4">
            <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              Connect {meta.label}
            </Dialog.Title>
            <button
              onClick={onClose}
              className="flex items-center justify-center rounded-md flex-shrink-0"
              style={{ width: "28px", height: "28px", backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)", cursor: "pointer" }}
            >
              <X size={13} />
            </button>
          </div>

          {isNest && !showManualNest ? (
            <div className="flex flex-col gap-4 my-2">
              <div className="p-3.5 rounded-lg border border-border bg-muted/20 text-xs flex flex-col gap-2">
                <div className="flex items-center gap-2">
                  <Cloud size={16} className="text-blue-400" />
                  <p style={{ color: "var(--foreground)", fontWeight: 600 }}>
                    1-Click Google OAuth Authorization
                  </p>
                </div>
                <p style={{ color: "var(--muted-foreground)", lineHeight: "1.4" }}>
                  Authorize SGX Guardian to connect with your Google Device Access project. Click below to grant Nest device access on Google's consent screen.
                </p>
              </div>

              <button
                type="button"
                onClick={handleNestRedirect}
                className="w-full py-2.5 px-4 text-xs font-semibold rounded-lg text-white bg-blue-600 hover:bg-blue-500 transition-colors flex items-center justify-center gap-2 shadow-sm"
              >
                <ExternalLink size={15} /> Connect with Google Nest
              </button>

              <div className="text-center pt-2">
                <button
                  type="button"
                  onClick={() => setShowManualNest(true)}
                  className="text-[11px] text-muted-foreground hover:text-foreground underline transition-colors"
                >
                  Advanced: Manual Token Entry (Demo / Mock)
                </button>
              </div>
            </div>
          ) : isKasa ? (
            <div className="flex flex-col gap-3">
              <div>
                <label className={labelClass}>Mode</label>
                <select className={inputClass} value={mode} onChange={(e) => setMode(e.target.value as "cloud" | "local")}>
                  <option value="cloud">Cloud (TP-Link account)</option>
                  <option value="local">Local (LAN discovery only)</option>
                </select>
              </div>
              {mode === "cloud" && (
                <>
                  <div>
                    <label className={labelClass}>Username</label>
                    <input className={inputClass} value={username} onChange={(e) => setUsername(e.target.value)} placeholder="user@kasa.com" />
                  </div>
                  <div>
                    <label className={labelClass}>Password</label>
                    <input type="password" className={inputClass} value={password} onChange={(e) => setPassword(e.target.value)} />
                  </div>
                </>
              )}
            </div>
          ) : (
            <div className="flex flex-col gap-3">
              <div className="flex items-center justify-between">
                <span className={labelClass} style={{ marginBottom: 0 }}>OAuth credentials</span>
                <button
                  type="button"
                  onClick={fillMockCredentials}
                  style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", fontWeight: "var(--font-weight-medium)", color: "var(--primary)", background: "none", border: "none", cursor: "pointer", textDecoration: "underline" }}
                >
                  Fill demo credentials
                </button>
              </div>
              <div>
                <label className={labelClass}>Access token</label>
                <input className={inputClass} value={accessToken} onChange={(e) => setAccessToken(e.target.value)} placeholder="access_token" />
              </div>
              <div>
                <label className={labelClass}>Refresh token</label>
                <input className={inputClass} value={refreshToken} onChange={(e) => setRefreshToken(e.target.value)} placeholder="refresh_token" />
              </div>
              <div>
                <label className={labelClass}>Expires in (seconds)</label>
                <input type="number" className={inputClass} value={expiresIn} onChange={(e) => setExpiresIn(e.target.value)} />
              </div>
            </div>
          )}

          {(!isNest || showManualNest) && (
            <button onClick={handleSubmit} disabled={submitting} className="mt-4" style={primaryButtonStyle({ disabled: submitting, fullWidth: true })}>
              {submitting ? <Loader2 size={15} className="animate-spin" /> : <Check size={15} />} Connect
            </button>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function IntegrationsTab({
  data, loading, error, onRefetch, cyleniumConnected, onConnectCylenium,
}: {
  data: IntegrationsOverview | null; loading: boolean; error: Error | null; onRefetch: () => void;
  cyleniumConnected: boolean; onConnectCylenium: () => void;
}) {
  const [connectTarget, setConnectTarget] = useState<string | null>(null);
  const [disconnecting, setDisconnecting] = useState<string | null>(null);

  const handleDisconnect = async (provider: string) => {
    const label = PROVIDER_META[provider]?.label ?? provider;
    if (!window.confirm(`Disconnect ${label}? Stored credentials will be wiped from disk.`)) return;
    setDisconnecting(provider);
    try {
      const res = await smartHomeService.disconnectIntegration(provider);
      toast.success(res.message || "Disconnected");
      onRefetch();
    } catch (err) {
      toast.error("Disconnect failed", { description: errorMessage(err) });
    } finally {
      setDisconnecting(null);
    }
  };

  if (loading) return <CenteredSpinner />;

  const providers = data?.providers ?? {};

  return (
    <div className="flex flex-col gap-4">
      {error && <ErrorBanner error={error} onRetry={onRefetch} />}

      {/* Cylenium Cloud — unrelated to the HA bridge; kept as-is (existing OAuth flow) */}
      <div
        className="rounded-lg p-4 flex flex-col gap-3"
        style={{ backgroundColor: "color-mix(in srgb, var(--primary) 5%, var(--card))", border: "1.5px solid var(--primary)" }}
      >
        <div className="flex items-center justify-between">
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "9px", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", letterSpacing: "0.14em" }}>
            CERVAIS
          </span>
          {cyleniumConnected && <StatusBadge status="Connected" variant="success" />}
        </div>
        <div className="flex items-center gap-3">
          <div
            className="rounded-lg flex items-center justify-center flex-shrink-0"
            style={{ width: "44px", height: "44px", backgroundColor: "color-mix(in srgb, var(--primary) 15%, transparent)", border: "1px solid color-mix(in srgb, var(--primary) 25%, transparent)" }}
          >
            <Cloud size={22} style={{ color: "var(--primary)" }} />
          </div>
          <div>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "2px" }}>
              Cylenium Cloud
            </p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              Unified security visibility for your Guardian network
            </p>
          </div>
        </div>
        {cyleniumConnected ? (
          <>
            <div className="rounded-md p-3 flex flex-col gap-2" style={{ backgroundColor: "color-mix(in srgb, var(--chart-2) 8%, transparent)", border: "1px solid color-mix(in srgb, var(--chart-2) 20%, transparent)" }}>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginBottom: "4px" }}>Last sync: Just now</p>
              {syncFeatures.map(({ label }) => (
                <div key={label} className="flex items-center gap-2">
                  <Check size={12} style={{ color: "var(--chart-2)", flexShrink: 0 }} />
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>{label}</span>
                </div>
              ))}
            </div>
            <a href="#" className="flex items-center gap-1.5" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--primary)", textDecoration: "none" }}>
              <ExternalLink size={12} /> View in Cylenium Dashboard
            </a>
          </>
        ) : (
          <button onClick={onConnectCylenium} style={{ ...primaryButtonStyle({ fullWidth: true }), height: "44px", boxShadow: "0 0 20px color-mix(in srgb, var(--primary) 20%, transparent)" }}>
            <Cloud size={15} /> Connect Cylenium
          </button>
        )}
      </div>

      <div className="flex items-center gap-3">
        <div style={{ flex: 1, height: "1px", backgroundColor: "var(--border)" }} />
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", flexShrink: 0 }}>
          Home Assistant vendor integrations
        </span>
        <div style={{ flex: 1, height: "1px", backgroundColor: "var(--border)" }} />
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {Object.entries(PROVIDER_META).map(([key, meta]) => {
          const status = providers[key];
          const Icon = meta.icon;
          const connected = status?.status === "connected";
          return (
            <div key={key} className="rounded-lg border border-border p-4 flex flex-col gap-2" style={{ backgroundColor: "var(--card)" }}>
              <div className="flex items-center justify-between">
                <div className="rounded-lg flex items-center justify-center" style={{ width: "36px", height: "36px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)" }}>
                  <Icon size={18} style={{ color: "var(--primary)" }} />
                </div>
                <StatusBadge status={status?.status ?? "disconnected"} variant={connected ? "success" : "muted"} />
              </div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                {status?.name ?? meta.label}
              </p>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", lineHeight: 1.4 }}>{meta.desc}</p>
              <div className="flex flex-col gap-1 mt-1">
                <InfoLine label="Credentials" value={status?.has_credentials ? "Stored" : "None"} />
                <InfoLine label="Devices" value={String(status?.device_count ?? 0)} />
                <InfoLine label="Last synced" value={formatTimestamp(status?.last_synced ?? null)} />
                {status?.mode && <InfoLine label="Mode" value={status.mode} />}
              </div>
              {status?.error_message && (
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--destructive)" }}>{status.error_message}</p>
              )}
              {connected ? (
                <button onClick={() => handleDisconnect(key)} disabled={disconnecting === key} className="mt-1" style={smallButtonStyle("destructive", disconnecting === key)}>
                  {disconnecting === key ? <Loader2 size={12} className="animate-spin" /> : <Power size={12} />} Disconnect
                </button>
              ) : (
                <button onClick={() => setConnectTarget(key)} className="mt-1" style={smallButtonStyle("primary")}>
                  Connect
                </button>
              )}
            </div>
          );
        })}
      </div>

      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>
        Ring Security, Wyze, and Arlo are not yet supported by SGX Guardian's Home Assistant bridge.
      </p>

      {connectTarget && (
        <ConnectIntegrationDialog
          provider={connectTarget}
          onClose={() => setConnectTarget(null)}
          onConnected={() => { setConnectTarget(null); onRefetch(); }}
        />
      )}
    </div>
  );
}

// ── Automations tab ──────────────────────────────────────────────────────────
type OnFailurePolicy = "continue" | "abort" | "log" | "retry";
const ON_FAILURE_OPTIONS: OnFailurePolicy[] = ["continue", "abort", "log", "retry"];

interface ActionDraft {
  entity_id: string;
  command: string;
  serviceDataText: string;
  on_failure: OnFailurePolicy;
}

function slugifyRuleId(name: string): string {
  const slug = name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "").slice(0, 40);
  return slug ? `rule_${slug}` : "";
}

function RuleDialog({
  rule, devices, onClose, onSaved,
}: { rule: AutomationRule | null; devices: SmartDevice[]; onClose: () => void; onSaved: () => void }) {
  const isEdit = !!rule;
  const [id, setId] = useState(rule?.id ?? "");
  const [name, setName] = useState(rule?.name ?? "");
  const [priority, setPriority] = useState(String(rule?.priority ?? 100));
  const [enabled, setEnabled] = useState(rule?.enabled ?? true);
  const [triggerEntity, setTriggerEntity] = useState(rule?.trigger.entity_id ?? "");
  const [triggerToState, setTriggerToState] = useState(rule?.trigger.to_state ?? "");
  const [actions, setActions] = useState<ActionDraft[]>(
    rule?.actions?.length
      ? rule.actions.map((a) => ({
          entity_id: a.entity_id,
          command: a.command,
          serviceDataText: a.service_data ? JSON.stringify(a.service_data) : "",
          on_failure: ON_FAILURE_OPTIONS.includes(a.on_failure as OnFailurePolicy) ? (a.on_failure as OnFailurePolicy) : "continue",
        }))
      : [{ entity_id: "", command: "turn_on", serviceDataText: "", on_failure: "continue" }],
  );
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (!isEdit) setId(slugifyRuleId(name));
  }, [name, isEdit]);

  const updateAction = (idx: number, patch: Partial<ActionDraft>) => {
    setActions((prev) => prev.map((a, i) => (i === idx ? { ...a, ...patch } : a)));
  };
  const addAction = () => setActions((prev) => [...prev, { entity_id: "", command: "turn_on", serviceDataText: "", on_failure: "continue" }]);
  const removeAction = (idx: number) => setActions((prev) => prev.filter((_, i) => i !== idx));

  const handleSave = async () => {
    if (!id.trim() || !name.trim() || !triggerEntity.trim() || actions.some((a) => !a.entity_id.trim() || !a.command.trim())) {
      toast.error("Fill in the rule name, ID, trigger entity, and every action's entity + command");
      return;
    }
    const builtActions: AutomationAction[] = [];
    for (let i = 0; i < actions.length; i++) {
      const a = actions[i];
      let serviceData: Record<string, unknown> | null = null;
      if (a.serviceDataText.trim()) {
        try {
          serviceData = JSON.parse(a.serviceDataText);
        } catch {
          toast.error(`Action ${i + 1}: params must be valid JSON`, { description: 'e.g. {"brightness":190}' });
          return;
        }
      }
      builtActions.push({
        type: "command",
        entity_id: a.entity_id.trim(),
        domain: domainOf(a.entity_id.trim()),
        command: a.command.trim(),
        service_data: serviceData,
        on_failure: a.on_failure,
      });
    }

    setSaving(true);
    try {
      const payload: AutomationRule = {
        id: id.trim(),
        name: name.trim(),
        priority: Number(priority) || 0,
        enabled,
        trigger: { type: "state_changed", entity_id: triggerEntity.trim(), to_state: triggerToState.trim() || null },
        conditions: [],
        actions: builtActions,
      };
      const res = isEdit
        ? await smartHomeService.updateAutomation(id.trim(), payload)
        : await smartHomeService.createAutomation(payload);
      toast.success(res.message || (isEdit ? "Rule updated" : "Rule created"));
      onSaved();
    } catch (err) {
      toast.error(isEdit ? "Update failed" : "Create failed", { description: errorMessage(err) });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog.Root open onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay style={overlayStyle()} />
        <Dialog.Content style={dialogPanelStyle("580px")}>
          <div className="flex items-start justify-between mb-4">
            <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              {isEdit ? "Edit Automation Rule" : "New Automation Rule"}
            </Dialog.Title>
            <button
              onClick={onClose}
              className="flex items-center justify-center rounded-md flex-shrink-0"
              style={{ width: "28px", height: "28px", backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)", cursor: "pointer" }}
            >
              <X size={13} />
            </button>
          </div>

          <div className="flex flex-col gap-3">
            <div>
              <label className={labelClass}>Name</label>
              <input className={inputClass} value={name} onChange={(e) => setName(e.target.value)} placeholder="Motion Bed Light" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className={labelClass}>Rule ID</label>
                <input className={inputClass} value={id} onChange={(e) => setId(e.target.value)} disabled={isEdit} placeholder="rule_motion_bed_light" />
              </div>
              <div>
                <label className={labelClass}>Priority</label>
                <input type="number" className={inputClass} value={priority} onChange={(e) => setPriority(e.target.value)} />
              </div>
            </div>
            <label className="flex items-center gap-2">
              <input type="checkbox" checked={enabled} onChange={(e) => setEnabled(e.target.checked)} />
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>Enabled</span>
            </label>

            <div className="border-t border-border pt-3">
              <p className={labelClass}>Trigger — when this entity's state changes</p>
              <div className="grid grid-cols-2 gap-3">
                <input className={inputClass} list="sh-entity-ids" value={triggerEntity} onChange={(e) => setTriggerEntity(e.target.value)} placeholder="binary_sensor.motion" />
                <input className={inputClass} value={triggerToState ?? ""} onChange={(e) => setTriggerToState(e.target.value)} placeholder="to state (blank = any)" />
              </div>
            </div>

            <div className="border-t border-border pt-3">
              <div className="flex items-center justify-between mb-2">
                <p className={labelClass} style={{ marginBottom: 0 }}>Actions — dispatched when the trigger fires</p>
                <button
                  type="button"
                  onClick={addAction}
                  style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", fontWeight: "var(--font-weight-medium)", color: "var(--primary)", background: "none", border: "none", cursor: "pointer" }}
                >
                  + Add action
                </button>
              </div>
              <div className="flex flex-col gap-3">
                {actions.map((a, idx) => (
                  <div key={idx} className="rounded-md border border-border p-3">
                    <div className="grid grid-cols-2 gap-2">
                      <input className={inputClass} list="sh-entity-ids" value={a.entity_id} onChange={(e) => updateAction(idx, { entity_id: e.target.value })} placeholder="light.bed_light" />
                      <input className={inputClass} value={a.command} onChange={(e) => updateAction(idx, { command: e.target.value })} placeholder="turn_on" />
                    </div>
                    <input
                      className={`${inputClass} mt-2`}
                      value={a.serviceDataText}
                      onChange={(e) => updateAction(idx, { serviceDataText: e.target.value })}
                      placeholder='optional params JSON, e.g. {"brightness":190}'
                    />
                    <div className="mt-2">
                      <label className={labelClass}>On failure</label>
                      <select className={inputClass} value={a.on_failure} onChange={(e) => updateAction(idx, { on_failure: e.target.value as OnFailurePolicy })}>
                        {ON_FAILURE_OPTIONS.map((opt) => <option key={opt} value={opt}>{opt}</option>)}
                      </select>
                    </div>
                    {actions.length > 1 && (
                      <button
                        type="button"
                        onClick={() => removeAction(idx)}
                        className="mt-2"
                        style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--destructive)", background: "none", border: "none", cursor: "pointer" }}
                      >
                        Remove action
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </div>

            <datalist id="sh-entity-ids">
              {devices.map((d) => <option key={d.id} value={d.ha_entity_id} />)}
            </datalist>
          </div>

          <button onClick={handleSave} disabled={saving} className="mt-4" style={primaryButtonStyle({ disabled: saving, fullWidth: true })}>
            {saving ? <Loader2 size={15} className="animate-spin" /> : <Check size={15} />} {isEdit ? "Save Changes" : "Create Rule"}
          </button>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function AutomationsTab({
  data, devices, loading, error, onRefetch,
}: {
  data: Paginated<AutomationRule> | null; devices: Paginated<SmartDevice> | null;
  loading: boolean; error: Error | null; onRefetch: () => void;
}) {
  const [search, setSearch] = useState("");
  const [page, setPage] = useState(1);
  const [editing, setEditing] = useState<AutomationRule | null>(null);
  const [creating, setCreating] = useState(false);
  const [togglingId, setTogglingId] = useState<string | null>(null);
  const [deletingId, setDeletingId] = useState<string | null>(null);
  const pageSize = 10;

  const items = data?.items ?? [];
  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return !q ? items : items.filter((r) => r.name.toLowerCase().includes(q) || r.id.toLowerCase().includes(q));
  }, [items, search]);
  useEffect(() => setPage(1), [search]);
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const paged = filtered.slice((page - 1) * pageSize, page * pageSize);

  const handleToggle = async (rule: AutomationRule) => {
    setTogglingId(rule.id);
    try {
      const res = rule.enabled ? await smartHomeService.disableAutomation(rule.id) : await smartHomeService.enableAutomation(rule.id);
      toast.success(res.message);
      onRefetch();
    } catch (err) {
      toast.error("Update failed", { description: errorMessage(err) });
    } finally {
      setTogglingId(null);
    }
  };

  const handleDelete = async (rule: AutomationRule) => {
    if (!window.confirm(`Delete automation "${rule.name}"? This cannot be undone.`)) return;
    setDeletingId(rule.id);
    try {
      const res = await smartHomeService.deleteAutomation(rule.id);
      toast.success(res.message);
      onRefetch();
    } catch (err) {
      toast.error("Delete failed", { description: errorMessage(err) });
    } finally {
      setDeletingId(null);
    }
  };

  if (loading) return <CenteredSpinner />;

  return (
    <div className="flex flex-col gap-4">
      {error && <ErrorBanner error={error} onRetry={onRefetch} />}

      <div className="rounded-lg border p-4" style={{ backgroundColor: "color-mix(in srgb, var(--primary) 5%, var(--card))", borderColor: "color-mix(in srgb, var(--primary) 20%, transparent)" }}>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", marginBottom: "4px" }}>Device Automation</p>
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>
          Rules fire instantly when a Home Assistant entity's state changes and dispatch one or more device commands.
        </p>
      </div>

      <div className="flex gap-2">
        <div className="relative flex-1">
          <Search size={14} style={{ position: "absolute", left: "12px", top: "50%", transform: "translateY(-50%)", color: "var(--muted-foreground)" }} />
          <input className={`${inputClass} pl-9`} placeholder="Search rules" value={search} onChange={(e) => setSearch(e.target.value)} />
        </div>
        <button onClick={() => setCreating(true)} style={secondaryButtonStyle()}>
          <Plus size={15} /> New Rule
        </button>
      </div>

      {paged.length === 0 ? (
        <EmptyState icon={Shield} title="No automation rules" desc="Create a rule to react to device state changes." />
      ) : (
        <div className="flex flex-col gap-3">
          {paged.map((rule) => (
            <div key={rule.id} className="rounded-lg border border-border p-4" style={{ backgroundColor: "var(--card)" }}>
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>{rule.name}</p>
                  <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--muted-foreground)" }}>id: {rule.id} · priority {rule.priority}</p>
                </div>
                <Switch.Root
                  checked={rule.enabled}
                  disabled={togglingId === rule.id}
                  onCheckedChange={() => handleToggle(rule)}
                  style={{ width: "40px", height: "22px", borderRadius: "11px", backgroundColor: rule.enabled ? "var(--primary)" : "var(--muted)", border: "none", cursor: togglingId === rule.id ? "wait" : "pointer", position: "relative", flexShrink: 0 }}
                >
                  <Switch.Thumb style={{ display: "block", width: "16px", height: "16px", borderRadius: "50%", backgroundColor: "white", transform: rule.enabled ? "translateX(20px)" : "translateX(3px)", transition: "transform 0.2s" }} />
                </Switch.Root>
              </div>
              <div className="mt-2 flex flex-col gap-1">
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>
                  <span style={{ color: "var(--muted-foreground)" }}>When </span>
                  <code style={{ fontFamily: "JetBrains Mono, monospace" }}>{rule.trigger.entity_id}</code>
                  <span style={{ color: "var(--muted-foreground)" }}> → </span>
                  {rule.trigger.to_state ? <code style={{ fontFamily: "JetBrains Mono, monospace" }}>{rule.trigger.to_state}</code> : <span style={{ color: "var(--muted-foreground)" }}>any state</span>}
                </p>
                {rule.actions.map((a, i) => (
                  <p key={i} style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>
                    → {a.command} <code style={{ fontFamily: "JetBrains Mono, monospace" }}>{a.entity_id}</code>
                    {a.service_data ? ` (${JSON.stringify(a.service_data)})` : ""}
                  </p>
                ))}
              </div>
              <div className="flex items-center gap-2 mt-3">
                <button onClick={() => setEditing(rule)} style={smallButtonStyle("secondary")}>
                  <Pencil size={12} /> Edit
                </button>
                <button onClick={() => handleDelete(rule)} disabled={deletingId === rule.id} style={smallButtonStyle("destructive", deletingId === rule.id)}>
                  {deletingId === rule.id ? <Loader2 size={12} className="animate-spin" /> : <Trash2 size={12} />} Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
      <Pager page={page} totalPages={totalPages} onChange={setPage} />

      {(creating || editing) && (
        <RuleDialog
          rule={editing}
          devices={devices?.items ?? []}
          onClose={() => { setCreating(false); setEditing(null); }}
          onSaved={() => { setCreating(false); setEditing(null); onRefetch(); }}
        />
      )}
    </div>
  );
}

// ── Telemetry tab ─────────────────────────────────────────────────────────────
function TelemetryTab({ devices, bump }: { devices: Paginated<SmartDevice> | null; bump: number }) {
  const [deviceId, setDeviceId] = useState("");
  const [from, setFrom] = useState("");
  const [to, setTo] = useState("");
  const [page, setPage] = useState(1);
  const [data, setData] = useState<Paginated<TelemetryEvent> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const perPage = 20;

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    smartHomeService
      .getTelemetry({
        page,
        per_page: perPage,
        device_id: deviceId || undefined,
        from: from ? new Date(from).toISOString() : undefined,
        to: to ? new Date(to).toISOString() : undefined,
      })
      .then(setData)
      .catch((err) => setError(errorMessage(err) ?? "Failed to load telemetry"))
      .finally(() => setLoading(false));
  }, [page, deviceId, from, to]);

  useEffect(() => { load(); }, [load]);
  // eslint-disable-next-line react-hooks/exhaustive-deps -- live telemetry_stream events bump this to trigger a refresh
  useEffect(() => { if (bump) load(); }, [bump]);
  useEffect(() => setPage(1), [deviceId, from, to]);

  return (
    <div className="flex flex-col gap-4">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
        <select className={inputClass} value={deviceId} onChange={(e) => setDeviceId(e.target.value)}>
          <option value="">All devices</option>
          {(devices?.items ?? []).map((d) => (
            <option key={d.id} value={d.ha_entity_id}>{d.friendly_name || d.ha_entity_id}</option>
          ))}
        </select>
        <input type="datetime-local" className={inputClass} value={from} onChange={(e) => setFrom(e.target.value)} />
        <input type="datetime-local" className={inputClass} value={to} onChange={(e) => setTo(e.target.value)} />
      </div>
      <button onClick={load} disabled={loading} style={secondaryButtonStyle({ disabled: loading })}>
        <RefreshCw size={14} className={loading ? "animate-spin" : ""} /> Refresh
      </button>

      {error && <ErrorBanner error={new Error(error)} onRetry={load} />}

      {loading && !data ? (
        <CenteredSpinner />
      ) : (data?.items.length ?? 0) === 0 ? (
        <EmptyState icon={Activity} title="No telemetry recorded" desc="Trigger a device state change to generate events." />
      ) : (
        <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
          {(data?.items ?? []).map((ev, i, arr) => (
            <div key={`${ev.entity_id}-${ev.timestamp}-${i}`} className="px-4 py-3" style={{ borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined }}>
              <div className="flex items-center justify-between gap-2">
                <code style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>{ev.entity_id}</code>
                <StatusBadge status={ev.state} variant={ev.state === "on" ? "success" : "muted"} />
              </div>
              <div className="flex items-center justify-between gap-2 mt-1">
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>
                  {Object.entries(ev.attributes || {}).map(([k, v]) => `${k}: ${String(v)}`).join(" · ") || "—"}
                </span>
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", flexShrink: 0 }}>{formatTimestamp(ev.timestamp)}</span>
              </div>
            </div>
          ))}
        </div>
      )}
      {data && <Pager page={data.page} totalPages={data.total_pages} onChange={setPage} />}
    </div>
  );
}

// ── Notifications tab ─────────────────────────────────────────────────────────
function NotificationsTab({
  data, loading, error, onRefetch,
}: { data: Paginated<SmartHomeNotification> | null; loading: boolean; error: Error | null; onRefetch: () => void }) {
  const [unreadOnly, setUnreadOnly] = useState(false);
  const [severity, setSeverity] = useState("all");
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [marking, setMarking] = useState(false);
  const [page, setPage] = useState(1);
  const pageSize = 10;

  const items = data?.items ?? [];
  const filtered = useMemo(
    () => items.filter((n) => (!unreadOnly || !n.read) && (severity === "all" || n.severity === severity)),
    [items, unreadOnly, severity],
  );
  useEffect(() => setPage(1), [unreadOnly, severity]);
  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const paged = filtered.slice((page - 1) * pageSize, page * pageSize);
  const unreadCount = items.filter((n) => !n.read).length;

  const toggleSelect = (id: string) =>
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });

  const markRead = async (ids: string[]) => {
    if (!ids.length) return;
    setMarking(true);
    try {
      const res = await smartHomeService.markNotificationsRead(ids);
      toast.success(res.message);
      setSelected(new Set());
      onRefetch();
    } catch (err) {
      toast.error("Failed to mark read", { description: errorMessage(err) });
    } finally {
      setMarking(false);
    }
  };

  if (loading) return <CenteredSpinner />;

  return (
    <div className="flex flex-col gap-4">
      {error && <ErrorBanner error={error} onRetry={onRefetch} />}

      <div className="flex items-center gap-3 flex-wrap">
        <label className="flex items-center gap-1.5" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>
          <input type="checkbox" checked={unreadOnly} onChange={(e) => setUnreadOnly(e.target.checked)} /> Unread only
        </label>
        <select className={inputClass} style={{ width: "150px", height: "34px" }} value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="all">All severities</option>
          <option value="info">Info</option>
          <option value="warning">Warning</option>
          <option value="critical">Critical</option>
        </select>
        <button onClick={() => markRead(items.filter((n) => !n.read).map((n) => n.id))} disabled={marking || unreadCount === 0} className="ml-auto" style={smallButtonStyle("secondary", marking || unreadCount === 0)}>
          Mark all read ({unreadCount})
        </button>
        {selected.size > 0 && (
          <button onClick={() => markRead(Array.from(selected))} disabled={marking} style={smallButtonStyle("primary", marking)}>
            Mark {selected.size} read
          </button>
        )}
      </div>

      {paged.length === 0 ? (
        <EmptyState icon={Bell} title="No notifications" desc="You're all caught up." />
      ) : (
        <div className="rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--card)" }}>
          {paged.map((n, i, arr) => (
            <div key={n.id} className="flex items-start gap-3 px-4 py-3" style={{ borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined, opacity: n.read ? 0.65 : 1 }}>
              <input type="checkbox" checked={selected.has(n.id)} onChange={() => toggleSelect(n.id)} className="mt-1 flex-shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{n.title}</p>
                  <StatusBadge status={n.severity} variant={severityVariant(n.severity)} />
                  {!n.read && <span style={{ width: "6px", height: "6px", borderRadius: "50%", backgroundColor: "var(--primary)" }} />}
                </div>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "2px" }}>{n.message}</p>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", marginTop: "4px" }}>{formatTimestamp(n.created_at)}</p>
              </div>
              {!n.read && (
                <button
                  onClick={() => markRead([n.id])}
                  disabled={marking}
                  title="Mark read"
                  className="flex items-center justify-center rounded-md flex-shrink-0"
                  style={{ width: "26px", height: "26px", backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)", cursor: marking ? "default" : "pointer" }}
                >
                  <Check size={13} />
                </button>
              )}
            </div>
          ))}
        </div>
      )}
      <Pager page={page} totalPages={totalPages} onChange={setPage} />
    </div>
  );
}

// ── Main screen ───────────────────────────────────────────────────────────────
export function DV11SmartHome() {
  const [activeTab, setActiveTab] = useState<Tab>("devices");
  const [wsConnected, setWsConnected] = useState(false);
  const [telemetryBump, setTelemetryBump] = useState(0);
  const [cyleniumFlow, setCyleniumFlow] = useState<CyleniumFlow>(null);
  const [connectProgress, setConnectProgress] = useState(0);

  const devicesQuery = useSmartHomeDevices();
  const healthQuery = useSmartHomeDeviceHealth();
  const integrationsQuery = useSmartHomeIntegrations();
  const automationsQuery = useSmartHomeAutomations();
  const notificationsQuery = useSmartHomeNotifications();

  const cyleniumConnected = localStorage.getItem("sgx_cylenium_connected") === "1" || cyleniumFlow === "done";

  const tabs: { id: Tab; label: string; icon: any }[] = [
    { id: "devices", label: "Devices", icon: Cpu },
    { id: "integrations", label: "Integrations", icon: Cloud },
    { id: "automations", label: "Automations", icon: Shield },
    { id: "telemetry", label: "Telemetry", icon: Activity },
    { id: "notifications", label: "Alerts", icon: Bell },
  ];

  // Keep a ref of the latest refetchers so the WS effect (mounted once) always
  // calls the current query's refetch, not whatever closed over on first render.
  const refetchersRef = useRef({
    devices: devicesQuery.refetch, health: healthQuery.refetch, integrations: integrationsQuery.refetch,
    automations: automationsQuery.refetch, notifications: notificationsQuery.refetch,
  });
  useEffect(() => {
    refetchersRef.current = {
      devices: devicesQuery.refetch, health: healthQuery.refetch, integrations: integrationsQuery.refetch,
      automations: automationsQuery.refetch, notifications: notificationsQuery.refetch,
    };
  });

  useEffect(() => {
    const close = openSmartHomeSocket(["all"], (evt) => {
      const r = refetchersRef.current;
      if (evt.topic === "device_events") { r.devices(); r.health(); }
      else if (evt.topic === "notifications") { r.notifications(); }
      else if (evt.topic === "rule_triggers") { r.automations(); r.devices(); }
      else if (evt.topic === "telemetry_stream") { setTelemetryBump((n) => n + 1); }
    }, setWsConnected);
    return close;
  }, []);

  const startCyleniumConnect = () => {
    setCyleniumFlow("connecting");
    setConnectProgress(0);
    const steps = [15, 35, 55, 72, 88, 100];
    steps.forEach((val, i) => {
      setTimeout(() => {
        setConnectProgress(val);
        if (val === 100) {
          setTimeout(() => {
            localStorage.setItem("sgx_cylenium_connected", "1");
            setCyleniumFlow("done");
          }, 400);
        }
      }, i * 600 + 300);
    });
  };

  // ── Cylenium flow screens (unchanged mock onboarding, preserved as-is) ────
  if (cyleniumFlow === "what-syncs") {
    return (
      <div className="flex flex-col h-full" style={{ backgroundColor: "var(--background)" }}>
        <PageHeader title="Connect Cylenium" showBack onBack={() => setCyleniumFlow(null)} />
        <div className="flex-1 overflow-y-auto">
          <div className="mx-auto w-full max-w-2xl p-4 md:p-6 flex flex-col gap-5">
            <div className="flex flex-col items-center py-4 text-center gap-3">
              <div
                className="rounded-full flex items-center justify-center"
                style={{ width: "72px", height: "72px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)", border: "2px solid color-mix(in srgb, var(--primary) 25%, transparent)" }}
              >
                <Cloud size={32} style={{ color: "var(--primary)" }} />
              </div>
              <div>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: 700, color: "var(--foreground)", marginBottom: "6px" }}>
                  Cylenium Cloud Sync
                </p>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.6, maxWidth: "260px" }}>
                  Connect your Guardian to Cervais's enterprise monitoring platform.
                </p>
              </div>
            </div>
            <div>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", letterSpacing: "0.08em", marginBottom: "10px" }}>
                What will sync
              </p>
              <div className="flex flex-col gap-3">
                {syncFeatures.map(({ label, desc }) => (
                  <div key={label} className="rounded-lg border border-border p-4 flex items-start gap-3" style={{ backgroundColor: "var(--card)" }}>
                    <div
                      className="rounded-full flex items-center justify-center flex-shrink-0 mt-0.5"
                      style={{ width: "28px", height: "28px", backgroundColor: "color-mix(in srgb, var(--chart-2) 15%, transparent)", border: "1px solid color-mix(in srgb, var(--chart-2) 30%, transparent)" }}
                    >
                      <Check size={13} style={{ color: "var(--chart-2)" }} />
                    </div>
                    <div>
                      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "2px" }}>{label}</p>
                      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>{desc}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
        <div className="mx-auto w-full max-w-2xl px-4 md:px-6 pb-10 pt-4">
          <button onClick={startCyleniumConnect} style={{ ...primaryButtonStyle({ fullWidth: true }), height: "52px", boxShadow: "0 0 24px color-mix(in srgb, var(--primary) 22%, transparent)" }}>
            Connect Now
          </button>
        </div>
      </div>
    );
  }

  if (cyleniumFlow === "connecting") {
    return (
      <div className="flex flex-col items-center justify-center px-6 gap-6 h-full" style={{ backgroundColor: "var(--background)" }}>
        <div
          className="rounded-full flex items-center justify-center"
          style={{ width: "80px", height: "80px", backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)", border: "1.5px solid color-mix(in srgb, var(--primary) 25%, transparent)" }}
        >
          <Loader2 size={36} style={{ color: "var(--primary)" }} className="animate-spin" />
        </div>
        <div className="text-center">
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "4px" }}>
            Connecting to Cylenium…
          </p>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>Establishing secure tunnel</p>
        </div>
        <div className="w-full" style={{ maxWidth: "260px" }}>
          <div className="rounded-full overflow-hidden" style={{ height: "6px", backgroundColor: "var(--muted)" }}>
            <div className="h-full rounded-full" style={{ width: `${connectProgress}%`, backgroundColor: "var(--primary)", transition: "width 0.5s ease" }} />
          </div>
          <div className="flex items-center justify-between mt-2">
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{connectProgress < 100 ? "Syncing…" : "Complete"}</span>
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{connectProgress}%</span>
          </div>
        </div>
      </div>
    );
  }

  if (cyleniumFlow === "done") {
    return (
      <div className="flex flex-col items-center justify-center px-6 gap-5 h-full" style={{ backgroundColor: "var(--background)" }}>
        <div
          className="rounded-full flex items-center justify-center"
          style={{ width: "88px", height: "88px", backgroundColor: "color-mix(in srgb, var(--chart-2) 15%, transparent)", border: "2px solid color-mix(in srgb, var(--chart-2) 35%, transparent)" }}
        >
          <Check size={44} strokeWidth={2.5} style={{ color: "var(--chart-2)" }} />
        </div>
        <div className="text-center">
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: 700, color: "var(--foreground)", marginBottom: "6px" }}>Cylenium Connected!</p>
          <div className="flex flex-col gap-1 mt-3">
            {syncFeatures.map(({ label }) => (
              <div key={label} className="flex items-center gap-2 justify-center">
                <Check size={13} style={{ color: "var(--chart-2)", flexShrink: 0 }} />
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{label} active</span>
              </div>
            ))}
          </div>
        </div>
        <button
          onClick={() => { setCyleniumFlow(null); setActiveTab("integrations"); }}
          style={{ ...primaryButtonStyle(), height: "48px", paddingLeft: "24px", paddingRight: "24px" }}
        >
          Back to Integrations
        </button>
      </div>
    );
  }

  // ── Main screen ───────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Smart Home Integration" right={<LiveIndicator connected={wsConnected} />} />
      <HealthStrip health={healthQuery.data} loading={healthQuery.loading} />

      <div className="flex border-b border-border" style={{ backgroundColor: "var(--card)" }}>
        {tabs.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setActiveTab(id)}
            className="flex-1 flex flex-col items-center gap-0.5 py-3"
            style={{ backgroundColor: "transparent", border: "none", cursor: "pointer", borderBottom: activeTab === id ? "2px solid var(--primary)" : "2px solid transparent" }}
          >
            <Icon size={16} style={{ color: activeTab === id ? "var(--primary)" : "var(--muted-foreground)" }} />
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", fontWeight: activeTab === id ? "var(--font-weight-semibold)" : "var(--font-weight-normal)", color: activeTab === id ? "var(--primary)" : "var(--muted-foreground)" }}>
              {label}
            </span>
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-2xl p-4 md:p-6">
          {activeTab === "devices" && (
            <DevicesTab
              data={devicesQuery.data}
              loading={devicesQuery.loading}
              error={devicesQuery.error}
              onRefetch={() => { devicesQuery.refetch(); healthQuery.refetch(); }}
            />
          )}
          {activeTab === "integrations" && (
            <IntegrationsTab
              data={integrationsQuery.data}
              loading={integrationsQuery.loading}
              error={integrationsQuery.error}
              onRefetch={integrationsQuery.refetch}
              cyleniumConnected={cyleniumConnected}
              onConnectCylenium={() => setCyleniumFlow("what-syncs")}
            />
          )}
          {activeTab === "automations" && (
            <AutomationsTab
              data={automationsQuery.data}
              devices={devicesQuery.data}
              loading={automationsQuery.loading}
              error={automationsQuery.error}
              onRefetch={automationsQuery.refetch}
            />
          )}
          {activeTab === "telemetry" && <TelemetryTab devices={devicesQuery.data} bump={telemetryBump} />}
          {activeTab === "notifications" && (
            <NotificationsTab
              data={notificationsQuery.data}
              loading={notificationsQuery.loading}
              error={notificationsQuery.error}
              onRefetch={notificationsQuery.refetch}
            />
          )}
        </div>
      </div>
    </div>
  );
}
