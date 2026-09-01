import { useEffect, useMemo, useRef, useState } from "react";
import type { ReactNode } from "react";
import { useNavigate } from "react-router";
import * as Dialog from "@radix-ui/react-dialog";
import {
  Radar,
  RefreshCw,
  Loader2,
  ShieldCheck,
  ShieldAlert,
  ShieldQuestion,
  Server,
  Cpu,
  Network,
  Save,
  Clock,
  ListChecks,
  Check,
  X,
  LayoutList,
  Trash2,
  History,
  CalendarClock,
  Power,
  CircleSlash,
  Settings2,
  AlertTriangle,
  CircleCheck,
  CircleX,
} from "lucide-react";
import { PageHeader } from "../../components/PageHeader";
import {
  useDiscoveryDevices,
  useDiscoveryWhitelist,
  useDiscoverySchedule,
  useDiscoveryScheduleRuns,
  useDiscoverySummary,
} from "../../hooks/useApiData";
import {
  useDiscoveryScan,
  loadLastRun,
  type ScanKey,
  type ScanRun,
  type LastRunRecord,
} from "../../hooks/useDiscoveryScan";
import { discoveryService } from "../../services/discoveryService";
import type {
  ConnectedDevice,
  DeviceDetail,
  DiscoveryIntensity,
  DiscoverySchedule,
  InventorySummary,
  OpenPort,
  RiskLevel,
  ScheduleDay,
  ScheduleRun,
  ScheduleRunStatus,
  WhitelistDoc,
  WhitelistDevice,
} from "../../services/discoveryService";
import { toast } from "sonner";

type Tab = "inventory" | "whitelist" | "schedule" | "runs";

function guardianDisplayText(value: string) {
  return value.replace(/suricata|nmap/gi, "Guardian");
}

// ScanKey / ScanRun / LastRunRecord and the scan lifecycle live in the shared
// useDiscoveryScan store so a running scan survives this screen unmounting
// (e.g. switching Settings panels).

const SCAN_BUTTONS: { key: ScanKey; label: string }[] = [
  { key: "default", label: "Default" },
  { key: "stealth", label: "Stealth" },
  { key: "standard", label: "Standard" },
  { key: "aggressive", label: "Aggressive" },
];

const INTENSITIES = ["stealth", "standard", "aggressive"] as const;

/** Maps a device status to a colour token + icon. */
function statusVisual(status: string) {
  const s = (status ?? "").toLowerCase();
  if (s === "approved" || s === "authorized") {
    return { color: "var(--chart-2)", label: "Approved", Icon: ShieldCheck };
  }
  if (s === "drifted") {
    return { color: "var(--chart-4)", label: "Drifted", Icon: ShieldQuestion };
  }
  if (s === "unauthorized") {
    return { color: "var(--destructive)", label: "Unauthorized", Icon: ShieldAlert };
  }
  return { color: "var(--muted-foreground)", label: status || "Unknown", Icon: ShieldQuestion };
}

function isUnauthorized(d: ConnectedDevice) {
  const s = (d.status ?? "").toLowerCase();
  return s === "unauthorized" || s === "drifted";
}

const RISK_COLORS: Record<RiskLevel, string> = {
  critical: "var(--destructive)",
  high: "var(--chart-4)",
  medium: "var(--chart-5)",
  low: "var(--chart-2)",
  unknown: "var(--muted-foreground)",
};

function RiskBadge({ level }: { level: RiskLevel }) {
  const color = RISK_COLORS[level] ?? "var(--muted-foreground)";
  const Icon = level === "critical" || level === "high" ? ShieldAlert : level === "unknown" ? ShieldQuestion : ShieldCheck;
  return (
    <span
      className="flex items-center gap-1"
      style={{
        fontFamily: "Inter, sans-serif",
        fontSize: "10px",
        fontWeight: "var(--font-weight-semibold)",
        color,
        backgroundColor: `color-mix(in srgb, ${color} 12%, transparent)`,
        border: `1px solid color-mix(in srgb, ${color} 25%, transparent)`,
        padding: "2px 8px",
        borderRadius: "6px",
        textTransform: "uppercase",
        letterSpacing: "0.04em",
      }}
    >
      <Icon size={11} /> {level} risk
    </span>
  );
}

// ── Status badge ────────────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const { color, label, Icon } = statusVisual(status);
  return (
    <span
      className="flex items-center gap-1"
      style={{
        fontFamily: "Inter, sans-serif",
        fontSize: "var(--text-xs)",
        fontWeight: "var(--font-weight-medium)",
        color,
        backgroundColor: `color-mix(in srgb, ${color} 12%, transparent)`,
        border: `1px solid color-mix(in srgb, ${color} 25%, transparent)`,
        padding: "2px 8px",
        borderRadius: "6px",
      }}
    >
      <Icon size={12} />
      {label}
    </span>
  );
}

// ── Device card ───────────────────────────────────────────────────────────────

function DeviceCard({
  device,
  onApprove,
  onOpenDetail,
}: {
  device: ConnectedDevice;
  onApprove: (d: ConnectedDevice) => void;
  onOpenDetail: (d: ConnectedDevice) => void;
}) {
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onOpenDetail(device)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onOpenDetail(device);
        }
      }}
      className="rounded-lg border p-4 flex flex-col gap-3 transition-colors"
      style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", cursor: "pointer" }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = "color-mix(in srgb, var(--primary) 40%, var(--border))";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = "var(--border)";
      }}
    >
      <div className="flex items-start gap-3">
        <div
          className="flex items-center justify-center rounded-lg flex-shrink-0"
          style={{
            width: "40px",
            height: "40px",
            backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)",
            color: "var(--primary)",
          }}
        >
          <Server size={18} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-0.5 flex-wrap">
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              {device.hostname || device.vendor || "Unknown device"}
            </p>
            <StatusBadge status={device.status} />
          </div>
          <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
            {device.ip} · {device.mac}
          </p>
          {device.vendor && (
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "2px" }}>
              {device.vendor}
            </p>
          )}
        </div>
        {isUnauthorized(device) && (
          <button
            onClick={(e) => {
              e.stopPropagation();
              onApprove(device);
            }}
            className="flex items-center gap-1 px-2.5 py-1.5 rounded-md flex-shrink-0"
            style={{
              backgroundColor: "color-mix(in srgb, var(--chart-2) 12%, transparent)",
              border: "1px solid color-mix(in srgb, var(--chart-2) 25%, transparent)",
              color: "var(--chart-2)",
              cursor: "pointer",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-medium)",
            }}
          >
            <Check size={12} />
            Approve
          </button>
        )}
      </div>

      <div className="flex items-center gap-4 flex-wrap" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
        {device.os_fingerprint && (
          <span className="flex items-center gap-1">
            <Cpu size={12} /> {device.os_fingerprint}
          </span>
        )}
        <span className="flex items-center gap-1">
          <Network size={12} /> {device.open_ports.length} open port{device.open_ports.length === 1 ? "" : "s"}
        </span>
      </div>

      {device.open_ports.length > 0 && (
        <div className="flex items-center gap-1.5 flex-wrap">
          {device.open_ports.map((p) => (
            <span
              key={`${p.protocol}-${p.port}`}
              style={{
                fontFamily: "JetBrains Mono, monospace",
                fontSize: "10px",
                color: "var(--foreground)",
                backgroundColor: "var(--muted)",
                padding: "2px 6px",
                borderRadius: "4px",
              }}
              title={p.product_version || p.service}
            >
              {p.port}/{p.protocol} {p.service}
            </span>
          ))}
        </div>
      )}

      <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--muted-foreground)" }}>
        Last seen {device.last_seen}
      </p>
    </div>
  );
}

// ── Device detail dialog ──────────────────────────────────────────────────────

/** Best-effort renderer for a Guardian script result. Backend returns
 *  `unknown[]`, but real script entries usually look like `{id, output}`. */
function ScriptBlock({ script }: { script: unknown }) {
  let id: string;
  let output: string;
  if (script && typeof script === "object") {
    const s = script as Record<string, unknown>;
    id = typeof s.id === "string" ? s.id : "script";
    if (typeof s.output === "string") output = s.output;
    else output = JSON.stringify(s, null, 2);
  } else {
    id = "script";
    output = String(script);
  }
  return (
    <div className="rounded-md border p-2.5" style={{ backgroundColor: "var(--background)", borderColor: "var(--border)" }}>
      <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--primary)", marginBottom: "4px" }}>
        {id}
      </p>
      <pre style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--foreground)", whiteSpace: "pre-wrap", wordBreak: "break-word", lineHeight: 1.5, margin: 0 }}>
        {output}
      </pre>
    </div>
  );
}

function PortDetailCard({ port }: { port: OpenPort }) {
  const [expanded, setExpanded] = useState(false);
  const hasScripts = port.scripts.length > 0;
  return (
    <div className="rounded-md border" style={{ backgroundColor: "var(--background)", borderColor: "var(--border)" }}>
      <div
        role={hasScripts ? "button" : undefined}
        tabIndex={hasScripts ? 0 : undefined}
        onClick={() => hasScripts && setExpanded((v) => !v)}
        onKeyDown={(e) => {
          if (hasScripts && (e.key === "Enter" || e.key === " ")) {
            e.preventDefault();
            setExpanded((v) => !v);
          }
        }}
        className="flex items-start justify-between gap-3 p-2.5"
        style={{ cursor: hasScripts ? "pointer" : "default" }}
      >
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              {port.port}/{port.protocol}
            </span>
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--primary)" }}>
              {port.service || "—"}
            </span>
            {port.product_version && (
              <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                {port.product_version}
              </span>
            )}
          </div>
          {port.cpe.length > 0 && (
            <div className="flex flex-wrap gap-1 mt-1.5">
              {port.cpe.map((c) => (
                <Chip key={c}>{c}</Chip>
              ))}
            </div>
          )}
        </div>
        {hasScripts && (
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", flexShrink: 0 }}>
            {port.scripts.length} script{port.scripts.length === 1 ? "" : "s"} {expanded ? "▾" : "▸"}
          </span>
        )}
      </div>
      {hasScripts && expanded && (
        <div className="flex flex-col gap-2 p-2.5 pt-0">
          {port.scripts.map((s, i) => (
            <ScriptBlock key={i} script={s} />
          ))}
        </div>
      )}
    </div>
  );
}

function DetailInfoRow({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", fontWeight: "var(--font-weight-medium)", textTransform: "uppercase", letterSpacing: "0.03em" }}>
        {label}
      </p>
      <p style={{ fontFamily: mono ? "JetBrains Mono, monospace" : "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", marginTop: "2px", wordBreak: "break-word" }}>
        {value}
      </p>
    </div>
  );
}

function DetailSection({ title, count, children }: { title: string; count?: number; children: ReactNode }) {
  return (
    <div className="mt-4">
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "8px" }}>
        {title}{count !== undefined ? ` (${count})` : ""}
      </p>
      {children}
    </div>
  );
}

function DeviceDetailDialog({
  device,
  onClose,
  onApprove,
}: {
  device: ConnectedDevice | null;
  onClose: () => void;
  onApprove: (d: ConnectedDevice) => void;
}) {
  // The list carries the base ConnectedDevice; fetch the full detail (with risk
  // classification + per-port CVE scripts) from GET /discovery/devices/{id} when
  // the dialog opens. Falls back to the list record if the fetch fails.
  const [detail, setDetail] = useState<DeviceDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  useEffect(() => {
    if (!device) {
      setDetail(null);
      return;
    }
    let cancelled = false;
    setDetail(null);
    setDetailLoading(true);
    discoveryService
      .getDevice(device.device_id)
      .then((d) => {
        if (!cancelled) setDetail(d);
      })
      .catch(() => {
        /* keep the list record — non-fatal */
      })
      .finally(() => {
        if (!cancelled) setDetailLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [device]);

  if (!device) return null;
  // Prefer the richer fetched detail; the base record keeps the dialog usable
  // while the detail loads or if it errors.
  const view: ConnectedDevice = detail ?? device;
  const flagged = isUnauthorized(view);
  return (
    <Dialog.Root open={!!device} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay style={{ position: "fixed", inset: 0, backgroundColor: "rgba(0,0,0,0.5)", zIndex: 50 }} />
        <Dialog.Content
          style={{
            position: "fixed",
            top: "50%",
            left: "50%",
            transform: "translate(-50%, -50%)",
            width: "calc(100vw - 32px)",
            maxWidth: "720px",
            maxHeight: "calc(100vh - 64px)",
            overflowY: "auto",
            backgroundColor: "var(--card)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-card, 12px)",
            padding: "20px",
            zIndex: 51,
          }}
        >
          <div className="flex items-start justify-between gap-3 mb-4">
            <div className="min-w-0 flex-1">
              <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                {view.hostname || view.vendor || "Unknown device"}
              </Dialog.Title>
              <div className="flex items-center gap-2 mt-1 flex-wrap">
                <StatusBadge status={view.status} />
                {detail && <RiskBadge level={detail.risk_level} />}
                {detailLoading && <Loader2 size={12} className="animate-spin" style={{ color: "var(--muted-foreground)" }} />}
                <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--muted-foreground)" }}>
                  id: {view.device_id}
                </span>
              </div>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              {flagged && (
                <button
                  onClick={() => onApprove(view)}
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded-md"
                  style={{
                    backgroundColor: "color-mix(in srgb, var(--chart-2) 12%, transparent)",
                    border: "1px solid color-mix(in srgb, var(--chart-2) 25%, transparent)",
                    color: "var(--chart-2)",
                    cursor: "pointer",
                    fontFamily: "Inter, sans-serif",
                    fontSize: "var(--text-xs)",
                    fontWeight: "var(--font-weight-medium)",
                  }}
                >
                  <Check size={12} /> Approve
                </button>
              )}
              <button
                onClick={onClose}
                title="Close"
                className="flex items-center justify-center rounded-md"
                style={{ width: "28px", height: "28px", backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)", cursor: "pointer" }}
              >
                <X size={13} />
              </button>
            </div>
          </div>

          {/* Risk assessment — from GET /discovery/devices/{id} */}
          {detail && detail.risk_reasons.length > 0 && (
            <div
              className="rounded-md p-3 mb-4"
              style={{
                backgroundColor: `color-mix(in srgb, ${RISK_COLORS[detail.risk_level]} 8%, transparent)`,
                border: `1px solid color-mix(in srgb, ${RISK_COLORS[detail.risk_level]} 22%, transparent)`,
              }}
            >
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", textTransform: "uppercase", letterSpacing: "0.05em", marginBottom: "6px" }}>
                Why it's flagged
              </p>
              <ul className="flex flex-col gap-1" style={{ margin: 0, paddingLeft: "16px" }}>
                {detail.risk_reasons.map((r, i) => (
                  <li key={i} style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)", lineHeight: 1.5 }}>
                    {r}
                  </li>
                ))}
              </ul>
              {detail.flagged_ports.length > 0 && (
                <div className="flex items-center gap-1.5 flex-wrap mt-2">
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>Flagged ports:</span>
                  {detail.flagged_ports.map((p) => (
                    <Chip key={p} color={RISK_COLORS[detail.risk_level]}>:{p}</Chip>
                  ))}
                </div>
              )}
            </div>
          )}

          <div className="grid grid-cols-2 gap-x-4 gap-y-3">
            <DetailInfoRow label="IP" value={view.ip || "—"} mono />
            <DetailInfoRow label="MAC" value={view.mac || "—"} mono />
            <DetailInfoRow label="Vendor" value={view.vendor || "—"} />
            <DetailInfoRow label="OS" value={view.os_fingerprint || "—"} />
            <DetailInfoRow label="First seen" value={view.first_seen || "—"} mono />
            <DetailInfoRow label="Last seen" value={view.last_seen || "—"} mono />
          </div>

          {view.os_cpe.length > 0 && (
            <DetailSection title="OS CPEs">
              <div className="flex flex-wrap gap-1.5">
                {view.os_cpe.map((c) => (
                  <Chip key={c} color="var(--foreground)">{c}</Chip>
                ))}
              </div>
            </DetailSection>
          )}

          <DetailSection title="Open ports" count={view.open_ports.length}>
            {view.open_ports.length === 0 ? (
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                No open ports detected.
              </p>
            ) : (
              <div className="flex flex-col gap-2">
                {view.open_ports.map((p) => (
                  <PortDetailCard key={`${p.protocol}-${p.port}`} port={p} />
                ))}
              </div>
            )}
          </DetailSection>

          {view.host_scripts.length > 0 && (
            <DetailSection title="Host scripts" count={view.host_scripts.length}>
              <div className="flex flex-col gap-2">
                {view.host_scripts.map((s, i) => (
                  <ScriptBlock key={i} script={s} />
                ))}
              </div>
            </DetailSection>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// ── Inventory tab ─────────────────────────────────────────────────────────────

interface InventoryTabProps {
  data: ConnectedDevice[] | null;
  loading: boolean;
  error: Error | null;
  refetch: () => void;
  scanning: ScanKey | null;
  onScan: (key: ScanKey) => void;
  whitelistCount: number | null;
  onApproved?: () => void;
  lastRun: LastRunRecord | null;
  realLastRun: ScheduleRun | null;
  summary: InventorySummary | null;
}

// ── Risk breakdown ────────────────────────────────────────────────────────────

const RISK_META: { key: keyof InventorySummary; label: string; color: string }[] = [
  { key: "critical_devices", label: "Critical", color: "var(--destructive)" },
  { key: "high_risk_devices", label: "High", color: "var(--chart-4)" },
  { key: "medium_risk_devices", label: "Medium", color: "var(--chart-5)" },
  { key: "low_risk_devices", label: "Low", color: "var(--chart-2)" },
  { key: "unknown_risk_devices", label: "Unknown", color: "var(--muted-foreground)" },
];

/** Risk-bucket breakdown row, driven by GET /discovery/summary. */
function RiskBreakdown({ summary }: { summary: InventorySummary }) {
  const buckets = RISK_META.map((m) => ({ ...m, value: Number(summary[m.key] ?? 0) }));
  const hasAny = buckets.some((b) => b.value > 0);
  if (!hasAny) return null;
  return (
    <div className="rounded-lg border p-3" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
      <div className="flex items-center justify-between mb-2.5">
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-semibold)", color: "var(--muted-foreground)", textTransform: "uppercase", letterSpacing: "0.05em" }}>
          Risk breakdown
        </p>
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>
          {summary.devices_with_open_ports} with open ports · {summary.total_open_ports} ports
        </span>
      </div>
      <div className="flex flex-wrap gap-2">
        {buckets.map((b) => (
          <span
            key={b.key}
            className="flex items-center gap-1.5"
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-medium)",
              color: b.color,
              backgroundColor: `color-mix(in srgb, ${b.color} 12%, transparent)`,
              border: `1px solid color-mix(in srgb, ${b.color} 25%, transparent)`,
              padding: "3px 8px",
              borderRadius: "6px",
              opacity: b.value === 0 ? 0.45 : 1,
            }}
          >
            {b.label}
            <span style={{ fontWeight: "var(--font-weight-bold)" }}>{b.value}</span>
          </span>
        ))}
      </div>
    </div>
  );
}

/**
 * Persistent card showing the last discovery run's type, name and time.
 * Source priority:
 *   1. `realRun`     — authoritative run timestamp from GET /discovery/runs
 *                      (sourced from the forensic XML archive). Carries no
 *                      intensity/trigger, so those are enriched from `record`
 *                      when the timestamps line up (same scan).
 *   2. `record`      — locally-recorded manual scan (localStorage), which does
 *                      capture the chosen intensity/label.
 *   3. `fallbackTime`— newest inventory `last_seen`, so the card always shows
 *                      something even before the runs endpoint answers.
 */
function LastRunCard({
  realRun,
  record,
  fallbackTime,
}: {
  realRun: ScheduleRun | null;
  record: LastRunRecord | null;
  fallbackTime: Date | null;
}) {
  // Resolve a single view model from the highest-priority available source.
  let intensity: string | null = null; // intensity key, or null for default/unknown
  let name: string | null = null; // display name, e.g. "Aggressive"
  let when: Date | null = null;
  let trigger: string | null = null; // manual / hourly / daily
  let inferred = false;

  const isIntensityKey = (k: string) => (INTENSITIES as readonly string[]).includes(k);

  if (realRun) {
    when = new Date(realRun.started_at);
    // The runs archive doesn't record intensity/trigger. If the local manual-scan
    // record was written within ~2 min of this run, it's the same scan — borrow
    // its intensity and label.
    const recordMatches = record && Math.abs(record.at - when.getTime()) < 120_000;
    if (realRun.intensity) {
      intensity = realRun.intensity;
      name = realRun.intensity.charAt(0).toUpperCase() + realRun.intensity.slice(1);
    } else if (recordMatches && record) {
      intensity = isIntensityKey(record.key) ? record.key : null;
      name = record.label;
    }
    if (realRun.trigger) {
      trigger = realRun.trigger === "manual" ? "manual" : `${realRun.trigger} · scheduled`;
    } else if (recordMatches) {
      trigger = "manual";
    }
  } else if (record) {
    intensity = isIntensityKey(record.key) ? record.key : null;
    name = record.label;
  } else if (fallbackTime) {
    inferred = true;
  }
  if (!when && record) when = new Date(record.at);
  if (!when && fallbackTime) when = fallbackTime;

  return (
    <div className="rounded-lg border p-4" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2.5 min-w-0">
          <div
            className="flex items-center justify-center rounded-lg flex-shrink-0"
            style={{ width: 34, height: 34, backgroundColor: "color-mix(in srgb, var(--primary) 12%, transparent)" }}
          >
            <History size={16} style={{ color: "var(--primary)" }} />
          </div>
          <div className="min-w-0">
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", textTransform: "uppercase", letterSpacing: "0.04em", color: "var(--muted-foreground)" }}>
              Last run
            </p>
            {name ? (
              <div className="flex items-center gap-2 mt-0.5 flex-wrap">
                {intensity ? (
                  <IntensityBadge intensity={intensity} />
                ) : (
                  <span
                    style={{
                      fontFamily: "Inter, sans-serif", fontSize: "10px", fontWeight: "var(--font-weight-medium)",
                      color: "var(--muted-foreground)", backgroundColor: "var(--muted)",
                      border: "1px solid var(--border)", padding: "2px 6px", borderRadius: "4px",
                    }}
                  >
                    Default
                  </span>
                )}
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                  {name} scan
                </span>
                {trigger && (
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>
                    · {trigger}
                  </span>
                )}
              </div>
            ) : (
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: when ? "var(--foreground)" : "var(--muted-foreground)", marginTop: "2px" }}>
                {when ? "Scan (type unknown)" : "No scan run yet"}
              </p>
            )}
          </div>
        </div>
        {when && (
          <div className="flex flex-col items-end flex-shrink-0" title={formatAbsolute(when)}>
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
              {formatRelative(when)}
            </span>
            <span className="flex items-center gap-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>
              <Clock size={10} />
              {formatAbsolute(when)}
              {inferred && " · inferred"}
            </span>
          </div>
        )}
      </div>
    </div>
  );
}

function InventoryTab({ data, loading, error, refetch, scanning, onScan, whitelistCount, onApproved, lastRun, realLastRun, summary }: InventoryTabProps) {
  const [unauthorizedOnly, setUnauthorizedOnly] = useState(false);
  const [approveTarget, setApproveTarget] = useState<ConnectedDevice | null>(null);
  const [detailTarget, setDetailTarget] = useState<ConnectedDevice | null>(null);

  const devices = data ?? [];
  // Prefer the authoritative backend summary; fall back to client-side counts
  // over the device list when /discovery/summary hasn't answered.
  const counts = useMemo(() => {
    if (summary) {
      return { total: summary.total, approved: summary.approved, unauthorized: summary.unauthorized };
    }
    const total = devices.length;
    const unauthorized = devices.filter(isUnauthorized).length;
    return { total, approved: total - unauthorized, unauthorized };
  }, [summary, devices]);

  // Fallback timestamp when no locally-recorded run exists (e.g. the last scan
  // was scheduled, or triggered from another browser): the newest device
  // `last_seen` marks roughly when discovery last touched the network.
  const inventoryLastSeen = useMemo(() => {
    let latest: number | null = null;
    for (const d of devices) {
      const t = new Date(d.last_seen).getTime();
      if (!Number.isNaN(t) && (latest === null || t > latest)) latest = t;
    }
    return latest === null ? null : new Date(latest);
  }, [devices]);

  const shown = unauthorizedOnly ? devices.filter(isUnauthorized) : devices;

  return (
    <div className="flex flex-col gap-4">
      {/* Scan controls */}
      <div className="rounded-lg border p-4" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
        <div className="flex items-center gap-2 mb-3">
          <Radar size={16} style={{ color: "var(--primary)" }} />
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
            Run discovery scan
          </p>
        </div>
        <div className="grid grid-cols-2 gap-2">
          {SCAN_BUTTONS.map((b) => {
            const busy = scanning === b.key;
            const disabled = scanning !== null;
            return (
              <button
                key={b.key}
                onClick={() => onScan(b.key)}
                disabled={disabled}
                className="flex items-center justify-center gap-2 py-2 rounded-lg"
                style={{
                  backgroundColor: "color-mix(in srgb, var(--primary) 10%, transparent)",
                  border: "1px solid color-mix(in srgb, var(--primary) 25%, transparent)",
                  color: "var(--primary)",
                  cursor: disabled ? "not-allowed" : "pointer",
                  opacity: disabled && !busy ? 0.5 : 1,
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  fontWeight: "var(--font-weight-medium)",
                }}
              >
                {busy ? <Loader2 size={12} className="animate-spin" /> : <Radar size={12} />}
                {busy ? "Scanning…" : b.label}
              </button>
            );
          })}
        </div>
      </div>

      {/* Last run — persistent summary of the most recent scan (type + name + time) */}
      <LastRunCard realRun={realLastRun} record={lastRun} fallbackTime={inventoryLastSeen} />

      {/* Stats */}
      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "Total", sub: undefined as string | undefined, value: counts.total, color: "var(--primary)", Icon: Server },
          {
            label: "Approved",
            sub: whitelistCount != null ? `of ${whitelistCount} whitelisted` : undefined,
            value: counts.approved,
            color: "var(--chart-2)",
            Icon: ShieldCheck,
          },
          { label: "Flagged", sub: undefined, value: counts.unauthorized, color: "var(--destructive)", Icon: ShieldAlert },
        ].map((s) => (
          <div key={s.label} className="rounded-lg border p-3 text-center" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
            <s.Icon size={18} style={{ color: s.color, margin: "0 auto 8px" }} />
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: "var(--font-weight-bold)", color: s.color }}>{s.value}</p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{s.label}</p>
            {s.sub && (
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", marginTop: "2px" }}>{s.sub}</p>
            )}
          </div>
        ))}
      </div>

      {/* Risk breakdown — from GET /discovery/summary */}
      {summary && <RiskBreakdown summary={summary} />}

      {/* Filter + refresh */}
      <div className="flex items-center justify-between">
        <button
          onClick={() => setUnauthorizedOnly((v) => !v)}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md"
          style={{
            backgroundColor: unauthorizedOnly ? "color-mix(in srgb, var(--destructive) 12%, transparent)" : "var(--muted)",
            border: `1px solid ${unauthorizedOnly ? "color-mix(in srgb, var(--destructive) 25%, transparent)" : "var(--border)"}`,
            color: unauthorizedOnly ? "var(--destructive)" : "var(--muted-foreground)",
            cursor: "pointer",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            fontWeight: "var(--font-weight-medium)",
          }}
        >
          <ShieldAlert size={12} />
          {unauthorizedOnly ? "Showing flagged only" : "Show flagged only"}
        </button>
        <button
          onClick={() => refetch()}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-md"
          style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)" }}
        >
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {/* Device list */}
      {loading ? (
        <div className="flex items-center justify-center py-10">
          <Loader2 className="animate-spin" size={24} style={{ color: "var(--primary)" }} />
        </div>
      ) : error ? (
        <div className="rounded-lg border p-6 text-center" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
            {error.message.includes("404") ? "No discovery inventory yet. Run a scan to populate it." : guardianDisplayText(error.message)}
          </p>
        </div>
      ) : shown.length === 0 ? (
        <div className="rounded-lg border p-6 text-center" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
          <Radar size={32} style={{ color: "var(--muted-foreground)", margin: "0 auto 12px" }} />
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
            {unauthorizedOnly ? "No flagged devices." : "No devices discovered yet."}
          </p>
        </div>
      ) : (
        <div className="flex flex-col gap-3">
          {shown.map((d) => (
            <DeviceCard key={d.device_id} device={d} onApprove={setApproveTarget} onOpenDetail={setDetailTarget} />
          ))}
        </div>
      )}

      <ApproveDialog
        device={approveTarget}
        onClose={() => setApproveTarget(null)}
        onApproved={() => {
          setApproveTarget(null);
          refetch();
          onApproved?.();
        }}
      />

      <DeviceDetailDialog
        device={detailTarget}
        onClose={() => setDetailTarget(null)}
        onApprove={(d) => {
          setDetailTarget(null);
          setApproveTarget(d);
        }}
      />
    </div>
  );
}

// ── Approve dialog ────────────────────────────────────────────────────────────

function ApproveDialog({
  device,
  onClose,
  onApproved,
}: {
  device: ConnectedDevice | null;
  onClose: () => void;
  onApproved: () => void;
}) {
  const [label, setLabel] = useState("");
  const [submitting, setSubmitting] = useState(false);

  useEffect(() => {
    setLabel(device?.hostname || device?.vendor || "");
  }, [device]);

  const handleApprove = async () => {
    if (!device) return;
    setSubmitting(true);
    try {
      const res = await discoveryService.approve({ mac: device.mac, label: label.trim() || undefined });
      toast.success(res.created ? "Device approved" : "Whitelist updated", {
        description: `${device.mac} · ${res.inventory_updated} inventory record(s) refreshed`,
      });
      onApproved();
    } catch (err) {
      toast.error("Approval failed", { description: err instanceof Error ? guardianDisplayText(err.message) : undefined });
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <Dialog.Root open={!!device} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay style={{ position: "fixed", inset: 0, backgroundColor: "rgba(0,0,0,0.5)", zIndex: 50 }} />
        <Dialog.Content
          style={{
            position: "fixed",
            top: "50%",
            left: "50%",
            transform: "translate(-50%, -50%)",
            width: "calc(100vw - 32px)",
            maxWidth: "400px",
            backgroundColor: "var(--card)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-card, 12px)",
            padding: "20px",
            zIndex: 51,
          }}
        >
          <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "4px" }}>
            Approve device
          </Dialog.Title>
          <Dialog.Description style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginBottom: "16px" }}>
            Adds this MAC to the discovery whitelist and reclassifies it as authorized.
          </Dialog.Description>

          <label style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>MAC address</label>
          <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", color: "var(--foreground)", margin: "4px 0 12px" }}>
            {device?.mac}
          </p>

          <label htmlFor="approve-label" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>Label (optional)</label>
          <input
            id="approve-label"
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            placeholder="e.g. Office printer"
            className="w-full mt-1 mb-4 px-3 py-2 rounded-md"
            style={{ backgroundColor: "var(--background)", border: "1px solid var(--border)", color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)" }}
          />

          <div className="flex items-center justify-end gap-2">
            <button
              onClick={onClose}
              className="flex items-center gap-1 px-3 py-2 rounded-md"
              style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)" }}
            >
              <X size={12} /> Cancel
            </button>
            <button
              onClick={handleApprove}
              disabled={submitting}
              className="flex items-center gap-1 px-3 py-2 rounded-md"
              style={{ backgroundColor: "var(--primary)", color: "var(--primary-foreground)", cursor: submitting ? "not-allowed" : "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)" }}
            >
              {submitting ? <Loader2 size={12} className="animate-spin" /> : <Check size={12} />}
              Approve
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// ── Whitelist tab ─────────────────────────────────────────────────────────────

function Chip({ children, color = "var(--muted-foreground)" }: { children: ReactNode; color?: string }) {
  return (
    <span
      style={{
        fontFamily: "JetBrains Mono, monospace",
        fontSize: "10px",
        color,
        backgroundColor: "var(--muted)",
        padding: "2px 6px",
        borderRadius: "4px",
      }}
    >
      {children}
    </span>
  );
}

type WhitelistPresence = "active" | "not_seen" | "drifted";

function deriveWhitelistPresence(mac: string, inv: ConnectedDevice[] | null): WhitelistPresence {
  if (!inv) return "not_seen";
  const target = (mac ?? "").toLowerCase();
  if (!target) return "not_seen";
  const match = inv.find((d) => (d.mac ?? "").toLowerCase() === target);
  if (!match) return "not_seen";
  const s = (match.status ?? "").toLowerCase();
  if (s === "unauthorized" || s === "drifted") return "drifted";
  return "active";
}

function WhitelistPresenceChip({ presence }: { presence: WhitelistPresence }) {
  const map = {
    active: { color: "var(--chart-2)", label: "Active", Icon: ShieldCheck },
    not_seen: { color: "var(--muted-foreground)", label: "Not seen", Icon: ShieldQuestion },
    drifted: { color: "var(--chart-4)", label: "Drifted", Icon: ShieldAlert },
  } as const;
  const { color, label, Icon } = map[presence];
  return (
    <span
      className="flex items-center gap-1"
      style={{
        fontFamily: "Inter, sans-serif",
        fontSize: "10px",
        fontWeight: "var(--font-weight-medium)",
        color,
        backgroundColor: `color-mix(in srgb, ${color} 12%, transparent)`,
        border: `1px solid color-mix(in srgb, ${color} 25%, transparent)`,
        padding: "2px 6px",
        borderRadius: "4px",
      }}
    >
      <Icon size={10} />
      {label}
    </span>
  );
}

function WhitelistEntryCard({
  device,
  presence,
  onRemove,
  onOpenDetail,
}: {
  device: WhitelistDevice;
  presence: WhitelistPresence;
  onRemove: () => void;
  onOpenDetail: () => void;
}) {
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onOpenDetail}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onOpenDetail();
        }
      }}
      className="rounded-lg border p-3 flex flex-col gap-2 transition-colors"
      style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", cursor: "pointer" }}
      onMouseEnter={(e) => {
        e.currentTarget.style.borderColor = "color-mix(in srgb, var(--primary) 40%, var(--border))";
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.borderColor = "var(--border)";
      }}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              {device.mac}
            </p>
            <WhitelistPresenceChip presence={presence} />
          </div>
          {device.label && (
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{device.label}</p>
          )}
        </div>
        <button
          onClick={(e) => {
            e.stopPropagation();
            onRemove();
          }}
          title="Remove from whitelist"
          className="flex items-center justify-center rounded-md flex-shrink-0"
          style={{ width: "28px", height: "28px", backgroundColor: "color-mix(in srgb, var(--destructive) 10%, transparent)", border: "1px solid color-mix(in srgb, var(--destructive) 22%, transparent)", color: "var(--destructive)", cursor: "pointer" }}
        >
          <Trash2 size={13} />
        </button>
      </div>
      <div className="flex items-center gap-1.5 flex-wrap">
        {device.expected_os && <Chip color="var(--foreground)">OS: {device.expected_os}</Chip>}
        {(device.expected_ports ?? []).map((p) => (
          <Chip key={`p-${p}`}>:{p}</Chip>
        ))}
        {(device.expected_ips ?? []).map((ip) => (
          <Chip key={`ip-${ip}`}>{ip}</Chip>
        ))}
        {!device.expected_os && !(device.expected_ports ?? []).length && !(device.expected_ips ?? []).length && (
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>No expected fingerprint set</span>
        )}
      </div>
    </div>
  );
}

/** Read-only detail view for a single whitelist entry, opened on row click. */
function WhitelistDetailDialog({
  device,
  presence,
  onClose,
  onRemove,
}: {
  device: WhitelistDevice | null;
  presence: WhitelistPresence;
  onClose: () => void;
  onRemove: () => void;
}) {
  if (!device) return null;
  const hasFingerprint =
    !!device.expected_os || (device.expected_ports ?? []).length > 0 || (device.expected_ips ?? []).length > 0;
  return (
    <Dialog.Root open={!!device} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay style={{ position: "fixed", inset: 0, backgroundColor: "rgba(0,0,0,0.5)", zIndex: 50 }} />
        <Dialog.Content
          style={{
            position: "fixed",
            top: "50%",
            left: "50%",
            transform: "translate(-50%, -50%)",
            width: "calc(100vw - 32px)",
            maxWidth: "560px",
            maxHeight: "calc(100vh - 64px)",
            overflowY: "auto",
            backgroundColor: "var(--card)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-card, 12px)",
            padding: "20px",
            zIndex: 51,
          }}
        >
          <div className="flex items-start justify-between gap-3 mb-4">
            <div className="min-w-0 flex-1">
              <Dialog.Title style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                {device.mac}
              </Dialog.Title>
              <div className="flex items-center gap-2 mt-1 flex-wrap">
                <WhitelistPresenceChip presence={presence} />
                {device.label && (
                  <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{device.label}</span>
                )}
              </div>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              <button
                onClick={onRemove}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-md"
                style={{
                  backgroundColor: "color-mix(in srgb, var(--destructive) 10%, transparent)",
                  border: "1px solid color-mix(in srgb, var(--destructive) 22%, transparent)",
                  color: "var(--destructive)",
                  cursor: "pointer",
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  fontWeight: "var(--font-weight-medium)",
                }}
              >
                <Trash2 size={12} /> Remove
              </button>
              <button
                onClick={onClose}
                title="Close"
                className="flex items-center justify-center rounded-md"
                style={{ width: "28px", height: "28px", backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)", cursor: "pointer" }}
              >
                <X size={13} />
              </button>
            </div>
          </div>

          <div className="grid grid-cols-2 gap-x-4 gap-y-3">
            <DetailInfoRow label="MAC" value={device.mac || "—"} mono />
            <DetailInfoRow label="Label" value={device.label || "—"} />
            <DetailInfoRow label="Expected OS" value={device.expected_os || "—"} />
          </div>

          <DetailSection title="Expected ports" count={(device.expected_ports ?? []).length}>
            {(device.expected_ports ?? []).length === 0 ? (
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>None specified.</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {device.expected_ports.map((p) => (
                  <Chip key={`p-${p}`}>:{p}</Chip>
                ))}
              </div>
            )}
          </DetailSection>

          <DetailSection title="Expected IPs" count={(device.expected_ips ?? []).length}>
            {(device.expected_ips ?? []).length === 0 ? (
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>None specified.</p>
            ) : (
              <div className="flex flex-wrap gap-1.5">
                {device.expected_ips.map((ip) => (
                  <Chip key={`ip-${ip}`}>{ip}</Chip>
                ))}
              </div>
            )}
          </DetailSection>

          {!hasFingerprint && (
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "12px" }}>
              No expected fingerprint set for this entry.
            </p>
          )}
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

interface WhitelistTabProps {
  inventoryDevices: ConnectedDevice[] | null;
  data: WhitelistDoc | null;
  loading: boolean;
  error: Error | null;
  refetch: () => void;
  onSaved?: () => void;
}

function WhitelistTab({ inventoryDevices, data, loading, error, refetch, onSaved }: WhitelistTabProps) {
  const [text, setText] = useState("");
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);
  const [view, setView] = useState<"table">("table");
  const [detailMac, setDetailMac] = useState<string | null>(null);

  useEffect(() => {
    if (dirty) return;
    // Seed from the backend when it answers; otherwise fall back to an empty
    // whitelist so the editor is usable even if /discovery/whitelist is slow
    // or unavailable (no infinite spinner).
    if (data) setText(JSON.stringify(data, null, 2));
    else if (!loading) setText(JSON.stringify({ version: "1.0", devices: [] } as WhitelistDoc, null, 2));
  }, [data, loading, dirty]);

  // `text` is the single source of truth; the table view is derived from it.
  let parsed: WhitelistDoc | null = null;
  let parseError = false;
  try {
    parsed = text ? (JSON.parse(text) as WhitelistDoc) : null;
  } catch {
    parseError = true;
  }
  const devices = parsed?.devices ?? [];

  const presenceByMac = useMemo(() => {
    const map = new Map<string, WhitelistPresence>();
    for (const d of devices) map.set(d.mac, deriveWhitelistPresence(d.mac, inventoryDevices));
    return map;
  }, [devices, inventoryDevices]);

  const presenceCounts = useMemo(() => {
    let active = 0;
    let drifted = 0;
    let notSeen = 0;
    for (const p of presenceByMac.values()) {
      if (p === "active") active++;
      else if (p === "drifted") drifted++;
      else notSeen++;
    }
    return { active, drifted, notSeen };
  }, [presenceByMac]);

  const removeDevice = (mac: string) => {
    if (!parsed) return;
    setText(JSON.stringify({ ...parsed, devices: parsed.devices.filter((d) => d.mac !== mac) }, null, 2));
    setDirty(true);
  };

  const handleSave = async () => {
    let body: WhitelistDoc;
    try {
      body = JSON.parse(text);
    } catch {
      toast.error("Invalid JSON", { description: "Fix the syntax before saving." });
      return;
    }
    setSaving(true);
    try {
      const updated = await discoveryService.putWhitelist(body);
      setText(JSON.stringify(updated, null, 2));
      setDirty(false);
      toast.success("Whitelist updated", { description: `${updated.devices.length} device(s)` });
      refetch();
      onSaved?.();
    } catch (err) {
      toast.error("Save failed", { description: err instanceof Error ? guardianDisplayText(err.message) : undefined });
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ListChecks size={16} style={{ color: "var(--primary)" }} />
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
            Discovery whitelist
          </p>
          {loading && <Loader2 className="animate-spin" size={13} style={{ color: "var(--muted-foreground)" }} />}
        </div>
        <div className="flex items-center gap-1 p-0.5 rounded-md" style={{ backgroundColor: "var(--muted)" }}>
          <button
            type="button"
            aria-pressed={view === "table"}
            onClick={() => setView("table")}
            className="flex items-center gap-1 px-2 py-1 rounded"
            style={{
              backgroundColor: "var(--card)",
              color: "var(--foreground)",
              border: "1px solid var(--border)",
              cursor: "pointer",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-medium)",
            }}
          >
            <LayoutList size={12} /> Table
          </button>
        </div>
      </div>

      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
        Approved devices in the discovery whitelist. Remove entries here to refresh matching inventory statuses.
      </p>

      {error && (
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--destructive)" }}>{guardianDisplayText(error.message)}</p>
      )}

      {view === "table" && parseError ? (
        <div className="rounded-lg border p-4" style={{ backgroundColor: "var(--card)", borderColor: "color-mix(in srgb, var(--chart-4) 30%, var(--border))" }}>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--chart-4)" }}>
            The whitelist could not be displayed. Reload the current whitelist and try again.
          </p>
        </div>
      ) : view === "table" && devices.length === 0 ? (
        <div className="rounded-lg border p-6 text-center" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
          <ListChecks size={32} style={{ color: "var(--muted-foreground)", margin: "0 auto 12px" }} />
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>No whitelisted devices yet</p>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "4px" }}>
            Approve a device from the Inventory tab to add it here.
          </p>
        </div>
      ) : view === "table" ? (
        <div className="flex flex-col gap-2">
          {devices.map((d) => (
            <WhitelistEntryCard
              key={d.mac}
              device={d}
              presence={presenceByMac.get(d.mac) ?? "not_seen"}
              onRemove={() => removeDevice(d.mac)}
              onOpenDetail={() => setDetailMac(d.mac)}
            />
          ))}
        </div>
      ) : null}

      <div className="flex items-center justify-between">
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
          {!parseError && (
            <>
              {devices.length} whitelisted
              {inventoryDevices && devices.length > 0 && (
                <>
                  {" · "}
                  <span style={{ color: "var(--chart-2)" }}>{presenceCounts.active} active</span>
                  {presenceCounts.drifted > 0 && (
                    <>
                      {" · "}
                      <span style={{ color: "var(--chart-4)" }}>{presenceCounts.drifted} drifted</span>
                    </>
                  )}
                  {presenceCounts.notSeen > 0 && (
                    <>
                      {" · "}
                      <span>{presenceCounts.notSeen} not seen</span>
                    </>
                  )}
                </>
              )}
            </>
          )}
          {dirty ? " · unsaved changes" : ""}
        </span>
        <div className="flex items-center gap-2">
          <button
            onClick={() => {
              setDirty(false);
              if (data) setText(JSON.stringify(data, null, 2));
            }}
            disabled={!dirty}
            className="flex items-center gap-1 px-3 py-2 rounded-md"
            style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)", cursor: dirty ? "pointer" : "not-allowed", opacity: dirty ? 1 : 0.5, fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)" }}
          >
            <RefreshCw size={12} /> Reset
          </button>
          <button
            onClick={handleSave}
            disabled={saving}
            className="flex items-center gap-1 px-3 py-2 rounded-md"
            style={{ backgroundColor: "var(--primary)", color: "var(--primary-foreground)", cursor: saving ? "not-allowed" : "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)" }}
          >
            {saving ? <Loader2 size={12} className="animate-spin" /> : <Save size={12} />}
            Save whitelist
          </button>
        </div>
      </div>

      <WhitelistDetailDialog
        device={devices.find((d) => d.mac === detailMac) ?? null}
        presence={detailMac ? presenceByMac.get(detailMac) ?? "not_seen" : "not_seen"}
        onClose={() => setDetailMac(null)}
        onRemove={() => {
          if (detailMac) removeDevice(detailMac);
          setDetailMac(null);
        }}
      />
    </div>
  );
}

// ── Schedule tab ──────────────────────────────────────────────────────────────

const fieldStyle = {
  backgroundColor: "var(--background)",
  border: "1px solid var(--border)",
  color: "var(--foreground)",
  fontFamily: "Inter, sans-serif",
  fontSize: "var(--text-sm)",
} as const;

const SCHEDULE_DAYS: { key: ScheduleDay; label: string; short: string }[] = [
  { key: "monday", label: "Monday", short: "Mon" },
  { key: "tuesday", label: "Tuesday", short: "Tue" },
  { key: "wednesday", label: "Wednesday", short: "Wed" },
  { key: "thursday", label: "Thursday", short: "Thu" },
  { key: "friday", label: "Friday", short: "Fri" },
  { key: "saturday", label: "Saturday", short: "Sat" },
  { key: "sunday", label: "Sunday", short: "Sun" },
];

const SCHEDULE_FREQUENCIES: { key: ScanScheduleProfile["frequency"]; label: string }[] = [
  { key: "once", label: "Once" },
  { key: "daily", label: "Daily" },
  { key: "weekly", label: "Weekly" },
  { key: "monthly", label: "Monthly" },
  { key: "yearly", label: "Yearly" },
];

const TIMEZONES: { key: string; label: string }[] = [
  { key: "America/New_York", label: "Eastern Time" },
  { key: "America/Chicago", label: "Central Time" },
  { key: "America/Denver", label: "Mountain Time" },
  { key: "America/Los_Angeles", label: "Pacific Time" },
  { key: "UTC", label: "UTC" },
];

const DEFAULT_SCAN_DAYS: ScheduleDay[] = ["monday", "wednesday", "friday"];
const EVERY_DAY: ScheduleDay[] = SCHEDULE_DAYS.map((day) => day.key);
const DEFAULT_SCAN_TIME = "23:00";
const DEFAULT_SCAN_TIMEZONE = "America/New_York";

function makeScheduleId(): string {
  return globalThis.crypto?.randomUUID?.() ?? `sched-${Math.random().toString(36).slice(2, 10)}`;
}

function createDefaultScheduleTask(): ScanScheduleProfile {
  return {
    id: makeScheduleId(),
    frequency: "weekly",
    intensity: "aggressive",
    days: [...DEFAULT_SCAN_DAYS],
    day_of_month: 1,
    month: 1,
    time: DEFAULT_SCAN_TIME,
    timezone: DEFAULT_SCAN_TIMEZONE,
  };
}

function hasMeaningfulLegacySchedule(cfg: DiscoverySchedule): boolean {
  if (cfg.legacy_schedule_mode) return true;
  const hourly = cfg.schedules?.hourly;
  const daily = cfg.schedules?.daily;
  const defaultHourly = DEFAULT_SCHEDULE.schedules.hourly;
  const defaultDaily = DEFAULT_SCHEDULE.schedules.daily;
  return Boolean(
    hourly && hourly.intensity !== defaultHourly.intensity
      || daily && (
        daily.intensity !== defaultDaily.intensity
        || (daily.days?.length ?? 0) > 0
        || daily.time !== defaultDaily.time
      ),
  );
}

function normalizeScheduleTask(task: Partial<ScanScheduleProfile> = {}): ScanScheduleProfile {
  const frequency = task.frequency ?? "weekly";
  const base = createDefaultScheduleTask();
  const days =
    frequency === "once"
      ? []
      : task.days?.length
        ? task.days
        : frequency === "daily"
          ? [...EVERY_DAY]
          : base.days;
  return {
    id: task.id?.trim() || base.id,
    frequency,
    intensity: task.intensity ?? base.intensity,
    days,
    day_of_month: frequency === "monthly" || frequency === "yearly" ? (task.day_of_month ?? 1) : null,
    month: frequency === "yearly" ? (task.month ?? 1) : null,
    time: task.time || DEFAULT_SCAN_TIME,
    timezone: task.timezone || DEFAULT_SCAN_TIMEZONE,
  };
}

const DEFAULT_SCHEDULE: DiscoverySchedule = {
  enabled: false,
  target_cidr: null,
  timeout_secs: 600,
  exclude: [],
  scan_schedules: [],
  schedules: {
    hourly: { intensity: "standard" },
    daily: { intensity: "aggressive", days: DEFAULT_SCAN_DAYS, time: DEFAULT_SCAN_TIME },
  },
};

function normalizeScheduleForm(cfg: DiscoverySchedule): DiscoverySchedule {
  const legacyDays = cfg.schedules?.daily?.days?.length ? cfg.schedules.daily.days : DEFAULT_SCAN_DAYS;
  const legacyDerivedTask: ScanScheduleProfile | null =
    cfg.scan_schedules === undefined && (cfg.enabled || hasMeaningfulLegacySchedule(cfg))
      ? normalizeScheduleTask({
          frequency: "weekly",
          intensity: cfg.schedules?.daily?.intensity ?? DEFAULT_SCHEDULE.schedules.daily.intensity,
          days: legacyDays,
          day_of_month: null,
          time: cfg.schedules?.daily?.time || DEFAULT_SCAN_TIME,
          timezone: DEFAULT_SCAN_TIMEZONE,
        })
      : null;
  return {
    ...cfg,
    scan_schedules: (cfg.scan_schedules ?? (legacyDerivedTask ? [legacyDerivedTask] : [])).map((task) =>
      normalizeScheduleTask({
        ...task,
        days: task.frequency === "once" ? [] : task.frequency === "daily" ? [...EVERY_DAY] : task.days?.length ? task.days : legacyDays,
        time: task.time || cfg.schedules?.daily?.time || DEFAULT_SCAN_TIME,
      }),
    ),
    schedules: {
      hourly: {
        intensity: cfg.schedules?.hourly?.intensity ?? DEFAULT_SCHEDULE.schedules.hourly.intensity,
      },
      daily: {
        intensity: cfg.schedules?.daily?.intensity ?? DEFAULT_SCHEDULE.schedules.daily.intensity,
        days: legacyDays,
        time: cfg.schedules?.daily?.time || DEFAULT_SCAN_TIME,
      },
    },
  };
}

function formatScheduleTime(time: string): string {
  const [hourText, minuteText] = time.split(":");
  const hour24 = Number(hourText);
  const minute = Number(minuteText);
  if (!Number.isFinite(hour24) || !Number.isFinite(minute)) return time;
  const hour12 = hour24 % 12 || 12;
  const suffix = hour24 >= 12 ? "PM" : "AM";
  return `${hour12}:${String(minute).padStart(2, "0")} ${suffix}`;
}

function getTimeZoneLabel(zone: string): string {
  const mapped = TIMEZONES.find((item) => item.key === zone);
  return mapped?.label || zone?.replaceAll("_", " ") || "Local Time";
}

function formatScheduleSummary(schedule: ScanScheduleProfile): string {
  if (schedule.frequency === "once") {
    return `Once at ${formatScheduleTime(schedule.time || DEFAULT_SCAN_TIME)} (${getTimeZoneLabel(schedule.timezone || DEFAULT_SCAN_TIMEZONE)})`;
  }
  if (schedule.frequency === "monthly") {
    return `Monthly on day ${schedule.day_of_month ?? 1} at ${formatScheduleTime(schedule.time || DEFAULT_SCAN_TIME)} (${getTimeZoneLabel(schedule.timezone || DEFAULT_SCAN_TIMEZONE)})`;
  }
  if (schedule.frequency === "yearly") {
    const month = Math.max(1, Math.min(12, schedule.month ?? 1));
    return `Yearly on ${new Date(2000, month - 1, 1).toLocaleString(undefined, { month: "long" })} ${schedule.day_of_month ?? 1} at ${formatScheduleTime(schedule.time || DEFAULT_SCAN_TIME)} (${getTimeZoneLabel(schedule.timezone || DEFAULT_SCAN_TIMEZONE)})`;
  }
  if (schedule.frequency === "daily") {
    return `Every day at ${formatScheduleTime(schedule.time || DEFAULT_SCAN_TIME)} (${getTimeZoneLabel(schedule.timezone || DEFAULT_SCAN_TIMEZONE)})`;
  }
  const selected = SCHEDULE_DAYS.filter((day) => (schedule.days ?? []).includes(day.key)).map((day) => day.label);
  const dayText = selected.length ? selected.join(", ") : "No days selected";
  return `${dayText} at ${formatScheduleTime(schedule.time || DEFAULT_SCAN_TIME)} (${getTimeZoneLabel(schedule.timezone || DEFAULT_SCAN_TIMEZONE)})`;
}

function computeNextScheduledScan(schedule: ScanScheduleProfile, now: Date = new Date()): Date | null {
  const time = schedule.time || DEFAULT_SCAN_TIME;
  const [hourText, minuteText] = time.split(":");
  const hour = Number(hourText);
  const minute = Number(minuteText);
  if (!Number.isInteger(hour) || !Number.isInteger(minute)) return null;

  if (schedule.frequency === "once") {
    const candidate = new Date(now);
    candidate.setHours(hour, minute, 0, 0);
    if (candidate <= now) candidate.setDate(candidate.getDate() + 1);
    return candidate;
  }

  if (schedule.frequency === "monthly") {
    const dayOfMonth = schedule.day_of_month ?? 1;
    for (let offset = 0; offset <= 12; offset++) {
      const candidate = new Date(now);
      candidate.setMonth(now.getMonth() + offset, 1);
      const daysInMonth = new Date(candidate.getFullYear(), candidate.getMonth() + 1, 0).getDate();
      candidate.setDate(Math.min(dayOfMonth, daysInMonth));
      candidate.setHours(hour, minute, 0, 0);
      if (candidate > now) return candidate;
      if (offset === 0 && candidate <= now) continue;
    }
    return null;
  }

  if (schedule.frequency === "yearly") {
    const month = Math.max(1, Math.min(12, schedule.month ?? 1));
    const dayOfMonth = schedule.day_of_month ?? 1;
    for (let offset = 0; offset <= 2; offset++) {
      const candidate = new Date(now.getFullYear() + offset, month - 1, 1);
      const daysInMonth = new Date(candidate.getFullYear(), candidate.getMonth() + 1, 0).getDate();
      candidate.setDate(Math.min(dayOfMonth, daysInMonth));
      candidate.setHours(hour, minute, 0, 0);
      if (candidate > now) return candidate;
    }
    return null;
  }

  const days = schedule.frequency === "daily" ? EVERY_DAY : (schedule.days ?? []);
  if (!days.length) return null;
  let best: Date | null = null;
  for (let offset = 0; offset <= 7; offset++) {
    const candidate = new Date(now);
    candidate.setDate(now.getDate() + offset);
    candidate.setHours(hour, minute, 0, 0);
    const dayKey = SCHEDULE_DAYS[(candidate.getDay() + 6) % 7].key;
    if (!days.includes(dayKey) || candidate <= now) continue;
    if (!best || candidate < best) best = candidate;
  }
  return best;
}

function frequencyLabel(frequency: ScanScheduleProfile["frequency"]): string {
  return SCHEDULE_FREQUENCIES.find((item) => item.key === frequency)?.label ?? "Scheduled";
}

type UpcomingScheduledScan = {
  id: string;
  label: string;
  scheduleText: string;
  nextRunText: string;
  relativeText: string;
  intensity: string;
  nextRunAt: number | null;
};

function buildUpcomingScheduledScans(cfg: DiscoverySchedule | null, now: Date = new Date()): UpcomingScheduledScan[] {
  if (!cfg?.enabled) return [];
  const tasks = cfg.scan_schedules ?? [];
  return tasks
    .map((schedule) => {
      const nextRun = computeNextScheduledScan(schedule, now);
      return {
        id: schedule.id,
        label: `${frequencyLabel(schedule.frequency)} scan`,
        scheduleText: `${frequencyLabel(schedule.frequency)} · ${formatScheduleSummary(schedule)}`,
        nextRunText: nextRun ? formatAbsolute(nextRun) : "No upcoming run",
        relativeText: nextRun ? formatRelative(nextRun) : "",
        intensity: schedule.intensity,
        nextRunAt: nextRun ? nextRun.getTime() : null,
      };
    })
    .sort((a, b) => {
      if (a.nextRunAt == null && b.nextRunAt == null) return a.id.localeCompare(b.id);
      if (a.nextRunAt == null) return 1;
      if (b.nextRunAt == null) return -1;
      return a.nextRunAt - b.nextRunAt;
    });
}

function ScheduleTab() {
  const { data, loading, error, refetch } = useDiscoverySchedule();
  // Start from defaults so the form is always usable — even if
  // /discovery/schedule is slow or unavailable (no infinite spinner). Real
  // config replaces the defaults once it arrives, unless the user has edited.
  const [form, setForm] = useState<DiscoverySchedule>(DEFAULT_SCHEDULE);
  const [draftTask, setDraftTask] = useState<ScanScheduleProfile>(createDefaultScheduleTask());
  const [editingIndex, setEditingIndex] = useState<number | null>(null);
  const [draftChanged, setDraftChanged] = useState(false);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (data && !dirty) {
      const normalized = normalizeScheduleForm(data);
      setForm(normalized);
      setDraftTask(normalized.scan_schedules[0] ?? createDefaultScheduleTask());
      setEditingIndex(null);
      setDraftChanged(false);
    }
  }, [data, dirty]);

  const persistSchedule = async (nextForm: DiscoverySchedule) => {
    setSaving(true);
    try {
      const normalized = normalizeScheduleForm(nextForm);
      const updated = await discoveryService.putSchedule({
        enabled: nextForm.enabled,
        target_cidr: nextForm.target_cidr && nextForm.target_cidr.trim() ? nextForm.target_cidr.trim() : null,
        timeout_secs: Number(nextForm.timeout_secs),
        exclude: nextForm.exclude,
        scan_schedules: normalized.scan_schedules,
        schedules: normalized.schedules,
      });
      setForm(normalizeScheduleForm(updated));
      setDraftTask(normalizeScheduleForm(updated).scan_schedules[0] ?? createDefaultScheduleTask());
      setEditingIndex(null);
      setDraftChanged(false);
      setDirty(false);
      toast.success("Schedule updated");
      refetch();
    } catch (err) {
      toast.error("Save failed", { description: err instanceof Error ? guardianDisplayText(err.message) : undefined });
    } finally {
      setSaving(false);
    }
  };

  const update = (patch: Partial<DiscoverySchedule>) => {
    setForm((current) => ({ ...current, ...patch }));
    setDirty(true);
  };

  const handleSave = async () => {
    const currentTasks = form.scan_schedules ?? [];
    const pendingTask = normalizeScheduleTask(draftTask);
    const tasksToSave = !draftChanged
      ? currentTasks
      : editingIndex === null
        ? [...currentTasks, pendingTask]
        : currentTasks.map((task, index) => index === editingIndex ? pendingTask : task);
    await persistSchedule({ ...form, scan_schedules: tasksToSave });
  };

  const labelStyle = { fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", fontWeight: "var(--font-weight-medium)" } as const;
  const normalized = normalizeScheduleForm(form);
  const tasks = normalized.scan_schedules;
  const schedule = draftTask;
  const selectedDays = schedule.days ?? [];
  const toggleDay = (day: ScheduleDay) => {
    const nextDays = selectedDays.includes(day) ? selectedDays.filter((d) => d !== day) : [...selectedDays, day];
    setDraftTask((task) => normalizeScheduleTask({
      ...task,
      days: SCHEDULE_DAYS.filter((d) => nextDays.includes(d.key)).map((d) => d.key),
    }));
    setDraftChanged(true);
  };
  const updateSchedule = (patch: Partial<ScanScheduleProfile>) => {
    setDraftTask((task) => normalizeScheduleTask({ ...task, ...patch }));
    setDraftChanged(true);
  };
  const commitDraftTask = () => {
    const nextTask = normalizeScheduleTask(draftTask);
    setForm((current) => {
      const next = (current.scan_schedules ?? []).slice();
      if (editingIndex === null) {
        next.push(nextTask);
      } else if (editingIndex >= 0 && editingIndex < next.length) {
        next[editingIndex] = nextTask;
      }
      return { ...current, scan_schedules: next };
    });
    setDraftTask(createDefaultScheduleTask());
    setEditingIndex(null);
    setDraftChanged(false);
    setDirty(true);
  };
  const editTask = (index: number) => {
    const task = tasks[index];
    if (!task) return;
    setDraftTask(task);
    setEditingIndex(index);
    setDraftChanged(false);
  };
  const removeTask = async (index: number) => {
    const nextForm = {
      ...form,
      scan_schedules: (form.scan_schedules ?? []).filter((_, taskIndex) => taskIndex !== index),
    };
    setForm(nextForm);
    setDirty(true);
    if (editingIndex === index) {
      setDraftTask(createDefaultScheduleTask());
      setEditingIndex(null);
      setDraftChanged(false);
    }
    await persistSchedule(nextForm);
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <Clock size={16} style={{ color: "var(--primary)" }} />
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
          Scheduled discovery
        </p>
        {loading && <Loader2 className="animate-spin" size={13} style={{ color: "var(--muted-foreground)" }} />}
      </div>

      {error && (
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--chart-4)" }}>
          Couldn't load the current schedule ({guardianDisplayText(error.message)}). Showing defaults — saving will overwrite the stored config.
        </p>
      )}

      {/* Enabled toggle */}
      <label className="flex items-center justify-between rounded-lg border p-3" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", cursor: "pointer" }}>
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>Enable scheduled scans</span>
        <input type="checkbox" checked={form.enabled} onChange={(e) => update({ enabled: e.target.checked })} />
      </label>

      <div className="flex flex-col gap-1">
        <label style={labelStyle}>Target CIDR <span style={{ fontWeight: 400 }}>(blank = auto-detect LAN)</span></label>
        <input
          value={form.target_cidr ?? ""}
          onChange={(e) => update({ target_cidr: e.target.value })}
          placeholder="192.168.50.0/24"
          className="w-full px-3 py-2 rounded-md"
          style={{ ...fieldStyle, fontFamily: "JetBrains Mono, monospace" }}
        />
      </div>

      <div className="flex flex-col gap-1">
        <label style={labelStyle}>Timeout (seconds)</label>
        <input
          type="number"
          min={1}
          value={form.timeout_secs}
          onChange={(e) => update({ timeout_secs: Number(e.target.value) })}
          className="w-full px-3 py-2 rounded-md"
          style={fieldStyle}
        />
      </div>

      <div className="flex flex-col gap-1">
        <label style={labelStyle}>Exclude (comma-separated IPs)</label>
        <input
          value={form.exclude.join(", ")}
          onChange={(e) => update({ exclude: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })}
          placeholder="192.168.50.1"
          className="w-full px-3 py-2 rounded-md"
          style={{ ...fieldStyle, fontFamily: "JetBrains Mono, monospace" }}
        />
      </div>

      <div className="flex flex-col gap-3 rounded-lg border p-3" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
        <div className="flex items-center justify-between gap-2">
          <label style={labelStyle}>Saved schedule tasks</label>
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
            {tasks.length} task{tasks.length === 1 ? "" : "s"}
          </span>
        </div>

        <div className="flex flex-col gap-2">
          {tasks.length > 0 ? (
            tasks.map((task, index) => {
              const nextRun = computeNextScheduledScan(task);
              return (
                <div key={task.id} className="rounded-md border px-3 py-2" style={{ backgroundColor: "var(--background)", borderColor: "var(--border)" }}>
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0 flex-1">
                      <div style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.4 }}>
                        {frequencyLabel(task.frequency)} scan
                      </div>
                      <div style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.4, marginTop: "2px" }}>
                        {formatScheduleSummary(task)}
                      </div>
                      <div style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.4, marginTop: "2px" }}>
                        Next run: {nextRun ? formatAbsolute(nextRun) : "—"}
                        {nextRun ? ` (${formatRelative(nextRun)})` : ""}
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <IntensityBadge intensity={task.intensity} />
                      <button
                        type="button"
                        onClick={() => editTask(index)}
                        className="px-2 py-1 rounded-md"
                        style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--foreground)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)" }}
                      >
                        Edit
                      </button>
                      <button
                        type="button"
                        onClick={() => { void removeTask(index); }}
                        className="px-2 py-1 rounded-md"
                        style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--destructive)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)" }}
                      >
                        Remove
                      </button>
                    </div>
                  </div>
                </div>
              );
            })
          ) : (
            <div
              className="rounded-md border px-3 py-2"
              style={{ backgroundColor: "var(--background)", borderColor: "var(--border)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}
            >
              No scheduled tasks saved yet
            </div>
          )}
        </div>
      </div>

      <div className="flex flex-col gap-3 rounded-lg border p-3" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
        <div className="flex items-center justify-between gap-2">
          <label style={labelStyle}>{editingIndex === null ? "Add schedule task" : "Edit schedule task"}</label>
          <button
            type="button"
            onClick={() => {
              setDraftTask(createDefaultScheduleTask());
              setEditingIndex(null);
              setDraftChanged(false);
            }}
            className="px-2 py-1 rounded-md"
            style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)" }}
          >
            Reset
          </button>
        </div>

        <div className="flex flex-col gap-1">
          <label style={labelStyle}>Intensity</label>
          <select
            value={schedule.intensity}
            onChange={(e) => updateSchedule({ intensity: e.target.value })}
            className="w-full px-3 py-2 rounded-md"
            style={fieldStyle}
          >
            {INTENSITIES.map((i) => (
              <option key={i} value={i}>{i}</option>
            ))}
          </select>
        </div>

        <div className="flex flex-col gap-1">
          <label style={labelStyle}>Frequency</label>
          <select
            value={schedule.frequency}
            onChange={(e) => {
              const nextFrequency = e.target.value as ScanScheduleProfile["frequency"];
              updateSchedule({
                frequency: nextFrequency,
                days: nextFrequency === "once" || nextFrequency === "monthly" || nextFrequency === "yearly" ? [] : nextFrequency === "daily" ? [...EVERY_DAY] : schedule.days?.length ? schedule.days : [...DEFAULT_SCAN_DAYS],
                day_of_month: nextFrequency === "monthly" || nextFrequency === "yearly" ? (schedule.day_of_month ?? 1) : null,
                month: nextFrequency === "yearly" ? (schedule.month ?? 1) : null,
              });
            }}
            className="w-full px-3 py-2 rounded-md"
            style={fieldStyle}
          >
            {SCHEDULE_FREQUENCIES.map((item) => (
              <option key={item.key} value={item.key}>
                {item.label}
              </option>
            ))}
          </select>
        </div>

        <div className="flex flex-col gap-1">
          <label style={labelStyle}>Time to run scan</label>
          <input
            type="time"
            value={schedule.time}
            onChange={(e) => updateSchedule({ time: e.target.value })}
            className="w-full px-3 py-2 rounded-md"
            style={fieldStyle}
          />
        </div>

        {schedule.frequency === "monthly" || schedule.frequency === "yearly" ? (
          <>
            <div className="flex flex-col gap-1">
              <label style={labelStyle}>Day of month</label>
              <input
                type="number"
                min={1}
                max={31}
                value={schedule.day_of_month ?? 1}
                onChange={(e) => updateSchedule({ day_of_month: Number(e.target.value) })}
                className="w-full px-3 py-2 rounded-md"
                style={fieldStyle}
              />
            </div>
          {schedule.frequency === "yearly" && (
            <div className="flex flex-col gap-1">
              <label style={labelStyle}>Month</label>
              <select value={schedule.month ?? 1} onChange={(e) => updateSchedule({ month: Number(e.target.value) })} className="w-full px-3 py-2 rounded-md" style={fieldStyle}>
                {Array.from({ length: 12 }, (_, index) => <option key={index + 1} value={index + 1}>{new Date(2000, index, 1).toLocaleString(undefined, { month: "long" })}</option>)}
              </select>
            </div>
          )}
          </>
        ) : schedule.frequency === "weekly" ? (
          <div className="flex flex-col gap-1">
            <label style={labelStyle}>Days (select days to scan)</label>
            <div className="grid grid-cols-7 gap-1">
              {SCHEDULE_DAYS.map((day) => {
                const selected = selectedDays.includes(day.key);
                return (
                  <button
                    key={day.key}
                    type="button"
                    onClick={() => toggleDay(day.key)}
                    className="flex items-center justify-center rounded-md px-2 py-2"
                    title={day.label}
                    style={{
                      backgroundColor: selected ? "var(--primary)" : "var(--background)",
                      border: selected ? "1px solid var(--primary)" : "1px solid var(--border)",
                      color: selected ? "var(--primary-foreground)" : "var(--foreground)",
                      cursor: "pointer",
                      fontFamily: "Inter, sans-serif",
                      fontSize: "var(--text-xs)",
                      fontWeight: "var(--font-weight-medium)",
                    }}
                  >
                    {day.short}
                  </button>
                );
              })}
            </div>
          </div>
        ) : null}

        <div className="flex flex-col gap-1">
          <label style={labelStyle}>Timezone</label>
          <select
            value={schedule.timezone}
            onChange={(e) => updateSchedule({ timezone: e.target.value })}
            className="w-full px-3 py-2 rounded-md"
            style={fieldStyle}
          >
            {TIMEZONES.map((tz) => (
              <option key={tz.key} value={tz.key}>
                {tz.label}
              </option>
            ))}
          </select>
        </div>

        <div className="flex items-center justify-end gap-2">
          {editingIndex !== null && (
            <button
              type="button"
              onClick={() => {
                setDraftTask(createDefaultScheduleTask());
                setEditingIndex(null);
                setDraftChanged(false);
              }}
              className="px-3 py-2 rounded-md"
              style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)" }}
            >
              Cancel
            </button>
          )}
          <button
            type="button"
            onClick={commitDraftTask}
            className="px-3 py-2 rounded-md"
            style={{ backgroundColor: "var(--primary)", color: "var(--primary-foreground)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)" }}
          >
            {editingIndex === null ? "Add task" : "Update task"}
          </button>
        </div>
      </div>

      <button
        onClick={handleSave}
        disabled={saving}
        className="flex items-center justify-center gap-1 px-3 py-2.5 rounded-md"
        style={{ backgroundColor: "var(--primary)", color: "var(--primary-foreground)", cursor: saving ? "not-allowed" : "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}
      >
        {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
        Save schedule
      </button>
    </div>
  );
}

// ── Runs tab ──────────────────────────────────────────────────────────────────

const INTENSITY_COLORS: Record<string, string> = {
  stealth: "var(--chart-3)",
  standard: "var(--primary)",
  aggressive: "var(--destructive)",
};

function IntensityBadge({ intensity }: { intensity: string }) {
  const color = INTENSITY_COLORS[intensity] ?? "var(--muted-foreground)";
  return (
    <span
      style={{
        fontFamily: "Inter, sans-serif",
        fontSize: "10px",
        fontWeight: "var(--font-weight-medium)",
        color,
        backgroundColor: `color-mix(in srgb, ${color} 12%, transparent)`,
        border: `1px solid color-mix(in srgb, ${color} 25%, transparent)`,
        padding: "2px 6px",
        borderRadius: "4px",
        textTransform: "capitalize",
      }}
    >
      {intensity}
    </span>
  );
}

function formatAbsolute(iso: string | Date): string {
  const d = typeof iso === "string" ? new Date(iso) : iso;
  if (Number.isNaN(d.getTime())) return String(iso);
  return d.toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
}

function formatRelative(iso: string | Date): string {
  const d = typeof iso === "string" ? new Date(iso) : iso;
  if (Number.isNaN(d.getTime())) return "";
  const diffMs = d.getTime() - Date.now();
  const abs = Math.abs(diffMs);
  const past = diffMs < 0;
  const mins = Math.round(abs / 60000);
  if (mins < 1) return past ? "just now" : "in <1 min";
  if (mins < 60) return past ? `${mins} min ago` : `in ${mins} min`;
  const hrs = Math.round(mins / 60);
  if (hrs < 24) return past ? `${hrs} hr ago` : `in ${hrs} hr`;
  const days = Math.round(hrs / 24);
  return past ? `${days} day${days === 1 ? "" : "s"} ago` : `in ${days} day${days === 1 ? "" : "s"}`;
}

/**
 * Compute the next top-of-hour and next midnight (local) as fallback estimates
 * when the backend doesn't return explicit next-run timestamps. Labelled as
 * estimates in the UI so users don't treat them as authoritative.
 */
function computeNextRuns(now: Date = new Date()): { hourly: Date; daily: Date } {
  const hourly = new Date(now);
  hourly.setMinutes(0, 0, 0);
  hourly.setHours(hourly.getHours() + 1);
  const daily = new Date(now);
  daily.setHours(0, 0, 0, 0);
  daily.setDate(daily.getDate() + 1);
  return { hourly, daily };
}

interface InferredRun {
  bucket: string;
  started_at: Date;
  devices_seen: number;
  devices_flagged: number;
  devices: ConnectedDevice[];
}

/**
 * Group inventory devices by their `last_seen` rounded to the minute. Each
 * group is treated as one inferred scan run — after a scan completes, every
 * touched device's last_seen advances to roughly the same timestamp, so
 * clustering by minute gives a reasonable approximation of run history.
 */
function deriveRunsFromInventory(devices: ConnectedDevice[]): InferredRun[] {
  const buckets = new Map<string, InferredRun>();
  for (const d of devices) {
    const parsed = new Date(d.last_seen);
    if (Number.isNaN(parsed.getTime())) continue;
    parsed.setSeconds(0, 0);
    const key = parsed.toISOString();
    const existing = buckets.get(key);
    const flagged = isUnauthorized(d) ? 1 : 0;
    if (existing) {
      existing.devices_seen += 1;
      existing.devices_flagged += flagged;
      existing.devices.push(d);
    } else {
      buckets.set(key, {
        bucket: key,
        started_at: parsed,
        devices_seen: 1,
        devices_flagged: flagged,
        devices: [d],
      });
    }
  }
  return Array.from(buckets.values())
    .sort((a, b) => b.started_at.getTime() - a.started_at.getTime())
    .slice(0, 10);
}

/**
 * Approximate the device list belonging to a backend-reported ScheduleRun by
 * filtering the current inventory to devices whose `last_seen` falls inside
 * the run window. Adds a 60s slack after `finished_at` so devices touched at
 * the tail of the scan are still included.
 */
function resolveDevicesForRun(run: ScheduleRun, inventory: ConnectedDevice[]): ConnectedDevice[] {
  const start = new Date(run.started_at).getTime();
  if (Number.isNaN(start)) return [];
  const end = run.finished_at ? new Date(run.finished_at).getTime() : Date.now();
  const endWithSlack = Number.isNaN(end) ? Date.now() : end + 60_000;
  return inventory.filter((d) => {
    const t = new Date(d.last_seen).getTime();
    return !Number.isNaN(t) && t >= start && t <= endWithSlack;
  });
}

/**
 * Compact per-device row inside the run details dialog. Deliberately simpler
 * than the Inventory `DeviceCard` so many devices fit at once, but still shows
 * the essentials (address + status + open-port count) and offers Approve for
 * unauthorized entries.
 */
function RunDeviceRow({
  device,
  onApprove,
  onOpenDetail,
}: {
  device: ConnectedDevice;
  onApprove: (d: ConnectedDevice) => void;
  onOpenDetail: (d: ConnectedDevice) => void;
}) {
  const flagged = isUnauthorized(device);
  const openPortCount = device.open_ports?.length ?? 0;
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={() => onOpenDetail(device)}
      onKeyDown={(e) => {
        if (e.key === "Enter" || e.key === " ") {
          e.preventDefault();
          onOpenDetail(device);
        }
      }}
      className="rounded-md border p-2.5 flex items-center gap-3"
      style={{ backgroundColor: "var(--background)", borderColor: "var(--border)", cursor: "pointer" }}
    >
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
            {device.ip || "—"}
          </span>
          <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--muted-foreground)" }}>
            {device.mac || "—"}
          </span>
          <StatusBadge status={device.status} />
        </div>
        <div className="flex items-center gap-2 mt-1 flex-wrap">
          {device.hostname && (
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>
              {device.hostname}
            </span>
          )}
          {device.vendor && (
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              {device.vendor}
            </span>
          )}
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>
            {openPortCount} open port{openPortCount === 1 ? "" : "s"}
          </span>
        </div>
      </div>
      {flagged && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            onApprove(device);
          }}
          className="flex items-center gap-1 px-2.5 py-1.5 rounded-md flex-shrink-0"
          style={{
            backgroundColor: "color-mix(in srgb, var(--chart-2) 12%, transparent)",
            border: "1px solid color-mix(in srgb, var(--chart-2) 25%, transparent)",
            color: "var(--chart-2)",
            cursor: "pointer",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            fontWeight: "var(--font-weight-medium)",
          }}
        >
          <Check size={12} /> Approve
        </button>
      )}
    </div>
  );
}

interface RunDetails {
  title: string;
  subtitle: string;
  intensity?: string;
  status?: ScheduleRunStatus;
  startedAt: Date;
  finishedAt?: Date | null;
  errorMessage?: string;
  devices: ConnectedDevice[];
  approximate: boolean;
}

function RunDetailsDialog({
  details,
  onClose,
  onApprove,
  onOpenDetail,
}: {
  details: RunDetails | null;
  onClose: () => void;
  onApprove: (d: ConnectedDevice) => void;
  onOpenDetail: (d: ConnectedDevice) => void;
}) {
  if (!details) return null;
  const flaggedCount = details.devices.filter(isUnauthorized).length;
  return (
    <Dialog.Root open={!!details} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay style={{ position: "fixed", inset: 0, backgroundColor: "rgba(0,0,0,0.5)", zIndex: 50 }} />
        <Dialog.Content
          style={{
            position: "fixed",
            top: "50%",
            left: "50%",
            transform: "translate(-50%, -50%)",
            width: "calc(100vw - 32px)",
            maxWidth: "720px",
            maxHeight: "calc(100vh - 64px)",
            overflowY: "auto",
            backgroundColor: "var(--card)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-card, 12px)",
            padding: "20px",
            zIndex: 51,
          }}
        >
          <div className="flex items-start justify-between gap-3 mb-4">
            <div className="min-w-0 flex-1">
              <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
                {details.title}
              </Dialog.Title>
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "2px" }}>
                {details.subtitle}
              </p>
            </div>
            <button
              onClick={onClose}
              title="Close"
              className="flex items-center justify-center rounded-md flex-shrink-0"
              style={{ width: "28px", height: "28px", backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)", cursor: "pointer" }}
            >
              <X size={13} />
            </button>
          </div>

          <div className="grid grid-cols-2 gap-x-4 gap-y-3 mb-4">
            <DetailInfoRow label="Started" value={formatAbsolute(details.startedAt)} mono />
            <DetailInfoRow
              label="Finished"
              value={details.finishedAt ? formatAbsolute(details.finishedAt) : "—"}
              mono
            />
            {details.intensity && <DetailInfoRow label="Intensity" value={details.intensity} />}
            {details.status && <DetailInfoRow label="Status" value={details.status} />}
          </div>

          {details.errorMessage && (
            <div
              className="rounded-md p-2.5 mb-4"
              style={{
                backgroundColor: "color-mix(in srgb, var(--destructive) 8%, transparent)",
                border: "1px solid color-mix(in srgb, var(--destructive) 22%, transparent)",
              }}
            >
              <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "11px", color: "var(--destructive)", whiteSpace: "pre-wrap", wordBreak: "break-word", margin: 0 }}>
                {guardianDisplayText(details.errorMessage)}
              </p>
            </div>
          )}

          {details.approximate && (
            <div
              className="flex items-start gap-2 rounded-md p-2.5 mb-4"
              style={{
                backgroundColor: "color-mix(in srgb, var(--chart-4) 8%, transparent)",
                border: "1px solid color-mix(in srgb, var(--chart-4) 22%, transparent)",
              }}
            >
              <AlertTriangle size={14} style={{ color: "var(--chart-4)", flexShrink: 0, marginTop: "2px" }} />
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>
                Devices shown are inferred from the current inventory's <code style={{ fontFamily: "JetBrains Mono, monospace" }}>last_seen</code> timestamps and may not exactly match what this run touched.
              </p>
            </div>
          )}

          <DetailSection title="Devices in this run" count={details.devices.length}>
            {details.devices.length === 0 ? (
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                No devices were associated with this run.
              </p>
            ) : (
              <div className="flex flex-col gap-2">
                {flaggedCount > 0 && (
                  <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--destructive)" }}>
                    {flaggedCount} unauthorized / drifted
                  </p>
                )}
                {details.devices.map((d) => (
                  <RunDeviceRow
                    key={d.device_id || `${d.mac}-${d.ip}`}
                    device={d}
                    onApprove={onApprove}
                    onOpenDetail={onOpenDetail}
                  />
                ))}
              </div>
            )}
          </DetailSection>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function RunsTab({ onEditSchedule }: { onEditSchedule: () => void }) {
  const schedule = useDiscoverySchedule();
  const runs = useDiscoveryScheduleRuns();
  const devices = useDiscoveryDevices();
  const [selectedRun, setSelectedRun] = useState<RunDetails | null>(null);
  const [approveTarget, setApproveTarget] = useState<ConnectedDevice | null>(null);
  const [detailTarget, setDetailTarget] = useState<ConnectedDevice | null>(null);

  const cfg = useMemo(() => (schedule.data ? normalizeScheduleForm(schedule.data) : null), [schedule.data]);
  const enabled = !!cfg?.enabled;
  const realRuns: ScheduleRun[] | null = useMemo(() => {
    if (!runs.data || !Array.isArray(runs.data) || runs.data.length === 0) return null;
    // /discovery/runs carries only timestamps. Enrich any run that lines up with
    // the local manual-scan record (~2 min window) so its intensity/trigger show.
    const record = loadLastRun();
    if (!record) return runs.data;
    const isIntensity = (INTENSITIES as readonly string[]).includes(record.key);
    return runs.data.map((r) => {
      const near = Math.abs(new Date(r.started_at).getTime() - record.at) < 120_000;
      if (!near) return r;
      return {
        ...r,
        intensity: isIntensity ? (record.key as DiscoveryIntensity) : r.intensity,
        trigger: r.trigger ?? "manual",
      };
    });
  }, [runs.data]);
  const inferredRuns = useMemo(() => deriveRunsFromInventory(devices.data ?? []), [devices.data]);
  const upcomingScans = useMemo(() => buildUpcomingScheduledScans(cfg), [cfg]);

  const openRealRun = (run: ScheduleRun) => {
    const runDevices = resolveDevicesForRun(run, devices.data ?? []);
    const title = run.trigger
      ? `${run.trigger[0].toUpperCase()}${run.trigger.slice(1)} scan`
      : "Discovery scan";
    setSelectedRun({
      title,
      subtitle: formatAbsolute(new Date(run.started_at)),
      intensity: run.intensity,
      status: run.status,
      startedAt: new Date(run.started_at),
      finishedAt: run.finished_at ? new Date(run.finished_at) : null,
      errorMessage: run.error_message,
      devices: runDevices,
      // The runs archive records only a timestamp, not per-run device IDs, so the
      // device list is reconstructed from inventory last_seen — approximate.
      approximate: true,
    });
  };

  const openInferredRun = (run: InferredRun) => {
    setSelectedRun({
      title: "Inferred scan run",
      subtitle: `Grouped from ${run.devices_seen} device${run.devices_seen === 1 ? "" : "s"} last seen at ${formatAbsolute(run.started_at)}`,
      startedAt: run.started_at,
      devices: run.devices,
      approximate: true,
    });
  };

  if (schedule.loading && !cfg) {
    return (
      <div className="flex items-center justify-center py-10">
        <Loader2 className="animate-spin" size={24} style={{ color: "var(--primary)" }} />
      </div>
    );
  }

  const labelStyle = {
    fontFamily: "Inter, sans-serif",
    fontSize: "var(--text-xs)",
    color: "var(--muted-foreground)",
    fontWeight: "var(--font-weight-medium)",
  } as const;

  return (
    <div className="flex flex-col gap-4">
      {/* ─── Schedule status ─────────────────────────────────────────────── */}
      <div className="rounded-lg border p-4" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
        <div className="flex items-start justify-between gap-3 mb-3">
          <div className="flex items-center gap-2">
            <Clock size={16} style={{ color: "var(--primary)" }} />
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              Schedule status
            </p>
          </div>
          <span
            className="flex items-center gap-1"
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              fontWeight: "var(--font-weight-medium)",
              color: enabled ? "var(--chart-2)" : "var(--muted-foreground)",
              backgroundColor: enabled
                ? "color-mix(in srgb, var(--chart-2) 12%, transparent)"
                : "var(--muted)",
              border: enabled
                ? "1px solid color-mix(in srgb, var(--chart-2) 25%, transparent)"
                : "1px solid var(--border)",
              padding: "2px 8px",
              borderRadius: "6px",
            }}
          >
            {enabled ? <Power size={12} /> : <CircleSlash size={12} />}
            {enabled ? "Enabled" : "Disabled"}
          </span>
        </div>

        <div className="grid grid-cols-2 gap-x-4 gap-y-2 mb-3">
          <div>
            <p style={labelStyle}>Target CIDR</p>
            <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>
              {cfg?.target_cidr || "auto-detect LAN"}
            </p>
          </div>
          <div>
            <p style={labelStyle}>Timeout</p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>
              {cfg?.timeout_secs ?? "—"}s
            </p>
          </div>
          <div className="col-span-2">
            <p style={labelStyle}>Exclude</p>
            <div className="flex flex-wrap gap-1 mt-1">
              {(cfg?.exclude ?? []).length === 0 ? (
                <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>None</span>
              ) : (
                cfg!.exclude.map((ip) => <Chip key={ip}>{ip}</Chip>)
              )}
            </div>
          </div>
        </div>

        <div className="grid gap-2 mb-3 sm:grid-cols-2">
          <div
            className="rounded-md border p-2 flex items-center justify-between"
            style={{ backgroundColor: "var(--background)", borderColor: "var(--border)" }}
          >
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              Scan Intensity
            </span>
            <IntensityBadge intensity={cfg?.schedules.hourly.intensity ?? "—"} />
          </div>
          <div
            className="rounded-md border p-2 flex items-center justify-between"
            style={{ backgroundColor: "var(--background)", borderColor: "var(--border)" }}
          >
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              Schedule Intensity
            </span>
            <IntensityBadge intensity={cfg?.schedules.daily.intensity ?? "—"} />
          </div>
          <div
            className="rounded-md border p-2 sm:col-span-2"
            style={{ backgroundColor: "var(--background)", borderColor: "var(--border)" }}
          >
            <p style={labelStyle}>Scan Schedule</p>
            <div className="flex flex-col gap-1 mt-1">
              {cfg?.scan_schedules?.length ? (
                cfg.scan_schedules.map((task) => (
                  <p key={task.id} style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--foreground)" }}>
                    ✓ {frequencyLabel(task.frequency)} · {formatScheduleSummary(task)}
                  </p>
                ))
              ) : (
                <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                  No scheduled scans saved
                </p>
              )}
            </div>
          </div>
        </div>

        <button
          onClick={onEditSchedule}
          className="w-full flex items-center justify-center gap-1 py-2 rounded-md"
          style={{
            backgroundColor: "var(--muted)",
            border: "1px solid var(--border)",
            color: "var(--foreground)",
            cursor: "pointer",
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-xs)",
            fontWeight: "var(--font-weight-medium)",
          }}
        >
          <Settings2 size={12} /> Edit schedule
        </button>
      </div>

      {/* ─── Next scheduled scans ───────────────────────────────────────── */}
      {enabled && (
        <div className="rounded-lg border p-4" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
          <div className="flex items-center gap-2 mb-3">
            <CalendarClock size={16} style={{ color: "var(--primary)" }} />
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              Upcoming scheduled scans
            </p>
          </div>

          <div className="flex flex-col gap-2">
            {upcomingScans.map((scan) => (
              <div key={scan.id} className="rounded-md border p-3" style={{ backgroundColor: "var(--background)", borderColor: "var(--border)" }}>
                <div className="flex items-start justify-between gap-3">
                  <div className="min-w-0 flex-1">
                    <div className="flex items-center gap-2">
                      <Check size={14} style={{ color: "var(--foreground)", flexShrink: 0 }} />
                      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", lineHeight: 1.4 }}>
                        {scan.label}
                      </p>
                    </div>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)", lineHeight: 1.4, marginTop: "2px", paddingLeft: "22px" }}>
                      {scan.scheduleText}
                    </p>
                    <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.4, marginTop: "2px", paddingLeft: "22px" }}>
                      Next run: {scan.nextRunText}
                      {scan.relativeText ? ` (${scan.relativeText})` : ""}
                    </p>
                  </div>
                  <IntensityBadge intensity={scan.intensity} />
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ─── Run history ─────────────────────────────────────────────────── */}
      <div className="rounded-lg border p-4" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-2">
            <History size={16} style={{ color: "var(--primary)" }} />
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              Run history
            </p>
          </div>
          <button
            onClick={() => {
              runs.refetch();
              devices.refetch();
            }}
            className="flex items-center gap-1 px-2 py-1 rounded-md"
            style={{
              backgroundColor: "var(--muted)",
              border: "1px solid var(--border)",
              color: "var(--muted-foreground)",
              cursor: "pointer",
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
            }}
          >
            <RefreshCw size={12} /> Refresh
          </button>
        </div>

        {realRuns ? (
          <div className="flex flex-col gap-2">
            {realRuns.map((r) => (
              <ScheduleRunCard key={r.run_id} run={r} onClick={() => openRealRun(r)} />
            ))}
          </div>
        ) : (
          <>
            {/* Inferred from inventory — flagged as approximate */}
            <div
              className="flex items-start gap-2 rounded-md p-2.5 mb-3"
              style={{
                backgroundColor: "color-mix(in srgb, var(--chart-4) 8%, transparent)",
                border: "1px solid color-mix(in srgb, var(--chart-4) 22%, transparent)",
              }}
            >
              <AlertTriangle size={14} style={{ color: "var(--chart-4)", flexShrink: 0, marginTop: "2px" }} />
              <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", lineHeight: 1.5 }}>
                Backend run history is not available yet — showing runs inferred from inventory <code style={{ fontFamily: "JetBrains Mono, monospace" }}>last_seen</code> timestamps. Each entry below is one batch of devices last touched at the same minute, which usually corresponds to one scan.
              </p>
            </div>

            {devices.loading && !devices.data ? (
              <div className="flex items-center justify-center py-6">
                <Loader2 className="animate-spin" size={20} style={{ color: "var(--primary)" }} />
              </div>
            ) : inferredRuns.length === 0 ? (
              <div className="text-center py-6">
                <History size={28} style={{ color: "var(--muted-foreground)", margin: "0 auto 8px" }} />
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>
                  No scan activity yet
                </p>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "4px" }}>
                  {enabled
                    ? "Waiting for the first scheduled run to complete."
                    : "Scheduled scans are disabled. Run a manual scan from the Inventory tab or enable the schedule."}
                </p>
              </div>
            ) : (
              <div className="flex flex-col gap-2">
                {inferredRuns.map((r) => (
                  <div
                    key={r.bucket}
                    role="button"
                    tabIndex={0}
                    onClick={() => openInferredRun(r)}
                    onKeyDown={(e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        openInferredRun(r);
                      }
                    }}
                    className="flex items-center justify-between rounded-md border p-2.5"
                    style={{ backgroundColor: "var(--background)", borderColor: "var(--border)", cursor: "pointer" }}
                  >
                    <div className="flex flex-col">
                      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>
                        {formatAbsolute(r.started_at)}
                      </span>
                      <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>
                        {formatRelative(r.started_at)} · inferred
                      </span>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="flex items-center gap-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
                        <Server size={12} /> {r.devices_seen}
                      </span>
                      {r.devices_flagged > 0 && (
                        <span className="flex items-center gap-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--destructive)" }}>
                          <ShieldAlert size={12} /> {r.devices_flagged}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </>
        )}
      </div>

      <RunDetailsDialog
        details={selectedRun}
        onClose={() => setSelectedRun(null)}
        onApprove={(d) => {
          setSelectedRun(null);
          setApproveTarget(d);
        }}
        onOpenDetail={(d) => setDetailTarget(d)}
      />

      <DeviceDetailDialog
        device={detailTarget}
        onClose={() => setDetailTarget(null)}
        onApprove={(d) => {
          setDetailTarget(null);
          setSelectedRun(null);
          setApproveTarget(d);
        }}
      />

      <ApproveDialog
        device={approveTarget}
        onClose={() => setApproveTarget(null)}
        onApproved={() => {
          setApproveTarget(null);
          devices.refetch();
          runs.refetch();
        }}
      />
    </div>
  );
}

function ScheduleRunCard({ run, onClick }: { run: ScheduleRun; onClick?: () => void }) {
  const statusColor =
    run.status === "success"
      ? "var(--chart-2)"
      : run.status === "failure"
        ? "var(--destructive)"
        : "var(--chart-4)";
  const StatusIcon = run.status === "success" ? ShieldCheck : run.status === "failure" ? ShieldAlert : Loader2;

  return (
    <div
      role={onClick ? "button" : undefined}
      tabIndex={onClick ? 0 : undefined}
      onClick={onClick}
      onKeyDown={(e) => {
        if (onClick && (e.key === "Enter" || e.key === " ")) {
          e.preventDefault();
          onClick();
        }
      }}
      className="flex flex-col gap-2 rounded-md border p-3"
      style={{ backgroundColor: "var(--background)", borderColor: "var(--border)", cursor: onClick ? "pointer" : "default" }}
    >
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <StatusIcon
            size={14}
            className={run.status === "running" ? "animate-spin" : undefined}
            style={{ color: statusColor }}
          />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", textTransform: "capitalize" }}>
            {run.trigger ? `${run.trigger} · ${run.status}` : run.status}
          </span>
          {run.intensity && <IntensityBadge intensity={run.intensity} />}
        </div>
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)" }}>
          {formatRelative(run.started_at)}
        </span>
      </div>
      <div className="flex items-center justify-between">
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
          {formatAbsolute(run.started_at)}
        </span>
        <div className="flex items-center gap-3">
          {run.devices_found != null && (
            <span className="flex items-center gap-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
              <Server size={12} /> {run.devices_found}
            </span>
          )}
          {(run.devices_new ?? 0) > 0 && (
            <span className="flex items-center gap-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--chart-2)" }}>
              <Check size={12} /> {run.devices_new} new
            </span>
          )}
          {(run.devices_flagged ?? 0) > 0 && (
            <span className="flex items-center gap-1" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--destructive)" }}>
              <ShieldAlert size={12} /> {run.devices_flagged}
            </span>
          )}
        </div>
      </div>
      {run.error_message && (
        <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "10px", color: "var(--destructive)" }}>
          {guardianDisplayText(run.error_message)}
        </p>
      )}
    </div>
  );
}

// ── Screen ────────────────────────────────────────────────────────────────────

const TABS: { key: Tab; label: string }[] = [
  { key: "inventory", label: "Inventory" },
  { key: "whitelist", label: "Whitelist" },
  { key: "schedule", label: "Schedule" },
  { key: "runs", label: "Runs" },
];

function ScanTargetDialog({
  pending,
  onCancel,
  onConfirm,
}: {
  pending: { key: ScanKey; label: string } | null;
  onCancel: () => void;
  onConfirm: (target: string | undefined) => void;
}) {
  const [target, setTarget] = useState("");

  useEffect(() => {
    if (pending) setTarget("");
  }, [pending]);

  const trimmed = target.trim();

  return (
    <Dialog.Root open={!!pending} onOpenChange={(o) => !o && onCancel()}>
      <Dialog.Portal>
        <Dialog.Overlay style={{ position: "fixed", inset: 0, backgroundColor: "rgba(0,0,0,0.5)", zIndex: 50 }} />
        <Dialog.Content
          style={{
            position: "fixed",
            top: "50%",
            left: "50%",
            transform: "translate(-50%, -50%)",
            width: "calc(100vw - 32px)",
            maxWidth: "420px",
            backgroundColor: "var(--card)",
            border: "1px solid var(--border)",
            borderRadius: "var(--radius-card, 12px)",
            padding: "20px",
            zIndex: 51,
          }}
        >
          <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", marginBottom: "4px" }}>
            Run {pending?.label} scan
          </Dialog.Title>
          <Dialog.Description style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginBottom: "16px" }}>
            Optionally target a specific IP or CIDR. Leave blank to use the configured LAN.
          </Dialog.Description>

          <label htmlFor="scan-target" style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>
            Target IP or CIDR (optional)
          </label>
          <input
            id="scan-target"
            autoFocus
            value={target}
            onChange={(e) => setTarget(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") onConfirm(trimmed || undefined);
            }}
            placeholder="e.g. 192.168.50.100 or 192.168.50.0/24"
            className="w-full mt-1 mb-4 px-3 py-2 rounded-md"
            style={{ backgroundColor: "var(--background)", border: "1px solid var(--border)", color: "var(--foreground)", fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)" }}
          />

          <div className="flex items-center justify-end gap-2">
            <button
              onClick={onCancel}
              className="flex items-center gap-1 px-3 py-2 rounded-md"
              style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)" }}
            >
              <X size={12} /> Cancel
            </button>
            <button
              onClick={() => onConfirm(trimmed || undefined)}
              className="flex items-center gap-1 px-3 py-2 rounded-md"
              style={{ backgroundColor: "var(--primary)", color: "var(--primary-foreground)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)" }}
            >
              <Radar size={12} /> Run scan
            </button>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

function formatElapsed(ms: number) {
  const totalSecs = Math.max(0, Math.floor(ms / 1000));
  const mins = Math.floor(totalSecs / 60);
  const secs = totalSecs % 60;
  return mins > 0 ? `${mins}m ${secs.toString().padStart(2, "0")}s` : `${secs}s`;
}

function ScanStatusBanner({ run, now }: { run: ScanRun; now: number }) {
  const running = !run.endedAt;
  const elapsed = (run.endedAt ?? now) - run.startedAt;
  const isError = run.result === "error";
  const accent = running ? "var(--primary)" : isError ? "var(--destructive)" : "var(--chart-2)";
  const Icon = running ? Loader2 : isError ? CircleX : CircleCheck;

  return (
    <div
      className="rounded-lg border p-3 flex items-center gap-3"
      style={{
        backgroundColor: `color-mix(in srgb, ${accent} 8%, var(--card))`,
        borderColor: `color-mix(in srgb, ${accent} 30%, var(--border))`,
      }}
    >
      <Icon
        size={18}
        className={running ? "animate-spin" : undefined}
        style={{ color: accent, flexShrink: 0 }}
      />
      <div className="flex-1 min-w-0">
        <p
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "var(--text-sm)",
            fontWeight: "var(--font-weight-semibold)",
            color: "var(--foreground)",
          }}
        >
          {run.label} scan {running ? "running…" : isError ? "failed" : "completed"}
          {run.target && (
            <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", fontWeight: "var(--font-weight-medium)", marginLeft: "8px" }}>
              → {run.target}
            </span>
          )}
        </p>
        {!running && run.message && (
          <p
            style={{
              fontFamily: "Inter, sans-serif",
              fontSize: "var(--text-xs)",
              color: "var(--muted-foreground)",
              marginTop: "2px",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            }}
            title={guardianDisplayText(run.message)}
          >
            {guardianDisplayText(run.message)}
          </p>
        )}
      </div>
      <div className="text-right flex-shrink-0">
        <p
          style={{
            fontFamily: "JetBrains Mono, monospace",
            fontSize: "var(--text-sm)",
            fontWeight: "var(--font-weight-semibold)",
            color: accent,
          }}
        >
          {formatElapsed(elapsed)}
        </p>
        <p
          style={{
            fontFamily: "Inter, sans-serif",
            fontSize: "10px",
            color: "var(--muted-foreground)",
          }}
        >
          {running ? "elapsed" : "time taken"}
        </p>
      </div>
    </div>
  );
}

export function NW07Discovery() {
  const navigate = useNavigate();
  const [tab, setTab] = useState<Tab>("inventory");

  const devicesQuery = useDiscoveryDevices();
  const whitelistQuery = useDiscoveryWhitelist();
  const runsQuery = useDiscoveryScheduleRuns();
  const summaryQuery = useDiscoverySummary();
  const realLastRun = runsQuery.data && runsQuery.data.length > 0 ? runsQuery.data[0] : null;
  const whitelistCount = whitelistQuery.data?.devices.length ?? null;

  // Scan state lives in a module-level store (useDiscoveryScan) so it survives
  // this screen unmounting — e.g. switching Settings panels while a scan runs.
  const { run: scanRun, scanning, lastRun, completedAt, startScan } = useDiscoveryScan();
  const [now, setNow] = useState(() => Date.now());
  const [pendingScan, setPendingScan] = useState<{ key: ScanKey; label: string } | null>(null);

  // Tick the elapsed clock while a scan is in flight (banner is mounted).
  useEffect(() => {
    if (!scanRun || scanRun.endedAt) return;
    setNow(Date.now());
    const id = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(id);
  }, [scanRun]);

  // When a scan completes (possibly while this screen was unmounted), refresh
  // the inventory-derived views. Guard on completedAt so we only refetch on an
  // actual completion, not on every mount.
  const lastCompletedRef = useRef(completedAt);
  useEffect(() => {
    if (completedAt !== lastCompletedRef.current) {
      lastCompletedRef.current = completedAt;
      devicesQuery.refetch();
      runsQuery.refetch();
      summaryQuery.refetch();
      whitelistQuery.refetch();
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [completedAt]);

  /** Route a scan-button click: Default runs immediately; others prompt for target IP. */
  const requestScan = (key: ScanKey) => {
    if (scanning) return;
    const label = SCAN_BUTTONS.find((b) => b.key === key)?.label ?? key;
    if (key === "default") {
      void startScan(key, label);
      return;
    }
    setPendingScan({ key, label });
  };

  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Network Discovery" subtitle="Guardian Inventory" onBack={() => navigate("/network")} />

      <div className="flex-1 overflow-y-auto">
        <div className="mx-auto w-full max-w-4xl p-4 md:p-6 flex flex-col gap-4">
        {scanRun && <ScanStatusBanner run={scanRun} now={now} />}

        {/* Tabs */}
        <div className="flex items-center gap-1 p-1 rounded-lg" style={{ backgroundColor: "var(--muted)" }}>
          {TABS.map((t) => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className="flex-1 py-1.5 rounded-md"
              style={{
                backgroundColor: tab === t.key ? "var(--card)" : "transparent",
                color: tab === t.key ? "var(--foreground)" : "var(--muted-foreground)",
                border: tab === t.key ? "1px solid var(--border)" : "1px solid transparent",
                cursor: "pointer",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                fontWeight: "var(--font-weight-medium)",
              }}
            >
              {t.label}
            </button>
          ))}
        </div>

        {tab === "inventory" && (
          <InventoryTab
            data={devicesQuery.data}
            loading={devicesQuery.loading}
            error={devicesQuery.error}
            refetch={devicesQuery.refetch}
            scanning={scanning}
            onScan={requestScan}
            whitelistCount={whitelistCount}
            onApproved={() => {
              whitelistQuery.refetch();
              summaryQuery.refetch();
            }}
            lastRun={lastRun}
            realLastRun={realLastRun}
            summary={summaryQuery.data}
          />
        )}
        {tab === "whitelist" && (
          <WhitelistTab
            inventoryDevices={devicesQuery.data}
            data={whitelistQuery.data}
            loading={whitelistQuery.loading}
            error={whitelistQuery.error}
            refetch={whitelistQuery.refetch}
            onSaved={() => devicesQuery.refetch()}
          />
        )}
        {tab === "schedule" && <ScheduleTab />}
        {tab === "runs" && <RunsTab onEditSchedule={() => setTab("schedule")} />}
        </div>
      </div>

      <ScanTargetDialog
        pending={pendingScan}
        onCancel={() => setPendingScan(null)}
        onConfirm={(target) => {
          if (pendingScan) {
            void startScan(pendingScan.key, pendingScan.label, target);
            setPendingScan(null);
          }
        }}
      />
    </div>
  );
}

export default NW07Discovery;
