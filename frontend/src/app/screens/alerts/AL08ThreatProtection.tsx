import { useEffect, useMemo, useState } from "react";
import type { ReactNode } from "react";
import { useNavigate } from "react-router";
import * as Dialog from "@radix-ui/react-dialog";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  ShieldQuestion,
  Ban,
  Play,
  RefreshCw,
  CheckCircle2,
  Loader2,
  X,
  Plus,
  Server,
  Activity,
  Save,
  ArrowRight,
  ChevronRight,
} from "lucide-react";
import { PageHeader } from "../../components/PageHeader";
import {
  useThreatStatus,
  useThreatAlerts,
  useThreatBlocks,
  useThreatConfig,
} from "../../hooks/useApiData";
import { threatService } from "../../services/threatService";
import type {
  ThreatAlert,
  ThreatSeverity,
  ThreatConfig,
  ThreatBlockMode,
  ThreatActionResponse,
} from "../../services/threatService";
import { toast } from "sonner";

type Tab = "overview" | "alerts" | "blocks" | "config";

const TABS: { key: Tab; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "alerts", label: "IDS Alerts" },
  { key: "blocks", label: "Blocked IPs" },
  { key: "config", label: "Config" },
];

const SEVERITY_ORDER: ThreatSeverity[] = ["critical", "high", "medium", "low", "info"];

const SEVERITY_COLORS: Record<ThreatSeverity, string> = {
  critical: "var(--destructive)",
  high: "var(--chart-4)",
  medium: "var(--chart-5)",
  low: "var(--chart-2)",
  info: "var(--muted-foreground)",
};

function severityColor(sev: string): string {
  return SEVERITY_COLORS[sev as ThreatSeverity] ?? "var(--muted-foreground)";
}

/** Format an RFC-3339 timestamp compactly; falls back to the raw string. */
function formatTs(iso: string): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}

/**
 * Canonicalize an IP for comparison. IPv6 is expanded to 8 zero-padded groups
 * so that a compressed form (fe80::d26d:54b:67c0:573f) and a full form
 * (fe80:0000:0000:0000:d26d:054b:67c0:573f) of the same address compare equal.
 */
function canonicalIp(ip: string): string {
  const raw = (ip ?? "").trim().toLowerCase();
  if (!raw.includes(":")) return raw; // IPv4 or empty
  const bare = raw.replace(/^\[|\]$/g, "").split("%")[0]; // strip brackets + zone id
  let groups: string[];
  if (bare.includes("::")) {
    const [head, tail] = bare.split("::");
    const h = head ? head.split(":") : [];
    const t = tail ? tail.split(":") : [];
    const missing = 8 - h.length - t.length;
    if (missing < 0) return bare;
    groups = [...h, ...Array(missing).fill("0"), ...t];
  } else {
    groups = bare.split(":");
  }
  if (groups.length !== 8) return bare;
  return groups.map((g) => (g || "0").padStart(4, "0")).join(":");
}

/** Surface a ThreatActionResponse as a toast, respecting its success flag. */
function toastAction(res: ThreatActionResponse, okTitle: string) {
  const detail = (res.stdout || res.stderr || "").split("\n").find((l) => l.trim());
  if (res.success) {
    toast.success(okTitle, {
      description: [detail, res.restartRequired ? "Restart required." : null].filter(Boolean).join(" · ") || undefined,
    });
  } else {
    toast.error(`${okTitle} failed`, { description: res.stderr || detail || undefined });
  }
}

// ── Badges ──────────────────────────────────────────────────────────────────────

function Pill({ color, icon: Icon, children }: { color: string; icon?: typeof Shield; children: ReactNode }) {
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
      {Icon && <Icon size={12} />}
      {children}
    </span>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const color = severityColor(severity);
  return (
    <span
      style={{
        fontFamily: "Inter, sans-serif",
        fontSize: "10px",
        fontWeight: "var(--font-weight-semibold)",
        color,
        backgroundColor: `color-mix(in srgb, ${color} 12%, transparent)`,
        border: `1px solid color-mix(in srgb, ${color} 25%, transparent)`,
        padding: "2px 7px",
        borderRadius: "5px",
        textTransform: "uppercase",
        letterSpacing: "0.04em",
      }}
    >
      {severity}
    </span>
  );
}

function suricataVisual(state: string) {
  const s = (state || "").toLowerCase();
  if (s === "active") return { color: "var(--chart-2)", label: "Active", Icon: ShieldCheck };
  if (s === "inactive") return { color: "var(--destructive)", label: "Inactive", Icon: ShieldAlert };
  if (s === "tailer-only") return { color: "var(--primary)", label: "Tailer only", Icon: ShieldQuestion };
  return { color: "var(--muted-foreground)", label: state || "Unknown", Icon: ShieldQuestion };
}

// ── Overview tab ──────────────────────────────────────────────────────────────

function OverviewTab({ onManageConfig }: { onManageConfig: () => void }) {
  const status = useThreatStatus();
  const [busy, setBusy] = useState<null | "start" | "validate" | "rules">(null);

  const s = status.data;
  const sv = suricataVisual(s?.suricata ?? "");
  const showStart = !!s && s.suricata.toLowerCase() !== "active" && (s.can_start ?? true);
  const showValidate = !!s && (s.can_validate ?? true);
  const showRules = !!s && (s.can_update_rules ?? true);
  const supportedActions = [showStart, showValidate, showRules].filter(Boolean).length;

  const run = async (
    kind: "start" | "validate" | "rules",
    fn: () => Promise<ThreatActionResponse>,
    okTitle: string,
  ) => {
    setBusy(kind);
    try {
      toastAction(await fn(), okTitle);
      status.refetch();
    } catch (err) {
      toast.error(`${okTitle} failed`, { description: err instanceof Error ? err.message : undefined });
    } finally {
      setBusy(null);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      <div className="rounded-lg border p-4" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
        <div className="flex items-center justify-between gap-3 mb-4">
          <div className="flex items-center gap-2">
            <Shield size={16} style={{ color: "var(--primary)" }} />
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
              Suricata engine
            </p>
            {status.loading && !s && <Loader2 className="animate-spin" size={13} style={{ color: "var(--muted-foreground)" }} />}
          </div>
          <Pill color={sv.color} icon={sv.Icon}>{sv.label}</Pill>
        </div>

        {status.error && !s ? (
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--muted-foreground)" }}>
            Couldn't load threat status ({status.error.message}).
          </p>
        ) : (
          <>
            <div className="grid grid-cols-2 gap-3 mb-4">
              <StatTile label="Alerts" value={s?.alert_count ?? 0} color="var(--chart-4)" Icon={Activity} />
              <StatTile label="Blocked IPs" value={s?.block_count ?? 0} color="var(--destructive)" Icon={Ban} />
            </div>
            <div className="flex items-center gap-2 flex-wrap mb-4">
              <Pill color={s?.enabled ? "var(--chart-2)" : "var(--muted-foreground)"} icon={s?.enabled ? ShieldCheck : ShieldQuestion}>
                {s?.enabled ? "Integration enabled" : "Integration disabled"}
              </Pill>
              <Pill color="var(--primary)">
                Block mode: {(s?.block_mode ?? "—").replace("_", " ")}
              </Pill>
              {s?.runtime_mode === "tailer_only" && (
                <Pill color="var(--primary)" icon={ShieldQuestion}>
                  Docker tailer mode
                </Pill>
              )}
            </div>

            {s?.runtime_note && (
              <p
                className="mb-4 rounded-md border px-3 py-2"
                style={{
                  fontFamily: "Inter, sans-serif",
                  fontSize: "var(--text-xs)",
                  color: "var(--muted-foreground)",
                  borderColor: "var(--border)",
                  backgroundColor: "color-mix(in srgb, var(--primary) 6%, var(--card))",
                }}
              >
                {s.runtime_note}
              </p>
            )}

            {supportedActions > 0 && (
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                {showStart && (
                  <ActionButton
                    busy={busy === "start"}
                    disabled={busy !== null}
                    icon={Play}
                    label="Start Suricata"
                    onClick={() => run("start", () => threatService.start(), "Suricata start")}
                  />
                )}
                {showValidate && (
                  <ActionButton
                    busy={busy === "validate"}
                    disabled={busy !== null}
                    icon={CheckCircle2}
                    label="Validate config"
                    onClick={() => run("validate", () => threatService.validate(), "Validation")}
                  />
                )}
                {showRules && (
                  <ActionButton
                    busy={busy === "rules"}
                    disabled={busy !== null}
                    icon={RefreshCw}
                    label="Update rules"
                    onClick={() => run("rules", () => threatService.updateRules(), "Rules update")}
                  />
                )}
              </div>
            )}
          </>
        )}
      </div>

      <button
        onClick={onManageConfig}
        className="w-full flex items-center justify-between rounded-lg border p-4"
        style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", cursor: "pointer" }}
      >
        <div className="flex items-center gap-2">
          <Server size={16} style={{ color: "var(--primary)" }} />
          <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>
            Threat configuration
          </span>
        </div>
        <ArrowRight size={16} style={{ color: "var(--muted-foreground)" }} />
      </button>
    </div>
  );
}

function StatTile({ label, value, color, Icon }: { label: string; value: number; color: string; Icon: typeof Shield }) {
  return (
    <div className="rounded-lg border p-3 text-center" style={{ backgroundColor: "var(--background)", borderColor: "var(--border)" }}>
      <Icon size={16} style={{ color, margin: "0 auto 6px" }} />
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-lg)", fontWeight: "var(--font-weight-bold)", color }}>{value}</p>
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{label}</p>
    </div>
  );
}

function ActionButton({
  busy,
  disabled,
  icon: Icon,
  label,
  onClick,
  danger,
}: {
  busy?: boolean;
  disabled?: boolean;
  icon: typeof Shield;
  label: string;
  onClick: () => void;
  danger?: boolean;
}) {
  const color = danger ? "var(--destructive)" : "var(--primary)";
  return (
    <button
      onClick={onClick}
      disabled={disabled}
      className="flex items-center justify-center gap-2 py-2 rounded-lg"
      style={{
        backgroundColor: `color-mix(in srgb, ${color} 10%, transparent)`,
        border: `1px solid color-mix(in srgb, ${color} 25%, transparent)`,
        color,
        cursor: disabled ? "not-allowed" : "pointer",
        opacity: disabled && !busy ? 0.5 : 1,
        fontFamily: "Inter, sans-serif",
        fontSize: "var(--text-xs)",
        fontWeight: "var(--font-weight-medium)",
      }}
    >
      {busy ? <Loader2 size={12} className="animate-spin" /> : <Icon size={12} />}
      {label}
    </button>
  );
}

// ── IDS Alerts tab ────────────────────────────────────────────────────────────

function AlertsTab({ onBlocked }: { onBlocked: () => void }) {
  const alertsQuery = useThreatAlerts({ limit: 500 });
  const blocksQuery = useThreatBlocks();
  const [severity, setSeverity] = useState<"all" | ThreatSeverity>("all");
  const [blockingIp, setBlockingIp] = useState<string | null>(null);
  const [detailAlert, setDetailAlert] = useState<ThreatAlert | null>(null);

  const alerts = alertsQuery.data ?? [];
  const shown = useMemo(() => {
    const list = severity === "all" ? alerts : alerts.filter((a) => a.severity === severity);
    // newest first
    return [...list].reverse();
  }, [alerts, severity]);

  // Canonicalized set of currently-blocked IPs, so an alert whose source is
  // already blocked shows "Blocked" instead of offering "Block IP" — even when
  // the block list and the alert use different IPv6 spellings.
  const blockedSet = useMemo(
    () => new Set((blocksQuery.data?.blocked ?? []).map(canonicalIp)),
    [blocksQuery.data],
  );
  const isBlocked = (a: ThreatAlert) => a.blocked || blockedSet.has(canonicalIp(a.src_ip));

  const blockIp = async (ip: string) => {
    setBlockingIp(ip);
    try {
      toastAction(await threatService.block(ip), `Blocked ${ip}`);
      alertsQuery.refetch();
      blocksQuery.refetch();
      onBlocked();
    } catch (err) {
      toast.error("Block failed", { description: err instanceof Error ? err.message : undefined });
    } finally {
      setBlockingIp(null);
    }
  };

  const is404 = alertsQuery.error?.message?.includes("404") || /no alerts yet/i.test(alertsQuery.error?.message ?? "");

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2">
          <ShieldAlert size={16} style={{ color: "var(--primary)" }} />
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
            IDS alerts
          </p>
          {alertsQuery.loading && !alertsQuery.data && <Loader2 className="animate-spin" size={13} style={{ color: "var(--muted-foreground)" }} />}
        </div>
        <div className="flex items-center gap-2">
          <select
            value={severity}
            onChange={(e) => setSeverity(e.target.value as "all" | ThreatSeverity)}
            className="outline-none"
            style={{ height: 32, backgroundColor: "var(--input-background)", border: "1px solid var(--border)", borderRadius: "var(--radius-sm)", color: "var(--foreground)", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", padding: "0 8px", cursor: "pointer" }}
          >
            <option value="all">All severities</option>
            {SEVERITY_ORDER.map((sv) => (
              <option key={sv} value={sv}>{sv}</option>
            ))}
          </select>
          <button
            onClick={() => alertsQuery.refetch()}
            className="flex items-center gap-1 px-2 py-1 rounded-md"
            style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)", cursor: "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)" }}
          >
            <RefreshCw size={12} /> Refresh
          </button>
        </div>
      </div>

      {is404 ? (
        <EmptyBox icon={ShieldCheck} title="No IDS alerts yet" subtitle="Suricata hasn't produced any events. Alerts appear here as the engine detects threats." />
      ) : alertsQuery.error && !alertsQuery.data ? (
        <EmptyBox icon={ShieldQuestion} title="Couldn't load alerts" subtitle={alertsQuery.error.message} />
      ) : shown.length === 0 ? (
        <EmptyBox icon={ShieldCheck} title="No matching alerts" subtitle="No alerts for the selected severity." />
      ) : (
        <div className="flex flex-col gap-2">
          {shown.map((a) => (
            <ThreatAlertCard key={a.alert_id} alert={a} blocked={isBlocked(a)} blocking={blockingIp === a.src_ip} onBlock={() => blockIp(a.src_ip)} onOpen={() => setDetailAlert(a)} />
          ))}
        </div>
      )}

      <ThreatAlertDetailDialog
        alert={detailAlert}
        blocked={!!detailAlert && isBlocked(detailAlert)}
        blocking={!!detailAlert && blockingIp === detailAlert.src_ip}
        onClose={() => setDetailAlert(null)}
        onBlock={() => {
          if (detailAlert) {
            void blockIp(detailAlert.src_ip);
            setDetailAlert(null);
          }
        }}
      />
    </div>
  );
}

function ThreatAlertCard({ alert, blocked, blocking, onBlock, onOpen }: { alert: ThreatAlert; blocked: boolean; blocking: boolean; onBlock: () => void; onOpen: () => void }) {
  return (
    <div
      role="button"
      tabIndex={0}
      onClick={onOpen}
      onKeyDown={(e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); onOpen(); } }}
      className="rounded-lg border p-3 flex flex-col gap-2 transition-colors"
      style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", cursor: "pointer" }}
      onMouseEnter={(e) => { e.currentTarget.style.borderColor = "color-mix(in srgb, var(--primary) 40%, var(--border))"; }}
      onMouseLeave={(e) => { e.currentTarget.style.borderColor = "var(--border)"; }}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2 flex-wrap mb-1">
            <SeverityBadge severity={alert.severity} />
            <Pill color="var(--muted-foreground)">{alert.category.replace("_", " ")}</Pill>
            {blocked && <Pill color="var(--destructive)" icon={Ban}>Blocked</Pill>}
          </div>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
            {alert.signature}
          </p>
          <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "2px" }}>
            {alert.src_ip}:{alert.src_port} → {alert.dst_ip}:{alert.dst_port} · {alert.protocol}
          </p>
          <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", marginTop: "3px" }}>
            SID {alert.signature_id} · {formatTs(alert.timestamp)}
          </p>
        </div>
        <div className="flex items-center gap-2 flex-shrink-0">
          {!blocked && (
            <button
              onClick={(e) => { e.stopPropagation(); onBlock(); }}
              disabled={blocking}
              className="flex items-center gap-1 px-2.5 py-1.5 rounded-md"
              style={{
                backgroundColor: "color-mix(in srgb, var(--destructive) 10%, transparent)",
                border: "1px solid color-mix(in srgb, var(--destructive) 25%, transparent)",
                color: "var(--destructive)",
                cursor: blocking ? "not-allowed" : "pointer",
                fontFamily: "Inter, sans-serif",
                fontSize: "var(--text-xs)",
                fontWeight: "var(--font-weight-medium)",
              }}
            >
              {blocking ? <Loader2 size={12} className="animate-spin" /> : <Ban size={12} />}
              Block IP
            </button>
          )}
          <ChevronRight size={16} style={{ color: "var(--muted-foreground)" }} />
        </div>
      </div>
    </div>
  );
}

/** Full detail modal for a single Suricata IDS alert. */
function ThreatAlertDetailDialog({ alert, blocked, blocking, onClose, onBlock }: { alert: ThreatAlert | null; blocked: boolean; blocking: boolean; onClose: () => void; onBlock: () => void }) {
  if (!alert) return null;
  const rows = [
    { label: "Source", value: `${alert.src_ip}:${alert.src_port}`, mono: true },
    { label: "Destination", value: `${alert.dst_ip}:${alert.dst_port}`, mono: true },
    { label: "Protocol", value: alert.protocol },
    { label: "Event Type", value: alert.event_type },
    { label: "Signature ID", value: String(alert.signature_id), mono: true },
    { label: "Rev · GID", value: `${alert.rev} · ${alert.gid}`, mono: true },
    { label: "Category", value: alert.category.replace("_", " ") },
    { label: "Detected", value: formatTs(alert.timestamp) },
  ];
  return (
    <Dialog.Root open={!!alert} onOpenChange={(o) => !o && onClose()}>
      <Dialog.Portal>
        <Dialog.Overlay style={{ position: "fixed", inset: 0, backgroundColor: "rgba(0,0,0,0.5)", zIndex: 50 }} />
        <Dialog.Content
          style={{
            position: "fixed", top: "50%", left: "50%", transform: "translate(-50%, -50%)",
            width: "calc(100vw - 32px)", maxWidth: "640px", maxHeight: "calc(100vh - 64px)", overflowY: "auto",
            backgroundColor: "var(--card)", border: "1px solid var(--border)", borderRadius: "var(--radius-card, 12px)", padding: "20px", zIndex: 51,
          }}
        >
          <div className="flex items-start justify-between gap-3 mb-4">
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap mb-2">
                <SeverityBadge severity={alert.severity} />
                <Pill color="var(--muted-foreground)">{alert.category.replace("_", " ")}</Pill>
                {blocked && <Pill color="var(--destructive)" icon={Ban}>Blocked</Pill>}
              </div>
              <Dialog.Title style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-base)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)", lineHeight: 1.3 }}>
                {alert.signature}
              </Dialog.Title>
            </div>
            <div className="flex items-center gap-2 flex-shrink-0">
              {!blocked && (
                <button
                  onClick={onBlock}
                  disabled={blocking}
                  className="flex items-center gap-1 px-2.5 py-1.5 rounded-md"
                  style={{ backgroundColor: "color-mix(in srgb, var(--destructive) 10%, transparent)", border: "1px solid color-mix(in srgb, var(--destructive) 25%, transparent)", color: "var(--destructive)", cursor: blocking ? "not-allowed" : "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)" }}
                >
                  {blocking ? <Loader2 size={12} className="animate-spin" /> : <Ban size={12} />} Block IP
                </button>
              )}
              <button onClick={onClose} title="Close" className="flex items-center justify-center rounded-md" style={{ width: "28px", height: "28px", backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)", cursor: "pointer" }}>
                <X size={14} />
              </button>
            </div>
          </div>

          {/* Flow summary */}
          <div className="rounded-lg border p-3 mb-4" style={{ backgroundColor: "var(--background)", borderColor: "var(--border)" }}>
            <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", color: "var(--foreground)", wordBreak: "break-all" }}>
              {alert.src_ip}:{alert.src_port} <span style={{ color: "var(--primary)" }}>→</span> {alert.dst_ip}:{alert.dst_port}
            </p>
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", marginTop: "2px", textTransform: "uppercase", letterSpacing: "0.04em" }}>
              {alert.protocol}
            </p>
          </div>

          {/* Details grid */}
          <div className="grid grid-cols-2 rounded-lg border border-border overflow-hidden" style={{ backgroundColor: "var(--background)" }}>
            {rows.map((row, i) => (
              <div key={row.label} className="px-3 py-2.5 min-w-0" style={{ borderRight: i % 2 === 0 ? "1px solid var(--border)" : undefined, borderBottom: i < rows.length - 2 ? "1px solid var(--border)" : undefined }}>
                <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", fontWeight: "var(--font-weight-medium)", textTransform: "uppercase", letterSpacing: "0.04em" }}>{row.label}</p>
                <p style={{ fontFamily: row.mono ? "JetBrains Mono, monospace" : "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)", fontWeight: "var(--font-weight-medium)", marginTop: "2px", wordBreak: "break-word" }}>{row.value}</p>
              </div>
            ))}
          </div>

          {/* Alert id */}
          <div className="mt-3">
            <p style={{ fontFamily: "Inter, sans-serif", fontSize: "10px", color: "var(--muted-foreground)", fontWeight: "var(--font-weight-medium)", textTransform: "uppercase", letterSpacing: "0.04em" }}>Alert ID</p>
            <p style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--foreground)", marginTop: "2px", wordBreak: "break-all" }}>{alert.alert_id}</p>
          </div>
        </Dialog.Content>
      </Dialog.Portal>
    </Dialog.Root>
  );
}

// ── Blocked IPs tab ─────────────────────────────────────────────────────────────

function BlocksTab({ onChanged }: { onChanged: () => void }) {
  const blocksQuery = useThreatBlocks();
  const [newIp, setNewIp] = useState("");
  const [busyIp, setBusyIp] = useState<string | null>(null);
  const [adding, setAdding] = useState(false);

  const blocked = blocksQuery.data?.blocked ?? [];

  const block = async () => {
    const ip = newIp.trim();
    if (!ip) return;
    setAdding(true);
    try {
      toastAction(await threatService.block(ip), `Blocked ${ip}`);
      setNewIp("");
      blocksQuery.refetch();
      onChanged();
    } catch (err) {
      toast.error("Block failed", { description: err instanceof Error ? err.message : undefined });
    } finally {
      setAdding(false);
    }
  };

  const unblock = async (ip: string) => {
    setBusyIp(ip);
    try {
      toastAction(await threatService.unblock(ip), `Unblocked ${ip}`);
    } catch (err) {
      // e.g. backend reports "not currently blocked" (block-list desync).
      toast.error("Unblock failed", { description: err instanceof Error ? err.message : undefined });
    } finally {
      // Reconcile the list either way so a stale/desynced entry drops off.
      blocksQuery.refetch();
      onChanged();
      setBusyIp(null);
    }
  };

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center gap-2">
        <Ban size={16} style={{ color: "var(--primary)" }} />
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
          Blocked IPs
        </p>
        {blocksQuery.loading && !blocksQuery.data && <Loader2 className="animate-spin" size={13} style={{ color: "var(--muted-foreground)" }} />}
      </div>

      {/* Add block */}
      <div className="flex items-center gap-2">
        <input
          value={newIp}
          onChange={(e) => setNewIp(e.target.value)}
          onKeyDown={(e) => { if (e.key === "Enter") block(); }}
          placeholder="e.g. 192.168.50.115"
          className="flex-1 px-3 py-2 rounded-md outline-none"
          style={{ backgroundColor: "var(--input-background)", border: "1px solid var(--border)", color: "var(--foreground)", fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)" }}
        />
        <button
          onClick={block}
          disabled={adding || !newIp.trim()}
          className="flex items-center gap-1 px-3 py-2 rounded-md"
          style={{ backgroundColor: "var(--primary)", color: "var(--primary-foreground)", cursor: adding || !newIp.trim() ? "not-allowed" : "pointer", opacity: !newIp.trim() ? 0.5 : 1, fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)" }}
        >
          {adding ? <Loader2 size={12} className="animate-spin" /> : <Plus size={12} />} Block IP
        </button>
      </div>

      {blocked.length === 0 ? (
        <EmptyBox icon={ShieldCheck} title="No active blocks" subtitle="Blocked IPs will appear here. Block one above, or from an IDS alert." />
      ) : (
        <div className="flex flex-col gap-2">
          {blocked.map((ip) => (
            <div key={ip} className="rounded-lg border p-3 flex items-center justify-between gap-3" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
              <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>{ip}</span>
              <button
                onClick={() => unblock(ip)}
                disabled={busyIp === ip}
                className="flex items-center gap-1 px-2.5 py-1.5 rounded-md"
                style={{ backgroundColor: "var(--muted)", border: "1px solid var(--border)", color: "var(--muted-foreground)", cursor: busyIp === ip ? "not-allowed" : "pointer", fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", fontWeight: "var(--font-weight-medium)" }}
              >
                {busyIp === ip ? <Loader2 size={12} className="animate-spin" /> : <X size={12} />} Unblock
              </button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Config tab ──────────────────────────────────────────────────────────────────

const fieldStyle = {
  backgroundColor: "var(--background)",
  border: "1px solid var(--border)",
  color: "var(--foreground)",
  fontFamily: "Inter, sans-serif",
  fontSize: "var(--text-sm)",
} as const;

const labelStyle = {
  fontFamily: "Inter, sans-serif",
  fontSize: "var(--text-xs)",
  color: "var(--muted-foreground)",
  fontWeight: "var(--font-weight-medium)",
} as const;

function ConfigTab({ onSaved }: { onSaved: () => void }) {
  const cfgQuery = useThreatConfig();
  const [form, setForm] = useState<ThreatConfig | null>(null);
  const [dirty, setDirty] = useState(false);
  const [saving, setSaving] = useState(false);

  useEffect(() => {
    if (cfgQuery.data && !dirty) setForm(cfgQuery.data);
  }, [cfgQuery.data, dirty]);

  const update = (patch: Partial<ThreatConfig>) => {
    setForm((f) => (f ? { ...f, ...patch } : f));
    setDirty(true);
  };

  const save = async () => {
    if (!form) return;
    setSaving(true);
    try {
      const res = await threatService.setConfig({
        enabled: form.enabled,
        block_mode: form.block_mode,
        block_ttl_secs: Number(form.block_ttl_secs),
        rule_update_hours: Number(form.rule_update_hours),
        block_exempt: form.block_exempt,
      });
      toastAction(res, "Config saved");
      setDirty(false);
      cfgQuery.refetch();
      onSaved();
    } catch (err) {
      toast.error("Save failed", { description: err instanceof Error ? err.message : undefined });
    } finally {
      setSaving(false);
    }
  };

  if (cfgQuery.loading && !form) {
    return (
      <div className="flex items-center justify-center py-10">
        <Loader2 className="animate-spin" size={24} style={{ color: "var(--primary)" }} />
      </div>
    );
  }
  if (!form) {
    return <EmptyBox icon={ShieldQuestion} title="Couldn't load config" subtitle={cfgQuery.error?.message ?? "No configuration available."} />;
  }

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-center gap-2">
        <Server size={16} style={{ color: "var(--primary)" }} />
        <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-semibold)", color: "var(--foreground)" }}>
          Threat configuration
        </p>
      </div>

      <label className="flex items-center justify-between rounded-lg border p-3" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)", cursor: "pointer" }}>
        <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", color: "var(--foreground)" }}>Threat integration enabled</span>
        <input type="checkbox" checked={form.enabled} onChange={(e) => update({ enabled: e.target.checked })} />
      </label>

      <div className="flex flex-col gap-1">
        <label style={labelStyle}>Block mode</label>
        <select
          value={form.block_mode}
          onChange={(e) => update({ block_mode: e.target.value as ThreatBlockMode })}
          className="w-full px-3 py-2 rounded-md outline-none"
          style={fieldStyle}
        >
          <option value="alert_only">alert_only — log only, no nftables drops</option>
          <option value="inline_block">inline_block — drop high/critical at nftables</option>
        </select>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div className="flex flex-col gap-1">
          <label style={labelStyle}>Block TTL (seconds)</label>
          <input type="number" min={0} value={form.block_ttl_secs} onChange={(e) => update({ block_ttl_secs: Number(e.target.value) })} className="w-full px-3 py-2 rounded-md outline-none" style={fieldStyle} />
        </div>
        <div className="flex flex-col gap-1">
          <label style={labelStyle}>Rule update (hours, 0 = manual)</label>
          <input type="number" min={0} value={form.rule_update_hours} onChange={(e) => update({ rule_update_hours: Number(e.target.value) })} className="w-full px-3 py-2 rounded-md outline-none" style={fieldStyle} />
        </div>
      </div>

      <div className="flex flex-col gap-1">
        <label style={labelStyle}>Block exempt CIDRs (comma-separated)</label>
        <input
          value={form.block_exempt.join(", ")}
          onChange={(e) => update({ block_exempt: e.target.value.split(",").map((s) => s.trim()).filter(Boolean) })}
          placeholder="127.0.0.0/8, 192.168.100.0/24"
          className="w-full px-3 py-2 rounded-md outline-none"
          style={{ ...fieldStyle, fontFamily: "JetBrains Mono, monospace" }}
        />
      </div>

      {/* Read-only paths for reference */}
      <div className="rounded-lg border overflow-hidden" style={{ borderColor: "var(--border)" }}>
        {[
          { label: "Interface", value: form.interface || "auto" },
          { label: "EVE log", value: form.eve_path },
          { label: "Suricata YAML", value: form.suricata_yaml },
        ].map((row, i, arr) => (
          <div key={row.label} className="flex items-center justify-between px-3 py-2.5" style={{ backgroundColor: "var(--card)", borderBottom: i < arr.length - 1 ? "1px solid var(--border)" : undefined }}>
            <span style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)" }}>{row.label}</span>
            <span style={{ fontFamily: "JetBrains Mono, monospace", fontSize: "var(--text-xs)", color: "var(--foreground)", wordBreak: "break-all", textAlign: "right", marginLeft: 12 }}>{row.value}</span>
          </div>
        ))}
      </div>

      <button
        onClick={save}
        disabled={saving || !dirty}
        className="flex items-center justify-center gap-1 px-3 py-2.5 rounded-md"
        style={{ backgroundColor: "var(--primary)", color: "var(--primary-foreground)", cursor: saving || !dirty ? "not-allowed" : "pointer", opacity: !dirty ? 0.6 : 1, fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)" }}
      >
        {saving ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
        Save config
      </button>
    </div>
  );
}

// ── Shared empty box ────────────────────────────────────────────────────────────

function EmptyBox({ icon: Icon, title, subtitle }: { icon: typeof Shield; title: string; subtitle: string }) {
  return (
    <div className="rounded-lg border p-6 text-center" style={{ backgroundColor: "var(--card)", borderColor: "var(--border)" }}>
      <Icon size={30} style={{ color: "var(--muted-foreground)", margin: "0 auto 10px" }} />
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-sm)", fontWeight: "var(--font-weight-medium)", color: "var(--foreground)" }}>{title}</p>
      <p style={{ fontFamily: "Inter, sans-serif", fontSize: "var(--text-xs)", color: "var(--muted-foreground)", marginTop: "4px" }}>{subtitle}</p>
    </div>
  );
}

// ── Screen ────────────────────────────────────────────────────────────────────

/**
 * The Threat Protection content (4 tabs), without page chrome. Rendered both
 * inline under the Alerts "Threat Protection" segmented tab and standalone at
 * the /alerts/threat route. Fills its parent — wrap in a bounded-height box.
 */
export function ThreatProtectionPanel() {
  const [tab, setTab] = useState<Tab>("overview");

  return (
    <div className="h-full overflow-y-auto">
      <div className="mx-auto w-full max-w-4xl p-4 md:p-6 flex flex-col gap-4">
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

        {tab === "overview" && <OverviewTab onManageConfig={() => setTab("config")} />}
        {tab === "alerts" && <AlertsTab onBlocked={() => setTab("blocks")} />}
        {tab === "blocks" && <BlocksTab onChanged={() => { /* status refresh handled by polling */ }} />}
        {tab === "config" && <ConfigTab onSaved={() => { /* status refresh handled by polling */ }} />}
      </div>
    </div>
  );
}

/** Standalone route wrapper at /alerts/threat (deep link) with page header. */
export function AL08ThreatProtection() {
  const navigate = useNavigate();
  return (
    <div className="flex flex-col h-full">
      <PageHeader title="Threat Protection" subtitle="Suricata IDS/IPS" onBack={() => navigate("/alerts")} />
      <div className="flex-1 min-h-0">
        <ThreatProtectionPanel />
      </div>
    </div>
  );
}

export default AL08ThreatProtection;
